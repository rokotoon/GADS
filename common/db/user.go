/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package db

import (
	"GADS/common/models"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (m *MongoStore) GetUser(username string) (models.User, error) {
	coll := m.GetCollection("users")
	filter := bson.D{{Key: "username", Value: username}}
	return GetDocument[models.User](m.Ctx, coll, filter)
}

func (m *MongoStore) GetUsers() ([]models.User, error) {
	coll := m.GetCollection("users")
	return GetDocuments[models.User](m.Ctx, coll, bson.D{{}})
}

func (m *MongoStore) AddOrUpdateUser(user models.User) error {
	coll := m.GetCollection("users")
	filter := bson.D{{Key: "username", Value: user.Username}}
	if user.AuthSource == models.AuthSourceLDAP {
		// LDAP credentials are verified by the directory and must never be stored
		// in the local user document, including records created by non-HTTP callers.
		user.Password = ""
		update := bson.M{
			"$set":   user,
			"$unset": bson.M{"password": ""},
		}
		_, err := coll.UpdateOne(m.Ctx, filter, update, options.Update().SetUpsert(true))
		return err
	}
	return UpsertDocument[models.User](m.Ctx, coll, filter, user)
}

// CreateUserIndexes creates the indexes needed to keep user identities unique.
func (m *MongoStore) CreateUserIndexes() error {
	coll := m.GetCollection("users")
	_, err := coll.Indexes().CreateOne(m.Ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (m *MongoStore) DeleteUser(nickname string) error {
	coll := m.GetCollection("users")
	filter := bson.M{"username": nickname}
	return DeleteDocument(m.Ctx, coll, filter)
}

func (m *MongoStore) AddAdminUserIfMissing() error {
	dbUser, err := GlobalMongoStore.GetUser("admin")
	if err != nil && err != mongo.ErrNoDocuments {
		return fmt.Errorf("AddAdminUserIfMissing: Failed to check if admin user is in the DB - %s", err)
	}

	if dbUser.Username != "" {
		return nil // User exists
	}

	err = GlobalMongoStore.AddOrUpdateUser(models.User{Username: "admin", Password: "password", Role: "admin", AuthSource: models.AuthSourceLocal})
	if err != nil {
		return fmt.Errorf("Failed to add/update admin user - %s", err)
	}
	return nil
}

func (m *MongoStore) UpdateUserWorkspaces(username string, workspaceIDs []string) error {
	coll := m.GetCollection("users")
	filter := bson.M{"username": username}
	updates := bson.M{
		"workspace_ids": workspaceIDs,
	}
	return PartialDocumentUpdate(m.Ctx, coll, filter, updates)
}

// UpdateUserPassword updates only the password field for the given user, leaving
// role and workspaces untouched (a full upsert of a partial User struct would
// clobber those fields).
func (m *MongoStore) UpdateUserPassword(username, newPassword string) error {
	coll := m.GetCollection("users")
	filter := bson.M{"username": username}
	updates := bson.M{
		"password": newPassword,
	}
	return PartialDocumentUpdate(m.Ctx, coll, filter, updates)
}
