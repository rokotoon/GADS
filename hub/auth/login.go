/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"GADS/common/models"

	"go.mongodb.org/mongo-driver/mongo"
)

// ErrInvalidCredentials is intentionally shared by unknown users and invalid
// passwords so the HTTP layer never exposes which part of authentication
// failed.
var ErrInvalidCredentials = errors.New("invalid credentials")

type loginStore interface {
	GetUser(username string) (models.User, error)
	AddOrUpdateUser(user models.User) error
	GetDefaultWorkspace() (models.Workspace, error)
}

func authenticateCredentials(ctx context.Context, store loginStore, directory DirectoryAuthenticator, creds AuthCreds) (models.User, error) {
	username := strings.TrimSpace(creds.Username)
	if username == "" || creds.Password == "" {
		return models.User{}, ErrInvalidCredentials
	}

	submittedUser, err := store.GetUser(username)
	if err == nil && authenticationSource(submittedUser) != models.AuthSourceLDAP {
		if subtle.ConstantTimeCompare([]byte(submittedUser.Password), []byte(creds.Password)) != 1 {
			return models.User{}, ErrInvalidCredentials
		}
		return submittedUser, nil
	}
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return models.User{}, fmt.Errorf("load user profile: %w", err)
	}
	if directory == nil {
		return models.User{}, ErrInvalidCredentials
	}

	identity, err := directory.Authenticate(ctx, username, creds.Password)
	if err != nil {
		return models.User{}, err
	}
	identity.Username = strings.TrimSpace(identity.Username)
	if identity.Username == "" {
		return models.User{}, fmt.Errorf("directory returned an empty username")
	}
	// The built-in local admin is a deliberately separate break-glass account.
	// A differently-cased directory identity must not create a second admin-like
	// account or take over that local profile.
	if strings.EqualFold(identity.Username, "admin") {
		return models.User{}, ErrInvalidCredentials
	}

	canonicalUser, canonicalErr := store.GetUser(identity.Username)
	if canonicalErr == nil {
		if authenticationSource(canonicalUser) != models.AuthSourceLDAP {
			return models.User{}, ErrInvalidCredentials
		}
		return syncLDAPUser(store, canonicalUser, identity)
	}
	if !errors.Is(canonicalErr, mongo.ErrNoDocuments) {
		return models.User{}, fmt.Errorf("load canonical LDAP user profile: %w", canonicalErr)
	}

	// A manually provisioned LDAP profile must use the configured canonical
	// username attribute. This avoids silently cloning an alias into a new user.
	if err == nil && submittedUser.Username != "" && authenticationSource(submittedUser) == models.AuthSourceLDAP {
		return models.User{}, fmt.Errorf("LDAP profile username %q does not match canonical username %q", submittedUser.Username, identity.Username)
	}
	if !directory.AutoProvision() {
		return models.User{}, ErrInvalidCredentials
	}

	return provisionLDAPUser(store, identity)
}

func authenticationSource(user models.User) string {
	if user.AuthSource == models.AuthSourceLDAP {
		return models.AuthSourceLDAP
	}
	return models.AuthSourceLocal
}

func provisionLDAPUser(store loginStore, identity DirectoryIdentity) (models.User, error) {
	role, err := ldapRole(identity.Role, "user")
	if err != nil {
		return models.User{}, err
	}

	user := models.User{
		Username:   identity.Username,
		Role:       role,
		AuthSource: models.AuthSourceLDAP,
	}
	if role == "user" {
		workspace, err := store.GetDefaultWorkspace()
		if err != nil {
			return models.User{}, fmt.Errorf("load default workspace for LDAP user: %w", err)
		}
		user.WorkspaceIDs = []string{workspace.ID}
	}
	if err := store.AddOrUpdateUser(user); err != nil {
		return models.User{}, fmt.Errorf("provision LDAP user: %w", err)
	}
	return user, nil
}

func syncLDAPUser(store loginStore, user models.User, identity DirectoryIdentity) (models.User, error) {
	role, err := ldapRole(identity.Role, user.Role)
	if err != nil {
		return models.User{}, err
	}
	if role == "" {
		role = "user"
	}

	user.Role = role
	user.AuthSource = models.AuthSourceLDAP
	user.Password = ""
	if role == "user" && len(user.WorkspaceIDs) == 0 {
		workspace, err := store.GetDefaultWorkspace()
		if err != nil {
			return models.User{}, fmt.Errorf("load default workspace for LDAP user: %w", err)
		}
		user.WorkspaceIDs = []string{workspace.ID}
	}

	toPersist := user
	toPersist.ID = "" // Never include MongoDB's immutable _id in a $set update.
	if err := store.AddOrUpdateUser(toPersist); err != nil {
		return models.User{}, fmt.Errorf("synchronize LDAP user: %w", err)
	}
	return user, nil
}

func ldapRole(directoryRole, currentRole string) (string, error) {
	if directoryRole == "" {
		return currentRole, nil
	}
	if directoryRole != "admin" && directoryRole != "user" {
		return "", fmt.Errorf("directory returned unsupported role %q", directoryRole)
	}
	return directoryRole, nil
}
