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
	"errors"
	"testing"

	"GADS/common/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
)

type fakeLoginStore struct {
	users            map[string]models.User
	defaultWorkspace models.Workspace
	writes           []models.User
	getErr           error
	writeErr         error
}

func (f *fakeLoginStore) GetUser(username string) (models.User, error) {
	if f.getErr != nil {
		return models.User{}, f.getErr
	}
	user, ok := f.users[username]
	if !ok {
		return models.User{}, mongo.ErrNoDocuments
	}
	return user, nil
}

func (f *fakeLoginStore) AddOrUpdateUser(user models.User) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, user)
	f.users[user.Username] = user
	return nil
}

func (f *fakeLoginStore) GetDefaultWorkspace() (models.Workspace, error) {
	return f.defaultWorkspace, nil
}

type fakeDirectoryAuthenticator struct {
	identity      DirectoryIdentity
	err           error
	autoProvision bool
	calls         int
}

func (f *fakeDirectoryAuthenticator) Authenticate(_ context.Context, _, _ string) (DirectoryIdentity, error) {
	f.calls++
	return f.identity, f.err
}

func (f *fakeDirectoryAuthenticator) AutoProvision() bool {
	return f.autoProvision
}

func newFakeLoginStore(users ...models.User) *fakeLoginStore {
	store := &fakeLoginStore{
		users:            make(map[string]models.User),
		defaultWorkspace: models.Workspace{ID: "default-workspace", IsDefault: true},
	}
	for _, user := range users {
		store.users[user.Username] = user
	}
	return store
}

func TestAuthenticateCredentialsKeepsLegacyLocalAuthentication(t *testing.T) {
	store := newFakeLoginStore(models.User{Username: "local-user", Password: "secret", Role: "user"})
	directory := &fakeDirectoryAuthenticator{err: errors.New("must not be called")}

	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "local-user", Password: "secret"})

	require.NoError(t, err)
	assert.Equal(t, "local-user", user.Username)
	assert.Zero(t, directory.calls)
}

func TestAuthenticateCredentialsNeverFallsBackAfterWrongLocalPassword(t *testing.T) {
	store := newFakeLoginStore(models.User{Username: "local-user", Password: "local-secret", Role: "user"})
	directory := &fakeDirectoryAuthenticator{
		identity: DirectoryIdentity{Username: "local-user"},
	}

	_, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "local-user", Password: "ldap-secret"})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Zero(t, directory.calls)
}

func TestAuthenticateCredentialsAutoProvisionsLDAPUser(t *testing.T) {
	store := newFakeLoginStore()
	directory := &fakeDirectoryAuthenticator{
		identity:      DirectoryIdentity{Username: "alice"},
		autoProvision: true,
	}

	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "Alice", Password: "secret"})

	require.NoError(t, err)
	assert.Equal(t, models.AuthSourceLDAP, user.AuthSource)
	assert.Equal(t, "user", user.Role)
	assert.Equal(t, []string{"default-workspace"}, user.WorkspaceIDs)
	assert.Empty(t, user.Password)
	require.Len(t, store.writes, 1)
	assert.Equal(t, "alice", store.writes[0].Username)
}

func TestAuthenticateCredentialsHonorsDisabledAutoProvision(t *testing.T) {
	store := newFakeLoginStore()
	directory := &fakeDirectoryAuthenticator{
		identity: DirectoryIdentity{Username: "alice"},
	}

	_, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice", Password: "secret"})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Empty(t, store.writes)
}

func TestAuthenticateCredentialsPreservesMongoRoleWithoutGroupMapping(t *testing.T) {
	store := newFakeLoginStore(models.User{
		Username:     "alice",
		Role:         "admin",
		AuthSource:   models.AuthSourceLDAP,
		WorkspaceIDs: []string{"workspace-a"},
	})
	directory := &fakeDirectoryAuthenticator{identity: DirectoryIdentity{Username: "alice"}}

	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice", Password: "secret"})

	require.NoError(t, err)
	assert.Equal(t, "admin", user.Role)
	assert.Equal(t, []string{"workspace-a"}, user.WorkspaceIDs)
}

func TestAuthenticateCredentialsSynchronizesAdminGroupRole(t *testing.T) {
	store := newFakeLoginStore(models.User{
		Username:   "alice",
		Role:       "user",
		AuthSource: models.AuthSourceLDAP,
	})
	directory := &fakeDirectoryAuthenticator{identity: DirectoryIdentity{Username: "alice", Role: "admin"}}

	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice", Password: "secret"})

	require.NoError(t, err)
	assert.Equal(t, "admin", user.Role)
	require.Len(t, store.writes, 1)
	assert.Equal(t, "admin", store.writes[0].Role)
}

func TestAuthenticateCredentialsDemotesRemovedLDAPAdminAndAddsWorkspace(t *testing.T) {
	store := newFakeLoginStore(models.User{
		Username:   "alice",
		Role:       "admin",
		AuthSource: models.AuthSourceLDAP,
	})
	directory := &fakeDirectoryAuthenticator{identity: DirectoryIdentity{Username: "alice", Role: "user"}}

	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice", Password: "secret"})

	require.NoError(t, err)
	assert.Equal(t, "user", user.Role)
	assert.Equal(t, []string{"default-workspace"}, user.WorkspaceIDs)
}

func TestAuthenticateCredentialsRejectsCanonicalLocalCollision(t *testing.T) {
	store := newFakeLoginStore(models.User{
		Username:   "alice",
		Password:   "local-secret",
		Role:       "admin",
		AuthSource: models.AuthSourceLocal,
	})
	directory := &fakeDirectoryAuthenticator{
		identity:      DirectoryIdentity{Username: "alice"},
		autoProvision: true,
	}

	_, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice@example.com", Password: "ldap-secret"})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Empty(t, store.writes)
}

func TestAuthenticateCredentialsNeverLetsLDAPTakeOverAdmin(t *testing.T) {
	store := newFakeLoginStore()
	directory := &fakeDirectoryAuthenticator{
		identity:      DirectoryIdentity{Username: "Admin", Role: "admin"},
		autoProvision: true,
	}

	_, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "Admin", Password: "secret"})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Empty(t, store.writes)
}

func TestAuthenticateCredentialsReturnsStoreFailures(t *testing.T) {
	store := newFakeLoginStore()
	store.getErr = errors.New("database unavailable")
	directory := &fakeDirectoryAuthenticator{}

	_, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{Username: "alice", Password: "secret"})

	assert.ErrorContains(t, err, "load user profile")
	assert.Zero(t, directory.calls)
}
