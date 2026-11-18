package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"GADS/common/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LDAP logins must use the same renewable, revocable sessions as local logins.
func TestLDAPUserSessionLifecycle(t *testing.T) {
	withTestLifetimes(t, time.Hour, 24*time.Hour)
	withEmptySessions(t)
	withTestSecretCache(t)

	store := newFakeLoginStore()
	directory := &fakeDirectoryAuthenticator{
		identity:      DirectoryIdentity{Username: "alice", Role: "admin"},
		autoProvision: true,
	}
	user, err := authenticateCredentials(context.Background(), store, directory, AuthCreds{
		Username: "Alice", Password: "ldap-secret",
	})
	require.NoError(t, err)
	require.Equal(t, models.AuthSourceLDAP, user.AuthSource)
	require.Empty(t, user.Password)

	token, err := GenerateJWT(user.Username, user.Role, "tenant1", []string{"user", "admin"})
	require.NoError(t, err)
	claims, err := ValidateJWT(token)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "admin", claims.Role)
	require.NotEmpty(t, claims.SessionID)

	// Activity keeps a directory user's session usable beyond the idle TTL.
	ageSession(t, claims.SessionID, 5*time.Hour, 30*time.Minute)
	require.Equal(t, http.StatusOK, authedRequest(t, token).Code)

	// The absolute lifetime still applies even to an active LDAP session.
	ageSession(t, claims.SessionID, 25*time.Hour, time.Minute)
	assert.Equal(t, http.StatusUnauthorized, authedRequest(t, token).Code)

	token, err = GenerateJWT(user.Username, user.Role, "tenant1", []string{"user", "admin"})
	require.NoError(t, err)
	DeleteSession(sessionIDOf(t, token))
	assert.Equal(t, http.StatusUnauthorized, authedRequest(t, token).Code)
}
