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
	"crypto/tls"
	"errors"
	"testing"
	"time"

	hubconfig "GADS/hub/config"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLDAPConnection struct {
	binds         [][2]string
	bindErrors    []error
	searches      []*ldap.SearchRequest
	searchResults []*ldap.SearchResult
	searchErrors  []error
	timeout       time.Duration
	startedTLS    bool
	closed        bool
}

func (f *fakeLDAPConnection) Bind(username, password string) error {
	f.binds = append(f.binds, [2]string{username, password})
	index := len(f.binds) - 1
	if index < len(f.bindErrors) {
		return f.bindErrors[index]
	}
	return nil
}

func (f *fakeLDAPConnection) Close() error {
	f.closed = true
	return nil
}

func (f *fakeLDAPConnection) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches = append(f.searches, request)
	index := len(f.searches) - 1
	if index < len(f.searchErrors) && f.searchErrors[index] != nil {
		return nil, f.searchErrors[index]
	}
	if index < len(f.searchResults) {
		return f.searchResults[index], nil
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeLDAPConnection) SetTimeout(timeout time.Duration) {
	f.timeout = timeout
}

func (f *fakeLDAPConnection) StartTLS(_ *tls.Config) error {
	f.startedTLS = true
	return nil
}

func testLDAPConfig() hubconfig.LDAPConfig {
	return hubconfig.LDAPConfig{
		Enabled:              true,
		URL:                  "ldap://ldap.example.com:389",
		BaseDN:               "ou=people,dc=example,dc=com",
		BindDN:               "cn=reader,dc=example,dc=com",
		BindPassword:         "reader-secret",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		UsernameAttribute:    "uid",
		StartTLS:             true,
		Timeout:              5 * time.Second,
		GroupMemberAttribute: "member",
		AutoProvision:        true,
	}
}

func TestLDAPAuthenticateEscapesFilterAndBindsReturnedDN(t *testing.T) {
	config := testLDAPConfig()
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{{Entries: []*ldap.Entry{
			ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
		}}},
	}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	identity, err := authenticator.Authenticate(context.Background(), "alice*)(uid=*)", "user-secret")

	require.NoError(t, err)
	assert.Equal(t, DirectoryIdentity{Username: "alice"}, identity)
	require.Len(t, connection.searches, 1)
	assert.Equal(t, "(&(objectClass=person)(uid=alice\\2a\\29\\28uid=\\2a\\29))", connection.searches[0].Filter)
	assert.Equal(t, [][2]string{
		{"cn=reader,dc=example,dc=com", "reader-secret"},
		{"uid=alice,ou=people,dc=example,dc=com", "user-secret"},
	}, connection.binds)
	assert.Equal(t, 5*time.Second, connection.timeout)
	assert.True(t, connection.startedTLS)
	assert.True(t, connection.closed)
}

func TestLDAPAuthenticateRejectsEmptyPasswordBeforeDial(t *testing.T) {
	authenticator, err := NewLDAPAuthenticator(testLDAPConfig())
	require.NoError(t, err)
	dialed := false
	authenticator.dial = func() (ldapConnection, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}

	_, err = authenticator.Authenticate(context.Background(), "alice", "")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.False(t, dialed)
}

func TestLDAPAuthenticateMapsInvalidUserBindToGenericCredentialsError(t *testing.T) {
	connection := &fakeLDAPConnection{
		bindErrors: []error{nil, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password"))},
		searchResults: []*ldap.SearchResult{{Entries: []*ldap.Entry{
			ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
		}}},
	}
	authenticator, err := NewLDAPAuthenticator(testLDAPConfig())
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	_, err = authenticator.Authenticate(context.Background(), "alice", "wrong")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.True(t, connection.closed)
}

func TestLDAPAuthenticateRequiresExactlyOneUser(t *testing.T) {
	tests := []struct {
		name    string
		entries []*ldap.Entry
	}{
		{name: "missing user"},
		{name: "duplicate user", entries: []*ldap.Entry{
			ldap.NewEntry("uid=alice,ou=one,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			ldap.NewEntry("uid=alice,ou=two,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := &fakeLDAPConnection{
				searchResults: []*ldap.SearchResult{{Entries: test.entries}},
			}
			authenticator, err := NewLDAPAuthenticator(testLDAPConfig())
			require.NoError(t, err)
			authenticator.dial = func() (ldapConnection, error) { return connection, nil }

			_, err = authenticator.Authenticate(context.Background(), "alice", "secret")

			assert.ErrorIs(t, err, ErrInvalidCredentials)
			assert.Len(t, connection.binds, 1, "only the service bind should run")
		})
	}
}

func TestLDAPAuthenticateMapsConfiguredAdminGroup(t *testing.T) {
	config := testLDAPConfig()
	config.AdminGroupDN = "cn=gads-admins,ou=groups,dc=example,dc=com"
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{{Entries: []*ldap.Entry{
			ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{
				"uid":      {"alice"},
				"memberOf": {"CN=GADS-ADMINS,OU=GROUPS,DC=EXAMPLE,DC=COM"},
			}),
		}}},
	}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	identity, err := authenticator.Authenticate(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Role)
	assert.Len(t, connection.searches, 1, "memberOf should avoid a second group search")
}

func TestLDAPAuthenticateChecksOpenLDAPGroupMemberAttribute(t *testing.T) {
	config := testLDAPConfig()
	config.AdminGroupDN = "cn=gads-admins,ou=groups,dc=example,dc=com"
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{
			{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			}},
			{Entries: []*ldap.Entry{
				ldap.NewEntry(config.AdminGroupDN, nil),
			}},
		},
	}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	identity, err := authenticator.Authenticate(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Role)
	require.Len(t, connection.searches, 2)
	assert.Equal(t, "cn=gads-admins,ou=groups,dc=example,dc=com", connection.searches[1].BaseDN)
	assert.Equal(t, "(member=uid=alice,ou=people,dc=example,dc=com)", connection.searches[1].Filter)
}

func TestLDAPAuthenticateChecksPosixGroupMemberUID(t *testing.T) {
	config := testLDAPConfig()
	config.AdminGroupDN = "cn=gads-admins,ou=posix-groups,ou=groups,dc=example,dc=com"
	config.GroupMemberAttribute = "memberUid"
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{
			{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			}},
			{Entries: []*ldap.Entry{
				ldap.NewEntry(config.AdminGroupDN, nil),
			}},
		},
	}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	identity, err := authenticator.Authenticate(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Role)
	require.Len(t, connection.searches, 2)
	assert.Equal(t, "(memberUid=alice)", connection.searches[1].Filter)
}

func TestLDAPAuthenticateRequiresAllowedGroupMembership(t *testing.T) {
	config := testLDAPConfig()
	config.AllowedGroupDNs = []string{
		"cn=gads-users,ou=groups,dc=example,dc=com",
		"cn=gads-qa,ou=groups,dc=example,dc=com",
	}
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{
			{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			}},
			{Entries: []*ldap.Entry{}},
		},
	}
	connection.searchResults[1] = &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(config.AllowedGroupDNs[0], nil)}}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	identity, err := authenticator.Authenticate(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "alice", identity.Username)
	assert.Empty(t, identity.Role)
	assert.Len(t, connection.searches, 2)
	assert.Equal(t, "(member=uid=alice,ou=people,dc=example,dc=com)", connection.searches[1].Filter)
}

func TestLDAPAuthenticateRejectsUserOutsideAllowedGroups(t *testing.T) {
	config := testLDAPConfig()
	config.AllowedGroupDNs = []string{"cn=gads-users,ou=groups,dc=example,dc=com"}
	connection := &fakeLDAPConnection{
		searchResults: []*ldap.SearchResult{
			{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			}},
			{Entries: []*ldap.Entry{}},
		},
	}
	authenticator, err := NewLDAPAuthenticator(config)
	require.NoError(t, err)
	authenticator.dial = func() (ldapConnection, error) { return connection, nil }

	_, err = authenticator.Authenticate(context.Background(), "alice", "secret")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Len(t, connection.binds, 1, "the user bind must not run for a disallowed group")
}

func TestNewLDAPAuthenticatorRejectsPlaintextByDefault(t *testing.T) {
	config := testLDAPConfig()
	config.StartTLS = false

	_, err := NewLDAPAuthenticator(config)

	assert.ErrorContains(t, err, "explicit insecure opt-in")
}
