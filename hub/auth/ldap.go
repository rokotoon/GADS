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
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	hubconfig "GADS/hub/config"

	"github.com/go-ldap/ldap/v3"
)

// DirectoryIdentity is the canonical identity returned by an external
// directory. An empty Role means the role remains managed by GADS. When an
// LDAP admin group is configured, Role is always either "admin" or "user".
type DirectoryIdentity struct {
	Username string
	Role     string
}

// DirectoryAuthenticator verifies credentials against an external directory.
// AutoProvision reports whether a missing local authorization profile may be
// created after successful directory authentication.
type DirectoryAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (DirectoryIdentity, error)
	AutoProvision() bool
}

type ldapConnection interface {
	Bind(username, password string) error
	Close() error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeout(timeout time.Duration)
	StartTLS(config *tls.Config) error
}

// LDAPAuthenticator authenticates users by searching for their entry with a
// service (or anonymous) connection and binding as the returned user DN.
type LDAPAuthenticator struct {
	config          hubconfig.LDAPConfig
	tlsConfig       *tls.Config
	adminGroupDN    *ldap.DN
	allowedGroupDNs []*ldap.DN
	dial            func() (ldapConnection, error)
}

var directoryAuthenticator DirectoryAuthenticator

var ldapAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$`)

// InitLDAPAuthenticator configures the process-wide LDAP authenticator. LDAP
// remains disabled (and legacy local authentication remains unchanged) unless
// config.Enabled is true.
func InitLDAPAuthenticator(config hubconfig.LDAPConfig) error {
	if !config.Enabled {
		directoryAuthenticator = nil
		return nil
	}

	authenticator, err := NewLDAPAuthenticator(config)
	if err != nil {
		return err
	}
	directoryAuthenticator = authenticator
	return nil
}

func getDirectoryAuthenticator() DirectoryAuthenticator {
	return directoryAuthenticator
}

// NewLDAPAuthenticator validates runtime LDAP settings and prepares a client.
// It deliberately does not connect during startup, so a temporary directory
// outage does not prevent the hub itself from starting.
func NewLDAPAuthenticator(config hubconfig.LDAPConfig) (*LDAPAuthenticator, error) {
	parsedURL, err := validateLDAPRuntimeConfig(config)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := newLDAPTLSConfig(config, parsedURL.Hostname())
	if err != nil {
		return nil, err
	}

	var adminGroupDN *ldap.DN
	if config.AdminGroupDN != "" {
		adminGroupDN, err = ldap.ParseDN(config.AdminGroupDN)
		if err != nil {
			return nil, fmt.Errorf("invalid LDAP admin group DN: %w", err)
		}
	}
	allowedGroupDNs := make([]*ldap.DN, 0, len(config.AllowedGroupDNs))
	for _, groupDN := range config.AllowedGroupDNs {
		parsedGroupDN, err := ldap.ParseDN(groupDN)
		if err != nil {
			return nil, fmt.Errorf("invalid LDAP allowed group DN: %w", err)
		}
		allowedGroupDNs = append(allowedGroupDNs, parsedGroupDN)
	}

	authenticator := &LDAPAuthenticator{
		config:          config,
		tlsConfig:       tlsConfig,
		adminGroupDN:    adminGroupDN,
		allowedGroupDNs: allowedGroupDNs,
	}
	authenticator.dial = func() (ldapConnection, error) {
		options := []ldap.DialOpt{
			ldap.DialWithDialer(&net.Dialer{Timeout: config.Timeout}),
		}
		if parsedURL.Scheme == "ldaps" {
			options = append(options, ldap.DialWithTLSConfig(tlsConfig.Clone()))
		}
		return ldap.DialURL(config.URL, options...)
	}

	return authenticator, nil
}

func validateLDAPRuntimeConfig(config hubconfig.LDAPConfig) (*url.URL, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("LDAP authenticator cannot be created while LDAP is disabled")
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("LDAP timeout must be greater than zero")
	}
	if config.BaseDN == "" {
		return nil, fmt.Errorf("LDAP base DN is required")
	}
	if _, err := ldap.ParseDN(config.BaseDN); err != nil {
		return nil, fmt.Errorf("invalid LDAP base DN: %w", err)
	}
	if config.BindDN != "" {
		if _, err := ldap.ParseDN(config.BindDN); err != nil {
			return nil, fmt.Errorf("invalid LDAP bind DN: %w", err)
		}
	}
	if (config.BindDN == "") != (config.BindPassword == "") {
		return nil, fmt.Errorf("LDAP bind DN and bind password must be provided together")
	}
	if !strings.Contains(config.UserFilter, "{username}") {
		return nil, fmt.Errorf("LDAP user filter must contain {username}")
	}
	if !ldapAttributePattern.MatchString(config.UsernameAttribute) {
		return nil, fmt.Errorf("invalid LDAP username attribute %q", config.UsernameAttribute)
	}
	if !ldapAttributePattern.MatchString(config.GroupMemberAttribute) {
		return nil, fmt.Errorf("invalid LDAP group member attribute %q", config.GroupMemberAttribute)
	}

	parsedURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP URL: %w", err)
	}
	if parsedURL.Scheme != "ldap" && parsedURL.Scheme != "ldaps" {
		return nil, fmt.Errorf("LDAP URL scheme must be ldap or ldaps")
	}
	if parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("LDAP URL must include a host")
	}
	if parsedURL.Scheme == "ldaps" && config.StartTLS {
		return nil, fmt.Errorf("LDAP StartTLS cannot be combined with an ldaps URL")
	}
	if parsedURL.Scheme == "ldap" && !config.StartTLS && !config.AllowInsecure {
		return nil, fmt.Errorf("plain LDAP requires StartTLS or explicit insecure opt-in")
	}

	return parsedURL, nil
}

func newLDAPTLSConfig(config hubconfig.LDAPConfig, serverName string) (*tls.Config, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if config.CACertFile != "" {
		certificate, err := os.ReadFile(config.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read LDAP CA certificate: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(certificate); !ok {
			return nil, fmt.Errorf("LDAP CA certificate contains no valid PEM certificates")
		}
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		RootCAs:            rootCAs,
		InsecureSkipVerify: config.InsecureSkipVerify, // Explicit operator opt-in for private test directories.
	}, nil
}

func (a *LDAPAuthenticator) AutoProvision() bool {
	return a.config.AutoProvision
}

// Authenticate performs an escaped subtree search and then verifies the
// supplied password by binding as the exact DN returned by LDAP.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (DirectoryIdentity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return DirectoryIdentity{}, ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return DirectoryIdentity{}, err
	}

	connection, err := a.dial()
	if err != nil {
		return DirectoryIdentity{}, fmt.Errorf("connect to LDAP: %w", err)
	}
	defer connection.Close() //nolint:errcheck
	connection.SetTimeout(a.config.Timeout)

	if a.config.StartTLS {
		if err = connection.StartTLS(a.tlsConfig.Clone()); err != nil {
			return DirectoryIdentity{}, fmt.Errorf("start LDAP TLS: %w", err)
		}
	}

	if a.config.BindDN != "" {
		if err = connection.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return DirectoryIdentity{}, fmt.Errorf("LDAP service bind failed: %w", err)
		}
	}

	filter := strings.ReplaceAll(a.config.UserFilter, "{username}", ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		ldapSearchTimeLimit(a.config.Timeout),
		false,
		filter,
		[]string{a.config.UsernameAttribute, "memberOf"},
		nil,
	)
	searchResult, err := connection.Search(searchRequest)
	if err != nil {
		return DirectoryIdentity{}, fmt.Errorf("search LDAP user: %w", err)
	}
	if len(searchResult.Entries) != 1 {
		return DirectoryIdentity{}, ErrInvalidCredentials
	}

	entry := searchResult.Entries[0]
	canonicalUsername := strings.TrimSpace(entry.GetAttributeValue(a.config.UsernameAttribute))
	if entry.DN == "" || canonicalUsername == "" {
		return DirectoryIdentity{}, fmt.Errorf("LDAP user entry is missing its DN or %s attribute", a.config.UsernameAttribute)
	}

	role := ""
	if len(a.allowedGroupDNs) > 0 {
		allowed, err := a.isMemberOfAnyGroup(connection, entry)
		if err != nil {
			return DirectoryIdentity{}, err
		}
		if !allowed {
			return DirectoryIdentity{}, ErrInvalidCredentials
		}
	}
	if a.adminGroupDN != nil {
		isAdmin, err := a.isAdmin(connection, entry)
		if err != nil {
			return DirectoryIdentity{}, err
		}
		role = "user"
		if isAdmin {
			role = "admin"
		}
	}

	if err = connection.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return DirectoryIdentity{}, ErrInvalidCredentials
		}
		return DirectoryIdentity{}, fmt.Errorf("LDAP user bind failed: %w", err)
	}

	return DirectoryIdentity{Username: canonicalUsername, Role: role}, nil
}

func (a *LDAPAuthenticator) isAdmin(connection ldapConnection, entry *ldap.Entry) (bool, error) {
	return a.isMemberOfGroup(connection, entry, a.adminGroupDN)
}

func (a *LDAPAuthenticator) isMemberOfAnyGroup(connection ldapConnection, entry *ldap.Entry) (bool, error) {
	for _, groupDN := range a.allowedGroupDNs {
		member, err := a.isMemberOfGroup(connection, entry, groupDN)
		if err != nil {
			return false, err
		}
		if member {
			return true, nil
		}
	}
	return false, nil
}

func (a *LDAPAuthenticator) isMemberOfGroup(connection ldapConnection, entry *ldap.Entry, groupDN *ldap.DN) (bool, error) {
	for _, memberOf := range entry.GetAttributeValues("memberOf") {
		memberOfDN, err := ldap.ParseDN(memberOf)
		if err == nil && groupDN.EqualFold(memberOfDN) {
			return true, nil
		}
	}

	// OpenLDAP posixGroup entries conventionally store login names in
	// memberUid, while groupOfNames/uniqueGroup entries store full user DNs.
	// Support both forms so the configured group member attribute matches the
	// directory schema rather than assuming every group stores DNs.
	memberValue := entry.DN
	if strings.EqualFold(a.config.GroupMemberAttribute, "memberUid") {
		memberValue = entry.GetAttributeValue(a.config.UsernameAttribute)
		if strings.TrimSpace(memberValue) == "" {
			return false, fmt.Errorf("LDAP user entry is missing its %s attribute", a.config.UsernameAttribute)
		}
	}
	groupFilter := fmt.Sprintf("(%s=%s)", a.config.GroupMemberAttribute, ldap.EscapeFilter(memberValue))
	request := ldap.NewSearchRequest(
		groupDN.String(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		ldapSearchTimeLimit(a.config.Timeout),
		false,
		groupFilter,
		[]string{"dn"},
		nil,
	)
	result, err := connection.Search(request)
	if err != nil {
		return false, fmt.Errorf("check LDAP admin group membership: %w", err)
	}
	return len(result.Entries) == 1, nil
}

func ldapSearchTimeLimit(timeout time.Duration) int {
	seconds := int(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}
