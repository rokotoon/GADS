/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterLDAPFlags(t *testing.T) {
	flags := newLDAPTestFlagSet(t)

	registeredFlags := []struct {
		name         string
		defaultValue string
	}{
		{name: "ldap-enabled", defaultValue: "false"},
		{name: "ldap-url", defaultValue: ""},
		{name: "ldap-base-dn", defaultValue: ""},
		{name: "ldap-bind-dn", defaultValue: ""},
		{name: "ldap-bind-password", defaultValue: ""},
		{name: "ldap-user-filter", defaultValue: DefaultLDAPUserFilter},
		{name: "ldap-username-attribute", defaultValue: DefaultLDAPUsernameAttribute},
		{name: "ldap-start-tls", defaultValue: "false"},
		{name: "ldap-ca-cert-file", defaultValue: ""},
		{name: "ldap-insecure-skip-verify", defaultValue: "false"},
		{name: "ldap-allow-insecure", defaultValue: "false"},
		{name: "ldap-timeout", defaultValue: DefaultLDAPTimeout.String()},
		{name: "ldap-admin-group-dn", defaultValue: ""},
		{name: "ldap-group-member-attribute", defaultValue: DefaultLDAPGroupMemberAttribute},
		{name: "ldap-auto-provision", defaultValue: "true"},
	}

	for _, registeredFlag := range registeredFlags {
		t.Run(registeredFlag.name, func(t *testing.T) {
			flag := flags.Lookup(registeredFlag.name)
			require.NotNil(t, flag)
			assert.Equal(t, registeredFlag.defaultValue, flag.DefValue)
		})
	}
}

func TestLoadLDAPConfigDefaults(t *testing.T) {
	config, err := loadLDAPConfig(newLDAPTestFlagSet(t), emptyEnvironment)
	require.NoError(t, err)

	assert.Equal(t, LDAPConfig{
		Enabled:              false,
		UserFilter:           DefaultLDAPUserFilter,
		UsernameAttribute:    DefaultLDAPUsernameAttribute,
		Timeout:              DefaultLDAPTimeout,
		GroupMemberAttribute: DefaultLDAPGroupMemberAttribute,
		AutoProvision:        true,
	}, config)
}

func TestLoadLDAPConfigFromEnvironment(t *testing.T) {
	environment := map[string]string{
		"GADS_LDAP_ENABLED":                "true",
		"GADS_LDAP_URL":                    "ldap://ldap.example.test:1389",
		"GADS_LDAP_BASE_DN":                "ou=people,dc=example,dc=test",
		"GADS_LDAP_BIND_DN":                "cn=gads,ou=services,dc=example,dc=test",
		"GADS_LDAP_BIND_PASSWORD":          "environment-secret",
		"GADS_LDAP_USER_FILTER":            "(&(objectClass=inetOrgPerson)(mail={username}))",
		"GADS_LDAP_USERNAME_ATTRIBUTE":     "mail",
		"GADS_LDAP_START_TLS":              "true",
		"GADS_LDAP_CA_CERT_FILE":           "/etc/gads/ldap-ca.pem",
		"GADS_LDAP_INSECURE_SKIP_VERIFY":   "true",
		"GADS_LDAP_ALLOW_INSECURE":         "false",
		"GADS_LDAP_TIMEOUT":                "12s",
		"GADS_LDAP_ADMIN_GROUP_DN":         "cn=gads-admins,ou=groups,dc=example,dc=test",
		"GADS_LDAP_GROUP_MEMBER_ATTRIBUTE": "uniqueMember",
		"GADS_LDAP_AUTO_PROVISION":         "false",
	}

	config, err := loadLDAPConfig(newLDAPTestFlagSet(t), mapEnvironment(environment))
	require.NoError(t, err)

	assert.Equal(t, LDAPConfig{
		Enabled:              true,
		URL:                  "ldap://ldap.example.test:1389",
		BaseDN:               "ou=people,dc=example,dc=test",
		BindDN:               "cn=gads,ou=services,dc=example,dc=test",
		BindPassword:         "environment-secret",
		UserFilter:           "(&(objectClass=inetOrgPerson)(mail={username}))",
		UsernameAttribute:    "mail",
		StartTLS:             true,
		CACertFile:           "/etc/gads/ldap-ca.pem",
		InsecureSkipVerify:   true,
		AllowInsecure:        false,
		Timeout:              12 * time.Second,
		AdminGroupDN:         "cn=gads-admins,ou=groups,dc=example,dc=test",
		GroupMemberAttribute: "uniqueMember",
		AutoProvision:        false,
	}, config)
}

func TestLoadLDAPConfigExplicitFlagsOverrideEnvironment(t *testing.T) {
	environment := map[string]string{
		"GADS_LDAP_ENABLED":                "false",
		"GADS_LDAP_URL":                    "ldaps://environment.example.test:636",
		"GADS_LDAP_BASE_DN":                "dc=environment,dc=test",
		"GADS_LDAP_BIND_DN":                "cn=environment,dc=environment,dc=test",
		"GADS_LDAP_BIND_PASSWORD":          "environment-secret",
		"GADS_LDAP_USER_FILTER":            "(mail={username})",
		"GADS_LDAP_USERNAME_ATTRIBUTE":     "mail",
		"GADS_LDAP_START_TLS":              "true",
		"GADS_LDAP_CA_CERT_FILE":           "/environment/ca.pem",
		"GADS_LDAP_INSECURE_SKIP_VERIFY":   "true",
		"GADS_LDAP_ALLOW_INSECURE":         "true",
		"GADS_LDAP_TIMEOUT":                "30s",
		"GADS_LDAP_ADMIN_GROUP_DN":         "cn=environment-admins,dc=environment,dc=test",
		"GADS_LDAP_GROUP_MEMBER_ATTRIBUTE": "uniqueMember",
		"GADS_LDAP_AUTO_PROVISION":         "false",
	}
	flags := newLDAPTestFlagSet(t,
		"--ldap-enabled=true",
		"--ldap-url=ldaps://flags.example.test:636",
		"--ldap-base-dn=dc=flags,dc=test",
		"--ldap-bind-dn=cn=flags,dc=flags,dc=test",
		"--ldap-bind-password=flag-secret",
		"--ldap-user-filter=(uid={username})",
		"--ldap-username-attribute=uid",
		"--ldap-start-tls=false",
		"--ldap-ca-cert-file=/flags/ca.pem",
		"--ldap-insecure-skip-verify=false",
		"--ldap-allow-insecure=false",
		"--ldap-timeout=9s",
		"--ldap-admin-group-dn=cn=flag-admins,dc=flags,dc=test",
		"--ldap-group-member-attribute=memberUid",
		"--ldap-auto-provision=true",
	)

	config, err := loadLDAPConfig(flags, mapEnvironment(environment))
	require.NoError(t, err)

	assert.Equal(t, LDAPConfig{
		Enabled:              true,
		URL:                  "ldaps://flags.example.test:636",
		BaseDN:               "dc=flags,dc=test",
		BindDN:               "cn=flags,dc=flags,dc=test",
		BindPassword:         "flag-secret",
		UserFilter:           "(uid={username})",
		UsernameAttribute:    "uid",
		StartTLS:             false,
		CACertFile:           "/flags/ca.pem",
		InsecureSkipVerify:   false,
		AllowInsecure:        false,
		Timeout:              9 * time.Second,
		AdminGroupDN:         "cn=flag-admins,dc=flags,dc=test",
		GroupMemberAttribute: "memberUid",
		AutoProvision:        true,
	}, config)
}

func TestLoadLDAPConfigExplicitFalseOverridesEnvironmentTrue(t *testing.T) {
	flags := newLDAPTestFlagSet(t,
		"--ldap-enabled=false",
		"--ldap-start-tls=false",
		"--ldap-insecure-skip-verify=false",
		"--ldap-allow-insecure=false",
		"--ldap-auto-provision=false",
	)
	environment := map[string]string{
		"GADS_LDAP_ENABLED":              "true",
		"GADS_LDAP_START_TLS":            "true",
		"GADS_LDAP_INSECURE_SKIP_VERIFY": "true",
		"GADS_LDAP_ALLOW_INSECURE":       "true",
		"GADS_LDAP_AUTO_PROVISION":       "true",
	}

	config, err := loadLDAPConfig(flags, mapEnvironment(environment))
	require.NoError(t, err)

	assert.False(t, config.Enabled)
	assert.False(t, config.StartTLS)
	assert.False(t, config.InsecureSkipVerify)
	assert.False(t, config.AllowInsecure)
	assert.False(t, config.AutoProvision)
}

func TestLoadLDAPConfigExplicitFlagIgnoresMalformedEnvironmentValue(t *testing.T) {
	flags := newLDAPTestFlagSet(t,
		"--ldap-enabled=false",
		"--ldap-timeout=7s",
	)
	environment := map[string]string{
		"GADS_LDAP_ENABLED": "not-a-boolean",
		"GADS_LDAP_TIMEOUT": "not-a-duration",
	}

	config, err := loadLDAPConfig(flags, mapEnvironment(environment))
	require.NoError(t, err)
	assert.False(t, config.Enabled)
	assert.Equal(t, 7*time.Second, config.Timeout)
}

func TestLoadLDAPConfigRejectsMalformedEnvironmentValues(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		errorText   string
	}{
		{
			name:        "invalid boolean",
			environment: map[string]string{"GADS_LDAP_ENABLED": "sometimes"},
			errorText:   "GADS_LDAP_ENABLED must be a boolean",
		},
		{
			name:        "invalid duration",
			environment: map[string]string{"GADS_LDAP_TIMEOUT": "eventually"},
			errorText:   "GADS_LDAP_TIMEOUT must be a duration",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadLDAPConfig(newLDAPTestFlagSet(t), mapEnvironment(test.environment))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errorText)
		})
	}
}

func TestLDAPConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*LDAPConfig)
		errorText string
	}{
		{name: "valid LDAPS configuration"},
		{
			name: "disabled configuration is backward compatible",
			mutate: func(config *LDAPConfig) {
				*config = LDAPConfig{Enabled: false}
			},
		},
		{
			name:      "missing URL",
			mutate:    func(config *LDAPConfig) { config.URL = "" },
			errorText: "LDAP URL is required",
		},
		{
			name:      "missing base DN",
			mutate:    func(config *LDAPConfig) { config.BaseDN = " " },
			errorText: "LDAP base DN is required",
		},
		{
			name:      "malformed URL",
			mutate:    func(config *LDAPConfig) { config.URL = "%" },
			errorText: "LDAP URL is invalid",
		},
		{
			name:      "unsupported URL scheme",
			mutate:    func(config *LDAPConfig) { config.URL = "https://ldap.example.test" },
			errorText: "scheme must be ldap or ldaps",
		},
		{
			name:      "missing URL host",
			mutate:    func(config *LDAPConfig) { config.URL = "ldaps:///directory" },
			errorText: "must include a host",
		},
		{
			name: "StartTLS with LDAPS",
			mutate: func(config *LDAPConfig) {
				config.StartTLS = true
			},
			errorText: "StartTLS cannot be used with an ldaps URL",
		},
		{
			name: "plain LDAP without explicit opt-in",
			mutate: func(config *LDAPConfig) {
				config.URL = "ldap://ldap.example.test:389"
			},
			errorText: "plain ldap requires StartTLS or explicit allow-insecure",
		},
		{
			name: "plain LDAP with StartTLS",
			mutate: func(config *LDAPConfig) {
				config.URL = "ldap://ldap.example.test:389"
				config.StartTLS = true
			},
		},
		{
			name: "explicitly allowed insecure LDAP",
			mutate: func(config *LDAPConfig) {
				config.URL = "ldap://ldap.example.test:389"
				config.AllowInsecure = true
			},
		},
		{
			name:      "zero timeout",
			mutate:    func(config *LDAPConfig) { config.Timeout = 0 },
			errorText: "timeout must be greater than zero",
		},
		{
			name:      "negative timeout",
			mutate:    func(config *LDAPConfig) { config.Timeout = -time.Second },
			errorText: "timeout must be greater than zero",
		},
		{
			name:      "bind DN without password",
			mutate:    func(config *LDAPConfig) { config.BindPassword = "" },
			errorText: "bind DN and bind password must be provided together",
		},
		{
			name:      "bind password without DN",
			mutate:    func(config *LDAPConfig) { config.BindDN = "" },
			errorText: "bind DN and bind password must be provided together",
		},
		{
			name:      "filter without username placeholder",
			mutate:    func(config *LDAPConfig) { config.UserFilter = "(uid=somebody)" },
			errorText: "user filter must contain {username}",
		},
		{
			name:      "empty username attribute",
			mutate:    func(config *LDAPConfig) { config.UsernameAttribute = " " },
			errorText: "username attribute must not be empty",
		},
		{
			name:      "empty group member attribute",
			mutate:    func(config *LDAPConfig) { config.GroupMemberAttribute = "" },
			errorText: "group member attribute must not be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validLDAPConfig()
			if test.mutate != nil {
				test.mutate(&config)
			}

			err := config.Validate()
			if test.errorText == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errorText)
			if config.BindPassword != "" {
				assert.NotContains(t, err.Error(), config.BindPassword)
			}
		})
	}
}

func TestLDAPConfigBindPasswordIsRedacted(t *testing.T) {
	config := validLDAPConfig()
	config.BindPassword = "never-print-this-secret"

	jsonValue, err := json.Marshal(config)
	require.NoError(t, err)

	formattedValues := []string{
		string(jsonValue),
		fmt.Sprint(config),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
		fmt.Sprintf("%v", &config),
	}

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	logger.Info("LDAP configuration", "config", config)
	formattedValues = append(formattedValues, logOutput.String())

	for _, value := range formattedValues {
		assert.NotContains(t, value, config.BindPassword)
	}
	assert.Contains(t, fmt.Sprint(config), "BindPassword:<redacted>")
}

func newLDAPTestFlagSet(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("ldap-test", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	RegisterLDAPFlags(flags)
	require.NoError(t, flags.Parse(args))
	return flags
}

func validLDAPConfig() LDAPConfig {
	return LDAPConfig{
		Enabled:              true,
		URL:                  "ldaps://ldap.example.test:636",
		BaseDN:               "ou=people,dc=example,dc=test",
		BindDN:               "cn=gads,ou=services,dc=example,dc=test",
		BindPassword:         "service-secret",
		UserFilter:           DefaultLDAPUserFilter,
		UsernameAttribute:    DefaultLDAPUsernameAttribute,
		Timeout:              DefaultLDAPTimeout,
		GroupMemberAttribute: DefaultLDAPGroupMemberAttribute,
		AutoProvision:        true,
	}
}

func mapEnvironment(values map[string]string) environmentLookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func emptyEnvironment(string) (string, bool) {
	return "", false
}
