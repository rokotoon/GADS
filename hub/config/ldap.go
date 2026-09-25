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
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	DefaultLDAPUserFilter           = "(&(objectClass=person)(uid={username}))"
	DefaultLDAPUsernameAttribute    = "uid"
	DefaultLDAPGroupMemberAttribute = "member"
	DefaultLDAPTimeout              = 5 * time.Second
)

// LDAPConfig contains the hub's OpenLDAP authentication settings. The bind
// password is deliberately excluded from serialization and all standard
// formatted/logged representations of the config.
type LDAPConfig struct {
	Enabled              bool          `json:"enabled"`
	URL                  string        `json:"url"`
	BaseDN               string        `json:"base_dn"`
	BindDN               string        `json:"bind_dn"`
	BindPassword         string        `json:"-" yaml:"-" bson:"-"`
	UserFilter           string        `json:"user_filter"`
	UsernameAttribute    string        `json:"username_attribute"`
	StartTLS             bool          `json:"start_tls"`
	CACertFile           string        `json:"ca_cert_file"`
	InsecureSkipVerify   bool          `json:"insecure_skip_verify"`
	AllowInsecure        bool          `json:"allow_insecure"`
	Timeout              time.Duration `json:"timeout"`
	AdminGroupDN         string        `json:"admin_group_dn"`
	AllowedGroupDNs      []string      `json:"allowed_group_dns,omitempty"`
	GroupMemberAttribute string        `json:"group_member_attribute"`
	AutoProvision        bool          `json:"auto_provision"`
}

type environmentLookup func(string) (string, bool)

// RegisterLDAPFlags adds all LDAP-related hub flags to the supplied flag set.
// The bind password flag exists for non-service use, but the environment
// variable is safer because command-line arguments may be visible to other
// processes on the host.
func RegisterLDAPFlags(flags *pflag.FlagSet) {
	flags.Bool("ldap-enabled", false, "Enable OpenLDAP authentication")
	flags.String("ldap-url", "", "LDAP server URL (ldap:// or ldaps://)")
	flags.String("ldap-base-dn", "", "Base DN used when searching for LDAP users")
	flags.String("ldap-bind-dn", "", "DN of the LDAP service account used for searches")
	flags.String("ldap-bind-password", "", "Password of the LDAP service account (prefer GADS_LDAP_BIND_PASSWORD)")
	flags.String("ldap-user-filter", DefaultLDAPUserFilter, "LDAP user search filter; must contain {username}")
	flags.String("ldap-username-attribute", DefaultLDAPUsernameAttribute, "LDAP attribute containing the username")
	flags.Bool("ldap-start-tls", false, "Upgrade an ldap:// connection with StartTLS")
	flags.String("ldap-ca-cert-file", "", "PEM CA certificate used to verify the LDAP server")
	flags.Bool("ldap-insecure-skip-verify", false, "Skip LDAP TLS certificate verification (insecure)")
	flags.Bool("ldap-allow-insecure", false, "Allow an unencrypted ldap:// connection without StartTLS")
	flags.Duration("ldap-timeout", DefaultLDAPTimeout, "LDAP connection and operation timeout")
	flags.String("ldap-admin-group-dn", "", "LDAP group DN whose members receive the admin role")
	flags.StringArray("ldap-allowed-group-dn", nil, "LDAP group DN allowed to authenticate (repeat for multiple groups)")
	flags.String("ldap-group-member-attribute", DefaultLDAPGroupMemberAttribute, "LDAP group attribute containing member DNs or usernames (for example memberUid)")
	flags.Bool("ldap-auto-provision", true, "Automatically create a local GADS user after the first successful LDAP login")
}

// LoadLDAPConfig resolves LDAP settings using explicit command-line flags
// first, then environment variables, then built-in defaults. It returns an
// error for malformed values or an invalid enabled configuration.
func LoadLDAPConfig(flags *pflag.FlagSet) (LDAPConfig, error) {
	return loadLDAPConfig(flags, os.LookupEnv)
}

func loadLDAPConfig(flags *pflag.FlagSet, lookupEnv environmentLookup) (LDAPConfig, error) {
	var config LDAPConfig
	var err error

	if config.Enabled, err = resolveBool(flags, "ldap-enabled", "GADS_LDAP_ENABLED", false, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.URL, err = resolveString(flags, "ldap-url", "GADS_LDAP_URL", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.BaseDN, err = resolveString(flags, "ldap-base-dn", "GADS_LDAP_BASE_DN", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.BindDN, err = resolveString(flags, "ldap-bind-dn", "GADS_LDAP_BIND_DN", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.BindPassword, err = resolveString(flags, "ldap-bind-password", "GADS_LDAP_BIND_PASSWORD", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.UserFilter, err = resolveString(flags, "ldap-user-filter", "GADS_LDAP_USER_FILTER", DefaultLDAPUserFilter, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.UsernameAttribute, err = resolveString(flags, "ldap-username-attribute", "GADS_LDAP_USERNAME_ATTRIBUTE", DefaultLDAPUsernameAttribute, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.StartTLS, err = resolveBool(flags, "ldap-start-tls", "GADS_LDAP_START_TLS", false, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.CACertFile, err = resolveString(flags, "ldap-ca-cert-file", "GADS_LDAP_CA_CERT_FILE", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.InsecureSkipVerify, err = resolveBool(flags, "ldap-insecure-skip-verify", "GADS_LDAP_INSECURE_SKIP_VERIFY", false, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.AllowInsecure, err = resolveBool(flags, "ldap-allow-insecure", "GADS_LDAP_ALLOW_INSECURE", false, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.Timeout, err = resolveDuration(flags, "ldap-timeout", "GADS_LDAP_TIMEOUT", DefaultLDAPTimeout, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.AdminGroupDN, err = resolveString(flags, "ldap-admin-group-dn", "GADS_LDAP_ADMIN_GROUP_DN", "", lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.AllowedGroupDNs, err = resolveStringArray(flags, "ldap-allowed-group-dn", "GADS_LDAP_ALLOWED_GROUP_DNS", nil, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.GroupMemberAttribute, err = resolveString(flags, "ldap-group-member-attribute", "GADS_LDAP_GROUP_MEMBER_ATTRIBUTE", DefaultLDAPGroupMemberAttribute, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}
	if config.AutoProvision, err = resolveBool(flags, "ldap-auto-provision", "GADS_LDAP_AUTO_PROVISION", true, lookupEnv); err != nil {
		return LDAPConfig{}, err
	}

	if err := config.Validate(); err != nil {
		return LDAPConfig{}, err
	}

	return config, nil
}

// Validate checks settings that are required when LDAP authentication is
// enabled. Disabled LDAP configuration deliberately remains permissive so an
// upgrade cannot break an existing local-authentication deployment.
func (config LDAPConfig) Validate() error {
	if !config.Enabled {
		return nil
	}

	if strings.TrimSpace(config.URL) == "" {
		return fmt.Errorf("LDAP URL is required when LDAP authentication is enabled")
	}
	if strings.TrimSpace(config.BaseDN) == "" {
		return fmt.Errorf("LDAP base DN is required when LDAP authentication is enabled")
	}

	parsedURL, err := url.Parse(config.URL)
	if err != nil {
		return fmt.Errorf("LDAP URL is invalid")
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return fmt.Errorf("LDAP URL scheme must be ldap or ldaps")
	}
	if parsedURL.Host == "" || parsedURL.Hostname() == "" {
		return fmt.Errorf("LDAP URL must include a host")
	}
	if scheme == "ldaps" && config.StartTLS {
		return fmt.Errorf("LDAP StartTLS cannot be used with an ldaps URL")
	}
	if scheme == "ldap" && !config.StartTLS && !config.AllowInsecure {
		return fmt.Errorf("plain ldap requires StartTLS or explicit allow-insecure")
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("LDAP timeout must be greater than zero")
	}

	hasBindDN := strings.TrimSpace(config.BindDN) != ""
	hasBindPassword := config.BindPassword != ""
	if hasBindDN != hasBindPassword {
		return fmt.Errorf("LDAP bind DN and bind password must be provided together")
	}

	if !strings.Contains(config.UserFilter, "{username}") {
		return fmt.Errorf("LDAP user filter must contain {username}")
	}
	if strings.TrimSpace(config.UsernameAttribute) == "" {
		return fmt.Errorf("LDAP username attribute must not be empty")
	}
	if strings.TrimSpace(config.GroupMemberAttribute) == "" {
		return fmt.Errorf("LDAP group member attribute must not be empty")
	}
	for _, groupDN := range config.AllowedGroupDNs {
		if strings.TrimSpace(groupDN) == "" {
			return fmt.Errorf("LDAP allowed group DN must not be empty")
		}
	}

	return nil
}

func resolveString(flags *pflag.FlagSet, flagName, envName, defaultValue string, lookupEnv environmentLookup) (string, error) {
	if flags != nil {
		if flag := flags.Lookup(flagName); flag != nil && flag.Changed {
			value, err := flags.GetString(flagName)
			if err != nil {
				return "", fmt.Errorf("read --%s: %w", flagName, err)
			}
			return value, nil
		}
	}

	if lookupEnv != nil {
		if value, ok := lookupEnv(envName); ok {
			return value, nil
		}
	}

	return defaultValue, nil
}

// resolveStringArray supports repeatable command-line flags and a semicolon-
// separated environment value. Semicolons are used deliberately because LDAP
// DNs themselves contain commas.
func resolveStringArray(flags *pflag.FlagSet, flagName, envName string, defaultValue []string, lookupEnv environmentLookup) ([]string, error) {
	if flags != nil {
		if flag := flags.Lookup(flagName); flag != nil && flag.Changed {
			value, err := flags.GetStringArray(flagName)
			if err != nil {
				return nil, fmt.Errorf("read --%s: %w", flagName, err)
			}
			return value, nil
		}
	}

	if lookupEnv != nil {
		if value, ok := lookupEnv(envName); ok {
			var values []string
			for _, item := range strings.Split(value, ";") {
				item = strings.TrimSpace(item)
				if item != "" {
					values = append(values, item)
				}
			}
			return values, nil
		}
	}

	return defaultValue, nil
}

func resolveBool(flags *pflag.FlagSet, flagName, envName string, defaultValue bool, lookupEnv environmentLookup) (bool, error) {
	if flags != nil {
		if flag := flags.Lookup(flagName); flag != nil && flag.Changed {
			value, err := flags.GetBool(flagName)
			if err != nil {
				return false, fmt.Errorf("read --%s: %w", flagName, err)
			}
			return value, nil
		}
	}

	if lookupEnv != nil {
		if value, ok := lookupEnv(envName); ok {
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return false, fmt.Errorf("%s must be a boolean: %w", envName, err)
			}
			return parsed, nil
		}
	}

	return defaultValue, nil
}

func resolveDuration(flags *pflag.FlagSet, flagName, envName string, defaultValue time.Duration, lookupEnv environmentLookup) (time.Duration, error) {
	if flags != nil {
		if flag := flags.Lookup(flagName); flag != nil && flag.Changed {
			value, err := flags.GetDuration(flagName)
			if err != nil {
				return 0, fmt.Errorf("read --%s: %w", flagName, err)
			}
			return value, nil
		}
	}

	if lookupEnv != nil {
		if value, ok := lookupEnv(envName); ok {
			parsed, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				return 0, fmt.Errorf("%s must be a duration: %w", envName, err)
			}
			return parsed, nil
		}
	}

	return defaultValue, nil
}

// String returns a safe representation suitable for diagnostics.
func (config LDAPConfig) String() string {
	return config.safeString()
}

// Format prevents fmt-based logging (including %+v and %#v) from exposing the
// bind password.
func (config LDAPConfig) Format(state fmt.State, verb rune) {
	safe := config.safeString()
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", safe)
		return
	}
	_, _ = fmt.Fprint(state, safe)
}

// LogValue prevents structured slog calls from reflecting over the exported
// BindPassword field.
func (config LDAPConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("enabled", config.Enabled),
		slog.String("url", config.URL),
		slog.String("base_dn", config.BaseDN),
		slog.String("bind_dn", config.BindDN),
		slog.String("user_filter", config.UserFilter),
		slog.String("username_attribute", config.UsernameAttribute),
		slog.Bool("start_tls", config.StartTLS),
		slog.String("ca_cert_file", config.CACertFile),
		slog.Bool("insecure_skip_verify", config.InsecureSkipVerify),
		slog.Bool("allow_insecure", config.AllowInsecure),
		slog.Duration("timeout", config.Timeout),
		slog.String("admin_group_dn", config.AdminGroupDN),
		slog.Any("allowed_group_dns", config.AllowedGroupDNs),
		slog.String("group_member_attribute", config.GroupMemberAttribute),
		slog.Bool("auto_provision", config.AutoProvision),
	)
}

func (config LDAPConfig) safeString() string {
	return fmt.Sprintf(
		"LDAPConfig{Enabled:%t URL:%q BaseDN:%q BindDN:%q BindPassword:<redacted> UserFilter:%q UsernameAttribute:%q StartTLS:%t CACertFile:%q InsecureSkipVerify:%t AllowInsecure:%t Timeout:%s AdminGroupDN:%q AllowedGroupDNs:%q GroupMemberAttribute:%q AutoProvision:%t}",
		config.Enabled,
		config.URL,
		config.BaseDN,
		config.BindDN,
		config.UserFilter,
		config.UsernameAttribute,
		config.StartTLS,
		config.CACertFile,
		config.InsecureSkipVerify,
		config.AllowInsecure,
		config.Timeout.String(),
		config.AdminGroupDN,
		config.AllowedGroupDNs,
		config.GroupMemberAttribute,
		config.AutoProvision,
	)
}
