# Hub Setup

Unless you are building from source, running the hub does not require any additional dependencies except a running MongoDB instance.

## IMPORTANT

This is only hub/UI, to actually have devices available you need to have at least one [**provider**](./provider.md) instance running on the same host (or another host on the same network) that will actually set up and provision devices.  
Follow the setup steps to create and run a provider instance.  
You can have multiple provider instances on different hosts providing devices.

## Starting hub instance

Run `./GADS hub` with the following flags:

- `--host-address=` - local IP address of the host machine, e.g. `192.168.1.6` (default is `localhost`, I would advise against using the default value)
- `--port=` - port on which the UI and backend service will be served
- `--auth=` - enable/disable authentication. When disabled you can access any UI page/hub endpoint without login token validation, note that this is **highly insecure** and should be used only for development - `true/false`
- `--mongo-db=` - IP address and port of the MongoDB instance, e.g `192.168.1.6:27017` (default is `localhost:27017`) - tested only on local network
- `--files-dir=` - directory where the UI static files will be unpacked and served from. By default the app tries to use a temporary folder available on the host automatically. **NB** Use this flag only if you have issues with the default behaviour.

Then access the hub UI and API on `http://{host-address}:{port}`

## LDAP authentication

GADS can authenticate users against OpenLDAP and compatible LDAPv3 directories. LDAP authentication is optional and disabled by default. When it is enabled, GADS uses a hybrid account model:

- Local accounts continue to authenticate with their password stored in MongoDB. The built-in local `admin` account remains available as a break-glass account.
- LDAP accounts authenticate against the directory. GADS never copies or stores their LDAP password.
- Every LDAP identity has a shadow user record in MongoDB. GADS uses that record for its role and workspace assignments, while LDAP remains the source of authentication.
- An account uses exactly one authentication source. A failed LDAP bind never falls back to a same-named local account, and an existing local account cannot be taken over by LDAP.

The existing login page and `/authenticate` API are used for both account types.

### LDAP settings

Every LDAP setting can be supplied as a command-line flag or through the corresponding environment variable. An explicitly supplied flag takes precedence over the environment variable, which takes precedence over the default.

| Flag | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `--ldap-enabled` | `GADS_LDAP_ENABLED` | `false` | Enable LDAP authentication in addition to local authentication. |
| `--ldap-url` | `GADS_LDAP_URL` | empty | LDAP server URL, for example `ldaps://ldap.example.com:636` or `ldap://ldap.example.com:389`. Required when LDAP is enabled. |
| `--ldap-base-dn` | `GADS_LDAP_BASE_DN` | empty | Base DN used to search for users, for example `ou=people,dc=example,dc=com`. |
| `--ldap-bind-dn` | `GADS_LDAP_BIND_DN` | empty | DN of the service account used to search for users and groups. Leave empty only if the directory permits anonymous searches. |
| `--ldap-bind-password` | `GADS_LDAP_BIND_PASSWORD` | empty | Service-account password, required when a bind DN is set. Prefer the environment variable so the secret is not exposed in the process command line. |
| `--ldap-user-filter` | `GADS_LDAP_USER_FILTER` | `(&(objectClass=person)(uid={username}))` | LDAP user search filter. `{username}` is replaced with the safely escaped login name. |
| `--ldap-username-attribute` | `GADS_LDAP_USERNAME_ATTRIBUTE` | `uid` | Attribute used as the canonical GADS username. |
| `--ldap-start-tls` | `GADS_LDAP_START_TLS` | `false` | Upgrade an `ldap://` connection with StartTLS before sending credentials. |
| `--ldap-ca-cert-file` | `GADS_LDAP_CA_CERT_FILE` | empty | PEM file containing the CA certificate used to verify the LDAP server. The system trust store is used when omitted. |
| `--ldap-insecure-skip-verify` | `GADS_LDAP_INSECURE_SKIP_VERIFY` | `false` | Disable TLS certificate verification. Unsafe; use only for temporary troubleshooting. |
| `--ldap-allow-insecure` | `GADS_LDAP_ALLOW_INSECURE` | `false` | Explicitly allow unencrypted `ldap://` without StartTLS. Unsafe; intended only for isolated development networks. |
| `--ldap-timeout` | `GADS_LDAP_TIMEOUT` | `5s` | Connection and operation timeout expressed as a Go duration, such as `5s` or `1m`. |
| `--ldap-admin-group-dn` | `GADS_LDAP_ADMIN_GROUP_DN` | empty | DN of the LDAP group whose members receive the GADS `admin` role. No LDAP user is promoted when omitted. |
| `--ldap-allowed-group-dn` | `GADS_LDAP_ALLOWED_GROUP_DNS` | empty | Allowlist of groups whose members may log in. Repeat the flag for multiple groups; separate environment values with `;`. If empty, every user found by the LDAP user filter may log in. |
| `--ldap-group-member-attribute` | `GADS_LDAP_GROUP_MEMBER_ATTRIBUTE` | `member` | Attribute on the admin group containing user DNs, or usernames when using OpenLDAP `posixGroup` (set this to `memberUid`). |
| `--ldap-auto-provision` | `GADS_LDAP_AUTO_PROVISION` | `true` | Create a MongoDB shadow user on the first successful LDAP login. |

Boolean environment variables accept `true` or `false`. A bind DN and bind password must be supplied together. StartTLS is valid only with an `ldap://` URL; `ldaps://` already establishes TLS when connecting. Do not place `GADS_LDAP_BIND_PASSWORD` in source control, container images, or service unit files readable by untrusted users. The bind password is not written to GADS logs.

### User provisioning and authorization

With auto-provisioning enabled, the first successful LDAP login creates a shadow user with the canonical value of `--ldap-username-attribute`. A new non-admin user is assigned to the default workspace immediately. With auto-provisioning disabled, an administrator must create the LDAP shadow user through `POST /admin/user` before that user can sign in. Use the canonical LDAP username, omit the password, and set the authentication source explicitly:

```json
{
  "username": "alice",
  "role": "user",
  "workspace_ids": ["workspace-id"],
  "auth_source": "ldap"
}
```

LDAP proves the user's identity; MongoDB remains the source of GADS authorization. Administrators can therefore change an LDAP user's workspace assignments without changing the directory. When `--ldap-admin-group-dn` is not configured, an existing shadow user's MongoDB role is preserved and a new shadow user receives the safe default role `user`.

When `--ldap-admin-group-dn` is configured, LDAP group membership is authoritative for the role on every successful LDAP login. GADS accepts the user's `memberOf` value or checks the configured member attribute on the group entry. A member is promoted to `admin`; a user who is no longer a member is demoted to `user`, the shadow record is updated in MongoDB, and the JWT receives the synchronized role. A demoted user without a workspace assignment is added to the default workspace.

When one or more `--ldap-allowed-group-dn` values are configured, a user must be a direct member of at least one listed group to log in. GADS checks the user's `memberOf` values and, when necessary, the configured group member attribute. This supports OpenLDAP `posixGroup` groups with `memberUid`; nested-group expansion is not performed. The allowlist controls login access, while `--ldap-admin-group-dn` controls the `admin` role.

LDAP passwords must be changed in the directory. GADS rejects password-change requests for LDAP-backed users; the existing change-password flow continues to work for local users.

### Secure LDAPS example

Use `ldaps://` and a trusted CA certificate for a direct TLS connection. Supply the service-account secret through the environment rather than `--ldap-bind-password`:

```bash
export GADS_LDAP_BIND_PASSWORD='replace-with-a-secret'

./GADS hub --port=10000 \
  --ldap-enabled=true \
  --ldap-url='ldaps://ldap.example.com:636' \
  --ldap-base-dn='ou=people,dc=example,dc=com' \
  --ldap-bind-dn='cn=gads,ou=service-accounts,dc=example,dc=com' \
  --ldap-ca-cert-file='/etc/gads/certs/openldap-ca.pem' \
  --ldap-user-filter='(&(objectClass=person)(uid={username}))' \
  --ldap-admin-group-dn='cn=gads-admins,ou=groups,dc=example,dc=com'
```

### Secure StartTLS example

For an LDAP endpoint on port 389, enable StartTLS. This begins with `ldap://` but negotiates TLS before the bind or any password is sent:

```bash
export GADS_LDAP_BIND_PASSWORD='replace-with-a-secret'

./GADS hub --port=10000 \
  --ldap-enabled=true \
  --ldap-url='ldap://ldap.example.com:389' \
  --ldap-start-tls=true \
  --ldap-base-dn='ou=people,dc=example,dc=com' \
  --ldap-bind-dn='cn=gads,ou=service-accounts,dc=example,dc=com' \
  --ldap-ca-cert-file='/etc/gads/certs/openldap-ca.pem'
```

Plain `ldap://` without StartTLS is rejected unless `--ldap-allow-insecure=true` (or `GADS_LDAP_ALLOW_INSECURE=true`) is set explicitly. Unencrypted LDAP exposes user and service-account credentials to anyone able to observe the connection; do not enable it in production. Likewise, `--ldap-insecure-skip-verify=true` encrypts traffic but does not authenticate the server and is not a safe substitute for installing the correct CA certificate.

## UI development

If you want to work on the React UI with hot reload you need to add a proxy in `package.json` to point to the Go backend

1. Open the `hub/gads-ui` folder.
2. Open the `package-json` file.
3. Add a new field `"proxy": "http://192.168.1.28:10000/"` providing the host and port of the Go backend service.
4. Run `npm start`

## Additional notes

### Users administration

You can add/delete users and change their roles/passwords via the `Admin` panel. LDAP-backed users are represented by shadow records so their roles and workspace assignments can be managed in GADS, but their passwords remain directory-managed and cannot be changed in GADS.

Only the default local `admin` user cannot be deleted or have its role changed (you can change its local password).

### Providers administration

For each provider instance you need to create a provider configuration via the `Admin` panel.  
All fields have tooltips to help you with the required information.

### Devices administration

Device configurations are added via the `Admin` panel.  
You have to provide all the required information and assign each device to a provider.  
Changes to the device configuration require the respective provider instance restarted.  
All fields have tooltips to help you with the required information.

**Android emulators** are the exception - providers with `Provide Android emulators?` enabled discover and report running emulators automatically as ephemeral devices. They never appear in `Admin > Devices` (there is nothing to configure), show up in the device selection list with an emulator badge while running, and are removed within ~15 seconds after the emulator or its provider stops. See the [provider documentation](./provider.md#android-emulators) for details.

### Appium grid

Using Selenium Grid 4 is a bit of a hassle and some versions do not work properly with Appium relay nodes.  
For this reason the hub embeds its own grid implementation - no Selenium Grid required. Point your Appium/Selenium driver URL at the hub, e.g. `http://192.168.1.6:10000/grid`, and create sessions as you usually would with any Appium language client.

**Session requests**
- Requests must use the W3C `capabilities` format (`alwaysMatch`/`firstMatch`). Legacy `desiredCapabilities`-only requests are rejected with `400 invalid argument` - Appium 2+ does not accept them either
- Every session request must carry the `gads:clientSecret` capability for authentication - see [Appium client credentials](./appium-credentials.md). All `gads:*` capabilities are stripped before the request is forwarded, so the secret never appears in Appium logs

**Device targeting**
- By UDID via `appium:udid`
- By `platformName` (iOS or Android) or `appium:automationName` (XCUITest or UiAutomator2)
  - Additionally the grid allows filtering by `appium:platformVersion` capability which supports exact version e.g. `17.5.1` or a major version e.g. `17`, `11` etc
- Devices whose usage is set to `Control` or `Disabled`, and devices on a provider configured without Appium servers, are never dispatched - requests pinned to one by UDID fail immediately with the reason instead of queueing

**Queueing**
- When no matching device is free the request waits in a FIFO queue - first come, first served
- The default wait is 10 seconds; the `gads:queueTimeout` capability (seconds, clamped to 300) sets it per request, and `0` means fail immediately when nothing is free

**Session behavior**
- `appium:newCommandTimeout` is honored by the hub as well (default 60 seconds); an explicit `0` disables idle expiry entirely
- Only the exact `DELETE /grid/session/{id}` ends a session - DELETEs on subpaths (`/window`, `/cookie`, `/actions`) are proxied as ordinary commands
- BiDi is not supported: sessions requesting `webSocketUrl: true` still create fine, but the `webSocketUrl` capability is always removed from the response

**Response enrichment** - a successful session response includes extra `gads:*` capabilities telling you which device you actually got:
- `gads:deviceUdid`, `gads:deviceName`, `gads:provider`
- `gads:controlUrl` - a direct link to the hub's remote control UI for the device serving your test; the session owner can also attach from the device list via the `Use` button (after confirming) and watch the test live

**Observability**
- `GET /grid/status` reports overall grid readiness; without credentials that is all it reports. Send your client secret as `Authorization: Bearer <secret>` to also get the per-device availability list and a readiness flag scoped to your tenant's workspaces
- `GET /automation-sessions` (authenticated) lists the currently active automation sessions

### Android devices remote control debugging

GADS allows you to create an adb tunnel to a remotely controlled Android device for local development and debugging - find more information on usage [here](./adb-tunnel.md)
