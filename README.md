# LDAP Sign-in Plugin for Silo

First-party [Silo](https://github.com/Silo-Server/silo-server) auth provider
that checks usernames and passwords against an LDAP directory: lldap, the
authentik LDAP outpost, Active Directory, Samba, FreeIPA, OpenLDAP, Kanidm, or
GLAuth. Its plugin ID is `silo.auth.ldap`.

The plugin answers three questions for the host and holds no Silo account
logic:

- **Sign-in** (`Authenticate`): is this password right, and who is this person?
- **Re-check** (`CheckAccount`): does the account still exist, is it enabled,
  and does it still pass the group rules?
- **Connection test** (`TestConnection`): do the staged settings work?

It returns typed facts: the unique ID (`external_subject`), username, email,
display name, groups, and the Silo role that the admin groups imply. Silo
decides what to do with them.

## How sign-in works

1. Connect to the first reachable directory URL (`ldaps://`, or `ldap://`
   with optional StartTLS). Certificate checks cannot be turned off; add a
   private CA as PEM instead. Silo allows a sign-in about 10 seconds, so with
   several URLs each attempt gets a share of the time left.
2. Bind as the service account (or stay anonymous when none is set).
3. Search the user base DN with the user filter. `{username}` is escaped per
   RFC 4515 before substitution, and the results are re-checked against the
   typed username because some servers turn escaped wildcards back into real
   ones.
4. Read the unique ID and groups (from `memberOf` or a group search). When
   the unique ID is not assigned by the directory (such as GLAuth's
   `uidNumber`), refuse the sign-in if another entry has the same ID.
5. Bind as the person with their password. Empty passwords are refused
   before any network call, because an empty password is an unauthenticated
   bind that many servers accept.
6. Apply the directory's disabled flags and the group rules.

Refusals come back as typed denials, not errors:

| Directory answer | Denial |
|---|---|
| Wrong password, unknown user, AD `data 52e`/`525` | `INVALID_CREDENTIALS` |
| Not in an allowed group, AD `data 530`/`531` (logon hours, workstation) | `NOT_PERMITTED` |
| AD `data 533`/`701`/`775`, FreeIPA "Account inactivated" (53), 389 retry limit (19), ppolicy `accountLocked`, `userAccountControl` ACCOUNTDISABLE, a past AD `accountExpires`, `nsAccountLock`, authentik `ak-active: FALSE`, GLAuth `accountStatus: inactive` | `ACCOUNT_DISABLED` |
| AD `data 532`/`773`, ppolicy `passwordExpired`/`changeAfterReset`, the 389/FreeIPA password-expired control | `PASSWORD_EXPIRED` |
| Unreachable directory, failed service bind, incomplete settings | `PROVIDER_UNAVAILABLE` |

`CheckAccount` looks the account up by its unique ID with the service
account, without the person's password. It answers `ACTIVE` (with current
groups and role), `NOT_FOUND`, `DISABLED`, `NOT_PERMITTED` (no longer in an
allowed group, or no longer matched by the user filter), or `UNAVAILABLE`.
Silo re-checks every 12 hours by default (configurable in Silo); the first three
answers end the person's Silo sessions at that re-check, not the moment the
directory changes.

`DISABLED` covers the directory flags in the table above that don't need the
password: `userAccountControl`, a past `accountExpires`, `nsAccountLock`,
`ak-active`, an administrative ppolicy lock, and GLAuth's `accountStatus`, plus
Kanidm's `account_expire` and `account_valid_from`.
Temporary lockouts after failed passwords are not reported, because anyone
could trigger them.

An answer that ends sessions is given only when the service account can see
the data behind it; otherwise the answer is `UNAVAILABLE` and Silo retries, so
a revoked read permission doesn't end everyone's sessions:

- Before `NOT_FOUND` or "no longer matched by the user filter", the service
  account must see some account the user filter admits.
- An account found by ID but not by the user filter is looked up again the way
  sign-in does, with its own username. That keeps filters such as
  `(uid:caseExactMatch:={username})`, where `{username}` can't become a
  presence test, from reading as "filtered out". With such a filter, a deleted
  account gets `UNAVAILABLE` rather than `NOT_FOUND`.
- Before `NOT_PERMITTED` for a missing group, or a demotion from admin for an
  account with no groups at all, some entry must show a `memberOf` value
  (memberOf source), or one of the configured groups must be visible (group
  search).

The plugin stores no refresh state.

## Settings

Settings are `global_config_schema` entries rendered by Silo's admin form:

| Entry | Fields |
|---|---|
| `display_name` | `value`: the directory's name, shown on the sign-in button and in labels such as "Company directory password" |
| `icon_url_path` | `value`: icon file under the plugin's public `/assets/` route (`ldap.svg`) |
| `directory` | `preset`, `urls`, `start_tls`, `ca_pem`, `bind_dn`, `bind_password` (secret), `connect_timeout_seconds`, `request_timeout_seconds` |
| `users` | `base_dn`, `filter`, `username_attribute`, `email_attribute`, `display_name_attribute`, `unique_id_attribute`, `picture_url_attribute`, `email_verified`, `test_username` |
| `groups` | `source`, `membership_attribute`, `base_dn`, `filter`, `name_attribute`, `allowed_groups`, `admin_groups` |

The directory type (`preset`) fills in every user and group field left blank:

| Preset | User filter | Unique ID | Groups |
|---|---|---|---|
| `generic` | `(&(objectClass=person)(uid={username}))` | `entryUUID` | `memberOf` |
| `lldap` | `(&(objectClass=person)(uid={username}))` | `entryUUID` | `memberOf` |
| `authentik` | `(&(objectClass=user)(cn={username}))` | `uid` | `memberOf` |
| `active_directory` | `(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))` | `objectGUID` | `memberOf` (direct memberships only; choose the group search for nested groups) |
| `freeipa` | `(&(objectClass=person)(uid={username}))` | `ipaUniqueID` | `memberOf` |
| `openldap` | `(&(objectClass=inetOrgPerson)(uid={username}))` | `entryUUID` | group search: `groupOfNames`, `groupOfUniqueNames`, `posixGroup` |
| `kanidm` | `(&(class=person)(name={username}))` | `uuid` | `memberof`; `ldaps://` only |
| `glauth` | `(&(objectClass=posixAccount)(uid={username}))` | `uidNumber` (never reuse one after deleting a user) | `memberOf` |

Directory notes:

- **lldap** and the **authentik outpost** don't support StartTLS; use
  `ldaps://`. authentik's service account needs permission to search the full
  directory.
- **Active Directory**: `memberOf` lists direct memberships only. For nested
  groups, set the group source to a group search; the preset's group filter
  uses `LDAP_MATCHING_RULE_IN_CHAIN`, which can be slow on large domains.
- **Kanidm**: bind the service account as `dn=token` with the API token of a
  service account in `idm_people_pii_read`; without it, searches find no
  people. User binds check the POSIX password, so turn on
  `ldap_allow_unix_pw_bind` for the domain and give each person a POSIX
  password. Kanidm refuses an expired account's bind as a wrong password;
  re-checks read `account_expire`.
- **GLAuth** has no server-assigned ID. If a deleted user's `uidNumber` goes
  to someone new, that person signs in to the old Silo account.

Allowed and admin groups take one group per line, as a name (`silo-users`) or
a full DN. A name matches the group's name attribute or the first RDN of its
DN, in any container; for Kanidm, `silo-users` also matches
`spn=silo-users@idm.example.com,...`. Admin groups must be full DNs except
with the lldap, authentik, FreeIPA, Kanidm, and GLAuth presets, whose group
names are unique across the directory; elsewhere anyone who can create a group
could otherwise make themselves an admin. For the same reason, prefer full DNs
for allowed groups on Active Directory and OpenLDAP. Names and DNs compare
ASCII letters case-insensitively and every other character exactly, so
look-alikes such as `ſilo-admins` don't match. Members of an admin group
always pass the allowed-groups gate. With no admin groups the plugin leaves
roles to Silo.

`objectGUID` values become the canonical GUID string, such as
`3f2504e0-4f89-11d3-9a0c-0305e82c3301`. Changing the unique ID attribute after
people have signed in disconnects their Silo accounts.

The login icon is compiled into the binary and served from the public
`GET /assets/*` route, because catalog installs ship only the binary.

## Process model

Each RPC opens its own directory connection and closes it before returning.
There are no pools or background goroutines, so the host can start the plugin
lazily and restart it at any time. `Configure` never fails: incomplete
settings are stored and reported by the connection test and at sign-in.

## Dependency model

This repository consumes `github.com/Silo-Server/silo-plugin-sdk` as a normal
Go module dependency. CI and release builds run with `GOWORK=off` and expect
the SDK version in `go.mod` to resolve from a published semver tag.

## Development

If the SDK version in `go.mod` is not tagged yet, a plain `go build` can't
resolve it. Until the tag exists, build against a local SDK checkout through a
`go.work` file, which `.gitignore` already excludes (replace `v0.22.0` with the
version `go.mod` requires):

```sh
go work init . ../silo-plugin-sdk
go work edit -replace github.com/Silo-Server/silo-plugin-sdk@v0.22.0=../silo-plugin-sdk
```

The `replace` line is needed because Go still looks up that version's
`go.mod` even when the SDK is a workspace module. Keep both in `go.work`:
`go.mod` must never carry a `replace` for the SDK, and CI rejects one.

Workspace modules don't record checksums in `go.sum`, so `GOWORK=off` builds,
including CI, keep failing until you switch back. Once the SDK version is
tagged:

```sh
rm go.work go.work.sum
GOWORK=off go mod tidy
```

Then commit the new `silo-plugin-sdk` lines in `go.sum`.

Common tasks:

```sh
make test              # unit tests against an in-process LDAP server
make test-directories  # lldap and OpenLDAP in Docker
make vet
make lint
make build             # ./plugin
make build-all         # dist/plugin-<os>-<arch> for darwin/arm64, linux/amd64, linux/arm64
./plugin manifest
```

To test against real directories, `make test-directories` starts lldap and
OpenLDAP in Docker, seeds them with test people and groups, runs
`TestContainerDirectories`, and removes the containers. It needs Docker and
openssl; CI runs the same script. See `scripts/directory-containers.sh` for
settings, including running the containers on another Docker host.

Maintainers with access to the SSO lab also cover the authentik LDAP outpost
and Kanidm:

```sh
SSO_LAB_ENV=path/to/lab.env SSO_LAB_CA=path/to/ca.pem make test-lab
```

`SSO_LAB_ENV` is a `KEY=value` file with the lab host and credentials; see
`ldapauth/lab_test.go` for the keys it reads.

For a local Silo, install the plugin by uploading the binary; the installer
reads `<binary> manifest`.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
Changes to denial mapping, group matching, presets, or the settings schema
should start as an issue.

## License

`silo-plugin-auth-ldap` is licensed under `AGPL-3.0-or-later`. See
[LICENSE](LICENSE).
