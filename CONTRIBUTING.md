# Contributing to the LDAP Sign-in Plugin

The [Silo contribution guide](https://github.com/Silo-Server/.github/blob/main/CONTRIBUTING.md)
covers project-wide coordination, focused changes, evidence, AI disclosure, and
pull request expectations. Those requirements apply here; this guide adds the
plugin-specific workflow.

## Before you start

Open an [issue](https://github.com/Silo-Server/silo-plugin-auth-ldap/issues)
before changing denial mapping, group matching, presets, the settings schema,
or the advertised capabilities. This repository owns LDAP directory behavior;
plugin contracts belong in
[`silo-plugin-sdk`](https://github.com/Silo-Server/silo-plugin-sdk), while
Silo accounts, linking, sessions, and roles belong in
[`silo-server`](https://github.com/Silo-Server/silo-server). Keep account
logic out of this plugin: it returns facts about the directory account and
nothing else.

## Security rules

- Escape every value substituted into a filter (RFC 4515) and never build a
  DN from user input without RFC 4514 escaping.
- Never send an empty password to the directory.
- Never add an option that skips certificate verification; add a CA instead.
- Never log or return passwords, and keep secrets out of denial details and
  connection-test messages.

## Development setup

Use the Go version declared in `go.mod`. A local `go.work` may point at a sibling
SDK checkout while developing both repositories, but committed code and CI must
resolve released dependencies with `GOWORK=off`. Never commit directory
credentials, captured private data, or any `replace` directive for the SDK in
`go.mod`; CI rejects one. The README's Development section explains how to
switch back from `go.work` once the SDK version is tagged.

## Validate your change

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go build ./...
GOWORK=off go run . manifest >/dev/null
gofmt -l .
```

The manifest command must exit successfully and `gofmt -l .` should print
nothing. Add focused coverage for filters, denial mapping, group matching, and
connection-test steps when those behaviors change. The unit tests run an
in-process LDAP server. Changes that depend on how a real directory behaves
should also pass `make test-directories`, which runs the live tests against
lldap and OpenLDAP containers the same way CI does (it needs Docker and
openssl). For the authentik LDAP outpost and Kanidm, ask a maintainer to run
`make test-lab`.

## Open the pull request

Use a Conventional Commit title, explain any compatibility or security risk,
and paste the actual validation results. Read the
[AI-assisted contribution policy](https://github.com/Silo-Server/silo-server/blob/main/docs/ai-contributions.md)
and include its disclosure block.
