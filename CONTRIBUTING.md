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

## Release

Maintainers cut releases. Pushing a `v<semver>` tag runs
[`release.yml`](.github/workflows/release.yml), which calls the shared
`Silo-Server/.github` plugin release workflow. It builds the binaries, signs
them with GitHub artifact attestations, publishes the GitHub release, and asks
the [`silo-plugins`](https://github.com/Silo-Server/silo-plugins) catalog to
pick it up. There is no manual-dispatch release.

The catalog is notified only for a full release, and only when this repository
has the `SILO_PLUGINS_DISPATCH_TOKEN` secret. A prerelease tag (`vX.Y.Z-rc.1`)
publishes a GitHub prerelease and skips the notification. If the notification
failed or was skipped, set the secret and re-run the release run's
`Notify the silo-plugins catalog` job.

1. Open a pull request that sets `version` in `manifest.json` to the new
   version (for example `0.1.1`), and merge it.
2. Tag the commit that pull request put on `main` and push the tag. Tag that
   commit itself, not a later one:

   ```sh
   git switch main && git pull --ff-only
   git tag v0.1.1 <commit that changed manifest.json>
   git push origin v0.1.1
   ```

The workflow fails without publishing anything if the tag is not `v<semver>`,
`manifest.json` `version` does not match the tag, or the tagged commit is not
the commit on `main` that changed `version`. Only that one commit can be
released for a version. Do not move or delete a pushed tag; fix `manifest.json`
in a new pull request and tag the next version.

Each release carries `plugin-<os>-<arch>` binaries, `checksums.txt`, and
`plugin.sigstore.json`. To verify a download, check its attestation with the
GitHub CLI, naming the release's tag:

```sh
gh attestation verify plugin-linux-amd64 \
  --repo Silo-Server/silo-plugin-auth-ldap \
  --cert-identity https://github.com/Silo-Server/.github/.github/workflows/plugin-release.yml@refs/heads/main \
  --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
```

This is the check Silo servers apply: the shared release workflow on its
`main` branch built the binary from that tag of this repository. To check
against the bundle shipped with the release instead of fetching the attestation
from GitHub, add `--bundle plugin.sigstore.json`; `gh` still fetches Sigstore's
trusted root unless you follow GitHub's
[offline verification steps](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).
Verify before running a downloaded binary.
`sha256sum plugin-linux-amd64` (`shasum -a 256` on macOS) must also match the
binary's line in `checksums.txt`.
