# agents-secret-manager

Secrets and environment manager for AI agents — local-first, `.env`-native.
Values never enter the model's context; the repo carries a manifest of references.

Status: **M0/M1** — skeleton, manifest, local vault. Design frozen in [docs/DESIGN.md](docs/DESIGN.md).

## Quickstart

```sh
go build -o sm ./cmd/sm
./sm init                 # vault identity (Keychain) + project manifest
./sm add GITHUB_TOKEN     # prompted; stored encrypted, never on disk in plaintext
./sm env                  # declared secrets, transports and status — never values
```

## Layout

```
cmd/sm/            CLI
internal/manifest/ .agentsecrets.toml schema, discovery, validation
internal/store/    Store interface + encrypted vault (age)
internal/keys/     master identity in the OS Keychain
internal/generate/ --generate profiles
```
