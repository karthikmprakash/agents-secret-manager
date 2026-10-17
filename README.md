# agents-secret-manager

Secrets and environment manager for AI agents — local-first, `.env`-native.
Values never enter the model's context; the repo carries a manifest of references.

Status: **M0–M2** — skeleton, manifest, local vault, resolver + `sm exec`.
Design frozen in [docs/DESIGN.md](docs/DESIGN.md).

## Quickstart

```sh
go build -o sm ./cmd/sm
./sm init                 # vault identity (Keychain) + project manifest
./sm add GITHUB_TOKEN     # prompted; stored encrypted, never on disk in plaintext
./sm env                  # declared secrets, transports and status — never values
./sm exec -- npm test     # child process gets vault secrets + .env refs
```

`.env` can reference declared secrets by name:

```sh
OPENAI_API_KEY=sm://OPENAI_KEY   # resolves via .agentsecrets.toml → vault
DATABASE_URL=postgres://localhost/dev
```

Precedence: `.env` < `.env.<profile>` < `.env.local` < process env. A
plaintext value that differs from a vault-managed name refuses to run
(`SM_ALLOW_PLAINTEXT=1` overrides).

## Layout

```
cmd/sm/            CLI
internal/manifest/ .agentsecrets.toml schema, discovery, validation
internal/resolve/  dotenv parser, precedence, refuse-on-shadow
internal/store/    Store interface + encrypted vault (age)
internal/keys/     master identity in the OS Keychain
internal/generate/ --generate profiles
```
