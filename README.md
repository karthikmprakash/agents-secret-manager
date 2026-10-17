# agents-secret-manager

Secrets and environment manager for AI agents — local-first, `.env`-native.
Values never enter the model's context; the repo carries a manifest of references.

Status: **M0–M3** — skeleton, manifest, local vault, resolver + `sm exec`,
output redaction, hash-chained audit.
Design frozen in [docs/DESIGN.md](docs/DESIGN.md).

## Quickstart

```sh
go build -o sm ./cmd/sm
./sm init                 # vault identity (Keychain) + project manifest
./sm add GITHUB_TOKEN     # prompted; stored encrypted, never on disk in plaintext
./sm env                  # declared secrets, transports and status — never values
./sm exec -- npm test     # child process gets vault secrets + .env refs
./sm log                  # audit trail (names only)
./sm log verify           # verify the hash chain
```

`.env` can reference declared secrets by name:

```sh
OPENAI_API_KEY=sm://OPENAI_KEY   # resolves via .agentsecrets.toml → vault
DATABASE_URL=postgres://localhost/dev
```

Precedence: `.env` < `.env.<profile>` < `.env.local` < process env. A
plaintext value that differs from a vault-managed name refuses to run
(`SM_ALLOW_PLAINTEXT=1` overrides).

When output is piped (the agent case), `sm exec` masks injected values in the
child's stdout/stderr as `[redacted:NAME]`; `--redact always|never` overrides
the auto heuristic. Every exec is recorded in `~/.config/sm/audit.jsonl`
(names, command, cwd — never values), hash-chained and verifiable.

## Layout

```
cmd/sm/            CLI
internal/manifest/ .agentsecrets.toml schema, discovery, validation
internal/resolve/  dotenv parser, precedence, refuse-on-shadow
internal/store/    Store interface + encrypted vault (age)
internal/keys/     master identity in the OS Keychain
internal/generate/ --generate profiles
internal/redact/   streaming value redaction
internal/audit/    hash-chained JSONL audit log
```
