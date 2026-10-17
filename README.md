# agents-secret-manager

Secrets and environment manager for AI agents — local-first, `.env`-native.
Values never enter the model's context; the repo carries a manifest of references.

**v0.1 complete (M0–M5).** Design frozen in [docs/DESIGN.md](docs/DESIGN.md).

## Quickstart

```sh
go build -o sm ./cmd/sm
./sm init                 # vault identity (Keychain) + project manifest
./sm add GITHUB_TOKEN     # prompted; stored encrypted, never on disk in plaintext
./sm add --global DEEPSEEK_API_KEY
                          # model key shared by every project / agent
./sm import .env          # or migrate an existing .env (interactive; --all for all)
./sm env                  # declared secrets, transports and status — never values
./sm exec -- npm test     # child process gets vault secrets + .env refs
./sm inject --tpl config.tpl --out config.json -- npm start
                          # render {{sm:NAME}} → 0600 file, shred on exit
./sm rotate GITHUB_TOKEN  # new value; every ref keeps working
./sm doctor               # find plaintext copies: rc files, transcripts, git history
./sm log verify           # audit trail + hash chain

./sm setup                # detect installed agents, wire the MCP server into each (one time)
                          # after this, agents see secret_list / secret_run — no per-folder setup
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
internal/resolve/  dotenv parser, precedence, refuse-on-shadow, ref rewrite
internal/store/    Store interface + encrypted vault (age)
internal/keys/     master identity in the OS Keychain
internal/generate/ --generate profiles
internal/redact/   streaming value redaction
internal/audit/    hash-chained JSONL audit log
internal/scan/     doctor: rc files, transcripts, MCP configs, git history
internal/tpl/      template rendering, 0600 materialization, shred
internal/mcpserver/ MCP stdio server: secret_list, secret_run (never get)
internal/agentcfg/  MCP config merges for agent harnesses (JSON/YAML)
```
