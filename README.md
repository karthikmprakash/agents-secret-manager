# agents-secret-manager

Secrets and environment manager for AI agents — local-first, `.env`-native.
Values never enter the model's context; the repo carries a manifest of references.

**v0.1 complete; v0.2 adds the MCP server, auto-setup and onboarding.**
Design frozen in [docs/DESIGN.md](docs/DESIGN.md).

## Quickstart

```sh
go build -o ~/.local/bin/sm ./cmd/sm

sm onboard                # first run: creates the vault, offers to store secrets,
                          # detects every agent harness and wires the MCP server in
                          # (non-interactive: sm onboard --yes)

# everyday
sm add --global AWS_ACCESS_KEY_ID   # stored once, usable in every folder
sm import --global --file creds.env --all
                                    # bulk-add a set; the file becomes sm:// refs
sm exec -- aws s3 ls                # child gets secrets; values never printed
sm doctor                           # find plaintext copies: rc files, transcripts, git history
sm setup                            # re-wire agents after installing a new harness
```

Per-project (optional):

```sh
sm init                  # project manifest (.agentsecrets.toml)
sm import .env           # migrate plaintext values into the vault, leave sm:// refs
sm env                   # declared secrets, status — never values
sm inject --tpl config.tpl --out config.json -- npm start
sm rotate GITHUB_TOKEN   # new value; every ref keeps working
sm log verify            # audit trail + hash chain
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

## Mac app

```sh
./scripts/build-mac-app.sh     # → dist/sm.app
open dist/sm.app
```

A native WKWebView shell around the same core: secrets list, add/rotate, agent
wiring, leak scan and audit. It launches the bundled `sm ui` on a loopback-only
server with a per-run token; values are never rendered. `sm ui` opens the same
UI in a browser.

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
