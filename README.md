# sm

**Local encrypted secrets for AI coding agents. One vault, every harness, MCP-native.**

[![CI](https://github.com/karthikmprakash/agents-secret-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/karthikmprakash/agents-secret-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go 1.27+](https://img.shields.io/badge/go-1.27%2B-00ADD8.svg)](go.mod)
[![macOS 13+](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey.svg)](#install)

Add a credential once on your Mac. Every agent harness you use can then run
commands with it through MCP — **without the model ever seeing the value**.

```sh
sm add --global STRIPE_API_KEY --service stripe
# the agent calls: secret_run { command: "curl ... $STRIPE_API_KEY", service: "stripe" }
```

> **Status: 0.x, macOS-first prototype.** Strong enough for daily use on your own
> machine; not a hardened sandbox, per-agent ACL or notarized consumer product.
> Read [Security boundaries](#security-boundaries) before trusting it with
> anything critical. Remaining work is tracked in [docs/REVIEW.md](docs/REVIEW.md).

## Why

- **One vault, not one `.env` per folder.** Credentials live once in an
  age-encrypted file on your machine, protected by a Keychain-held identity.
- **Capability, not credentials.** Agents get `secret_list` and `secret_run`.
  There is no `secret_get`, so a value cannot be pulled into the model context.
- **Coexist with `.env`.** Repos carry `sm://NAME` references; values are
  resolved only when a command runs. Plaintext shadows are refused by default.
- **Honest about limits.** Children receive plaintext credentials; redaction is
  exact-value masking of captured output, not a sandbox. The docs say so.

## What you get

- Encrypted local vault (age X25519) with the identity in the macOS Keychain.
- MCP stdio server with bounded output, cancellation and exact-value redaction.
- Automatic wiring for **OpenCode, Claude Code, Hermes, Codex, DeepSeek Harness,
  Cursor, Claude Desktop, Gemini CLI and Windsurf** — plus copy-paste snippets
  for anything else.
- Global and per-project manifests that contain references only.
- **Service groups** for related values (`BASE_URL` + `API_KEY`) and plain
  config values that skip secret treatment.
- Dotenv import with preview, template injection, leak scanning (`doctor`), and
  a hash-chained audit log.
- A loopback-only web UI and a native macOS WKWebView shell.

## Install

Requirements: macOS 13+, Go **1.27+**. Xcode command-line tools only for the
`.app` bundle.

```sh
git clone https://github.com/karthikmprakash/agents-secret-manager
cd agents-secret-manager

# CLI
mkdir -p ~/.local/bin
go build -o ~/.local/bin/sm ./cmd/sm

# Optional Mac app (ad-hoc signed dev build, not notarized)
./scripts/build-mac-app.sh
open dist/sm.app
```

Then:

```sh
sm onboard        # create/verify the vault, add secrets, wire detected agents
sm ui             # open the local UI (loopback, random per-run token)
```

`sm onboard --yes` skips the secret prompts and explicitly opts into wiring all
detected harnesses. `sm setup --dry-run` previews changes without writing.

> No Homebrew formula or signed installer yet. Build from source for now.
> Moving the binary or app later requires re-running `sm setup`, because agent
> configs reference an absolute path.

## Agent access

Every configured harness launches the same binary as an MCP server:

```
Agent (opencode / claude / hermes / codex / deepseek / cursor / …)
   │  MCP stdio
   ▼
sm mcp ── reads the global manifest + the project manifest for `cwd`
   │      opens the vault with the Keychain identity
   ▼
spawns: /bin/sh -c "the command"   (selected secrets as env vars)
   │      captured output: exact known values → [redacted:NAME]
   ▼
agent receives exit code + redacted output
```

| Tool | Returns |
| --- | --- |
| `secret_list` | Names, service, transport, present/missing — **never values** |
| `secret_run` | Command output + exit code; values are injected, not returned |

```jsonc
// how an agent uses it
{ "command": "curl -s https://api.stripe.com/v1/charges -u $STRIPE_API_KEY:",
  "service": "stripe",              // or names: ["STRIPE_API_KEY"]
  "cwd": "/path/to/project",        // selects the project manifest
  "timeout_seconds": 60 }
```

Omitting both `names` and `service` injects every env-deliverable secret
(cooperative least privilege, not authorization). New secrets are visible on the
next tool call; configuration changes need a harness reconnect/restart.

## Supported harnesses

| Harness | Wiring |
| --- | --- |
| OpenCode | global MCP entry via its CLI |
| Claude Code | `~/.claude.json` (user scope) |
| Hermes | `~/.hermes/config.yaml` |
| Codex (OpenAI app/CLI) | `~/.codex/config.toml` |
| DeepSeek Harness | `~/.dsh/profiles/*/cordis.patch.yml` (requires the official `dsh-mcp-client` plugin) |
| Cursor | `~/.cursor/mcp.json` |
| Claude Desktop | `Claude/claude_desktop_config.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Status in the UI reflects **configuration on disk**, not a verified live
connection. Cloud-only chat apps (for example the ChatGPT web view) cannot reach
a local vault.

For manual wiring:

```sh
sm config                 # every shape
sm config --agent codex   # one harness
```

The same snippets are in the UI under **Agents → Manual setup**.

## Services and plain config

Related values can be grouped, and non-secret config can skip secret treatment:

```sh
sm add --global STRIPE_API_KEY  --service stripe
sm add --global STRIPE_BASE_URL --service stripe --sensitive=false
sm exec --service stripe -- ./app        # injects every member of "stripe"

sm group STRIPE_WEBHOOK_SECRET --service stripe   # move an existing entry
sm group OLD_VALUE --ungroup
```

Agents use `secret_run {service: "stripe"}`. Values marked `sensitive=false` are
still stored, injected and never displayed, but they are **not masked** in
output and `doctor` does not report them as leaks. In the UI, the Secret /
Plain config choice sits directly under the Value field, and groups are managed
from the Secrets list.

## Import existing secrets

```sh
sm import --global --file credentials.env --dry-run
sm import --global --file credentials.env AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
# Use --all only when every plaintext entry should become a secret.
```

The CLI rewrites the selected assignments to `NAME=sm://NAME` at mode 0600;
unselected config is left as-is. Dry-run writes nothing. A conflicting stored
value aborts the preflight: there is no silent replacement. The source file and
the vault are separate files, not one crash-atomic transaction.

## Projects

```sh
sm init                 # .agentsecrets.toml (committed; references only)
sm add GITHUB_TOKEN
sm exec -- npm test
sm inject --tpl config.tpl --out config.json -- npm start
```

```toml
[secrets.GITHUB_TOKEN]
ref = "vault://global/GITHUB_TOKEN"
transport = "env"
```

```sh
# .env (also committed safely)
GH_TOKEN=sm://GITHUB_TOKEN
LOG_LEVEL=debug
```

Precedence: `.env` < `.env.<profile>` < `.env.local` < process environment.
Registered names and aliased refs refuse differing plaintext shadows unless
`SM_ALLOW_PLAINTEXT=1` explicitly allows them. The dotenv parser supports
single-line values and escaped newlines, not shell execution or interpolation.

Templates use `{{sm:NAME}}`. `inject` refuses existing output paths, creates a
0600 file for the command, and removes it on normal/signal-handled completion.
Substitution is raw — use the correct quoting for the target format. Cleanup is
best effort, not guaranteed secure erasure on APFS/SSDs or after `SIGKILL`.

## Security boundaries

- **Vault**: age X25519 ciphertext at `~/.config/sm/vault.age`; identity in the
  Keychain (service `sm`, account `identity`). Writes are serialized, atomic and
  fsynced.
- **Children receive plaintext credentials.** Arbitrary code can encode them,
  send them over a network, or write them to disk. Same-user processes can
  access user files and the Keychain according to OS permissions. This is not a
  sandbox, prompt-injection defense, per-agent ACL or egress firewall.
- **Redaction** masks exact known *sensitive* values in captured output.
  `--redact auto` masks when output is not a TTY; `always`/`never` override.
  Raw TTY output, encoded values, unregistered plaintext `.env` values and
  alternate channels are outside that guarantee. `--only` and `service` are
  cooperative selection, not authorization.
- **Audit** entries record intent before operations. Hash links detect accidental
  interior damage; they do not stop same-user rewriting or truncation.
- **`sm doctor`** scans registered exact values and managed assignments in
  bounded locations/history. It is not a complete secret-pattern scanner and
  cannot certify a transcript or repository is safe to share.
- **`scope`, `hosts`, `default_ttl`** are advisory metadata today. Proxy and
  dynamic delivery are not implemented. Never rely on them as enforcement.
- **Test overrides** (`SM_CONFIG_DIR`, `SM_IDENTITY`) are for CI and throwaway
  runs. Never commit them, log them or put `SM_IDENTITY` in an agent config; it
  is stripped from task children.
- **Recovery is unfinished.** Backing up `vault.age` alone is not enough without
  the Keychain identity. Do not delete the identity. A portable encrypted
  backup/restore flow, per-agent policy and notarized distribution are
  prerequisites for broad distribution.

## Development

```sh
make check                                            # gofmt, vet, test -race
make build                                            # ~/.local/bin/sm
go test ./internal/redact -fuzz=FuzzStreaming -fuzztime=10s
SM_UI_PREVIEW=1 SM_UI_PREVIEW_SEEDED=1 \
  go test -v ./internal/uiserver -run TestInteractivePreview -timeout 16m
```

Tests use temporary vaults and generated identities; they never configure your
installed harnesses. See [CONTRIBUTING.md](CONTRIBUTING.md) for the code map and
adapter guide, and [SECURITY.md](SECURITY.md) for private vulnerability
reporting.

## Docs

- [Architecture](docs/ARCHITECTURE.md) — components, data flow, invariants.
- [Contributing](CONTRIBUTING.md) — setup, adapter checklist, style.
- [Security policy](SECURITY.md) — reporting and threat model.
- [Implementation review](docs/REVIEW.md) — fixes and remaining work.
- [Historical design](docs/DESIGN.md) — original v0.1 proposal (superseded).
- [Changelog](CHANGELOG.md).

## Credits

Brand marks in the UI use [Simple Icons](https://simpleicons.org) (CC0) and a
caduceus glyph from [game-icons.net](https://game-icons.net) (CC BY 3.0). All
product names and logos are trademarks of their respective owners; they are
shown only to identify the harness being configured. This project is not
affiliated with or endorsed by any of them.

## License

[MIT](LICENSE) © 2026 Karthik M Prakash
