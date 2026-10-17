# Agent Secrets Manager — v0.1 design

**Frozen 2026-10-17.** Manifest schema and the v0.1 CLI surface are locked.
Post-freeze changes ship in v0.2 unless they break the schema — in which case
the schema gets a version.

## The one rule

Secret values never enter the model's context. The repo carries a manifest of
references; values are injected at the last moment — into a child process, a
0600 file, or (v0.3) at egress. The manifest is the protocol; every surface is
an adapter over the same resolver.

## Locked decisions

| Decision | Choice |
| --- | --- |
| Goal | Personal daily-driver first — generalize later if it earns it |
| Security | T1 now: inject + redact + audit. T2 broker seam designed in; T3 later |
| Storage | Local vault behind a `Store` interface; master key in the OS Keychain; connectors later |
| Stack | Go — one static binary, no runtime |
| v0.1 scope | Manifest + exec + doctor + redaction + audit. No daemon, no MCP, no proxy |

## Architecture

```
agents ─┬─ sm exec            (v0.1 · universal: env injection)
        ├─ sm inject          (v0.1 · file materialize, 0600)
        ├─ MCP · stdio        (v0.2)
        └─ daemon + proxy     (v0.3)
             │
       core ─┴─ resolver (.env refs + manifest + store)
             │  policy (refuse-on-shadow)
             │  redaction + audit (hash-chained)
             │
       store ── vault.age (X25519) · master key in Keychain
             └─ connectors: op:// infisical:// aws-sm:// (v0.3)
```

## Manifest schema

```toml
# .agentsecrets.toml — committed; no values, ever
[project]
name        = "slavia-api"
default_ttl = "8h"

[secrets.GITHUB_TOKEN]
ref       = "vault://dev/github/pat"      # logical name → store
transport = "env"                         # env | file | proxy | generated
scope     = ["cmd:gh", "cmd:git"]         # local policy; advisory in v0.1
hosts     = []

[secrets.STRIPE_KEY]
ref       = "vault://dev/stripe/live"
transport = "proxy"                       # never materialized (enforced v0.3)
hosts     = ["api.stripe.com"]

[secrets.DB_PASSWORD]
ref       = "vault://dev/db/password"
transport = "env"
generate  = "postgres/32"                 # v0.1: at add-time · v0.3: minted per lease
```

Store schemes: `vault://` (local, v0.1) · `op://` `infisical://` `aws-sm://`
(connectors, v0.3).

## .env & precedence

```sh
# .env — committed-safe: refs, not values
OPENAI_API_KEY=sm://OPENAI_KEY       # logical name → manifest → store
DATABASE_URL=postgres://app@localhost:5432/dev
SMTP_HOST=smtp.example.com           # plain config stays plaintext
```

- Registered names (in the manifest): the vault wins. A plaintext value at the
  same name refuses to run — override with `SM_ALLOW_PLAINTEXT=1`.
- Unregistered names: process env > `.env.local` > `.env.profile` > `.env`.
- Discovery: `.agentsecrets.toml` walked up from cwd (git-style); global
  `~/.config/sm/manifest.toml` merged underneath — project wins.

## Delivery model

| Mechanism | Kind | Ships | Notes |
| --- | --- | --- | --- |
| env injection | transport | v0.1 | into the child process env — only the command that needs it |
| file materialize | transport | v0.1 | template → 0600 file inside a wrapper session; shredded on exit |
| proxy | transport | v0.3 | egress injection; value never materialized; CA-trust friction |
| generated | transport | v0.3 | minted per lease; makes never-reveal real |
| `sm exec` · `sm inject` | surface | v0.1 | universal — any agent that spawns a process |
| MCP · stdio | surface | v0.2 | list / use / run / generate — never get |
| daemon | surface | v0.3 | leases, agent identity, revocation |

Per-secret `transport` in the manifest; surfaces route to allowed transports.

## Security ladder

| Tier | Enforcement | Stops | Ceiling |
| --- | --- | --- | --- |
| T1 · v0.1 | inject + redact + audit | transcript echoes · env dumps · accidental commits | a determined, injected agent |
| T2 · v0.3 | egress broker (HTTPS_PROXY) | exfiltration of brokered keys | clients that ignore proxy env · CA trust setup |
| T3 · later | sandbox + leases + agent identity | lateral movement · replay · standing credentials | — |

T1 honesty: env injection + redaction is accident prevention, not a sandbox.
An agent that can run arbitrary code can still exfiltrate a value it was given.
The broker (v0.3) is the real fix for API keys.

Audit entries record names, never values:

```json
{"ts":"2026-10-17T09:12:03Z","session":"01J…","cmd":"npm test","secrets":["GITHUB_TOKEN"],"action":"inject","cwd":"~/dev/slavia-api","prev":"sha256:9f3a…"}
```

`sm log verify` walks the hash chain.

## CLI surface — v0.1

| Command | What it does | Ships |
| --- | --- | --- |
| `sm init` | create vault + manifest, wire Keychain, update .gitignore | v0.1 |
| `sm add NAME` | store a secret (prompt · stdin · --generate), map its ref | v0.1 |
| `sm import` | migrate plaintext .env values into the vault, leave sm:// refs | v0.1 |
| `sm doctor` | scan git history, shell rc, .env files, agent transcripts; report + migrate | v0.1 |
| `sm exec -- cmd` | resolve refs → inject env → redact output → audit | v0.1 |
| `sm inject --tpl` | materialize a template inside a wrapper session: 0600, shred on exit | v0.1 |
| `sm env` | resolved names + sources — never values | v0.1 |
| `sm log · verify` | read the audit trail; verify the hash chain | v0.1 |
| `sm rotate NAME` | new value; every ref keeps working | v0.1 |
| `sm mcp` | MCP stdio server — list / use / run / generate, never get | v0.2 |

## Repo layout

```
cmd/sm/            main · command routing
internal/manifest/ schema · discovery (walk-up + global) · validation
internal/store/    Store interface · vaultfile (age) · Keychain master key
internal/resolve/  .env + refs → env map · precedence · refuse-on-shadow
internal/run/      child spawn · env injection · redaction · TTY passthrough
internal/audit/    hash-chained JSONL · verify
internal/scan/     doctor · git history · rc files · transcripts · known-value match
internal/tpl/      sm inject · materialize 0600 · shred on exit
internal/mcp/      v0.2 · stdio server
internal/broker/   v0.3 · daemon · HTTPS_PROXY egress injection
```

## Build order

- **M0 · Skeleton** — CLI routing, config, module layout; gofmt / vet / test.
- **M1 · Store + manifest** — vault.age behind the Store interface; master key
  in Keychain; manifest parse + validate; `sm init`, `sm add`, `sm env`.
- **M2 · Resolve + exec** — .env parsing, ref resolution, precedence +
  refuse-on-shadow; `sm exec` spawns the child with injected env.
- **M3 · Redaction + audit** — exact-match masking of registered values in
  stdout/stderr (longest-first); hash-chained audit.jsonl; `sm log verify`.
- **M4 · Doctor + import** — scans git history, shell rc, .env files, agent
  transcripts; known-value matching; `sm import` leaves `sm://` refs behind.
- **M5 · Template + rotate** — `sm inject --tpl` (0600, shred on exit);
  `sm rotate`. Then v0.2: MCP + agent glue.

## Deliberately deferred

- **v0.2 — MCP + agent glue.** list / use / run / generate tools; never get.
  AGENTS.md snippet + Claude Code hook so Bash calls route through `sm exec`.
- **v0.3 — daemon + broker.** HTTPS_PROXY egress injection, capability leases,
  per-agent identity, revocation; connectors; token minting (GitHub App, STS).
- **Never-reveal keygen** becomes real only when the manager can set a
  credential on the target (connectors) or hold it at egress (broker).

## Non-goals (v0.1)

- No cloud dependency. No values in the manifest, ever.
- No `secret_get` over MCP — values never return to model context.
- No daemon, no proxy, no leases in v0.1.
- T1 is not a sandbox.

## Implementation notes (as built)

- Config dir: `~/.config/sm/` — overridable with `SM_CONFIG_DIR` (tests).
- Vault: `~/.config/sm/vault.age` — age X25519, JSON map keyed by ref path,
  atomic writes, mode 0600.
- Identity: Keychain service `sm`, account `identity`; `SM_IDENTITY`
  (AGE-SECRET-KEY-1…) overrides the Keychain for CI and throwaway runs.
- Module: `github.com/karthikmprakash/agents-secret-manager`.
- `sm exec [--profile NAME] [-v] -- <cmd>`: `.env` files are read from the
  project root (the manifest's directory; cwd when only the global manifest
  exists). Precedence: `.env` < `.env.<profile>` < `.env.local` < process env.
- Managed names: a differing plaintext value (from `.env` or the process env)
  refuses to run unless `SM_ALLOW_PLAINTEXT=1`; empty and identical values are
  allowed (identical values keep nested `sm exec` calls working).
- dotenv (v0.1): `KEY=VALUE`, optional `export `, `#` comments, single/double
  quoted values, no variable expansion. Inline comments start at ` #`.
- Redaction: injected values are masked in the child's stdout/stderr as
  `[redacted:NAME]`, longest-first, safe across write boundaries.
  `--redact auto` (default) redacts when stdout or stderr is not a TTY;
  `always`/`never` override.
- Audit: `~/.config/sm/audit.jsonl`, mode 0600, append-only JSONL, flock-
  serialized. Each line carries the SHA-256 of the previous line. `sm log`
  lists entries; `sm log verify` walks the chain. Interior edits, reordering
  and truncation from the middle are detectable; truncation of the tail and
  edits to the last line are not (no external anchor). Command lines are
  redacted against injected values before writing.
