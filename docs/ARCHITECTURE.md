# Architecture

`sm` is a single Go binary with four entry points that share one core:

```
            ┌─────────────────────────────────────────────┐
            │                  sm binary                  │
            │                                             │
  CLI ──────┤ cmd/sm  (add, exec, mcp, setup, ui, …)      │
  MCP ──────┤ internal/mcpserver  (secret_list/run)       │
  Web UI ───┤ internal/uiserver   (loopback + embedded UI)│
  Mac app ──┤ WKWebView → loopback UI                     │
            └───────────────┬─────────────────────────────┘
                            │
             ┌──────────────┴──────────────┐
             │        core packages        │
             │  manifest · resolve · scan  │
             │  secrets · redact · audit   │
             ├──────────────┬──────────────┤
             │ vault (age)  │ Keychain     │
             └──────────────┴──────────────┘
```

## Entry points

| Entry point | Package | Notes |
| --- | --- | --- |
| CLI | `cmd/sm` | One file per command; `main.go` is the dispatch and usage text |
| MCP | `internal/mcpserver` | stdio transport; two tools, no value-returning tool |
| Web UI | `internal/uiserver` | loopback only, capability token + HttpOnly cookie, strict CSP, embedded HTML |
| Mac app | `macapp/` | WKWebView shell around `sm ui`; ad-hoc signed dev build |

## Mutations

All writes go through shared, validated services so CLI and UI behave the same:

- `internal/secrets.AddBatch` — validates every input, writes vault values first,
  rolls back on failure, then appends manifest entries (`manifest.AppendSecrets`).
- `internal/secrets.Rotate` / `SetService` — operate on an existing entry.
- `internal/manifest` — schema + in-place edits that preserve comments and
  formatting, with a parse-and-validate step before writing.
- `internal/safeio` — atomic writes (temp file + rename + fsync) and lock files.

Runtime artifacts live under `~/.config/sm/` (or `SM_CONFIG_DIR` in tests):
`vault.age`, `manifest.toml`, `audit.jsonl`, plus lock files.

## Resolution (`sm exec`, `sm mcp`)

`internal/resolve.Build` produces both the child environment and the redaction
set. Precedence, lowest to highest:

```
.env  <  .env.<profile>  <  .env.local  <  process environment
```

- Manifest names are injected under their own name.
- `.env` values of the form `sm://NAME` bind an environment variable to a
  declared secret.
- A differing plaintext value for a managed name refuses to run unless
  `SM_ALLOW_PLAINTEXT=1` is set explicitly.
- The redaction set contains **sensitive** registered values only. Values marked
  `sensitive = false` are plain config: they are injected, but not masked and not
  reported by `doctor`.
- `SM_IDENTITY` is removed from the child environment.

## MCP

`secret_list` returns names, services, transport and vault presence.
`secret_run` runs a shell command with selected secrets as environment variables.

- Selection: `names`, `service`, or all env-deliverable secrets.
- Output is bounded (100 KB) and passed through the redactor before returning.
- Cancellation kills the process group; `timeout_seconds` is bounded.
- There is deliberately no `secret_get`: values never appear as tool results.

## Manifests

```toml
[project]
name = "example"
default_ttl = "8h"

[secrets.STRIPE_API_KEY]
ref = "vault://global/STRIPE_API_KEY"
transport = "env"
service = "stripe"

[secrets.STRIPE_BASE_URL]
ref = "vault://global/STRIPE_BASE_URL"
transport = "env"
service = "stripe"
sensitive = false
```

Global (`~/.config/sm/manifest.toml`) is merged underneath the project manifest;
the project wins per name. Manifests contain references, never values.

## Harness adapters

`internal/wireup.Detect` returns targets with `Status()` and `Apply()`.
`Status` reflects configuration **on disk**, not a live connection. Each adapter
merges only its own entry via `internal/agentcfg`, which preserves unrelated
tables/comments and validates before writing. `internal/wireup/snippets.go`
provides the same shapes for manual wiring (`sm config`, UI **Manual setup**).

## Invariants

1. No MCP tool or stored-state endpoint returns a raw vault value. The import
   preview echoes only values from the user's current paste for local review;
   recovery downloads contain passphrase-encrypted bytes, never plaintext.
2. The model only sees names, status and redacted command output.
3. Child processes receive plaintext credentials — this is not a sandbox.
4. Manifests carry references only; values live in the vault.
5. Writes are locked, atomic and validated; edits preserve unrelated content.
6. Redaction covers exact registered *sensitive* values in captured output only.
7. Test overrides (`SM_CONFIG_DIR`, `SM_IDENTITY`) never ship in agent configs.
8. Parsing, review, recovery, and UI assets are local-only: no model API,
   telemetry, cloud account, or remote storage. User-invoked child commands may
   contact their providers; sm does not sandbox those commands.

## Import review and recovery

`internal/detect.Analyze` handles structured objects, env lines, supported CLIs,
curl headers and labeled text. Stable per-paste IDs identify entries independently
of their editable names. Different values are preserved; unknown classifications
default to sensitive. `/api/review-detected` compares selected drafts locally;
`/api/add-detected` validates IDs, names, values and metadata before the shared
batch mutation. Same-value reuse never silently changes existing metadata.

`internal/recovery` encrypts the global manifest and all vault values into an age
scrypt archive. Restore authenticates and bounds the full archive before writing,
then re-encrypts under the destination identity. It refuses existing destinations.
The CLI and authenticated local UI share this core; no recovery tools are exposed
over MCP. Project manifests and audit history are not included.

## Tests

- Unit tests per package; `go test -race ./...` in CI.
- CLI flows live in `cmd/sm/workflow_test.go`.
- Adapter merges are tested in `internal/agentcfg` and `internal/wireup`.
- The streaming redactor has a fuzz target (`FuzzStreaming`).
- `internal/uiserver/preview_test.go` drives a real browser when
  `SM_UI_PREVIEW=1` is set (Playwright; not part of default CI).
- `python3 scripts/test-ui.py` starts its own isolated fixtures and exercises
  editable import/conflicts, group Undo, backup download, clean restore and
  light/dark layouts at 390/1040/1440 px. No real vault or Keychain is used.
