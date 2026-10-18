# Contributing to sm

Thanks for taking a look. `sm` is a small, security-sensitive tool, so the bar is
"boring and correct" before "clever". This guide covers the local setup, the code
map, and the kinds of contributions that help most.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

> **Never include real credentials** in issues, pull requests, screenshots or
> test fixtures. For vulnerabilities, use [SECURITY.md](SECURITY.md) instead of
> a public issue.

## Ways to contribute

- **Harness adapters** — add support for an agent runtime that speaks MCP and
  stores its configuration on disk.
- **Bug reports** — include the exact `sm version`, macOS version, harness and
  reproduction steps. Redact paths and values.
- **Docs and UX** — clearer copy, accessibility, mobile layout, error states.
- **Tests** — resolver precedence, redaction edge cases, adapter merges,
  manifest edits, UI states.
- **Platform work** — Linux/Windows identity backends, notarized macOS
  distribution, and stronger recovery/retention workflows. These are tracked in
  [docs/REVIEW.md](docs/REVIEW.md).

## Development setup

Requirements:

- Go **1.27+** (see `go.mod`).
- macOS 13+ for the full experience: the vault identity uses the Keychain and
  the desktop shell uses WKWebView.
- Xcode command-line tools only if you want to build the `.app` bundle.

```sh
git clone https://github.com/karthikmprakash/agents-secret-manager
cd agents-secret-manager

make check          # gofmt, go vet and go test -race
make build          # ~/.local/bin/sm
make app            # dist/sm.app (ad-hoc signed, not notarized)
```

Tests never touch your real vault or your installed harness configs. They use
`SM_CONFIG_DIR` (throwaway directory) and `SM_IDENTITY` (generated test
identity). Never set `SM_IDENTITY` in an agent configuration; it is a test
override and is stripped from task children.

### Landing page and screenshots

The GitHub Pages site is static HTML/CSS/JS under `docs/`. Its palette follows
the app's light/dark tokens; don't introduce a separate marketing theme.

```sh
python3 -m pip install playwright
python3 -m playwright install chromium
make test-landing     # responsive layouts, images, copy controls and install commands
make screenshots      # recapture current app branding with isolated dummy data
```

Never take documentation screenshots of your actual vault. `make screenshots`
starts a throwaway UI fixture and refreshes both themes for the README and site.

## Code map

| Path | Responsibility |
| --- | --- |
| `cmd/sm/` | CLI commands (one file per command) and end-to-end tests |
| `internal/manifest/` | `.agentsecrets.toml` schema, layers, validated manifest edits |
| `internal/store/` | `Store` interface and the age-encrypted vault file |
| `internal/keys/` | Keychain identity lookup/create (with the test override) |
| `internal/resolve/` | `.env` chain, precedence, injection and its redaction set |
| `internal/redact/` | Streaming exact-value masker |
| `internal/mcpserver/` | MCP tools: `secret_list`, `secret_run` |
| `internal/wireup/` | Harness detection, status and wiring; manual snippets |
| `internal/agentcfg/` | Comment-preserving merges for JSON/YAML/TOML agent configs |
| `internal/secrets/` | Shared validated mutations used by CLI and UI |
| `internal/detect/` | Parses pasted commands/env lines for the detect → review flow |
| `internal/recovery/` | Local passphrase-encrypted archives and empty-vault restore |
| `internal/scan/` | `sm doctor` scanner (registered values only) |
| `internal/uiserver/` | Loopback HTTP server, API and embedded UI |
| `macapp/` | Swift WKWebView shell with the app lock (Touch ID / passphrase) |
| `desktopapp/` | GTK + WebKitGTK shell for Linux (separate Go module) |
| `internal/applock/` | Argon2id verifier for the desktop app passphrase |
| `scripts/` | Build, screenshot and browser-test scripts |

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Adding a harness adapter

Adapters live in `internal/wireup/wireup.go`. An adapter is a target with four
pieces:

1. **Detection** — a binary on `PATH` (use `findBin`) or a config path that must
   exist. Don't claim support for a harness you cannot verify.
2. **Status** — parse the file on disk and compare the command against the
   current absolute path of `sm`. Status means *configuration on disk*, not a
   live connection.
3. **Apply** — merge only your entry, preserve unrelated configuration, back up
   the file, validate before writing. Use or extend `internal/agentcfg`:
   - JSON: `MergeJSONMCPServers`
   - YAML: `MergeYAMLMCPServers`
   - TOML: `MergeTOMLMCPServers`
   - marker-delimited blocks in user-editable files: `UpsertYAMLBlock`
4. **Tests** — status reflects disk changes, apply is idempotent, existing
   comments/formatting survive. See `internal/wireup/wireup_test.go`.

Then:

- add a copy-paste snippet in `internal/wireup/snippets.go` (`sm config` and the
  UI **Manual setup** sheet read from it),
- update the supported-harness table in `README.md`,
- note the restart/reconnect requirement in the apply message.

## Tests

```sh
make test                 # unit + CLI flows
make test-race
python3 scripts/test-ui.py  # opt-in Playwright regressions, isolated vaults
go test ./internal/redact -fuzz=FuzzStreaming -fuzztime=10s
```

The UI has an interactive preview fixture (requires Playwright and a browser):

The complete browser regression script requires `python3 -m pip install playwright`
and `python3 -m playwright install chromium`. It starts and stops its own isolated
fixtures. Set `SM_UI_SCREENSHOTS` to retain screenshots of dummy data locally.

```sh
SM_UI_PREVIEW=1 SM_UI_PREVIEW_SEEDED=1 go test -v ./internal/uiserver \
  -run TestInteractivePreview -timeout 16m
```

## Style

- Run `make check` before pushing. CI enforces gofmt, vet and `-race`.
- Keep the security boundaries in the README honest. If a feature does not
  enforce something, say so in the docs and in the CLI copy.
- Errors should state the problem and the next action, without echoing values.
- Prefer the standard library. New dependencies need a short rationale in the PR.
- Small, focused PRs. Describe the user-visible change and the tests that cover
  it. Screenshots are welcome for UI changes.
- Commit messages: imperative summary, then a short body explaining why.

## Good first issues

- Add a harness adapter from the list in [docs/REVIEW.md](docs/REVIEW.md).
- Improve empty/error states in the web UI.
- Add resolver tests for `.env` profile precedence edge cases.
- Document a real-world workflow (AWS, Modal, GitHub, database clients).
- Add a Linux identity backend (Secret Service) behind the `keys` interface.

## Pull request checklist

- [ ] `make check` passes.
- [ ] New behavior has tests; existing tests were not weakened.
- [ ] Docs updated (README / ARCHITECTURE / CHANGELOG where relevant).
- [ ] No credentials, personal paths or machine-specific values are included.
- [ ] Security implications are called out explicitly.
