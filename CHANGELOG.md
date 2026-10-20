# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the `0.x` series.

## [Unreleased]

### Changed

- Group headers no longer repeat a labeled **Manage group** button on every
  section. Each header now carries one `+` and one `⋯` disclosure, matching the
  row action group. A group that spans global and project entries lists one
  menu entry per scope instead of two buttons in the header.

## [0.5.5] - 2026-10-20

Reveal control moved into a proper row action group.

### Changed

- The reveal control is now a row action in a right-aligned action group next
  to the overflow menu, instead of sitting inside the value text. It no longer
  shifts or crowds the masked hint, every eye in the list shares one column,
  and the overflow menu keeps the same position on rows with and without a
  reveal control.

## [0.5.4] - 2026-10-20

Reveal-control alignment and clearer redaction boundaries.

### Changed

- Clarified that redaction covers MCP output before it reaches the harness, not
  the harness's own request/session logs, model context, or child-written
  files.
- The sensitive-value eye button now sits directly beside the masked hint and
  is vertically centered with it, instead of at the far edge of the row.

## [0.5.3] - 2026-10-19

Cached update checks and eye-button value reveal.

### Added

- Update checks from GitHub Releases: `sm update` plus an explicit download
  icon in the UI. Results are cached in `~/.config/sm/update.json`, shown in
  `sm status`, and surfaced as an **Update available** banner. No background
  check or telemetry.

### Changed

- Sensitive values use an eye button on the row instead of a menu action; the
  value auto-hides after 20 seconds.

### Fixed

- Symlinked `sm` paths (for example `~/.local/bin/sm` pointing at the Homebrew
  binary) count as configured instead of showing as "different path".

## [0.5.2] - 2026-10-19

OpenCode wiring fallback, harness removal, and local value access.

### Added

- Local value visibility: plain config is shown in the UI and with
  `sm env --show-config`; sensitive entries show a last-four hint and can be
  revealed in the UI for 20 seconds. `sm get NAME` prints one value locally.
  Reveals are audited; MCP still has no value-returning tool.
- Harness removal: `sm setup --remove --agent NAME` (or `--all`) and a
  **Remove** action in the UI Agents view delete only the sm MCP entry, with
  backups and unrelated config preserved.

### Fixed

- OpenCode wiring no longer depends on an `opencode` binary being on the GUI
  PATH or on a version-specific CLI syntax. It now edits the JSON/JSONC config
  directly when the CLI is unavailable or fails, and status parses JSONC.

## [0.5.1] - 2026-10-18

Homebrew distribution for the macOS app.

### Added

- `brew tap karthikmprakash/tap && brew install --cask sm` installs the
  universal macOS app and the `sm` CLI.
- The macOS app zip is now universal (Apple Silicon + Intel) and contains the
  CLI, so the cask can install both from one verified download.

### Changed

- README, guide and landing page now lead with Homebrew and direct-download
  commands for the macOS app, Linux desktop app and CLI.

## [0.5.0] - 2026-10-18

Desktop apps with an app lock, and a GTK/WebKitGTK shell for Linux.

### Added

- Desktop app lock: a passphrase plus Touch ID on macOS and a passphrase plus
  optional `fprintd` fingerprint on Linux. `sm lock` manages the Argon2id
  verifier; macOS locks on launch, sleep and screen lock, and the Linux shell
  locks after 15 minutes idle or with Ctrl+Shift+L.
- A GTK + WebKitGTK desktop shell for Linux (`make desktop-linux`), sharing the
  loopback UI with the macOS WKWebView app. Release builds now include a macOS
  app zip and Linux CLI/desktop binaries.
- A self-contained GitHub Pages landing page with the product screenshot,
  Archify architecture diagram, install steps and security boundaries.
- The SM monogram brand pack across the Mac app icon, local UI, README and
  landing page, including favicons, web manifest and a social card.

### Changed

- Landing page now shares the app's cool-neutral colors, ink actions and blue
  accent; refreshed light/dark screenshots include the current app branding.
- README uses an opaque logo tile for contrast on any GitHub theme. Added
  repeatable dummy-data screenshot capture and responsive landing-page tests.
- Install instructions download both the binary and its checksum, with an
  Apple Silicon/Intel selector and working clipboard fallback.
- Landing page compatibility strip uses the actual harness logos instead of
  text wordmarks, with accessible names and local SVGs.

## [0.4.0] - 2026-10-17

Editable local import review, broader deterministic parsing, group management,
passphrase-encrypted recovery, a redesigned CLI, and developer-focused docs and
diagrams.

### Added

- A developer-focused README and [user guide](docs/GUIDE.md): problem, quick
  start, MCP surface, supported harnesses, import behavior, recovery, security
  boundaries and honest alternatives, with a current UI screenshot.
- An Archify-generated runtime architecture diagram, with its editable JSON
  source checked in under `docs/assets/`.
- A real CLI experience: plain `sm` opens a status dashboard with actionable
  next steps, `sm agents` lists detected harnesses and wiring state, and
  `sm help <command>` documents usage, options and examples. `sm help` groups
  commands by task, with TTY-aware color, status symbols and `NO_COLOR` support.
- Shell completion for bash, zsh and fish (`sm completion <shell>`).
- `sm setup --agent NAME` wires one detected harness; `sm add --group` and
  `--config` are readable aliases for `--service` and `--sensitive=false`;
  `sm env --verbose` groups by service and reveals references on request;
  `sm log --limit N` bounds audit output.
- CLI recovery operations are now recorded in the same hash-chained audit trail
  as the UI.

- Fully editable local import review (name, value, group, Secret/Config), local
  same/different-value checks, line warnings, stable entry IDs, and preservation
  of differing duplicate names. Unknown values now default to Secret.
- Local parsing of JSON/YAML, labeled text, email addresses within prose, and
  curl authorization/API-key headers. Labeled blocks may separate labels from
  values with whitespace, and Cloudflare R2 blocks (API token, access key ID,
  secret access key, S3 endpoint) are grouped automatically. Credential-bearing
  URLs stay sensitive.
- Group-level rename/ungroup with guarded UI Undo; `sm service` CLI, and search
  by service, scope, type and status.
- Passphrase-encrypted local recovery in CLI and UI: export, verify, restore
  into an empty destination with a new identity. No cloud storage or master-key
  export. Native macOS save-dialog support for encrypted recovery downloads.
- Isolated Playwright regression script for import, groups and recovery.

- The Import sheet accepts any pasted text — .env lines, setup commands, bare
  emails/URLs/tokens, or a mix — and auto-detects entries (Modal, AWS, generic
  `KEY=value`), with secret/config classification, inferred groups, editable
  names, and masked values that can be revealed for verification. Missing
  groups are created on save; values are never logged or exposed in stored
  state.

- Secrets are organized into distinct group cards with member counts; each
  group has a quick-add action that preselects it.
- The add-secret sheet asks for a group: assign an existing one, create a new
  one inline, or leave it ungrouped.
- Group pickers are a styled combobox with filtering, keyboard navigation and
  an explicit create-new row, replacing the native datalist/select popups.

## [0.3.0] - 2026-10-17

First public release.

### Added

- Encrypted local vault (age X25519) with the identity stored in the macOS
  Keychain; atomic, locked writes.
- MCP stdio server with `secret_list` and `secret_run` (no `secret_get`), exact
  value redaction, bounded output, cancellation and timeouts.
- Automatic wiring for OpenCode, Claude Code, Hermes, Codex, DeepSeek Harness,
  Cursor, Claude Desktop, Gemini CLI and Windsurf, with on-disk status.
- `sm config` and the UI **Manual setup** sheet for copy-paste MCP snippets.
- Global and per-project manifests (`.agentsecrets.toml`) that carry references
  only; `.env` files can use `sm://NAME` references.
- Service groups for related values (`sm add --service`, `sm group`,
  `sm exec --service`, `secret_run {service}`).
- `sensitive = false` plain config values: injected and never displayed, but not
  masked and not reported as leaks by `doctor`.
- `sm import` (bulk dotenv migration with preview), `sm inject` (template
  rendering with cleanup), `sm doctor` (leak scan), audit log with hash-chain
  verification.
- Loopback-only web UI with a random capability token, HttpOnly session cookie
  and a strict CSP; optional native macOS WKWebView shell.
- CLI onboarding wizard (`sm onboard`) and first-run guidance.

### Security notes

- Children receive plaintext credentials; redaction applies to captured output
  only. This is not a sandbox or a prompt-injection defense.
- `scope`, `hosts` and `default_ttl` are advisory metadata, not enforcement.
- Backups of `vault.age` alone are not sufficient without the Keychain identity.
