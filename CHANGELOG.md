# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
the `0.x` series.

## [Unreleased]

### Added

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
