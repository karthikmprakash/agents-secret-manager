# Implementation review and refinement

Reviewed 2026-10-17. Scope: every Go package, CLI workflows, MCP tools, agent
configuration adapters, loopback API, embedded UI, Swift shell and Mac build.
This is a source review with regression testing, not an independent penetration
test or production security certification.

## Outcome

The original implementation was a working prototype, not a release-ready
secrets manager. Passing smoke tests had missed important security and data-loss
cases. The fixes below make it substantially safer for a trusted-agent personal
workflow. Untrusted-agent isolation remains a separate architectural project.

## Fixed: data integrity

- `internal/store/vaultfile/vaultfile.go`: stale parallel writers could overwrite
  each other's maps. Mutations now reload under a cross-process lock; failed
  persistence does not mutate the instance's snapshot. `SetNew` rejects collisions.
- `internal/manifest/manifest.go`: new default refs no longer collide across
  repositories or case-sensitive names. Project refs use a canonical-path-derived
  namespace; global refs use `vault://global/NAME`. Existing refs stay unchanged.
- `internal/secrets/secrets.go`: one validated mutation service for CLI and UI.
  Batch preflight detects conflicts before writing; invalid names, transports,
  reserved vault controls and NUL values are rejected. Store/replace attempts
  are audited before writes. Mutation locking coordinates cooperating sm processes.
- `cmd/sm/import.go`: dry-run no longer creates a manifest; global input paths
  are relative to cwd even inside a repository. Imports refuse differing stored
  values rather than discarding the source. Rewrites are atomic, mode 0600.
- `internal/manifest/manifest.go`: locked, atomic manifest appends; unknown
  manifest fields are rejected so an accidental `value` field is not ignored.
- `internal/agentcfg/agentcfg.go`: config merges are locked/atomic and preserve
  the original backup across retries. Invalid JSON roots/containers fail rather
  than panic or replace the surrounding config. Config/backup files use 0600.

## Fixed: credential and process handling

- `internal/resolve/resolve.go`, `internal/runner/runner.go`: `SM_IDENTITY` was
  inherited by task children, exposing the CI/test master identity. It is now
  stripped from exec, inject and MCP task environments. Internal control names
  cannot be added as user secrets.
- `internal/resolve/resolve.go`: aliases now receive the same refuse-on-shadow
  policy as directly registered names. Both original and overridden values stay
  in the redaction set. Unimplemented generated delivery is no longer env-injected.
- `internal/redact/redact.go`: replacement markers are no longer rescanned for
  shorter secrets. Streaming matches one-shot results over write boundaries and
  only retains actual partial prefixes, so ordinary progress output is not held
  until command exit.
- `internal/mcpserver/server.go`: bounded capture replaces unbounded
  `CombinedOutput`; deadlines, cancellation of descendants, and bounded pipe
  shutdown prevent hung tool calls. Command errors do not echo raw command text.
  CLI `--only` and MCP `names` optionally limit credential delivery.
- `internal/tpl/tpl.go`, `cmd/sm/inject.go`: output paths are exclusively created,
  not overwritten; cleanup is deferred and bound to the created inode; symlinks
  are not followed. Signal forwarding no longer races process startup. Invalid
  templates are checked before substitution, not by reinterpreting secret data.
- `internal/audit/audit.go`: appends reject a broken/incomplete chain, enforce
  0600 and sync writes. Verification errors do not echo untrusted stored fields.
- `internal/scan/scan.go`: no raw transcript context in findings; surrounding
  unregistered keys could otherwise be printed. Quoted refs are not misreported
  as plaintext assignments; history limits reset per file and external diff/text
  conversion is disabled. Output describes scan limits rather than claiming safety.

## Fixed: UI, onboarding and Mac shell

- `internal/uiserver/server.go`: a fresh install can explicitly initialize a
  vault from the app; existing/unavailable identities are not replaced.
- `internal/uiserver/ui/index.html`: bulk import with a names-only preview,
  per-entry selection, inline conflicts and no source-file rewrite. Password,
  pasted input and file selection are cleared on dismissal/success.
- `internal/wireup/wireup.go`: on-disk configuration is checked on each request.
  UI says Configured, not Connected; it no longer invents live connection status
  from an in-memory Set. Reconfiguring Claude updates its user config instead of
  treating an arbitrary 'already' CLI error as success. No config changes were
  applied to the user's installed harnesses during this review.
- `internal/uiserver/server.go`: explicit methods, body limits, strict JSON,
  loopback Host/Origin checks, constant-time capability comparison, HttpOnly
  per-run cookie bootstrap, no query-token authorization for mutations, CSP,
  no-store and anti-framing headers. Refresh no longer loses authentication.
- `internal/uiserver/ui/index.html`: persistent load errors, truthful unavailable
  status, no false empty state, names-only metadata, focus return and inert
  background for sheets, unsaved-change handling, busy-state safety, accessible
  segmented controls, clipboard error fallback, readable timestamps, responsive
  toolbars/touch targets and higher-contrast secondary text.
- `macapp/SMApp.swift`: nonpersistent WebKit storage; navigation restricted to
  the service origin; startup buffer no longer retains its token indefinitely;
  service failure is visible; AppDelegate is main-actor isolated and retained
  across the application run loop.
- `scripts/build-mac-app.sh`: host/Intel architecture selection and code-signing
  verification errors are no longer ignored.

## Not implemented — prioritize before wider release

1. **Portable encrypted backup and restore.** Keychain loss without a separately
   backed-up identity makes the vault unrecoverable. Add a passphrase-encrypted
   recovery archive and test restore into a clean Mac. No hidden export/get tool.
2. **Enforced access boundaries.** Current MCP runs arbitrary shell code as the
   user. Exact-value redaction can be bypassed with encoding/network/file writes.
   Add identity-bound permissions, approvals, process isolation and a broker
   outside the agent's security principal. TTL/host/scope metadata is advisory.
3. **Lifecycle management.** Delete/archive, shared-ref awareness, project picker,
   environments/profiles in the UI, and retained-version policy need deliberate
   designs. Replacing a value is not provider-side key rotation or revocation.
4. **Harness compatibility.** Codex (`~/.codex/config.toml`) and DeepSeek Harness
   (`~/.dsh/profiles/*/cordis.patch.yml`) adapters were added after the first
   pass. JSONC editing/status, nonstandard install paths, multiple profiles and
   cloud/container execution still need support and client-version integration
   tests. The DeepSeek wiring matches the file format and loader semantics of the
   installed 0.2.0-rc.2 app but has not been exercised in CI against a live
   harness session. Cloud-only clients (for example the ChatGPT web view) cannot
   reach a local vault. MCP does not automatically onboard every harness. Moving
   the app requires updating registrations.
5. **Distribution.** No published Homebrew formula, installer, notarization,
   stable signing identity, auto-update or universal binary release pipeline.
   Earlier example `brew install sm` was aspirational, not an available package.
6. **Operational hardening.** Multi-file mutations are not crash-atomic; a crash
   can leave orphaned ciphertext or a source file still containing plaintext.
   Add a recovery journal, authenticated audit anchoring and log rotation. Full
   OpenCode/Hermes history scanning requires understanding their database formats;
   current doctor coverage is bounded file/history matching, not a complete audit.

## Verification

- Unit/integration suite plus race detector: `go test -race ./...`.
- CLI regressions: dry-run purity, conflicting imports preserve source, invalid
  transport rejection, master-key stripping and exit-code propagation.
- Vault concurrency: 20 independent stale snapshots write without lost updates.
- Stream redaction: every chunk size plus a 10-second fuzz run (~2.6M cases).
- MCP tests: names-only listing, redacted output, bounded output, cancellation
  of a shell with descendants, and audit entries without values.
- HTTP tests: no unauthenticated access, cookie refresh, method/origin/Host guards,
  strict bodies, first initialization, batch preview/conflicts, corrupt manifest
  errors and secret-free responses.
- Browser checks use a generated, isolated fixture, not real credentials. A live
  add and bulk import succeeded and cleared inputs; refresh preserved access.
- Playwright checked 390, 768, 1024 and 1440 px viewports in light and dark
  themes: no horizontal overflow or page JavaScript errors. Add, selective bulk
  import, reload authentication, unsaved-change discard and input clearing passed.
- Lighthouse snapshot on the secrets view: accessibility 100, best practices
  100, SEO 100. The initial contrast failure (96 accessibility) was corrected;
  these automated scores are not a full accessibility certification.
- `govulncheck` found no reachable vulnerable symbols/packages. Updated
  `golang.org/x/crypto` to v0.56.0 for SSH fixes; one module-level advisory remains
  for unused, unmaintained OpenPGP code. sm does not import that package.
- Mac bundle rebuilt and signature verified. Full signed-install/upgrade and
  real mobile hardware testing remain outstanding.

Known security limits above are intentional disclosures, not test failures that
can be fixed with more output filtering. Do not market the prototype as preventing
prompt-injection exfiltration or keeping credentials outside an agent-controlled
runtime.
