# Local-only roadmap

sm is a single-user, locally hosted secrets and configuration manager. These
ideas do not require a hosted backend, cloud model, account, or remote database.
They are proposals, not implemented guarantees.

## Delivered in this iteration

- Editable import review with local conflict checks and conservative sensitivity.
- Broader deterministic parsing; differing values are not silently discarded.
- Service-label management with guarded Undo.
- Passphrase-encrypted local export, verification and empty-vault restore.

## Recommended next

1. **Service environments and variable aliases.** Separate development/staging/
   production sets and map each service's logical `API_KEY` / `BASE_URL` to the
   environment variables a command expects. No implicit production default.
   This needs a schema migration and collision checks; groups currently remain
   labels in a flat environment-variable namespace.
2. **Safe archive and history.** Archive entries without removing shared vault
   values; show affected project refs, offer restore/Undo, and deliberately
   control retention. Replacing a value is not provider-side key rotation.
3. **On-device reminders.** Optional local expiry and rotation reminders,
   backup reminders, and a checklist for testing a recovery archive. No remote
   notifications or telemetry.
4. **Service templates.** Local presets for AWS, Modal, databases and custom
   tools, with required/optional fields and expected env names. Community
   parsers should ship with dummy fixtures and never execute pasted commands.
5. **Better access visibility.** Local MCP activity, names used and recent
   connection evidence. Show “configured” separately from “connected”. Do not
   imply authenticated per-agent identity before it exists.
6. **Local approvals and OS authentication.** Explicit approvals and optional
   Touch ID/Keychain controls, backed by a local broker when enforcing access.
   A web-UI lock alone must not be described as locking independent CLI/MCP
   processes or defending against arbitrary same-user code.
7. **Power-user navigation.** Command palette, saved service filters and bulk
   organization, while keeping raw credentials off the clipboard by default.
8. **Entry lifecycle and metadata.** Explicit rename/delete with confirmation,
   deliberate handling of shared vault paths, and local notes/tags/URLs for
   humans. Deleting a declaration must never silently orphan or remove a value
   another project still references.

## Constraints

- Import/review must work offline; do not forward pasted values to cloud models.
- Bind the UI to loopback, keep assets embedded, and never add telemetry by default.
- Backups are user-owned encrypted files, not a synchronization service.
- A provider connection test is an explicit user-invoked network action, not an
  automatic side effect of parsing. Warn before sending credentials to a host.
- Agent commands may access the network today. Local hosting is not an egress
  firewall, sandbox, per-agent permission boundary or prompt-injection defense.
