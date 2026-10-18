# Security Policy

`sm` stores credentials, so security reports are taken seriously — and handled
privately.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue with enough detail to reproduce it.

If private reporting is unavailable, contact the maintainer
[@karthikmprakash](https://github.com/karthikmprakash) via a private channel
listed on their GitHub profile.

Please include:

- affected version or commit (`sm version` / `git rev-parse HEAD`),
- macOS version and, if relevant, the harness and its version,
- a minimal reproduction,
- the impact you believe it has.

**Never paste real credentials.** Use throwaway values in reproductions and
redact paths and tokens. If you think a credential was exposed, rotate it with
the provider first.

## Supported versions

This is pre-1.0 software. Security fixes land on `main`; there are no maintained
release branches yet. Please reproduce issues against the latest `main`.

## What to expect

- Acknowledgement within a few days, best effort.
- A fix or a documented decision, with credit if you want it.
- No bug bounty program at this time.

## Security model (what is and is not a vulnerability)

The full boundaries are in the [README](README.md#security-boundaries). In short:

**In scope**

- Reading vault contents without the Keychain identity.
- Path traversal or reference collisions that read another project's secret.
- MCP tools or stored-state endpoints returning raw vault values (there is no
  `secret_get`). The authenticated import preview deliberately returns only
  values from the text the user just pasted, for local editing/verification.
- Recovery archives exposing plaintext, accepting tampered ciphertext, or
  replacing existing vault data without an explicit safe workflow.
- Authentication flaws in the loopback UI server (token, cookie, CSP, origin).
- Bypassing the "refuse plaintext shadow" rule unintentionally.
- Manifest writes that corrupt unrelated entries or leave broken files.
- Redaction bypasses for *exact registered values* in captured output.
- Desktop app lock bypasses that show the UI without Touch ID or the
  passphrase, or a verifier that accepts a wrong passphrase.

**Known limitations, not vulnerabilities**

- Child processes receive **plaintext** credentials; arbitrary code can encode
  or exfiltrate them. This is not a sandbox.
- Redaction is exact-value masking in captured output only. Encoded or
  transformed values, raw TTY output, and alternate channels are out of scope.
- `--only` and `service` are cooperative selection, not authorization; the same
  OS user can read the vault through `sm` regardless.
- `scope`, `hosts` and `default_ttl` are advisory metadata today.
- The desktop app lock gates the UI only. CLI and MCP are not gated by it, and
  a same-user process can read `~/.config/sm/desktop.lock` and attempt an
  offline brute force of the Argon2id verifier. It is not a vault boundary.
- The audit hash chain detects interior damage but cannot stop same-user
  rewriting or truncation.
- `sm doctor` is a bounded scanner for registered values, not a proof that a
  transcript or repository is clean.
- `vault.age` alone is not enough without the Keychain identity. The separate
  passphrase-encrypted recovery archive is portable, but its passphrase cannot
  be reset. Project manifests and audit history must be backed up separately.
- Restore uses two no-replace file installations, not a crash-atomic multi-file
  transaction. Do not delete an original recovery archive until restore is verified.

If you are unsure whether something is a limitation or a vulnerability, report
it privately and we will figure it out together.
