# sm guide

The details behind the README: workflows, commands, import behavior, project
references and recovery.

- [First run](#first-run)
- [Commands](#commands)
- [Groups and plain config](#groups-and-plain-config)
- [Import and review](#import-and-review)
- [Projects and dotenv](#projects-and-dotenv)
- [MCP and agent access](#mcp-and-agent-access)
- [Recovery](#recovery)
- [Audit and leak scan](#audit-and-leak-scan)
- [Security details](#security-details)
- [Development](#development)

## First run

Requirements: macOS 13+, Go 1.27+. The Mac app additionally needs the Xcode
command-line tools.

```sh
git clone https://github.com/karthikmprakash/agents-secret-manager
cd agents-secret-manager
mkdir -p ~/.local/bin
go build -o ~/.local/bin/sm ./cmd/sm

./scripts/build-mac-app.sh
open dist/sm.app
```

Then:

```sh
sm onboard        # vault, optional secrets, detected harness wiring
sm ui             # loopback UI; a random token is generated for each run
```

`sm onboard --yes` skips prompts and wires detected harnesses. `sm setup
--dry-run` previews wiring without writing; `sm setup --agent NAME` wires one
harness.

The app is ad-hoc signed, not notarized. There is no Homebrew formula yet.
Harness configs store the absolute path to `sm`, so moving the binary requires
re-running `sm setup`.

## Commands

`sm` with no arguments opens a status dashboard. `sm help` groups every command
by task; `sm help add` documents one command.

```sh
sm onboard                  vault, secrets, agent wiring
sm status                   vault, project, agents, audit and next steps
sm agents                   detected harnesses and wiring state

sm add NAME [flags]         store and declare a secret
sm import [flags]           migrate plaintext values, leave sm:// refs
sm env [--verbose]          declared entries, groups and presence
sm exec [flags] -- CMD      run with selected secrets injected

sm setup [--agent NAME]     wire detected harnesses
sm config [--agent NAME]    print manual MCP snippets

sm init                     project manifest in the current directory
sm group NAME --service S   assign one secret to a group
sm service NAME --rename N  rename or ungroup a whole group
sm log [--limit N] [verify] audit trail and hash chain
sm doctor                   scan for plaintext copies
sm backup --out FILE        encrypted recovery archive
sm restore --file FILE      verify or restore into an empty vault
sm ui                       local browser UI
```

Color is used only on a terminal. `NO_COLOR=1` or `SM_NO_COLOR=1` disables it.
Bash, zsh and fish completion are available with `sm completion <shell>`.

## Groups and plain config

Related values can share a group:

```sh
sm add --global STRIPE_SECRET_KEY --service stripe
sm add --global STRIPE_BASE_URL  --service stripe --config
sm exec --service stripe -- ./app
```

`--group` is an alias for `--service`. `--config` is shorthand for
`--sensitive=false`: the value is still stored, injected and never displayed,
but it is not masked in captured output and `doctor` does not report it as a
leak.

Agents can ask for a group (`secret_run {service: "stripe"}`) or individual
names. Groups are labels, not an authorization boundary.

Move one existing entry:

```sh
sm group STRIPE_WEBHOOK_SECRET --service stripe
sm group OLD_VALUE --ungroup
```

Manage a whole group:

```sh
sm service stripe --rename payments
sm service payments --ungroup
sm service stripe --rename payments --scope project
```

Group edits change only labels. Values and references are untouched. The UI's
guarded Undo checks current labels and refuses to undo over later changes.

## Import and review

The CLI migrates dotenv assignments and rewrites the selected lines to
`NAME=sm://NAME` at mode 0600:

```sh
sm import --global --file credentials.env --dry-run
sm import --global --file credentials.env OPENAI_API_KEY STRIPE_SECRET_KEY
sm import --global --file credentials.env --group stripe STRIPE_SECRET_KEY
```

`--all` imports every entry without prompting. A conflicting stored value
aborts the preflight; there is no silent replacement. The source file and the
vault are separate files, not one crash-atomic transaction.

The UI's **Import secrets** sheet accepts `.env`, JSON/YAML, supported setup
commands, `curl` headers, labeled text and bare values. Parsing is deterministic
and local: no model, network request or command execution.

```text
STRIPE_BASE_URL=https://api.stripe.com
modal token set --token-id … --token-secret … --profile=karthik
aws configure set aws_access_key_id AKIA…
my email address is person@example.org
Your API Token cfat_…
Access Key ID …
Secret Access Key …
S3 API endpoint https://….r2.cloudflarestorage.com
```

Names and groups are suggestions. The review workspace lets you edit **name,
value, group and type** before saving:

- Unknown values default to **Secret**.
- URLs with passwords, query parameters or fragments stay sensitive, even when
  named `BASE_URL`.
- Config is suggested only for recognized plain configuration; you can override
  it.
- Cloudflare R2 blocks are grouped under `cloudflare`.
- Different values with the same suggested name are kept as separate entries
  with unique names. Identical name/value pairs coalesce.
- A local comparison marks entries **new**, **already saved** or **different
  value**. Differing stored values are never overwritten; rename the new entry.
- Unrecognized lines are reported, not executed or sent anywhere. Parsing is
  rule-based, not universal natural-language understanding. Review it.

Values are masked until revealed; config values are shown as-is. The pasted text
and review are cleared when the sheet closes. Stored values never appear in
`/api/state`.

## Projects and dotenv

```sh
sm init                 # creates .agentsecrets.toml (commit it; refs only)
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
# .env can be committed safely when it only contains references
GH_TOKEN=sm://GITHUB_TOKEN
LOG_LEVEL=debug
```

Precedence: `.env` < `.env.<profile>` < `.env.local` < process environment.
Registered names and aliased refs refuse differing plaintext shadows unless
`SM_ALLOW_PLAINTEXT=1` explicitly allows them. The dotenv parser supports
single-line values and escaped newlines, not shell execution or interpolation.

Templates use `{{sm:NAME}}`. `inject` refuses existing output paths, creates a
0600 file for the command, and removes it on normal or signal-handled
completion. Substitution is raw: use the correct quoting for the target format.
Cleanup is best effort, not a guaranteed secure erase on APFS/SSDs or after
`SIGKILL`.

## Desktop apps and the app lock

Two desktop shells open the same loopback UI:

- **macOS:** `./scripts/build-mac-app.sh` builds `dist/sm.app` (WKWebView,
  ad-hoc signed).
- **Linux:** `make desktop-linux` builds `dist/sm-desktop-linux-amd64`
  (GTK + WebKitGTK). It needs `libgtk-3-dev` and `libwebkit2gtk-4.0-dev`
  (Ubuntu 22.04) or `libwebkit2gtk-4.1-dev` (24.04+, via the build script's
  pkg-config shim).

Both apps start locked. On macOS, Touch ID unlocks when available; otherwise
the app asks for the desktop passphrase. macOS quarantines unsigned downloads:
if the CLI is blocked, run `xattr -d com.apple.quarantine ~/.local/bin/sm`,
and for the app use right-click **Open** once or remove the same attribute. On Linux, the passphrase unlocks, and
a **Use fingerprint** button appears when `fprintd-verify` is installed.

```sh
sm lock status          # is an app passphrase set?
sm lock set             # set or replace one (prompts twice)
sm lock set --force     # replace a forgotten passphrase
sm lock clear --yes     # remove it
```

Manage it from the CLI with `sm lock`; desktop shells use
`sm lock verify --stdin --quiet`, so the passphrase never appears in argv or
the environment. macOS locks again on sleep and screen lock, and **sm → Lock
now** (`⌘L`) locks immediately. The Linux shell locks after 15 minutes without
input and with **Ctrl+Shift+L**.

**Scope:** this is an app-level lock. It gates the desktop UI only. The vault
identity still lives in the Keychain or Secret Service, and the CLI and MCP are
deliberately not gated by it. The verifier is a salted Argon2id hash stored at
`~/.config/sm/desktop.lock` with mode 0600; a same-user process can read it and
attempt an offline brute force. See [SECURITY.md](../SECURITY.md).

## MCP and agent access

The MCP server exposes only:

- `secret_list` — names, group, transport, present/missing; never values.
- `secret_run` — runs a command with selected values in its environment and
  returns the exit code plus captured output.

There is no `secret_get`. Output is bounded; timeouts and cancellation are
supported. Exact registered *sensitive* values in captured output are replaced
with `[redacted:NAME]`. Encoded values, raw TTY output and alternate channels
are not detected.

Use `names: ["STRIPE_SECRET_KEY"]` or `service: "stripe"` to select values.
Omitting both injects every env-deliverable secret. This is cooperative least
privilege, not authorization.

## Recovery

```sh
sm backup --out sm-recovery.age
sm restore --file sm-recovery.age --verify    # authenticate, change nothing
sm restore --file sm-recovery.age             # empty destination vault only
```

The CLI prompts for a passphrase without echo and never accepts it as an
argument. Archives use age's passphrase encryption (scrypt), contain the global
reference manifest and **all** vault values, and do not export the Keychain
identity. Restore re-encrypts with the destination Mac's identity.

Keep the passphrase separately and verify the archive. Project manifests, agent
configuration and audit history are **not** included. Restore refuses any
existing `vault.age` or `manifest.toml`, even an empty one. On a new Mac,
restore **before** onboarding creates a vault. The archive format is bounded to
32 MiB. Installation uses two no-replace file writes, not a crash-atomic
transaction; keep the original archive until restore is verified.

There is no cloud backup and no password-reset service.

## Audit and leak scan

```sh
sm log --limit 20      # recent entries
sm log verify          # check the hash chain
sm doctor              # scan for plaintext copies of registered values
sm env --verbose       # inspect references and presence, never values
```

Audit entries record intent before operations and contain names, not values.
The hash chain detects accidental interior damage, not same-user rewriting or
truncation.

`sm doctor` scans registered exact values and managed assignments in bounded
locations and git history. It is not a complete secret-pattern scanner and
cannot certify a transcript or repository as safe to share.

## Security details

- **Vault:** age X25519 ciphertext at `~/.config/sm/vault.age`; the identity is
  stored in the macOS Keychain (service `sm`, account `identity`). Writes are
  serialized, atomic and fsynced.
- **Children receive plaintext credentials.** Arbitrary code can encode them,
  send them over a network or write them to disk. Same-user processes can access
  user files and the Keychain according to OS permissions. This is not a
  sandbox, prompt-injection defense, per-agent ACL or egress firewall.
- **Redaction** masks exact known sensitive values in captured output.
  `--redact auto` masks when output is not a TTY; `always` and `never` override.
  Raw TTY output, encoded values, unregistered plaintext `.env` values and
  alternate channels are outside the guarantee. `--only` and `service` are
  cooperative selection, not authorization.
- **Audit** is tamper-evident, not tamper-proof.
- **Advisory metadata:** `scope`, `hosts` and `default_ttl` are not enforced.
  Proxy and dynamic delivery are not implemented.
- **Test overrides:** `SM_CONFIG_DIR` and `SM_IDENTITY` are for CI and throwaway
  runs. Never commit them or put `SM_IDENTITY` in an agent config; it is stripped
  from task children.
- **Recovery:** `vault.age` alone is not enough without the Keychain identity.
  Keep a verified archive and its passphrase separately.

The full reporting process and vulnerability scope are in
[SECURITY.md](../SECURITY.md).

## Development

```sh
make check                                            # gofmt, vet, test -race
make build                                            # ~/.local/bin/sm
python3 scripts/test-ui.py                             # isolated Playwright flows
go test ./internal/redact -fuzz=FuzzStreaming -fuzztime=10s
SM_UI_PREVIEW=1 SM_UI_PREVIEW_SEEDED=1 \
  go test -v ./internal/uiserver -run TestInteractivePreview -timeout 16m
```

Tests use temporary vaults and generated identities; they never configure your
installed harnesses. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the code map
and adapter guide.
