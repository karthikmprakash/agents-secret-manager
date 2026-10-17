# sm — secrets for agents

A local encrypted credential store shared across coding-agent harnesses. Add
AWS, Modal, GitHub or other credentials once, then use them from any folder.
An optional project manifest and `.env` references layer on top of global secrets.

**Status: macOS-first prototype, not a hardened security boundary.** The CLI,
MCP server and Mac app share a Go core. There is no cloud sync or credential
broker yet. See [review and remaining work](docs/REVIEW.md).

## Start with the Mac app

Requires Go and the Xcode command-line tools to build from source:

```sh
./scripts/build-mac-app.sh
open dist/sm.app
```

1. Click **Create vault**. The app keeps the encryption identity in your OS
   Keychain; it never replaces an existing vault identity automatically.
2. **Add secret**, or **Import secrets** to paste/read a dotenv file. Preview
   and select names before storing them globally. The UI does not modify your
   source file. Clear any plaintext copies yourself after checking the import.
3. Open **Agents** and configure the detected harnesses. Reconnect or restart
   the harnesses, then ask your agent to use the secrets manager.

Agent status reflects the configuration on disk, **not a verified live
connection**. Supported adapters: OpenCode V2, Claude Code, Hermes, Codex
(OpenAI app/CLI), DeepSeek Harness, Cursor, Claude Desktop, Gemini CLI and
Windsurf. Detection depends on local install paths; this is not automatic
support for every harness or cloud chat app. DeepSeek Harness is wired through
its profile patch files (`~/.dsh/profiles/*/cordis.patch.yml`) and needs its
official MCP client plugin. Cloud-only clients (for example the ChatGPT web
view) cannot reach a local vault.

The app uses a loopback-only server, a random per-run capability token and an
HttpOnly session cookie. Refresh keeps the session. It serves all assets locally.
The bundle is ad-hoc signed for development, not notarized for distribution.
`ARCH=x86_64 ./scripts/build-mac-app.sh` builds an Intel bundle; the default
is the host architecture. Move the app to a stable location before configuring
agents: their MCP entries reference the bundled binary's absolute path.

## Or use the CLI

```sh
mkdir -p ~/.local/bin
go build -o ~/.local/bin/sm ./cmd/sm
sm onboard
```

`sm onboard` verifies/creates the vault, prompts for global secrets using hidden
input, then offers to configure detected harnesses. `sm onboard --yes` skips
secret prompts and explicitly opts into configuring all detected harnesses.
`sm setup --dry-run` previews wiring without changing configs. `sm config`
prints copy-pasteable MCP snippets for manual wiring (all clients, or one with
`sm config --agent codex`); the same snippets are under **Manual setup** in the
Agents view of the UI.

Related values can be grouped into a **service**, and plain config values can
opt out of secret treatment:

```sh
sm add --global STRIPE_API_KEY  --service stripe
sm add --global STRIPE_BASE_URL --service stripe --sensitive=false
sm exec --service stripe -- ./app     # injects every member of "stripe"
```

Agents request the same group with `secret_run {service: "stripe"}`. Values
marked `sensitive=false` are still stored, injected and never displayed, but
they are not masked in output and `doctor` does not treat them as leaks.

Move existing entries between groups from the Secrets list in the UI (**Group**
on any row), or with `sm group NAME --service stripe` (`--ungroup` to remove).
When adding in the UI, the Secret / Plain config choice sits right under the
Value field.

```sh
sm add --global AWS_ACCESS_KEY_ID
sm add --global AWS_SECRET_ACCESS_KEY
sm add --global MODAL_TOKEN_ID
sm add --global MODAL_TOKEN_SECRET
sm env                              # names and status, never a value dump
sm exec --only AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY -- aws s3 ls
sm rotate MODAL_TOKEN_SECRET         # replace the locally stored value
sm setup                            # configure a newly installed harness
sm log verify
```

`rotate` does **not** issue/revoke a provider credential. Create the new key at
the provider, update it here, verify it, then revoke the old provider key.

## Import existing secrets

```sh
sm import --global --file credentials.env --dry-run
sm import --global --file credentials.env AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
# Only use --all when every plaintext entry should become a secret.
```

The **CLI** rewrites selected assignments to `NAME=sm://NAME` at mode 0600;
unselected config is left as-is. Dry-run writes nothing. A conflicting stored
value aborts the entire preflight: no silent replacement/discard of the source
value. The source and vault are separate files, not one crash-atomic transaction;
if a rewrite fails, values remain in the vault and the source can be retried.

Use `--file .env` explicitly. Positional arguments are key names, not filenames.

## Optional project configuration

```sh
sm init
sm add GITHUB_TOKEN
sm import --file .env GITHUB_TOKEN
sm exec -- npm test
sm inject --tpl config.tpl --out config.json -- npm start
```

Project `.agentsecrets.toml` files contain references, never values. The global
manifest is merged underneath; a project may override the same logical name.
New refs are namespaced by project and preserve case. Existing refs are not
rewritten or migrated automatically.

```toml
[secrets.GITHUB_TOKEN]
ref = "vault://global/GITHUB_TOKEN"
transport = "env"
```

```sh
# .env
GH_TOKEN=sm://GITHUB_TOKEN
LOG_LEVEL=debug
```

Precedence: `.env` < `.env.<profile>` < `.env.local` < process environment.
Registered names and aliased refs refuse differing plaintext shadows unless
`SM_ALLOW_PLAINTEXT=1` explicitly allows them. `.env` files are read from the
project manifest's directory (cwd for global-only operation). The parser supports
single-line values and escaped newlines, not shell execution or interpolation.

Templates use `{{sm:NAME}}`. `inject` refuses existing output paths, creates a
0600 file for the command, and removes it on normal/signal-handled completion.
Replacement paths are left untouched. Template substitution is raw: use the
correct quoting/encoding for your target format. Cleanup is best effort, not
guaranteed secure erasure on APFS/SSDs or after SIGKILL/power loss.

## Agent protocol

`sm mcp` serves standard MCP over stdio:

- `secret_list`: declared names, delivery and vault presence.
- `secret_run`: shell command, optional `cwd`, optional secret `names`, optional
  `timeout_seconds` (default 120, max 600). Output is bounded and redacted before
  returning; cancellation kills the command's process group.

No raw `secret_get` tool. MCP instructions guide the agent toward these tools,
but instruction following is not enforcement. Existing sessions may need a
reconnect/restart to load them. Provider/model API credentials needed to start
the harness are a separate bootstrap problem; an MCP server cannot bootstrap
its own client's model connection.

## Security boundaries

- Vault: age X25519 ciphertext at `~/.config/sm/vault.age`; identity in Keychain
  service `sm`, account `identity`. Writes are serialized, atomic and fsynced.
- Children still receive **plaintext credentials**. Arbitrary code can encode
  them, send them over a network, or write them to disk. Same-user processes can
  access user files/Keychain according to OS permissions. This is not a sandbox,
  prompt-injection defense, per-agent ACL or egress firewall.
- Exact known values are masked in captured output. `--redact auto` enables
  masking for non-TTY output; `always` forces it, `never` disables it. Raw TTY,
  encoded values, unregistered plaintext `.env` values and alternate output
  channels are outside that guarantee. `--only` is cooperative least privilege,
  not authorization.
- Audit entries record intent before operations. Hash links detect accidental
  interior damage but do not stop same-user rewriting or suffix truncation.
- `sm doctor` scans registered exact values and managed assignments in bounded
  locations/history. It is not a complete secret-pattern scanner, and cannot
  certify that a transcript or repository is safe to share.
- `default_ttl`, `scope`, and `hosts` are advisory metadata today. Proxy delivery
  and dynamically generated delivery are not implemented. Never rely on them as
  enforcement. Generate at add-time with `--generate hex/32` instead.
- `SM_CONFIG_DIR` isolates test data. `SM_IDENTITY` is a test/CI override: never
  commit/log it or set it in an agent config. It is stripped from task children.

**Recovery is not finished:** backing up `vault.age` alone is insufficient for a
new device without its encryption identity. Do not delete the Keychain identity.
A portable encrypted backup/restore workflow, per-agent policy and notarized
distribution are prerequisites for a broadly distributed product.

## Development

```sh
go test -race ./...
go vet ./...
go test ./internal/redact -fuzz=FuzzStreaming -fuzztime=10s
```

Tests use temporary vaults and generated test identities; they do not configure
your installed harnesses. [Historical proposal](docs/DESIGN.md) ·
[Implementation review](docs/REVIEW.md)
