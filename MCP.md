# Blackbook MCP server

`bbk mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server
on stdio, so AI agents (Claude Code, Claude Desktop, or any MCP client) can use
Blackbook's data-security features as tools.

It has two tiers:

- **Offline tools** — hashing, passphrase encryption/decryption, key derivation,
  secure random, and visual fingerprints. These run entirely locally, need no
  server, and never send data anywhere. They use the exact same cryptographic
  primitives as the rest of Blackbook.
- **Online tools** — read, list, and (optionally) write secrets on a Blackbook
  server. These go through the normal authenticated client, so **the server
  still enforces mTLS, tokens, ACLs, MFA, and K-of-N**. The agent is just
  another client, and can only reach what the chosen profile is allowed to.

## Security model (secure by default)

The integration follows Blackbook's usual posture — the safe option is the
default, and you opt *in* to more power:

| Situation | What the agent can do |
|---|---|
| `bbk mcp --offline` | Offline crypto tools only. **No network, ever.** |
| `bbk mcp` (no unlocked profile) | Offline crypto tools only, until a profile is available. |
| `bbk -P NAME mcp` | Offline tools **+ read** secrets/files the profile is authorized for. |
| `bbk -P NAME mcp --allow-write` | The above **+ write/delete** secrets. |

Additional guarantees:

- **Server-side controls are never bypassed.** Every online call is an ordinary
  authenticated request; the Blackbook server applies the profile's ACLs, plus
  MFA and K-of-N where required. Give the agent a **least-privilege profile**
  (a dedicated client scoped to just the domains/patterns it needs) and its
  reach is bounded no matter what it's asked to do.
- **No blocking prompts.** The server sets `BLACKBOOK_NO_PROMPT=1`, so a locked
  profile makes online tools return a clear "run `bbk unlock`" error instead of
  hanging (stdin is the protocol channel, not a place to type a passphrase).
- **stdout is protocol-only.** All logging goes to stderr.
- **External (client-side-encrypted) secrets stay opaque.** `bbk_secret_get`
  returns plaintext only for server-side secrets; for `--external` secrets it
  reports that the value is client-side encrypted rather than exposing anything.
- Treat any agent with online access as able to *read the secrets that profile
  can read*. Scope the profile accordingly, and don't paste real secrets into a
  shared transcript.

## Tools

### Offline (always available)

| Tool | What it does |
|---|---|
| `bbk_hash` | SHA3-256/512 or SHA-256/512 of text or base64 data. |
| `bbk_random` | CSPRNG bytes as hex / base64 / URL-safe token (keys, passwords). |
| `bbk_encrypt` | Encrypt text under a passphrase (Argon2id → AES-256-GCM); returns a portable `bbkx1:` envelope. |
| `bbk_decrypt` | Decrypt a `bbkx1:` envelope with its passphrase. |
| `bbk_derive_key` | Derive a 256-bit key from a passphrase (Argon2id or scrypt); returns key + salt so it's reproducible. |
| `bbk_fingerprint` | Human-verifiable fingerprint: OpenSSH-style randomart + braille + SHA3-256. |

### Online (need a profile; listed only when available)

| Tool | Requires | What it does |
|---|---|---|
| `bbk_status` | profile | Connected identity, server URL, and health. |
| `bbk_secret_list` | profile | Secret names + metadata in a domain (no values). |
| `bbk_secret_get` | profile | Read a secret value (subject to ACL/MFA/K-of-N). |
| `bbk_file_list` | profile | List files (metadata only). |
| `bbk_secret_put` | `--allow-write` | Store/overwrite a secret. |
| `bbk_secret_delete` | `--allow-write` | Delete a secret. |

## Running it

```bash
# Crypto-only utility (no Blackbook server needed at all):
bbk mcp --offline

# Read-only access as a profile (unlock it first so no prompt is needed):
bbk -P agent unlock --ttl-minutes 60
bbk -P agent mcp

# Full read/write as a profile:
bbk -P agent mcp --allow-write
```

Online tools read the profile's cached unlock key (from `bbk unlock`) or
`$BLACKBOOK_PASSPHRASE`. If neither is present, online tools return an error
telling you to unlock; offline tools keep working regardless.

## Registering with Claude Code

```bash
# Offline crypto tools:
claude mcp add blackbook -- bbk mcp --offline

# Read-only, as the `agent` profile (run `bbk -P agent unlock` first):
claude mcp add blackbook -- bbk -P agent mcp

# Full access:
claude mcp add blackbook -- bbk -P agent mcp --allow-write
```

## Registering with Claude Desktop

Add to `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "blackbook": {
      "command": "bbk",
      "args": ["-P", "agent", "mcp"]
    }
  }
}
```

For a crypto-only server, use `"args": ["mcp", "--offline"]`. If the profile
isn't kept unlocked via `bbk unlock`, you can supply the passphrase in the
server's environment (`"env": { "BLACKBOOK_PASSPHRASE": "…" }`), but prefer the
unlock agent so the passphrase isn't stored in a config file.

## Notes

- Use the **release** build. (Provide `bbk` on `PATH`, e.g. via `cargo install --path .`.)
- The `bbkx1:` envelope is: `base64( "BBKX1" ‖ salt(16) ‖ AES-256-GCM(Argon2id(passphrase, salt), plaintext) )`.
  Anyone with the passphrase and `bbk_decrypt` (or the same construction) can open it — no server required.
