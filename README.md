# Blackbook

A secrets engine you run as a Docker container and drive from a CLI. Holds string secrets and arbitrary files, encrypted end-to-end, behind TLS 1.3 + mTLS, with per-domain namespaces, group ACLs, resource policy flags, TOTP MFA, and K-of-N threshold approvals.

## What's in the box

- **HTTPS-only**, TLS 1.3 with AEAD ciphers. **Two-factor by mandate** — every request must present *both* a CA-issued client certificate (CN + fingerprint pinned to the row in `blackbook_clients`) *and* a matching bearer token, and both must resolve to the same client. There is no cert-only or token-only path: a leaked token alone or a copied certificate alone is useless. The full bundle (server + token + cert + key + ca) is the unit of access.
- **Credential profiles** — hold multiple identities on one machine under `~/.bbk/profiles/<name>.json`. Pick one per command with `--profile`/`-P` (or `$BLACKBOOK_PROFILE`, or the persisted active profile), so you can drive several identities from one shell: `blackbook -P alice get x` then `blackbook -P bob get y`.
- **Encrypted-at-rest credentials.** A profile is sealed under a strong passphrase before it touches disk: `Argon2id(passphrase, salt)` (64 MiB, t=3, p=1) → KEK, then `AES-256-GCM` over the credential bundle. The on-disk file is an opaque `v2` envelope — no token, cert, or private key in the clear. The passphrase is never stored. Everyday commands don't re-prompt: `blackbook unlock` caches only the *derived KEK* (not the credentials) in a local agent with a TTL; `blackbook lock` clears it; `$BLACKBOOK_PASSPHRASE` works for automation. Using a credential now requires the encrypted profile **and** an unlock factor (agent or passphrase) — a stolen `~/.bbk` is inert. Each profile also carries a rotation-stable **Client Master Key** sealed in the same envelope, independent of the auth token/cert.
- **Strong key hierarchy.** One `PrimaryKey` (pure secret material), six named `SecondaryKey`s with distinct domain strings — `secret/layer1/v1`, `secret/layer2/v1`, `file/dek-kek/v1`, `index/v1`, `hmac/v1`, `mfa/secret-kek/v1`. Domain separation is enforced at construction time so two call sites can't accidentally share a key.
- **String secrets** (2-layer AES-256-GCM, scrypt-derived envelope) and **encrypted files** (random per-file DEK, AES-256-GCM blob, wrapped under the master).
- **Domains** as both *namespace partition* (the same name can exist in different domains) and *access-control group* (an ACL granted to `@engineering` applies to every member of that domain).
- **Rich ACLs** — per-client OR group, with `expires_at`, `not_before`, and `max_uses` bounds. Use counter increments atomically; once spent the rule stops authorizing.
- **Resource policy flags** (extensible JSONB) — `mfa_required`, `delete_on_read`, `max_reads`, `rotate_on_read`, `preserve_on_cleanup`, `no_overwrite`. Each flag has explicit server-side enforcement. Unknown or misspelled flag names are **rejected with 400** at the API boundary — a typo is never silently discarded. **The full flag set, K-of-N thresholds, tombstone/cleanup, and read-only-by-default apply equally to secrets and files.**
- **Immutable resources** — `--no-overwrite` at creation makes a secret or file permanently un-replaceable: even an explicit `--overwrite` is refused with 409; you must delete it first (subject to the `delete` ACL).
- **Client-side ("external") storage** — `put --external` / `file put --external` encrypt the value *on the client* under a key derived from a passphrase that never leaves the machine. The server stores only an opaque envelope (`{salt, wrapped_dek, ciphertext}`) it can't open — even with the master key and full DB/disk access it sees only ciphertext. Yet the client can't decrypt alone either: the envelope lives on the server behind all the usual gates (mTLS+token, ACL, K-of-N, MFA, max_reads), so reading still requires authorization *and* the passphrase. Both factors, neither sufficient alone.
- **TOTP MFA** — enroll with `mfa enroll`, get a provisioning URI, verify with the 6-digit code. Resources flagged `mfa_required` demand a fresh TOTP on every read.
- **K-of-N threshold approvals** — set `--quorum K --signatories alice,bob,carol` at store time (secrets *and* files). The first read opens an approval request; **repeat reads return that same request, never a duplicate** (deduplicated per requester + resource). Once K distinct signatories have approved, the requester replays with `--request-id ID` (or `--wait` to block on a single call). Requests are single-use (a consumed one is replaced by a fresh request on the next read) and expire after 24 hours. Concurrent approvals are serialized so none are lost. `requests <ID>` / `requests -v` show **who can approve and who already has**.
- **Advance approval (pre-authorization)** — a signatory can pre-approve a reader for a *pattern* (scoped to domain + grantee + pattern, with a mandatory TTL and optional use cap), so K-of-N reads of matching resources go through with no live approval and no waiting. Grants compose with live approvals (effective approvers = the union), count only where the granting client is an actual signatory, and are revocable. Same scoping/limits as any ACL rule.
- **Persistent master key, CA, server cert, DEK** on a Docker volume. Token + cert rotation per client. Per-file DEK rotation. Append-only audit log of every operation, denial, approval, and admin op.
- **Tamper-evident audit log** — every audit row carries a keyed SHA3-256 hash chained over the previous row, so altering, deleting, or reordering any past entry is detectable. The MAC key is derived from the master key and never stored in the DB. Verify with `blackbook audit --verify`.
- **At-rest encryption of every user-supplied identifier.** Resource names, client names, domain names, ACL patterns, file metadata (name, MIME, size, hash), audit `resource`/`message`, and access-request resource names are all AEAD-encrypted at the column level under a `metadata_enc` key derived from the master `BlackbookKey`. Stable lookups go through `*_id` HMAC columns (different domain-separation tag per scope). A DB-only attacker — even one with full SQL access — sees only opaque IDs, ciphertext, timestamps, and a low-entropy action/status vocabulary; no user name, secret name, or pattern is recoverable without the master key. ACL pattern matching moved from SQL `LIKE` into in-memory glob matching (`*` any, `_` one char) over decrypted patterns.
- **Versioned schema migrations** — `blackbook_schema_migrations` ledger + `Database::migrate_once(version, name, sql)` helper for future numbered migrations. The current schema is encrypted-from-day-1 and ships with zero migrations applied — no plaintext columns ever existed in this codebase to migrate away from.

## Quick start

```powershell
# One-time: create the master keyfile that protects the DEK. It stays OFF the
# data volume (mounted as a Docker secret) — without it the wrapped DEK can't be
# opened, so back it up separately. The server refuses to start without a
# provider (this keyfile, or BLACKBOOK_MASTER_PASSPHRASE).
mkdir secrets; openssl rand 32 > secrets/master_keyfile

# One-time: generate the TLS material for the server↔Postgres channel. The app
# connects to Postgres over TLS 1.3 and verifies it against this CA.
./scripts/generate-postgres-certs.sh

docker compose up -d

# First start writes a complete admin bundle (server + token + cert + key + ca)
# to the data volume. Grab it (the bundle file is the only place the token
# appears — it is NOT logged).
docker cp blackbook-app:/opt/blackbook/data/admin-bundle.json .

# Build & install the CLI on the host (requires perl on Windows for openssl-sys).
cargo install --path .

# Log in from the bundle. No individual credential flags — the bundle carries
# everything, and the server requires both cert and token. The profile is named
# after the identity automatically, so this lands in profile `admin`. You'll be
# prompted for a passphrase that encrypts the saved profile (the credentials are
# never written in the clear); set $BLACKBOOK_PASSPHRASE to skip the prompt.
blackbook login admin-bundle.json
# (The bundle's server defaults to https://127.0.0.1:8443; if you reach the host
#  another way, override once: `blackbook login admin-bundle.json -s https://host:8443`.)

# After login the profile is unlocked. In a later shell, unlock it for a while
# so commands don't re-prompt (the agent caches only the derived key):
blackbook -P admin unlock --ttl-minutes 30
blackbook put api-key sk_live_super_secret
blackbook get api-key
blackbook -P admin lock          # drop the cached key when you're done

# Multiple identities: provision a client, log in from its bundle (auto-named
# profile `alice`), then switch per-command with -P. No re-login between calls.
blackbook -P admin client create alice -o alice.json
blackbook login alice.json            # saves to profile `alice`
blackbook -P alice get api-key        # acts as alice
blackbook -P admin client ls          # acts as admin
blackbook profile use admin           # set the default for flag-less commands
blackbook profile ls                  # '*' marks the active profile

# Secrets are read-only by default: a second put on the same name returns 409.
# Pass --overwrite to replace it (also requires the `update` action on the ACL).
blackbook put api-key sk_live_rotated --overwrite
```

## Shell completion

Tab-complete commands, flags, and local values (profiles, domains, resident
files). Everything is computed locally from clap's command tree and `~/.bbk` —
no network call, nothing sent to the server.

```powershell
# One-off for the current session:
blackbook completions powershell | Out-String | Invoke-Expression

# Persist it — add that line to your $PROFILE:
Add-Content $PROFILE 'blackbook completions powershell | Out-String | Invoke-Expression'
```

```bash
# bash / zsh / fish:
source <(blackbook completions bash)
source <(blackbook completions zsh)
blackbook completions fish | source
```

Then e.g. `blackbook -P <Tab>` lists your profiles, `blackbook file get <Tab>`
lists resident files on this machine, and `blackbook file put --<Tab>` lists
every flag.

## Web console 🕮

A browser front-end that **is** the CLI. `blackbook web` serves one self-contained
local page and runs your commands by re-invoking `blackbook` — so every command,
flag, and future feature is inherited automatically, with no separate API to keep
in sync. Dark by default, with command colorization, sidebar quick-actions, command
history, and `Tab` completion (reusing the same `__complete` engine as the shell).

```powershell
blackbook web                      # → http://127.0.0.1:8088
blackbook web --bind 127.0.0.1:9000
```

It runs as whoever launched it — the same trust level as a terminal — and drives
your local profiles/agent exactly as the CLI does. Passphrases set in the page's
🔑 dialog are kept only in the tab and passed to each command via environment
variables (`$BLACKBOOK_PASSPHRASE` / `$BLACKBOOK_EXTERNAL_PASSPHRASE`), never on
the command line. The long-running `server` and nested `web` commands are refused.
Bind to loopback (the default) unless you intend to expose it.

## Secure tunnels 🔌

A tunnel is an **end-to-end-encrypted channel between two clients**, relayed by
the blackbook server but unreadable to it. The server acts as a *trusted
introducer*: it authenticates both ends over mTLS and tells each peer the
other's client name + certificate fingerprint, then relays opaque frames. The
two clients run an authenticated key exchange and prove identity to each other
**using their existing client certificates** — so the server positively
identifies the parties, yet cannot read or modify the inner traffic.

How the four properties hold:

- **End-to-end secured** — ephemeral **X25519** ECDH → HKDF-SHA256 → per-direction
  **AES-256-GCM** with counter nonces. Forward secrecy; tamper and replay are
  detected. The server never sees an ephemeral private key, so it can't derive
  the session key.
- **Server as trusted intermediary** — it pairs the two mTLS-authenticated
  parties and vouches each peer's name + fingerprint while relaying frames.
- **Positive mutual identification via existing credentials** — each side signs
  the session (bound to both ephemeral keys + its own name/fingerprint) with its
  **client-certificate private key** (ECDSA P-256). The peer verifies that
  signature against the vouched fingerprint. The server holds no client private
  key, so it cannot forge this — identity is cryptographic, not "the server says
  so." A wrong key or a forged fingerprint is rejected at the handshake.
- **Server can't decrypt or modify** — it only ever handles AEAD frames; GCM
  catches any tampering.

It carries arbitrary **TCP or UDP** via local port-forwarding (ssh -L style),
multiplexing many streams over the one channel — no TUN device or admin rights.

```powershell
# On the machine that can reach the target service (e.g. bob's host):
blackbook -P bob tunnel accept --from alice

# On alice's machine: forward a local port to bob, who dials the target.
blackbook -P alice tunnel forward bob --listen 127.0.0.1:5432 --to 10.0.0.5:5432
#   → anything hitting 127.0.0.1:5432 is E2E-encrypted to bob, who connects to
#     10.0.0.5:5432 and pipes it back. Add --udp for UDP.

blackbook tunnel ls    # tunnels you offered or are the target of
```

The relay is ephemeral (in-memory; no DB row) and reuses the existing
HTTPS+mTLS endpoint via a WebSocket upgrade — no new ports, privileges, or
external VPN software.

## User domains

Every client gets a **private, fully-featured domain of its own** at creation,
named `~<client>` (e.g. `~alice`). The client is the *admin* of this domain, so
it has full features there — secrets, files, ACLs, K-of-N, the lot — without any
admin having to grant anything. The `~` prefix is reserved: regular domain and
client names can't start with it.

On `login`, a fresh profile's **default domain is set to its user domain**, so
commands land in your own private namespace with no `-D` needed. An explicit
`domain use` always wins, and `-D` / `$BLACKBOOK_DOMAIN` override per command.
Resolution order: `-D` → `$BLACKBOOK_DOMAIN` → saved `domain use` → user domain
(from login) → `default`.

```powershell
blackbook whoami                 # shows e.g. "user domain: ~alice"
blackbook put api-key sk_xxx     # lands in ~alice (no -D needed)
blackbook -D default put k v     # opt out per-command; everyone still shares `default`
blackbook domain use engineering # or switch your default elsewhere
```

## Domains, ACLs, time + use bounds

```powershell
# Create a domain — both a namespace and an ACL group.
blackbook domain create engineering

# Same name "api-key" can exist in two domains, isolated.
blackbook --domain engineering put api-key sk_eng_only

# Provision alice; she auto-joins `default` AND gets her private `~alice` domain.
blackbook client create alice --out alice.json
blackbook domain add-member engineering alice

# Domain admins (in-domain role 'admin') are scoped administrators of just
# that domain: they read/write every resource in it AND can manage its ACLs and
# members (including delegating co-admins) — but have NO global privilege
# (can't create clients, read other domains, view the global audit log, etc.).
# A domain admin can only grant/revoke ACLs and add/remove members within their
# own domain; cross-domain management is refused with 403.
blackbook domain add-member engineering alice --role admin
# Now alice can, scoped to engineering only:
#   blackbook -P alice -D engineering acl grant bob "eng-*" --read
#   blackbook -P alice -D engineering domain add-member engineering bob

# Stop typing -D every time: set a per-profile default domain.
blackbook -P alice domain use engineering   # alice's commands now target engineering
blackbook -P alice get eng-key               # no -D needed
blackbook -P alice -D default get other      # one-off override still wins
blackbook -P alice domain use --clear        # back to 'default'

# Group ACL: every member of @engineering gets read+update on prod-*.
blackbook acl grant "@engineering" "prod-*" --read --update --domain engineering

# Time-bounded + capped grant.
blackbook acl grant alice "rotated-keys/*" --read --max-uses 5 --expires-at 2026-12-31T00:00:00Z

# Single-use grant: --max-uses 1.
blackbook acl grant alice "incident-log" --read --max-uses 1

# ACL patterns use SQL LIKE semantics: * maps to % (any sequence), and _
# matches any single character. Quote patterns that contain _ if you mean
# a literal underscore.
# The use counter increments on every authorized operation and is never reset;
# once exhausted, the rule permanently stops authorizing even if --expires-at
# has not been reached.
```

## Resource flags

```powershell
# Burn-after-read: deleted server-side after first successful retrieve.
blackbook put exec-token EX_TOK_RAW --delete-on-read

# Capped reads. On the Nth (final allowed) read the row is *tombstoned*:
# data_layer1/data_layer2/wrapped_key are scrubbed in place and `exhausted_at`
# is set. Subsequent reads return 410 Gone; the name slot stays "taken" so a
# later `put` still trips 409 unless --overwrite is passed.
blackbook put pager-key PD_KEY --max-reads 10

# Preserve the forensic record indefinitely — even `cleanup` keeps this row.
blackbook put audit-trail SECRET --max-reads 1 --preserve-on-cleanup

# Admin: purge tombstoned secrets in the current domain. Rows flagged
# --preserve-on-cleanup are kept. Each removal lands in the audit log as a
# `cleanup` action, plus a `cleanup.summary` totals event.
blackbook cleanup

# Per-read TOTP: get fails without --mfa CODE.
blackbook put root-pat root_pat_xxx --mfa-required
blackbook --mfa 123456 get root-pat

# Rotate-on-read: encryption envelope is re-keyed after every successful read.
blackbook put session-key SK_RAW --rotate-on-read
# All flag names (mfa_required, delete_on_read, max_reads, rotate_on_read,
# preserve_on_cleanup) are validated at store time — any other key is rejected.
```

## Client-side ("external") storage

The value is encrypted on the client; the server keeps only an opaque envelope
it can never decrypt. Decryption needs the client key factor *and* the
server-held envelope (released only after the normal authorization gates), so
neither side can recover the plaintext alone.

Client-side storage is the product of **two independent axes** — choose them
separately:

**Axis 1 — key source** (who holds the wrapping key):

- **`--external-key` (`-e`) — managed.** The data key is wrapped under the
  profile's **Client Master Key** — the rotation-stable key sealed inside your
  passphrase-encrypted profile (see *Encrypted-at-rest credentials*). No second
  passphrase to manage; your profile passphrase transitively protects the data.
  The CMK is carried forward across re-logins, so `client rotate` never orphans
  the data.
- **`--external-passphrase` — user-supplied.** The data key is wrapped under
  `Argon2id(passphrase, salt)` instead — decoupled from the profile, portable to
  any machine that knows the passphrase. **Requested on every read** and never
  cached: each access resolves it as flag → `$BLACKBOOK_EXTERNAL_PASSPHRASE` →
  interactive no-echo prompt, so a bare `get` with nothing configured asks for
  it rather than failing. (Managed-key items never prompt.)

**Axis 2 — data location** (where the ciphertext lives):

- **default — in blackbook.** The opaque envelope is stored server-side
  (it still can't read it). Available for secrets *and* files.
- **`--external-data` (`-E`, files only) — resident.** The ciphertext stays on
  *this client*; the server keeps only a manifest + its half of a split key.
  Mutual custody — neither side can decrypt alone. (A secret has no on-disk
  home, so `--external-data` is rejected for secrets.)

**`--external`** is the shorthand for both axes at once: managed key + resident
data (for a secret, where residency doesn't apply, it means managed-key,
data-in-blackbook). The legacy `--resident` is an alias for `--external-data`.

```powershell
# Secret, managed key (no passphrase), stored in blackbook:
blackbook put --external-key my-secret some-secret-value      # [external-key/managed]
blackbook get my-secret                                        # decrypts locally, no prompt

# Secret, user passphrase (portable, Argon2id):
blackbook put --external-passphrase pp shared-secret value    # [external-key/passphrase]
blackbook get shared-secret                                    # prompts for the passphrase

# File, the four key×data quadrants:
blackbook file put ./r.pdf -n r --external-key                 # managed key, in blackbook
blackbook file put ./r.pdf -n r --external-passphrase pp       # user key,    in blackbook
blackbook file put ./r.pdf -n r --external-data                # managed key, resident
blackbook file put ./r.pdf -n r --external-data --external-passphrase pp  # user key, resident
blackbook file get r ./out.pdf

# External composes with every policy flag and K-of-N — the server still gates
# release; the client still needs its key. e.g. burn-after-one-read:
blackbook put --external one-time SENSITIVE --max-reads 1
```

Crypto: per-item `K` = random 256-bit key; `ciphertext = AES-256-GCM(K, value)`;
`wrapped_dek = AES-256-GCM(kek, K)` where `kek` is the **CMK** (default) or
`Argon2id(passphrase, salt)` (explicit). The envelope is **versioned** (`v2`)
and records the mode + KDF cost parameters, so `get` reverses it automatically;
legacy `v1` (scrypt-passphrase) envelopes still decode. The server stores the
full envelope (secrets) or the envelope header + a separate ciphertext blob
(files) — and, per *server at-rest encryption*, wraps even that in its own
AEAD. `--rotate-on-read` is rejected for external items — the server can't
re-key what it can't read.

### External *key* vs resident *file*

There are two distinct client-side file models:

- **External key** (`file put --external`, above): the **ciphertext lives in
  blackbook**; only the unwrap key is client-side. Good when you want the
  server to hold the bytes but never be able to read them.
- **Resident file** (`file put --resident` / `-E`): the **ciphertext lives on
  *this machine*** (under `~/.bbk/resident/`, tracked by a local index);
  blackbook holds only a manifest + *its half of a split file key*. This is
  true mutual custody — encrypted by both parties:

  ```
  Kf       = random file key            ct = AES-256-GCM(Kf, file)   → client stash
  Kf_c     = random client half         Kf_s = Kf XOR Kf_c           → server (its half)
  wrapped_c= AES-256-GCM(client_kek, Kf_c)                           → client stash header
  ```

  Neither side can read it alone: the server never sees `Kf_c` (so it can't
  rebuild `Kf` even though it could fetch `ct` with `--server-copy`), and the
  client can't get `Kf_s` back without passing every auth/ACL/K-of-N/MFA gate.

  ```powershell
  blackbook file put ./report.pdf --name report --resident          # CMK; stash kept locally
  blackbook file put ./report.pdf --name report -E --shred          # also delete the plaintext
  blackbook file put ./report.pdf --name report -E --server-copy    # keep an opaque server backup
  blackbook file get report ./out.pdf                                # fetches Kf_s (gated), decrypts the stash
  ```

  Resident files compose with every policy flag and K-of-N. `--max-reads`
  tombstoning **scrubs the server's key half**, making the file permanently
  unrecoverable even though the client still holds `ct`. If this machine loses
  the stash, the file is unrecoverable unless you used `--server-copy` (an
  encrypted backup that the server still can't read). `--external` and
  `--resident` are mutually exclusive.

## TOTP enrollment

```powershell
blackbook mfa enroll
# → prints an otpauth:// URI (paste into Google Authenticator / Authy / 1Password)
#   and the base32 secret as a fallback.

blackbook mfa verify 123456    # confirms enrollment with a current code
# Enrollment is not active until verify succeeds. Resources flagged
# --mfa-required will reject reads until the client's totp_enrolled flag is set.
```

## K-of-N threshold approval

```powershell
# Store a secret that requires 2 of {bob, carol} before alice can read it.
blackbook put prod-rootkey 'ceremony output' --quorum 2 --signatories bob,carol

# Alice (with normal read ACL) tries:
blackbook -P alice get prod-rootkey
# → 412 Precondition Failed:
#   "threshold 2 of 2 required — request <REQUEST_ID> has 0 approval(s); …"
# Running this again returns the SAME <REQUEST_ID> — no duplicate is created.

# Bob and carol approve out-of-band:
blackbook -P bob   approve <REQUEST_ID>
blackbook -P carol approve <REQUEST_ID>

# Once K approvals are in, a plain get reports it's ready:
blackbook -P alice get prod-rootkey
# → "request <REQUEST_ID> is approved (2/2) — retry with --request-id <REQUEST_ID>"

# Alice replays with the request id; request is consumed (one-shot).
blackbook -P alice get prod-rootkey --request-id <REQUEST_ID>
# → ceremony output
# A subsequent get opens a fresh request (the consumed one is done).

# See who can approve a request (signatories) and who already has:
blackbook requests <REQUEST_ID>     # detail: [approved]/[ pending] per signatory
blackbook requests -v               # same names, inline in the list

# Hands-off for automation: block on one call until approvals land.
blackbook -P alice get prod-rootkey --wait --wait-timeout 120

# Approval requests expire after 24 hours and are single-use. At most one
# OPEN request exists per (requester, resource). Concurrent approvals on the
# same request are serialized (SELECT … FOR UPDATE) so none are lost.
# Files support the same threshold policies — `file put PATH --quorum K
# --signatories a,b,c`, then `file get NAME --request-id ID` once approved.
```

### Advance approval (pre-authorization)

A signatory can pre-approve a *class* of reads so the reader never has to wait,
scoped exactly like an ACL rule (domain + grantee + pattern, with a mandatory
expiry and an optional use cap). An advance grant counts toward a resource's
K-of-N threshold wherever the granting client is one of that resource's
signatories — so K distinct matching grants let the reader through with no
live approval.

```powershell
# bob and carol each pre-approve alice to read monthly reports in `reporting`,
# for the next 30 days. bob caps it at 10 reads; carol leaves it unlimited.
blackbook -P bob   --domain reporting grants add alice "monthly-report-*" --max-uses 10 --ttl-hours 720
blackbook -P carol --domain reporting grants add alice "monthly-report-*" --ttl-hours 720

# A 2-of-{alice,bob,carol} report: alice now reads any matching report directly,
# as many times as the grants allow, for as long as they last — no request, no wait.
blackbook -P alice --domain reporting get monthly-report-june   # → released immediately

blackbook grants ls          # grants you issued or benefit from (USE shows count/cap)
blackbook -P bob grants rm <GRANT_ID>   # the issuing signatory (or admin) can revoke early
```

Advance grants compose with live approvals: the effective approver set for a
read is the **union** of distinct live approvers and distinct matching-grant
signatories. Each read consumes one use from each advance grant it relied on;
once a grant hits its `max_uses` or `expires_at` it simply stops counting.

## CLI surface

Every option has a short form. Three flags are **global** (valid on any
subcommand, before or after it):

| Global | Short | What it does |
|---|---|---|
| `--profile NAME` | `-P` | Credential profile for this command. Overrides `$BLACKBOOK_PROFILE` and the persisted active profile. |
| `--domain NAME` | `-D` | Target a non-default domain for resource commands (and the rule domain for `acl grant`). Precedence: `-D` → `$BLACKBOOK_DOMAIN` → the profile's saved default (`domain use`) → `default`. |
| `--mfa CODE` | `-m` | Send `X-Blackbook-MFA` on every request. |

| Verb | What it does |
|---|---|
| `login BUNDLE [-s SERVER]` | Log in from a bundle JSON (`client create` output or first-run `admin-bundle.json`; `-` for stdin). Prompts for a passphrase (or reads `$BLACKBOOK_PASSPHRASE`) and saves an **encrypted** profile **named after the authenticated identity** (override with `-P`), then leaves it unlocked and active. `-s` overrides the bundle's server URL. The bundle carries the full credential set (server + token + cert + key + ca) — the server rejects anything less. |
| `unlock [-t MINUTES]` / `lock` | Cache the active profile's derived unlock key in the local agent for `-t` minutes (default 15) so commands don't re-prompt / clear that cached key. Passphrase from `$BLACKBOOK_PASSPHRASE` or an interactive prompt. |
| `passphrase [--old P] [--new P]` | Change the passphrase that encrypts the active profile. The credential bundle is re-sealed locally under the new passphrase; the embedded **client master key is preserved**, so every CMK-sealed external item still decrypts. Old/new come from flags → `$BLACKBOOK_OLD_PASSPHRASE`/`$BLACKBOOK_NEW_PASSPHRASE` → prompts. |
| `completions [SHELL]` | Print a shell completion script (`powershell` (default) / `bash` / `zsh` / `fish`). Tab-completes commands, subcommands, and flags; also completes **real values** for `-P/--profile` (your profiles), `-D/--domain` (known domains), and `file get/rm` (resident files this machine holds). All local — no network, nothing sent to the server. |
| `logout`, `whoami` | Forget the active profile's session (also clears its cached unlock key) / inspect identity (`auth: mtls+token`, and your private `user domain: ~<name>`). |
| `profile ls` / `profile use NAME` / `profile show [NAME]` / `profile rm NAME [-y]` | List (active marked `*`) / switch the persisted default / inspect / delete a profile. |
| `put NAME VALUE [-o/--overwrite] [-i/--no-overwrite] [-e/--external-key] [--external-passphrase P] [--external] [-M/--mfa-required] [-d/--delete-on-read] [-n/--max-reads N] [-r/--rotate-on-read] [-p/--preserve-on-cleanup] [-q/--quorum K -s/--signatories a,b,c]` | Store a secret with optional policy flags + threshold. Read-only by default (409 unless `-o`). `-i` immutable. Client-side encryption (server can't read it): `-e/--external-key` uses the profile's managed CMK (`[external-key/managed]`); `--external-passphrase`/`$BLACKBOOK_EXTERNAL_PASSPHRASE` uses an Argon2id user key (`[external-key/passphrase]`). `--external` is shorthand (= managed key for a secret). `--external-data` is files-only (a secret has no on-disk home) and errors with a clear message. |
| `cleanup` | Admin only. Delete tombstoned **secrets and files** (`max_reads` hit, crypto/blob scrubbed) in the current domain. Resources flagged `preserve_on_cleanup` are kept. |
| `get NAME [-r/--request-id ID] [-w/--wait] [--wait-timeout S] [--external-passphrase P]` | Read; if threshold-gated, returns 412 + request id on first call. Pass `-r` once K approvals are in, or `-w` to block (one call) until approved. External secrets are decrypted locally — CMK-sealed ones need no passphrase; **passphrase-sealed ones request the passphrase on every read** (`--external-passphrase` → `$BLACKBOOK_EXTERNAL_PASSPHRASE` → interactive no-echo prompt). The passphrase is never cached, so each access re-requests it unless a flag/env supplies it. |
| `ls`, `rm NAME [-y]` | List / delete secrets (max 500). `ls` shows each secret's **KIND** (`server` vs `external` client-side), **STATUS** (active / exhausted), and a **RULES** summary of enforced policy — e.g. `mfa, max-reads 2/5, immutable, quorum 2-of-3`. |
| `rekey NAME [--old-external-passphrase P] [-e/--external-key] [--external-passphrase P]` | Change the client-side key on an external secret without changing its value: decrypt locally with the current key, re-encrypt under the new one (`-e` managed CMK, or `--external-passphrase` for a new user key), store back. Covers passphrase→passphrase, managed→passphrase, and passphrase→managed. Policy flags (MFA, max-reads, K-of-N…) are preserved. |
| `file put PATH [-n/--name N] [-t/--mime M] [-o/--overwrite] [-i/--no-overwrite] [-e/--external-key] [--external-passphrase P] [-E/--external-data] [--external] [-c/--server-copy] [--shred] [-M/--mfa-required] [-d/--delete-on-read] [-R/--max-reads N] [-r/--rotate-on-read] [-p/--preserve-on-cleanup] [-q/--quorum K -s/--signatories a,b,c]` | Upload a file (max 64 MiB). Same policy surface as `put`, plus the two client-side axes. **Key:** `-e/--external-key` (managed CMK) or `--external-passphrase` (Argon2id user key). **Data:** default = ciphertext in blackbook; `-E/--external-data` (alias `--resident`) keeps it **resident** on this machine under `~/.bbk/resident` (server holds only a manifest + its half of a split key — mutual custody). `--external` = managed + resident. `-c/--server-copy` also keeps an opaque server backup; `--shred` deletes the original plaintext (both require `--external-data`). Note `-R` for max-reads (`-r` is rotate-on-read). |
| `file get NAME [PATH\|-] [-r/--request-id ID] [-w/--wait] [--wait-timeout S] [--external-passphrase P]` / `file ls` / `file rm NAME [-y]` / `file rotate NAME` | Download (pass `-r` once a K-of-N file request is approved, or `-w` to block) / list / delete / DEK rotation. External-key and resident files decrypt locally; a resident `get` fetches the server's key half (gated) and recombines it with the local stash. `file ls` shows each file's **KIND** (`server` / `external-key` / `resident`, marked `(exhausted)` when tombstoned) and the same **RULES** summary as `ls`. |
| `file rekey NAME [--old-external-passphrase P] [-e/--external-key] [--external-passphrase P]` | Change the client-side key on an external/resident file. For an **external-key** file: decrypt, re-wrap, re-upload the envelope. For a **resident** file: only the local stash's wrapped client-half is rewritten — the ciphertext and the server's key-half are untouched, so there's no re-upload (must run where the stash lives). |
| `client create NAME [-r/--role admin\|user] [-t/--ttl-days N] [-o/--out PATH]` | Provision; new clients auto-join `default` **and get a private, fully-administered user domain `~NAME`** (which their next `login` adopts as the default domain). Names starting with `~` are rejected. Role defaults to `user`. `--ttl-days` defaults to 30 for `user`, 365 for `admin`. |
| `client rotate NAME [-t/--ttl-days N] [-o/--out PATH]` | Reissue token+cert; the old ones stop working immediately. |
| `client ls` / `client revoke NAME [-y]` | Admin. `revoke` prompts for confirmation unless `-y`/`--yes`. |
| `acl grant SUBJECT PATTERN [-c/--create] [-r/--read] [-u/--update] [-d/--delete] [-D/--domain D] [-e/--expires-at TS] [-b/--not-before TS] [-x/--max-uses N]` | `SUBJECT` is a client name; prefix `@` for a group (domain members). The rule's domain comes from the global `-D/--domain` (default `default`). At least one action flag is required. **Global admin or an admin of that domain.** |
| `acl ls` / `acl revoke ID` | `ls`: global admin sees all rules, a domain admin sees only their domains'. `revoke`: global admin, or an admin of the rule's own domain. |
| `domain create NAME [-d/--description D]` | Create a domain. **Global admin only.** |
| `domain use [NAME] [--clear]` | Set/show/clear this profile's default domain so you don't need `-D` every command. Self-service (no admin needed); stored per-profile under `~/.bbk/domains/<profile>`. |
| `domain ls` / `members NAME` | List domains / a domain's members. |
| `domain add-member D C [-r/--role user\|guest\|admin]` / `rm-member D C` | Manage members. **Global admin or an admin of domain `D`.** A domain admin may delegate the in-domain `admin` role, which confers no global privilege. |
| `mfa enroll` / `mfa verify CODE` | TOTP self-service. |
| `approve REQUEST_ID` | Approve someone else's K-of-N request. |
| `requests [ID] [-v/--verbose]` | List access requests you can act on (or one request's detail with `ID`). Shows signatories (who can approve) and current approvers. |
| `grants add GRANTEE PATTERN [-k/--kind secret\|file] [-x/--max-uses N] [-H/--ttl-hours H \| -e/--expires-at TS] [-b/--not-before TS]` | Pre-approve `GRANTEE` for reads matching `PATTERN` in the global `-D/--domain`. You become a standing approver where you're a signatory. A time limit (`-H` or `-e`) is required. |
| `grants ls` / `grants rm ID [-y]` | List advance grants you issued or benefit from / revoke one (issuing signatory or admin). |
| `audit [-n/--limit N]` / `audit -v/--verify` | Admin. `-v` recomputes the hash chain and reports the first tampered/deleted/reordered row (if any). |
| `server [-b/--bind ADDR]` / `health` | Server mode / DB ping. Root flags: `-d/--database-url`, `-L/--log-level`. |
| `web [-b/--bind ADDR]` | Launch the web console (default `127.0.0.1:8088`) — a local browser front-end that drives this CLI by re-invoking `blackbook`. No separate API; every command/flag stays in sync. Dark UI, colorized output, sidebar actions, history, `Tab` completion. |
| `tunnel forward PEER -l/--listen ADDR -t/--to ADDR [-u/--udp]` / `tunnel accept [-f/--from NAME] [--wait-timeout S]` / `tunnel ls` | **End-to-end-encrypted tunnel between two clients**, relayed but unreadable by the server (see [Secure tunnels](#secure-tunnels-)). `forward` binds a local TCP/UDP port and pipes each connection to PEER, who (running `accept`) dials `--to`. Peers are mutually authenticated by their existing client certs (ephemeral X25519 + ECDSA-signed handshake → AES-256-GCM); the server vouches identities and relays opaque frames only. `accept` waits for an offer addressed to you (optionally restricted `--from` a named offerer). |

## Architecture (post Phase D)

```
                                     ┌─────────────────────────────────────┐
                                     │  CLI (~/.bbk/profiles/<name>.json)  │
                                     │  cert / key / ca / token / domain   │
                                     └──────────────────┬──────────────────┘
                                                        │ TLS 1.3 + mTLS
                                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Blackbook API server                                                       │
│                                                                             │
│  on_connect       :  extract cert CN + SHA3 fingerprint into Extensions    │
│  FromRequest      :  CN+fp match OR bearer-token hash match                │
│                      → AuthenticatedClient (also checks expires_at)        │
│  resolve_domain   :  ?domain=… → domain_id  (caller must be a member)      │
│  acl_check        :  admin? domain-admin? direct or @group rule that's     │
│                      in-window AND under max_uses?                          │
│  flags enforce    :  max_reads / mfa_required / delete_on_read              │
│  policy enforce   :  K-of-N — create access request, gate retrieval        │
│                      on `X-Blackbook-Request-Id` of a fully-approved one    │
│  audit            :  every operation / denial / approval / admin op        │
└──────────┬───────────────────────────────────────────────┬─────────────────┘
           │ sqlx                                          │ tokio::fs
           ▼                                               ▼
┌────────────────────────────┐                ┌───────────────────────────────┐
│   PostgreSQL                │                │  /opt/blackbook/data/         │
│   blackbook_domains          │                │  ├─ dek.meta (salt|wrapped)  │
│   blackbook_domain_members   │                │  ├─ master.bbkey             │
│   blackbook_clients          │                │  ├─ ca.crt + ca.key          │
│      ↳ totp_secret_enc       │                │  ├─ server.crt + server.key  │
│   blackbook_acl              │                │  ├─ admin-bundle.json        │
│      (expires_at, not_before,│                │  │   (+ admin-cert/key/token)│
│       max_uses, group_id)    │                │  └─ contents/<id> (blobs)    │
│   blackbook_secrets          │                └───────────────────────────────┘
│      ↳ flags, access_policy  │
│      ↳ read_count            │
│   blackbook_pages            │
│      ↳ flags, wrapped_dek    │
│   blackbook_contents         │
│   blackbook_access_requests  │
│      (threshold_k, sigs,     │
│       approvers, consumed_at)│
│   blackbook_audit            │
└─────────────────────────────┘
```

## Crypto details

- **TLS**: 1.3 only, AEAD ciphers, ECDSA P-256 / SHA-256 certs (Blackbook's own CA), `NO_COMPRESSION | NO_RENEGOTIATION`.
- **Key hierarchy** ([src/blackbook_core.rs](src/blackbook_core.rs)):
  - `PrimaryKey` — 32-byte CSPRNG secret, *no derivation method*. Pure material.
  - `SecondaryKey { primary, domain, kdf }` — the only derivation surface. `kdf` is `Scrypt(n=2¹², r=16, p=4)` or `PBKDF2-HMAC-SHA3-512 (200k)`. `domain` is mandatory + immutable.
  - `WrappedKey` — 30 iterations of RFC 3394 AES-256 Key Wrap, each iteration's KEK derived via `SecondaryKey::handle_with_info(round_counter)`.
  - `BlackbookKey` — the bundle: `root` PrimaryKey + named SecondaryKeys (`secret_layer1`, `secret_layer2`, `file_dek_kek`, `index`, `hmac`, `mfa_secret_kek`) + `WrappedKey` self-encryption + Ed25519 identity key.
- **Secret envelope**: `timestamp(5) ‖ salt(32) ‖ AES-256-GCM(plain, key=scrypt(input_key, salt), nonce=salt[..12], aad=timestamp)`. Two layers per record (primary + secondary).
- **File envelope**: per-file random 32-byte DEK; AES-256-GCM with a random 12-byte nonce; SHA3-256 of plaintext stored separately and verified at retrieval — a hash mismatch returns 403 Forbidden. The DEK itself is wrapped using the secret envelope under `file_dek_kek`.
- **Token storage**: SHA3-256 of bearer tokens; never plaintext. **Cert fingerprint storage**: SHA3-256 of DER. Rotation overwrites both.
- **TOTP**: SHA1 (for authenticator-app compatibility), 30-second step, 6 digits, ±1 step skew. The 20-byte secret is `encrypt_aes_gcm(secret, mfa_secret_kek.handle())` at rest.

## Data model

| Table | Holds |
|---|---|
| `blackbook_domains` | namespace + ACL groups |
| `blackbook_domain_members` | (domain, client, role-in-domain) |
| `blackbook_clients` | identities + token_hash + cert_fingerprint + totp_secret_enc + expires_at |
| `blackbook_acl` | grants — `(domain_id, client_id OR group_domain_id, resource_pattern, actions, expires_at, not_before, max_uses, use_count)` |
| `blackbook_secrets` | encrypted resources + `name_id` + `resource_name_enc` + `flags` + `read_count` + `access_policy` (ids) + `exhausted_at` + `is_external`/`external_envelope` (client-side opaque blob) |
| `blackbook_pages` | file metadata: `name_enc` + `name_id` + `mime_type_enc` + `plaintext_size_enc` + `plaintext_hash_id` + `wrapped_dek` + `flags` + `read_count` + `access_policy` (ids) + `exhausted_at` + `is_external`/`external_meta` (external-key `{salt,wrapped_dek}`) + `external_kind` (0 normal / 1 external-key / 2 resident) + `server_key_component` (resident: server's split-key half, wrapped under `file_dek_kek`) + `has_server_copy` |
| `blackbook_contents` | blob refs to `data/contents/<id>` |
| `blackbook_clients` | `name_enc` + `name_id` + `token_hash` + `cert_fingerprint` + `role` + `totp_secret_enc` + `expires_at` |
| `blackbook_domains` | `name_enc` + `name_id` + `description_enc` (the only semantic plaintext is the timestamps and the random `id`) |
| `blackbook_acl` | `pattern_enc` (ACL pattern, encrypted); SQL `LIKE` matching moved to in-memory after decrypt |
| `blackbook_access_requests` | `resource_name_enc` + `resource_name_id` (HMAC, for per-(requester,resource) dedup) + `signatory_ids` (opaque) + `approvers` |
| `blackbook_access_grants` | advance approvals — `signatory_id` + `grantee_id` + `domain_id` + `resource_kind` + `pattern_enc` + `max_uses`/`use_count` + `not_before`/`expires_at` |
| `blackbook_audit` | append-only event log: `resource_enc` + `message_enc` + `prev_hash`/`row_hash` tamper-evidence chain |
| `blackbook_schema_migrations` | applied numbered migrations (version, name, applied_at) |

ACL action bits: `create=1, read=2, update=4, delete=8`.

## Configuration

| Env var | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes (server) | Postgres connection string |
| `BLACKBOOK_DATA_DIR` | no | Where master key / CA / admin bundle live (default `/opt/blackbook/data`) |
| `BLACKBOOK_SERVER_SANS` | no | Comma-separated SAN list for the server cert (default `localhost,127.0.0.1,blackbook,blackbook-app`) |
| **`BLACKBOOK_MASTER_KEYFILE`** | one master-key provider is **required** | Path to a keyfile (kept **off** the data volume, e.g. a Docker secret on tmpfs). A random DEK is generated once and stored on the data volume only *wrapped* under `KEK = SHA3-256(keyfile)`; the plaintext DEK is never written. Generate the keyfile once: `openssl rand 32 > secrets/master_keyfile`. |
| **`BLACKBOOK_MASTER_PASSPHRASE`** / `…_FILE` | one master-key provider is **required**, ≥16 chars | User-supplied secret. `DEK = Argon2id(passphrase, salt)`; only the salt is persisted. Prefer the `_FILE` form (a path, e.g. a Docker secret) so the passphrase isn't in the process environment. |
| `RUST_LOG` | no | Log filter |

> **The master DEK is never stored raw on disk.** The server requires exactly one provider above (keyfile *or* passphrase) and **refuses to start** without one. Only a salt or a wrapped-DEK blob lands on the data volume (`dek.meta`); the plaintext DEK is derived/unwrapped in memory at every boot. A copy of the data volume alone is therefore not decryptable. Legacy volumes that still hold a raw `dek`/`dek.mode` are migrated to a provider automatically on first boot (the master key is re-encrypted and the raw DEK securely erased). Switching providers, or losing the keyfile/passphrase, makes the data unrecoverable — back the secret up separately from the volume.

### Database (Postgres) security

The server↔Postgres link is hardened (run `./scripts/generate-postgres-certs.sh` once before first boot):

- **Mutual TLS 1.3.** The app connects with `sslmode=verify-full` (pinning Postgres to the CA in `secrets/postgres/`) **and presents its own client certificate**; `config/pg_hba.conf` requires `clientcert=verify-full` + SCRAM, so both ends are cryptographically authenticated and plaintext TCP is **refused**.
- **Least-privilege application role.** The app connects as `blackbook_app` (created by `scripts/01-blackbook-roles.sh`), which can manage only its own objects in the one database — it **cannot** create roles or databases, replicate, or bypass RLS. The superuser is reserved for break-glass. `PUBLIC` connect is revoked.
- **Config is actually loaded.** `config/postgres.conf` is applied via `-c config_file=…` (it was previously mounted but ignored), enabling `ssl`, SCRAM, and connection logging.
- DB credentials come from `./.env` (copy `config/blackbook.env`); generate strong values with `openssl rand -base64 32`. The dev defaults are clearly marked and must be changed for production.

## Known limitations / future work

- **True client-side Shamir shares.** The threshold gate today is server-mediated: the DEK stays whole and the server enforces the policy. Same operational guarantee as long as the server is in the trust boundary. Splitting the DEK into client-encrypted shares (one per signatory, encrypted under their X25519 public key) is the next defense-in-depth slice and unlocks the *server-compromise* threat model. **This is the one remaining item from the original roadmap.**
- **Audit-log verification cost is linear** in the number of *live* rows. Archival (below) bounds that set, but a single `audit --verify` still recomputes the whole live chain; there is no incremental/checkpointed verifier yet.

### Recently shipped (previously listed here as future work)

- **Per-client rate limiting** — a loose per-identity token bucket (keyed by mTLS CN, IP fallback) sheds load from a single flooding client without throttling normal use. Configurable via `BLACKBOOK_NET_RATE_PER_SEC` / `BLACKBOOK_NET_BURST` (`0` disables). See [`src/net_ratelimit.rs`](src/net_ratelimit.rs).
- **Audit-log archival / rotation** — `blackbook audit --archive [--keep-last N | --before TS] [--prune]` exports the oldest rows to a compressed, AES-256-GCM-encrypted, independently hash-chain-verifiable file on the data volume, records a chain anchor, and (with `--prune`) bounds the live table. Verify an archive end-to-end with `audit --verify-archive FILE`; list them with `audit --list-archives`. See [`src/audit_archive.rs`](src/audit_archive.rs).
- **Master DEK rotation** — `blackbook rekey-dek` re-wraps the master key under a freshly generated DEK for the current provider, in one command (the master key material itself is unchanged, so all data stays readable). A legacy raw-DEK volume is still migrated to a provider automatically on first boot.

## Source layout

```
src/
├── main.rs            ─ CLI, entrypoint, schema bootstrap
├── server.rs          ─ HTTPS + mTLS server, all endpoints
├── client.rs          ─ HTTP client, rustls config, session file
├── auth.rs            ─ FromRequest extractor, ACL check, audit, MFA, ResourceFlags
├── credstore.rs       ─ encrypted-at-rest credential profiles (Argon2id → AES-GCM)
├── persistence.rs     ─ DEK provider (keyfile/passphrase), master + CA + server cert load/init/rekey
├── tls.rs             ─ rcgen-based CA + cert issuance, CN extraction
├── blackbook_core.rs  ─ PrimaryKey, SecondaryKey + Kdf, WrappedKey, BlackbookKey,
│                        AES-GCM envelopes, scrypt, AsymmetricKey
├── net_ratelimit.rs   ─ per-client token-bucket rate limiter (anti-DoS)
├── audit_archive.rs   ─ encrypted, compressed, chain-verifiable audit-log archives
├── presentation.rs    ─ randomart / braille fingerprint rendering (display only)
├── webui.rs (+webui/) ─ local browser console that re-invokes the CLI (no shell)
├── tunnel_crypto.rs   ─ X25519 + HKDF + ECDSA handshake, per-direction AES-GCM frames
├── tunnel_relay.rs    ─ server-side opaque frame relay (pairs two mTLS peers)
└── tunnel_client.rs   ─ client tunnel: local TCP/UDP port-forward over the channel
```

## License

Blackbook is licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`). See [LICENSE](LICENSE). Because it is designed to be run as a
network service, the AGPL's network-use clause applies: if you offer a modified
Blackbook to users over a network, you must offer them its source.
