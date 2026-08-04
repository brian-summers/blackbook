use clap::{Parser, Subcommand, CommandFactory};
use zeroize::Zeroizing;
use sqlx::postgres::PgPoolOptions;
use sqlx::Pool;
use sqlx::Postgres;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub mod blackbook_core;
mod audit_archive;
mod net_ratelimit;
mod presentation;
mod server;
mod client;
mod credstore;
mod webui;
mod tunnel_crypto;
mod tunnel_relay;
mod tunnel_client;
pub mod auth;
pub mod persistence;
pub mod tls;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("client: {0}")]
    Client(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl From<client::ClientError> for AppError {
    fn from(e: client::ClientError) -> Self { AppError::Client(e.to_string()) }
}

impl From<credstore::CredError> for AppError {
    fn from(e: credstore::CredError) -> Self { AppError::Config(e.to_string()) }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "bbk", version, about, long_about = None)]
struct Cli {
    #[arg(short = 'd', long, env = "DATABASE_URL")]
    database_url: Option<String>,

    #[arg(short = 'L', long, default_value = "info")]
    log_level: String,

    /// Domain to target for resource commands. Overrides $BLACKBOOK_DOMAIN and
    /// the profile's saved default (`domain use`). Falls back to `default`.
    #[arg(short = 'D', long, global = true, env = "BLACKBOOK_DOMAIN")]
    domain: Option<String>,

    /// Provide a 6-digit TOTP code; sent as X-Blackbook-MFA on every request.
    /// Required when accessing a resource flagged `mfa_required`.
    #[arg(short = 'm', long, global = true)]
    mfa: Option<String>,

    /// Credential profile to use for this command (see `blackbook profile`).
    /// Overrides $BLACKBOOK_PROFILE and the active profile. Lets you drive
    /// several identities from one shell, e.g. `blackbook -P alice get x`.
    #[arg(short = 'P', long, global = true, env = "BLACKBOOK_PROFILE")]
    profile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the Blackbook API server (HTTPS + mTLS).
    Server {
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        bind: String,
    },
    /// Launch the web console — a browser front-end that drives this CLI.
    /// It serves one local page and runs your commands by re-invoking
    /// `blackbook`, so every command and flag stays in sync automatically.
    Web {
        /// Address to bind (loopback by default — it's a local convenience).
        #[arg(short, long, default_value = "127.0.0.1:8088")]
        bind: String,
    },
    /// Database connectivity ping (used by Docker healthcheck).
    Health,

    /// Rotate the master DEK: re-wrap the master key under a freshly generated
    /// DEK from the current provider (the master key itself is unchanged).
    /// Server-side maintenance — needs the same BLACKBOOK_DATA_DIR and master
    /// key provider env as the server. Safe to run while the server is up; to
    /// adopt a *new* keyfile, generate it, run this, then restart.
    RekeyDek,

    /// Log in from a credential bundle and save it as a profile.
    ///
    /// A bundle is the JSON produced by `client create` or the first-run
    /// `admin-bundle.json`; it carries server + token + cert + key + ca — the
    /// complete set the server requires (both cert and token are mandatory).
    ///
    /// By default the profile is named after the authenticated identity
    /// (`admin` → profile `admin`, `dave` → profile `dave`). Override the
    /// target profile with the global `--profile/-P`.
    Login {
        /// Path to the bundle JSON (or `-` to read it from stdin).
        bundle: String,
        /// Override the server URL recorded in the bundle (e.g. when the
        /// admin bundle's default `127.0.0.1` isn't how you reach the host).
        #[arg(short = 's', long)]
        server: Option<String>,
    },
    /// Forget the active profile's saved session.
    Logout,
    /// Unlock an encrypted profile for a while, caching the derived key in the
    /// local agent so subsequent commands don't re-prompt. The passphrase
    /// comes from $BLACKBOOK_PASSPHRASE or an interactive prompt.
    Unlock {
        /// Minutes to keep the profile unlocked (default 15).
        #[arg(short = 't', long, default_value_t = 15)]
        ttl_minutes: u64,
    },
    /// Clear the active profile's cached unlock key from the agent.
    Lock,
    /// Change the passphrase that encrypts the active profile (the credential
    /// bundle is re-sealed locally; the embedded client master key is preserved
    /// so all external data still decrypts). Old/new come from flags, or
    /// $BLACKBOOK_OLD_PASSPHRASE / $BLACKBOOK_NEW_PASSPHRASE, or prompts.
    Passphrase {
        /// Current passphrase (else env/prompt).
        #[arg(long)] old: Option<String>,
        /// New passphrase (else env/prompt, confirmed when prompted).
        #[arg(long)] new: Option<String>,
    },
    /// Manage credential profiles (multiple identities).
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Print the current authenticated identity.
    Whoami,

    /// Print a shell completion script. Source it (or add to your profile) to
    /// get tab-completion of commands, flags, and — for profiles, domains, and
    /// resident files — their actual values. Defaults to PowerShell.
    Completions {
        /// Target shell: powershell | bash | zsh | fish.
        #[arg(default_value = "powershell")]
        shell: String,
    },
    /// Internal: emit completion candidates for the current command line.
    /// Called by the generated completion scripts; not for direct use.
    #[command(hide = true)]
    #[command(name = "__complete")]
    Complete {
        /// The words typed so far (the full command line, argv-style).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },

    /// Store a new secret. Returns 409 if a secret with this name already
    /// exists; use --overwrite to intentionally replace it.
    Put {
        name: String,
        value: Option<String>,
        /// Require MFA (TOTP) on every future read of this secret.
        #[arg(short = 'M', long)] mfa_required: bool,
        /// Delete this secret immediately after the first successful read.
        #[arg(short = 'd', long)] delete_on_read: bool,
        /// Maximum number of reads before the secret refuses to authorize.
        #[arg(short = 'n', long)] max_reads: Option<i64>,
        /// Re-key the encryption envelope after every successful read.
        #[arg(short = 'r', long)] rotate_on_read: bool,
        /// Threshold K for K-of-N approvals. Requires --signatories.
        #[arg(short = 'q', long)] quorum: Option<i32>,
        /// Comma-separated list of client names allowed to approve.
        #[arg(short = 's', long, value_delimiter = ',')] signatories: Vec<String>,
        /// Replace an existing secret with the same name. Requires update permission.
        #[arg(short = 'o', long)] overwrite: bool,
        /// Mark this secret as exempt from `cleanup`. Even after the secret
        /// is tombstoned (e.g. by max_reads exhaustion), the forensic record
        /// — name + created_at + exhausted_at — is preserved.
        #[arg(short = 'p', long)] preserve_on_cleanup: bool,
        /// Make this secret immutable: once created it can never be overwritten,
        /// even with --overwrite. Delete it first to replace it.
        #[arg(short = 'i', long)] no_overwrite: bool,
        /// Client-side encryption under the profile's managed key (CMK): the
        /// server stores only an opaque envelope it can never decrypt.
        #[arg(short = 'e', long = "external-key")] external_key: bool,
        /// Client-side encryption under a user-supplied passphrase (Argon2id),
        /// never sent to the server. Prefer $BLACKBOOK_EXTERNAL_PASSPHRASE to
        /// keep it off the command line. Implies client-side encryption.
        #[arg(long)] external_passphrase: Option<String>,
        /// Alias: managed-key client-side encryption (same as --external-key
        /// for secrets, since a secret's data always lives in blackbook).
        #[arg(long)] external: bool,
        /// Not available for secrets (data residency is files-only); rejected
        /// with a clear message. Present so the error is explicit, not "unknown
        /// flag".
        #[arg(long, hide = true)] external_data: bool,
        /// Opt into passphrase-mode client-side encryption, sourcing the
        /// passphrase from $BLACKBOOK_EXTERNAL_PASSPHRASE instead of an argv
        /// value (so it never appears on the command line). Equivalent to
        /// `--external-passphrase <value>`. Used by the web console.
        #[arg(long, hide = true)] external_passphrase_env: bool,
    },
    /// Print a secret's value to stdout. If the secret has a K-of-N policy
    /// and you don't already have an approved request, the server returns
    /// 412 and prints the new request id — pass `--request-id ID` once K
    /// approvals are in, or `--wait` to block until it's approved.
    Get {
        name: String,
        #[arg(short = 'r', long)] request_id: Option<String>,
        /// Block and poll until the K-of-N request is approved (or timeout),
        /// so an automated reader makes a single call. No effect on
        /// non-threshold secrets.
        #[arg(short = 'w', long)] wait: bool,
        /// Max seconds to wait with --wait (default 300).
        #[arg(long, default_value_t = 300)] wait_timeout: u64,
        /// Passphrase to decrypt a client-side ("external") secret. Falls back
        /// to $BLACKBOOK_EXTERNAL_PASSPHRASE. Ignored for normal secrets.
        #[arg(long)] external_passphrase: Option<String>,
    },
    /// List secrets visible to the current client.
    Ls {
        /// Output as JSON (used by the web console's structured API).
        #[arg(long)] json: bool,
    },
    /// Delete a secret.
    Rm {
        name: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Change the client-side key on an external secret: decrypt it locally with
    /// its current key and re-encrypt under a new one, then store it back. Use
    /// `--old-external-passphrase` to supply the current passphrase, and the
    /// target-key flags (`--external-key` for the managed CMK, or
    /// `--external-passphrase` for a new user passphrase). Only the wrapping key
    /// changes — the secret value is unchanged.
    Rekey {
        name: String,
        /// Current passphrase, if the secret is passphrase-sealed (else env/prompt).
        #[arg(long)] old_external_passphrase: Option<String>,
        /// Re-wrap under the profile's managed key (CMK).
        #[arg(short = 'e', long = "external-key")] external_key: bool,
        /// Re-wrap under this new user passphrase (Argon2id).
        #[arg(long)] external_passphrase: Option<String>,
    },

    /// Manage encrypted files.
    #[command(subcommand)]
    File(FileCmd),

    /// Secure end-to-end tunnels between two clients (the server relays opaque
    /// frames but cannot read or modify them; peers are positively identified
    /// to each other by their existing client certificates).
    #[command(subcommand)]
    Tunnel(TunnelCmd),

    /// Manage API clients (admin only).
    #[command(subcommand)]
    Client(ClientCmd),
    /// Manage access-control rules (admin only).
    #[command(subcommand)]
    Acl(AclCmd),
    /// Manage domains — both resource namespaces and ACL groups (admin).
    #[command(subcommand)]
    Domain(DomainCmd),
    /// Enroll / verify time-based one-time-password (TOTP) MFA for your
    /// own client. Required to read resources flagged `--mfa-required`.
    #[command(subcommand)]
    Mfa(MfaCmd),
    /// Approve another client's pending K-of-N access request.
    Approve { request_id: String },
    /// View access requests where you're the requester or a signatory.
    /// With an ID, show that request's full detail (who can approve, who has).
    Requests {
        /// Show full detail for a single request id.
        id: Option<String>,
        /// In the list, expand the signatory and approver names per row.
        #[arg(short = 'v', long)] verbose: bool,
    },
    /// Manage advance-approval grants — pre-authorize a reader for a pattern
    /// (scoped to domain + grantee + pattern, with a TTL and optional use cap)
    /// so K-of-N reads don't need a live approval each time.
    #[command(subcommand)]
    Grants(GrantsCmd),
    /// View the audit log (admin only).
    Audit {
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: i64,
        /// Instead of listing entries, verify the tamper-evidence hash
        /// chain and report the first broken row (if any).
        #[arg(short = 'v', long)]
        verify: bool,
        /// Archive the oldest audit rows to a compressed, encrypted,
        /// chain-verifiable file on the server's data volume. Combine with
        /// --keep-last or --before, and optionally --prune.
        #[arg(long)]
        archive: bool,
        /// With --archive: keep the N most recent rows live (archive the rest).
        #[arg(long)]
        keep_last: Option<i64>,
        /// With --archive: archive rows older than this timestamp
        /// (RFC3339 or `YYYY-MM-DD[ HH:MM:SS]`).
        #[arg(long)]
        before: Option<String>,
        /// With --archive: delete the archived rows from the DB (a chain
        /// anchor is recorded so `--verify` still works on what remains).
        #[arg(long)]
        prune: bool,
        /// Verify a named archive file's hash chain end to end.
        #[arg(long, value_name = "FILE")]
        verify_archive: Option<String>,
        /// List archive files on the server's data volume.
        #[arg(long)]
        list_archives: bool,
    },
    /// Purge tombstoned secrets (whose `max_reads` was hit and whose crypto
    /// material has already been scrubbed) in the current domain. Secrets
    /// stored with `--preserve-on-cleanup` are kept. Admin only.
    Cleanup,
}

#[derive(Subcommand)]
enum TunnelCmd {
    /// Listener side: offer a tunnel to PEER, bind a local port, and forward
    /// each connection to the peer, who relays it to TARGET. ssh -L style.
    /// e.g. `tunnel forward bob --listen 127.0.0.1:5432 --to 10.0.0.5:5432`
    Forward {
        /// Peer client name to tunnel to (must be online to `accept`).
        peer: String,
        /// Local address to bind (host:port).
        #[arg(short = 'l', long)] listen: String,
        /// Address the peer should dial for each connection (host:port).
        #[arg(short = 't', long = "to")] target: String,
        /// Forward UDP instead of TCP.
        #[arg(short = 'u', long)] udp: bool,
    },
    /// Target side: wait for a tunnel offer addressed to you and serve the
    /// peer's dial requests (connecting to whatever host:port they ask for).
    /// Run this on the machine that can reach the target service.
    Accept {
        /// Only accept an offer from this client name (else accept any offerer
        /// who targeted you).
        #[arg(short = 'f', long)] from: Option<String>,
        /// Seconds to wait for an offer before giving up (default 300).
        #[arg(long, default_value_t = 300)] wait_timeout: u64,
    },
    /// List tunnels you offered or are the target of.
    Ls,
}

#[derive(Subcommand)]
enum FileCmd {
    /// Upload a local file. Name defaults to its basename. Read-only by
    /// default: re-uploading an existing name needs --overwrite. Supports the
    /// same policy flags + K-of-N threshold as `put`.
    Put {
        path: PathBuf,
        #[arg(short = 'n', long)]
        name: Option<String>,
        #[arg(short = 't', long)]
        mime: Option<String>,
        /// Require MFA (TOTP) on every future download of this file.
        #[arg(short = 'M', long)] mfa_required: bool,
        /// Delete this file immediately after the first successful download.
        #[arg(short = 'd', long)] delete_on_read: bool,
        /// Maximum number of downloads before the file refuses to authorize.
        #[arg(short = 'R', long)] max_reads: Option<i64>,
        /// Re-key the per-file DEK after every successful download.
        #[arg(short = 'r', long)] rotate_on_read: bool,
        /// Threshold K for K-of-N approvals. Requires --signatories.
        #[arg(short = 'q', long)] quorum: Option<i32>,
        /// Comma-separated list of client names allowed to approve.
        #[arg(short = 's', long, value_delimiter = ',')] signatories: Vec<String>,
        /// Replace an existing file of the same name. Requires update permission.
        #[arg(short = 'o', long)] overwrite: bool,
        /// Keep the forensic record even after tombstoning by `cleanup`.
        #[arg(short = 'p', long)] preserve_on_cleanup: bool,
        /// Make this file immutable: never overwritable, even with --overwrite.
        #[arg(short = 'i', long)] no_overwrite: bool,
        /// Managed-key client-side encryption (CMK), data stored in blackbook:
        /// the server keeps only an opaque envelope it can never decrypt.
        #[arg(short = 'e', long = "external-key")] external_key: bool,
        /// User-supplied passphrase (Argon2id) instead of the managed key.
        /// Never sent to the server; prefer $BLACKBOOK_EXTERNAL_PASSPHRASE.
        #[arg(long)] external_passphrase: Option<String>,
        /// Data residency: keep the encrypted file on *this machine* (under
        /// ~/.bbk), uploading only a manifest + the server's half of the split
        /// file key. Reading needs both this client AND the server. Combine
        /// with --external-passphrase for a user key; default key is managed.
        #[arg(short = 'E', long = "external-data", visible_alias = "resident")] external_data: bool,
        /// Shorthand for managed key + data residency
        /// (= --external-key --external-data).
        #[arg(long)] external: bool,
        /// With --external-data, also keep an encrypted backup copy server-side
        /// (still unreadable by the server).
        #[arg(short = 'c', long)] server_copy: bool,
        /// With --external-data, delete the original plaintext file after stashing.
        #[arg(long)] shred: bool,
        /// Opt into passphrase-mode client-side encryption, sourcing the
        /// passphrase from $BLACKBOOK_EXTERNAL_PASSPHRASE instead of an argv
        /// value. Equivalent to `--external-passphrase <value>`. Used by the
        /// web console.
        #[arg(long, hide = true)] external_passphrase_env: bool,
    },
    /// Download a file. Output defaults to ./<name> (or `-` for stdout).
    Get {
        name: String,
        path: Option<PathBuf>,
        /// Approved K-of-N request id (for threshold-gated files).
        #[arg(short = 'r', long)] request_id: Option<String>,
        /// Block and poll until the K-of-N request is approved (or timeout).
        #[arg(short = 'w', long)] wait: bool,
        /// Max seconds to wait with --wait (default 300).
        #[arg(long, default_value_t = 300)] wait_timeout: u64,
        /// Passphrase to decrypt a client-side ("external")/resident file.
        /// Falls back to $BLACKBOOK_EXTERNAL_PASSPHRASE.
        #[arg(long)] external_passphrase: Option<String>,
    },
    /// List files visible to the current client.
    Ls {
        /// Output as JSON (used by the web console's structured API).
        #[arg(long)] json: bool,
    },
    /// Delete a file.
    Rm { name: String, #[arg(short = 'y', long)] yes: bool },
    /// Re-encrypt a file under a new per-file DEK.
    Rotate { name: String },
    /// Change the client-side key on an external/resident file. Decrypts with
    /// the current key and re-wraps under a new one. For an external-key file
    /// the re-sealed envelope is re-uploaded; for a resident file only the
    /// local stash's wrapped client-half is rewritten (no re-upload — the
    /// ciphertext and the server's key-half are untouched).
    Rekey {
        name: String,
        /// Current passphrase, if the file is passphrase-sealed (else env/prompt).
        #[arg(long)] old_external_passphrase: Option<String>,
        /// Re-wrap under the profile's managed key (CMK).
        #[arg(short = 'e', long = "external-key")] external_key: bool,
        /// Re-wrap under this new user passphrase (Argon2id).
        #[arg(long)] external_passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Provision a new client. Prints the bundle JSON (cert + key + token).
    Create {
        name: String,
        #[arg(short = 'r', long, default_value = "user")]
        role: String,
        #[arg(short = 't', long)]
        ttl_days: Option<i64>,
        /// Save the bundle to PATH instead of printing it.
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
    /// Issue a fresh token + cert for an existing client.
    Rotate {
        name: String,
        #[arg(short = 't', long)]
        ttl_days: Option<i64>,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
    /// List provisioned clients.
    Ls,
    /// Revoke a client (its token/cert stop working immediately).
    Revoke {
        name: String,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)] yes: bool,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Grant a rule. SUBJECT is a client name; use `@DOMAIN` to grant to a
    /// group (all members of that domain).
    Grant {
        subject: String,
        pattern: String,
        #[arg(short = 'c', long)] create: bool,
        #[arg(short = 'r', long)] read: bool,
        #[arg(short = 'u', long)] update: bool,
        #[arg(short = 'd', long)] delete: bool,
        /// RFC3339 timestamp after which the grant stops authorizing.
        #[arg(short = 'e', long)] expires_at: Option<String>,
        /// RFC3339 timestamp before which the grant doesn't yet authorize.
        #[arg(short = 'b', long)] not_before: Option<String>,
        /// Cap on use count (use `--max-uses 1` for one-shot grants).
        #[arg(short = 'x', long)] max_uses: Option<i32>,
        /// Rate limit as `N/PERIOD`, e.g. `10/1h`, `5/30m`, `100/1d`, `2/90s`.
        /// At most N authorizations per window (fixed window).
        #[arg(long)] rate: Option<String>,
        /// Cron-style allowed-access window (5 fields, mask semantics), e.g.
        /// "* 9-17 * * 1-5" = weekdays 9am–6pm. Access outside it is denied.
        #[arg(long)] schedule: Option<String>,
    },
    Ls,
    Revoke { id: String },
}

#[derive(Subcommand)]
enum MfaCmd {
    /// Enroll: server generates a TOTP secret, prints the provisioning URI.
    /// Add the URI to your authenticator app, then run `mfa verify CODE`.
    Enroll,
    /// Verify a 6-digit code against the enrolled secret.
    Verify { code: String },
}

#[derive(Subcommand)]
enum DomainCmd {
    /// Create a new domain.
    Create {
        name: String,
        #[arg(short = 'd', long)] description: Option<String>,
    },
    /// List domains visible to you.
    Ls,
    /// Set this profile's default domain, so you don't need -D every command.
    /// Use `--clear` to go back to `default`. With no name, prints the current
    /// preference.
    Use {
        /// Domain to make the default for the active profile.
        name: Option<String>,
        /// Clear the saved preference (revert to `default`).
        #[arg(long)] clear: bool,
    },
    /// Show the members of a domain.
    Members { domain: String },
    /// Add a client as a member.
    AddMember {
        domain: String,
        client: String,
        #[arg(short = 'r', long, default_value = "user")] role: String,
    },
    /// Remove a client's membership.
    RmMember { domain: String, client: String },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// List saved profiles; the active one is marked with `*`.
    Ls,
    /// Set the active profile (persisted for future commands).
    Use { name: String },
    /// Show a profile's server + identity (defaults to the active profile).
    Show { name: Option<String> },
    /// Delete a saved profile.
    Rm {
        name: String,
        #[arg(short = 'y', long)] yes: bool,
    },
}

#[derive(Subcommand)]
enum GrantsCmd {
    /// Pre-approve a reader for resources matching PATTERN. You become a
    /// standing approver for GRANTEE's reads of K-of-N resources where you're
    /// a signatory — up to --max-uses times, until the grant expires. The
    /// domain comes from the global -D/--domain (default `default`).
    Add {
        /// Client name being pre-authorized.
        grantee: String,
        /// Resource pattern (`*` any, `_` one char), e.g. `monthly-report-*`.
        pattern: String,
        /// Whether the grant covers secrets or files.
        #[arg(short = 'k', long, default_value = "secret")] kind: String,
        /// Cap the number of reads this grant authorizes (default: unlimited
        /// within the TTL).
        #[arg(short = 'x', long)] max_uses: Option<i32>,
        /// Time limit in hours from now (required unless --expires-at given).
        #[arg(short = 'H', long)] ttl_hours: Option<i64>,
        /// Explicit RFC3339 expiry (overrides --ttl-hours).
        #[arg(short = 'e', long)] expires_at: Option<String>,
        /// RFC3339 time before which the grant doesn't yet authorize.
        #[arg(short = 'b', long)] not_before: Option<String>,
    },
    /// List advance grants you created or benefit from.
    Ls,
    /// Revoke an advance grant by id.
    Rm {
        id: String,
        #[arg(short = 'y', long)] yes: bool,
    },
}

// ---------------------------------------------------------------------------
// Database wrapper
// ---------------------------------------------------------------------------

struct Database { pool: Pool<Postgres> }

impl Database {
    async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;
        Ok(Database { pool })
    }

    async fn initialize(&self) -> Result<()> {
        // ------------------------------------------------------------------
        // Schema is encrypted-from-day-1: every user-supplied identifier
        // lives only as AEAD ciphertext (`_enc BYTEA`) or as a deterministic
        // HMAC (`_id CHAR(64)`). The plaintext name/resource/pattern/message
        // columns do not exist. A DB-only attacker without the master key
        // sees nothing but opaque ids, ciphertext, timestamps, and the
        // low-entropy action/status enums.
        //
        // The migrations ledger is kept for future numbered migrations via
        // `migrate_once(version, name, sql)`; on a fresh DB it stays empty.
        // ------------------------------------------------------------------
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_schema_migrations (
                version    INTEGER PRIMARY KEY,
                name       VARCHAR(128) NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                notes      TEXT
            )"#,
        ).execute(&self.pool).await?;

        // Domains: both a namespace partition and an ACL group. The friendly
        // name is `name_enc` (AEAD), looked up via `name_id` (HMAC).
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_domains (
                id              TEXT PRIMARY KEY,
                name_enc        BYTEA NOT NULL,
                name_id         CHAR(64) NOT NULL UNIQUE,
                description_enc BYTEA,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                archived_at     TIMESTAMP
            )"#,
        ).execute(&self.pool).await?;

        // Clients: encrypted name + HMAC lookup id. Token hash, cert
        // fingerprint, and TOTP-secret ciphertext stay as they were.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_clients (
                id               TEXT PRIMARY KEY,
                name_enc         BYTEA NOT NULL,
                name_id          CHAR(64) NOT NULL UNIQUE,
                token_hash       CHAR(64) NOT NULL UNIQUE,
                role             VARCHAR(16) NOT NULL CHECK (role IN ('admin','user')),
                created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at       TIMESTAMP,
                expires_at       TIMESTAMP,
                cert_fingerprint CHAR(64),
                totp_secret_enc  BYTEA,
                totp_enrolled    BOOLEAN NOT NULL DEFAULT FALSE
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_clients_token_hash ON blackbook_clients(token_hash) WHERE revoked_at IS NULL")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_clients_cert_fp ON blackbook_clients(cert_fingerprint) WHERE revoked_at IS NULL")
            .execute(&self.pool).await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_domain_members (
                domain_id TEXT NOT NULL REFERENCES blackbook_domains(id) ON DELETE CASCADE,
                client_id TEXT NOT NULL REFERENCES blackbook_clients(id) ON DELETE CASCADE,
                role      VARCHAR(16) NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user','guest')),
                added_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (domain_id, client_id)
            )"#,
        ).execute(&self.pool).await?;

        // Secrets: server-side two-layer AES-GCM ciphertext for normal values,
        // OR a client-supplied opaque `external_envelope` when `is_external`
        // (the server cannot decrypt those — see client-side external storage).
        // Encrypted resource_name + HMAC name_id for lookup. Tombstone
        // (`exhausted_at`) marks rows whose crypto material was scrubbed.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_secrets (
                resource_id       TEXT PRIMARY KEY,
                resource_name_enc BYTEA NOT NULL,
                name_id           CHAR(64) NOT NULL,
                domain_id         TEXT NOT NULL REFERENCES blackbook_domains(id),
                data_layer1       BYTEA NOT NULL,
                data_layer2       BYTEA NOT NULL,
                wrapped_key       TEXT NOT NULL,
                is_external       BOOLEAN NOT NULL DEFAULT FALSE,
                external_envelope BYTEA,
                flags             JSONB NOT NULL DEFAULT '{}'::jsonb,
                read_count        BIGINT NOT NULL DEFAULT 0,
                access_policy     JSONB,
                exhausted_at      TIMESTAMP,
                created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                deleted_at        TIMESTAMP,
                encryption_method VARCHAR(100),
                UNIQUE (domain_id, name_id)
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_secrets_name_id ON blackbook_secrets(domain_id, name_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_secrets_exhausted ON blackbook_secrets(exhausted_at) WHERE exhausted_at IS NOT NULL")
            .execute(&self.pool).await?;

        // ACL: encrypted resource_pattern (matched in-memory after decrypt).
        // Either client_id or group_domain_id is set, not both.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_acl (
                id               TEXT PRIMARY KEY,
                domain_id        TEXT NOT NULL REFERENCES blackbook_domains(id),
                client_id        TEXT REFERENCES blackbook_clients(id) ON DELETE CASCADE,
                group_domain_id  TEXT REFERENCES blackbook_domains(id),
                pattern_enc      BYTEA NOT NULL,
                actions          INTEGER NOT NULL,
                expires_at       TIMESTAMP,
                not_before       TIMESTAMP,
                max_uses         INTEGER,
                use_count        INTEGER NOT NULL DEFAULT 0,
                granted_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                granted_by       TEXT REFERENCES blackbook_clients(id),
                -- Per-rule rate limit ("rate_max accesses per rate_period_secs")
                -- and a fixed-window counter. NULL period = no rate limit.
                rate_max         INTEGER,
                rate_period_secs INTEGER,
                rate_count       INTEGER NOT NULL DEFAULT 0,
                rate_window_start TIMESTAMP,
                -- Cron-style allowed-access window (5 fields). NULL = always.
                schedule         TEXT
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_acl_client_id ON blackbook_acl(client_id)")
            .execute(&self.pool).await?;

        // Audit log: encrypted resource + message; hash chain (prev_hash,
        // row_hash) binds every row to the previous one over PLAINTEXT
        // content, so tampering with either ciphertext or the chain itself
        // is detectable by `audit --verify`.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_audit (
                id           BIGSERIAL PRIMARY KEY,
                ts           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                client_id    TEXT,
                action       VARCHAR(32) NOT NULL,
                status       VARCHAR(16) NOT NULL,
                resource_enc BYTEA,
                message_enc  BYTEA,
                prev_hash    CHAR(64),
                row_hash     CHAR(64) NOT NULL
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_audit_ts ON blackbook_audit(ts DESC)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_audit_id ON blackbook_audit(id)")
            .execute(&self.pool).await?;
        // Chain anchors: when old audit rows are archived-and-pruned, the
        // `row_hash` of the last pruned row is recorded here so live-chain
        // verification resumes from it instead of genesis (otherwise the first
        // surviving row's prev_hash would look "broken"). The latest anchor
        // (highest archived_through_id) is the current chain start.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_audit_anchors (
                id                  BIGSERIAL PRIMARY KEY,
                archived_through_id BIGINT NOT NULL,
                final_row_hash      CHAR(64) NOT NULL,
                archive_file        TEXT NOT NULL,
                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"#,
        ).execute(&self.pool).await?;

        // File blobs: encrypted on disk under per-file DEK. The row's
        // friendly name/MIME/size are AEAD ciphertext; the integrity hash is
        // stored as an HMAC so a DB-only attacker can't precompute
        // "do you have file with SHA3 X?".
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_contents (
                id              TEXT PRIMARY KEY,
                storage_path    TEXT NOT NULL UNIQUE,
                ciphertext_size BIGINT NOT NULL,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_pages (
                id                 TEXT PRIMARY KEY,
                name_enc           BYTEA NOT NULL,
                name_id            CHAR(64) NOT NULL,
                domain_id          TEXT NOT NULL REFERENCES blackbook_domains(id),
                owner_id           TEXT NOT NULL REFERENCES blackbook_clients(id),
                content_id         TEXT NOT NULL REFERENCES blackbook_contents(id) ON DELETE CASCADE,
                wrapped_dek        BYTEA NOT NULL,
                plaintext_hash_id  CHAR(64) NOT NULL,
                plaintext_size_enc BYTEA NOT NULL,
                mime_type_enc      BYTEA,
                is_external        BOOLEAN NOT NULL DEFAULT FALSE,
                external_meta      BYTEA,
                -- Phase 4 "client-resident" external files: the ciphertext
                -- lives on the client's disk; blackbook holds only this
                -- manifest. external_kind: 0=normal/none, 1=external-key
                -- (server holds the client-encrypted blob), 2=resident
                -- (client holds the blob; server holds the key component).
                -- server_key_component is a random value the client MUST fetch
                -- (gated) to reconstruct the file key — it is itself wrapped
                -- under the server's file_dek_kek at rest. has_server_copy
                -- records whether the blob row also holds a backup ciphertext.
                external_kind      SMALLINT NOT NULL DEFAULT 0,
                server_key_component BYTEA,
                has_server_copy    BOOLEAN NOT NULL DEFAULT FALSE,
                flags              JSONB NOT NULL DEFAULT '{}'::jsonb,
                read_count         BIGINT NOT NULL DEFAULT 0,
                access_policy      JSONB,
                exhausted_at       TIMESTAMP,
                created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (domain_id, name_id)
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_pages_owner ON blackbook_pages(owner_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_pages_name_id ON blackbook_pages(domain_id, name_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_blackbook_pages_exhausted ON blackbook_pages(exhausted_at) WHERE exhausted_at IS NOT NULL")
            .execute(&self.pool).await?;

        // K-of-N approval workflow. `signatory_ids` is opaque (client ids),
        // resource_name is AEAD ciphertext, and `resource_name_id` is the
        // deterministic HMAC of (domain, name) — the same value the resource
        // itself uses — so we can dedup open requests per (requester, resource)
        // without exposing the plaintext name in a query.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_access_requests (
                id                TEXT PRIMARY KEY,
                requester_id      TEXT NOT NULL REFERENCES blackbook_clients(id),
                resource_kind     VARCHAR(16) NOT NULL CHECK (resource_kind IN ('secret','file')),
                domain_id         TEXT REFERENCES blackbook_domains(id),
                resource_name_enc BYTEA NOT NULL,
                resource_name_id  CHAR(64) NOT NULL,
                threshold_k       INTEGER NOT NULL,
                signatory_ids     JSONB NOT NULL,
                approvers         JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at        TIMESTAMP NOT NULL,
                consumed_at       TIMESTAMP
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON blackbook_access_requests(requester_id)")
            .execute(&self.pool).await?;
        // Fast lookup for the "is there already an open request for this
        // (requester, kind, domain, resource)?" dedup check.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_access_requests_dedup ON blackbook_access_requests(requester_id, resource_kind, domain_id, resource_name_id) WHERE consumed_at IS NULL")
            .execute(&self.pool).await?;

        // Advance approval grants: a signatory pre-authorizes a reader for a
        // pattern, scoped like an ACL rule (domain + grantee + pattern, with a
        // mandatory expiry and optional use cap). At read time, a grant counts
        // toward a resource's K-of-N threshold iff its signatory is one of the
        // resource's signatories — so a reader with K distinct matching grants
        // can read without waiting for a live per-request approval.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS blackbook_access_grants (
                id              TEXT PRIMARY KEY,
                signatory_id    TEXT NOT NULL REFERENCES blackbook_clients(id) ON DELETE CASCADE,
                grantee_id      TEXT NOT NULL REFERENCES blackbook_clients(id) ON DELETE CASCADE,
                domain_id       TEXT NOT NULL REFERENCES blackbook_domains(id),
                resource_kind   VARCHAR(16) NOT NULL CHECK (resource_kind IN ('secret','file')),
                pattern_enc     BYTEA NOT NULL,
                max_uses        INTEGER,
                use_count       INTEGER NOT NULL DEFAULT 0,
                not_before      TIMESTAMP,
                expires_at      TIMESTAMP NOT NULL,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at      TIMESTAMP
            )"#,
        ).execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_access_grants_lookup ON blackbook_access_grants(grantee_id, domain_id, resource_kind) WHERE revoked_at IS NULL")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_access_grants_signatory ON blackbook_access_grants(signatory_id) WHERE revoked_at IS NULL")
            .execute(&self.pool).await?;

        log::info!("Database schema initialized successfully");
        Ok(())
    }

    /// Run `sql` exactly once and record it in `blackbook_schema_migrations`.
    /// Idempotent across restarts: if `version` is already recorded, the SQL
    /// is skipped. The migration row is inserted only after `sql` succeeds,
    /// so a failed migration can be retried on the next boot. No callers
    /// today — the schema is encrypted-from-day-1 and needs no migrations —
    /// but kept for future numbered migrations.
    #[allow(dead_code)]
    async fn migrate_once(&self, version: i32, name: &str, sql: &str) -> Result<()> {
        let already: Option<(i32,)> = sqlx::query_as(
            "SELECT version FROM blackbook_schema_migrations WHERE version = $1",
        )
        .bind(version)
        .fetch_optional(&self.pool).await?;
        if already.is_some() { return Ok(()); }
        // Allow multi-statement SQL by splitting on the trailing `;` per stmt.
        // We don't have to be clever — these are server-authored strings.
        for stmt in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(stmt).execute(&self.pool).await?;
        }
        sqlx::query(
            "INSERT INTO blackbook_schema_migrations (version, name) VALUES ($1, $2)",
        )
        .bind(version).bind(name)
        .execute(&self.pool).await?;
        log::info!("applied schema migration {version}: {name}");
        Ok(())
    }

    async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

fn read_stdin_line() -> String {
    use std::io::{BufRead, Write};
    let stdout = std::io::stdout();
    let _ = stdout.lock().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim().to_string()
}

// ---------------------------------------------------------------------------
// Client-side ("external") encryption.
//
// The server only ever stores an opaque envelope. Decryption needs the client
// key factor (never sent) AND the server-held envelope (only released after
// the normal ACL/K-of-N/MFA gates), so neither side can recover the plaintext
// alone.
//   K            = random 256-bit data key (per item)
//   ct           = AES-256-GCM(K, plaintext)
//   wrapped_dek  = AES-256-GCM(kek, K)
//
// The *key factor* depends on the envelope mode:
//   - mode 0 (CMK, the default): kek = the profile's rotation-stable Client
//     Master Key. No passphrase required; the CMK lives only inside the
//     passphrase-encrypted profile (Phase 2), so the user's profile passphrase
//     transitively protects external data too. Rotating the auth token/cert
//     does not change the CMK, so external data survives credential rotation.
//   - mode 1 (passphrase): kek = Argon2id(passphrase, salt). Used when the
//     user explicitly supplies a passphrase — stronger than the old v1 scrypt
//     and decoupled from the local profile (portable across machines).
//   - v1 (legacy 0x01): kek = scrypt(passphrase, salt). Still decodable.
//
// For secrets the whole envelope is stored. For files, ct is the on-disk blob
// and only the envelope header { mode, salt, wrapped_dek } ("meta") is stored.
// ---------------------------------------------------------------------------

const EXT_ENVELOPE_V1: u8 = 1; // legacy: scrypt(passphrase)
const EXT_ENVELOPE_V2: u8 = 2; // mode-tagged: CMK or Argon2id(passphrase)

const EXT_MODE_CMK: u8 = 0;
const EXT_MODE_ARGON2: u8 = 1;

/// How an external item should be sealed, decided at the call site.
enum ExtKey {
    /// Default: wrap under the profile's Client Master Key (no passphrase).
    Cmk([u8; 32]),
    /// Explicit passphrase: wrap under Argon2id(passphrase, salt).
    Passphrase(String),
}

/// Resolve the *optional* explicit passphrase for external storage:
/// explicit flag → $BLACKBOOK_EXTERNAL_PASSPHRASE → None. Unlike Phase 2, a
/// passphrase is no longer required — absent one we fall back to the CMK.
fn resolve_external_passphrase_opt(explicit: Option<String>) -> Option<String> {
    if let Some(p) = explicit { if !p.is_empty() { return Some(p); } }
    if let Ok(p) = std::env::var("BLACKBOOK_EXTERNAL_PASSPHRASE") {
        if !p.is_empty() { return Some(p); }
    }
    None
}

/// Resolve the passphrase needed to *read* a passphrase-sealed external item.
/// Resolution order: `--external-passphrase` → `$BLACKBOOK_EXTERNAL_PASSPHRASE`
/// → interactive no-echo prompt. The prompt is what makes the password
/// "requested on every access": a read with neither flag nor env var set asks
/// for it rather than failing. The passphrase is never cached — each read
/// re-derives the key — so it is genuinely requested each time when no
/// ambient source is configured. Errors only when there is no TTY to prompt on
/// (e.g. piped automation) and no flag/env was supplied.
fn resolve_external_passphrase_for_read(explicit: Option<String>) -> Result<String> {
    if let Some(p) = resolve_external_passphrase_opt(explicit) {
        return Ok(p);
    }
    // No interactive prompt when prompts are suppressed (e.g. the web console),
    // since the child can't read a terminal and would hang. Return a clear,
    // recognizable error instead.
    if credstore::prompts_suppressed() {
        return Err(AppError::Config(
            "external passphrase required — pass --external-passphrase or set \
             $BLACKBOOK_EXTERNAL_PASSPHRASE".into()));
    }
    let p = rpassword::prompt_password("Passphrase for this external item: ")
        .map_err(|_| AppError::Config(
            "this item is passphrase-sealed and no passphrase was provided — \
             pass --external-passphrase, set $BLACKBOOK_EXTERNAL_PASSPHRASE, \
             or run interactively so it can be requested".into()))?;
    if p.is_empty() {
        return Err(AppError::Config("empty passphrase".into()));
    }
    Ok(p)
}

// ---------------------------------------------------------------------------
// Client-side storage spec — two orthogonal axes
//
// Client-side ("external") storage is the product of two independent choices:
//
//   KEY SOURCE  — where the wrapping key comes from:
//       managed     (--external-key)        : the profile's CMK (Phase 3)
//       passphrase  (--external-passphrase) : user-supplied, Argon2id
//
//   DATA LOCATION — where the ciphertext lives:
//       in-server   (default)               : the opaque envelope is stored in
//                                             blackbook (external-key model)
//       resident    (--external-data)       : the ciphertext lives on this
//                                             client; the server keeps only a
//                                             manifest + its key-component half
//
//   --external  ==  --external-key + --external-data  (managed key, resident).
//
// Data residency is a *files-only* capability today (a secret has no on-disk
// home), so `--external-data` on a secret is rejected with a clear message.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum KeySource { Managed, Passphrase }

#[derive(Clone, Copy, PartialEq)]
enum DataLoc { InServer, Resident }

/// A fully-resolved client-side storage decision. `None` from the resolver
/// means "no client-side encryption — store normally".
struct ExtSpec { key: KeySource, data: DataLoc }

/// Raw client-side flags as they arrive from clap, before validation. The
/// resolver turns these into an `Option<ExtSpec>` (None = normal storage).
struct ExtFlags {
    /// `--external` — implies external-key AND external-data.
    external: bool,
    /// `--external-key` / `-e` — managed-key client-side encryption.
    external_key: bool,
    /// `--external-data` (alias `--resident`/`-E` for files) — resident data.
    external_data: bool,
    /// `--external-passphrase` — user-supplied key (value or None).
    passphrase: Option<String>,
    /// `--external-passphrase-env` — opt into passphrase-mode client-side
    /// encryption while taking the passphrase value from
    /// `$BLACKBOOK_EXTERNAL_PASSPHRASE` rather than an argv flag. Lets the web
    /// console create passphrase-sealed items without the secret ever touching
    /// the process command line. Still an *explicit* opt-in, so a normal `put`
    /// with the env var set stays a normal secret (no silent encryption).
    passphrase_from_env: bool,
}

/// Resolve the four client-side flags into a storage decision.
/// `data_allowed` is false for secrets (no on-disk residency).
///
/// Selection rules:
///   - Client-side encryption is opted into by an explicit `--external*` flag
///     or an explicit `--external-passphrase` value. The *env var* alone is
///     only a value source — a normal `put` with `$BLACKBOOK_EXTERNAL_PASSPHRASE`
///     set stays a normal secret (no silent client-side encryption).
///   - `--external-key` / `--external` choose the managed (CMK) key; an explicit
///     `--external-passphrase` chooses a user key. Combining the two is an error.
///   - `--external-data` requests resident data (files only); `--external` on a
///     file is the shorthand for managed-key + resident. On a secret, `--external`
///     degrades to external-key (no on-disk home), while an explicit
///     `--external-data` is rejected.
fn resolve_ext_spec(f: &ExtFlags, data_allowed: bool) -> Result<Option<ExtSpec>> {
    let managed_signal = f.external_key || f.external;
    let pass_flag = f.passphrase.as_deref().map_or(false, |s| !s.is_empty());
    // Explicit passphrase opt-in, whether the value arrives via the flag or via
    // the env-sourced `--external-passphrase-env` marker.
    let pass_signal = pass_flag || f.passphrase_from_env;

    if managed_signal && pass_signal {
        return Err(AppError::Config(
            "--external-key/--external select the managed key (CMK), but --external-passphrase \
             selects a user-supplied key — choose one. For resident data with a passphrase, \
             use --external-data --external-passphrase.".into()));
    }

    let wants_external = managed_signal || f.external_data || pass_signal;
    if !wants_external { return Ok(None); }

    // Explicit data-residency on a secret is rejected (no on-disk home).
    if f.external_data && !data_allowed {
        return Err(AppError::Config(
            "--external-data is not available for secrets — a secret has no on-disk home, so \
             its data always lives in blackbook. Use --external-key (managed key) or \
             --external-passphrase (user key) to encrypt it client-side.".into()));
    }

    // Key source: an explicit managed signal forces managed (ignoring any
    // ambient env var). An explicit passphrase opt-in (flag value OR the
    // `--external-passphrase-env` marker) forces the user key — the value is
    // sourced later in `ext_key_for_spec`, which errors clearly if neither flag
    // nor env supplied one. Otherwise the managed key.
    let key = if managed_signal {
        KeySource::Managed
    } else if pass_signal || resolve_external_passphrase_opt(f.passphrase.clone()).is_some() {
        KeySource::Passphrase
    } else {
        KeySource::Managed
    };

    // Data location: resident when --external-data, or --external on a target
    // that supports it (files). --external on a secret degrades to in-server.
    let data = if f.external_data || (f.external && data_allowed) {
        DataLoc::Resident
    } else {
        DataLoc::InServer
    };

    Ok(Some(ExtSpec { key, data }))
}

/// Build the seal key for an `ExtSpec`, sourcing the passphrase if needed.
fn ext_key_for_spec(spec: &ExtSpec, session: &client::Session, explicit: Option<String>) -> Result<ExtKey> {
    match spec.key {
        KeySource::Passphrase => {
            let p = resolve_external_passphrase_for_read(explicit)?;
            Ok(ExtKey::Passphrase(p))
        }
        KeySource::Managed => session.cmk_bytes().map(ExtKey::Cmk).ok_or_else(|| AppError::Config(
            "no managed key (CMK) for --external-key: this profile predates client master \
             keys. Re-run `blackbook login` to mint one, or use --external-passphrase.".into())),
    }
}

/// Seal `plaintext`, returning `(meta_header, ciphertext)`. `meta_header` is
/// the v2 envelope encoded with an *empty* ciphertext field; because ct is the
/// trailing field, `meta_header ++ ciphertext` is the full envelope. Secrets
/// store the concatenation; files store `meta_header` in the row and
/// `ciphertext` as the on-disk blob.
fn external_seal_parts(key: &ExtKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::RngCore;
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(dek.as_mut_slice());

    let (mode, salt, m, t, p, kek): (u8, Vec<u8>, u32, u32, u32, Zeroizing<[u8; 32]>) = match key {
        ExtKey::Cmk(cmk) => (EXT_MODE_CMK, Vec::new(), 0, 0, 0, Zeroizing::new(*cmk)),
        ExtKey::Passphrase(pass) => {
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let (k, m, t, p) = credstore::argon2_key(pass, &salt)?;
            (EXT_MODE_ARGON2, salt.to_vec(), m, t, p, k)
        }
    };
    let wrapped_dek = blackbook_core::aead_seal(dek.as_slice(), kek.as_slice())
        .map_err(|e| AppError::Crypto(format!("wrap dek: {e}")))?;
    let ciphertext = blackbook_core::aead_seal(plaintext, dek.as_slice())
        .map_err(|e| AppError::Crypto(format!("seal: {e}")))?;
    let meta = ext_encode_v2(mode, &salt, m, t, p, &wrapped_dek, &[]);
    Ok((meta, ciphertext))
}

/// Seal `plaintext` into a single full envelope (secrets path).
fn external_seal(key: &ExtKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (mut meta, mut ct) = external_seal_parts(key, plaintext)?;
    meta.append(&mut ct);
    Ok(meta)
}

/// `0x02 | mode | m(4) t(4) p(4) | salt_len(1) | salt | wdek_len(4) | wdek | ct`.
/// The Argon2 cost triple is present for all modes (zero for CMK) to keep the
/// layout fixed-position and easy to parse.
fn ext_encode_v2(mode: u8, salt: &[u8], m: u32, t: u32, p: u32, wrapped_dek: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 12 + 1 + salt.len() + 4 + wrapped_dek.len() + ciphertext.len());
    out.push(EXT_ENVELOPE_V2);
    out.push(mode);
    out.extend_from_slice(&m.to_be_bytes());
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&p.to_be_bytes());
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.extend_from_slice(&(wrapped_dek.len() as u32).to_be_bytes());
    out.extend_from_slice(wrapped_dek);
    out.extend_from_slice(ciphertext);
    out
}

/// Parsed external envelope, version-agnostic.
struct ExtEnvelope {
    version: u8,
    mode: u8,
    salt: Vec<u8>,
    argon: (u32, u32, u32),
    wrapped_dek: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Decode a v1 or v2 external envelope.
fn ext_decode(buf: &[u8]) -> Result<ExtEnvelope> {
    let bad = || AppError::Crypto("malformed external envelope".into());
    if buf.is_empty() { return Err(bad()); }
    match buf[0] {
        EXT_ENVELOPE_V1 => {
            if buf.len() < 2 { return Err(bad()); }
            let slen = buf[1] as usize;
            let mut p = 2;
            if buf.len() < p + slen + 4 { return Err(bad()); }
            let salt = buf[p..p + slen].to_vec(); p += slen;
            let wlen = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()) as usize; p += 4;
            if buf.len() < p + wlen { return Err(bad()); }
            let wrapped_dek = buf[p..p + wlen].to_vec(); p += wlen;
            Ok(ExtEnvelope { version: 1, mode: EXT_MODE_ARGON2, salt, argon: (0, 0, 0),
                             wrapped_dek, ciphertext: buf[p..].to_vec() })
        }
        EXT_ENVELOPE_V2 => {
            if buf.len() < 2 + 12 + 1 { return Err(bad()); }
            let mode = buf[1];
            let mut p = 2;
            let m = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()); p += 4;
            let t = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()); p += 4;
            let pc = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()); p += 4;
            let slen = buf[p] as usize; p += 1;
            if buf.len() < p + slen + 4 { return Err(bad()); }
            let salt = buf[p..p + slen].to_vec(); p += slen;
            let wlen = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()) as usize; p += 4;
            if buf.len() < p + wlen { return Err(bad()); }
            let wrapped_dek = buf[p..p + wlen].to_vec(); p += wlen;
            Ok(ExtEnvelope { version: 2, mode, salt, argon: (m, t, pc),
                             wrapped_dek, ciphertext: buf[p..].to_vec() })
        }
        _ => Err(bad()),
    }
}

/// Recover the wrapping KEK for an envelope, given the session (for the CMK)
/// and an optional passphrase (for passphrase/legacy modes).
fn external_kek(env: &ExtEnvelope, session: &client::Session, explicit_pass: Option<String>) -> Result<Zeroizing<[u8; 32]>> {
    match (env.version, env.mode) {
        (2, m) if m == EXT_MODE_CMK => {
            session.cmk_bytes().map(Zeroizing::new).ok_or_else(|| AppError::Crypto(
                "this external item is sealed under the profile's client master key, \
                 but the active profile has none (different identity?)".into()))
        }
        (2, _) => {
            // Passphrase-sealed: request the passphrase on this access (flag →
            // env → prompt). Never cached, so it's asked for each read.
            let pass = resolve_external_passphrase_for_read(explicit_pass)?;
            let (m, t, p) = env.argon;
            credstore::argon2_key_with(&pass, &env.salt, m, t, p)
                .map_err(|e| AppError::Crypto(format!("kdf: {e}")))
        }
        (_, _) => {
            // v1 legacy: scrypt(passphrase) — same per-access request.
            let pass = resolve_external_passphrase_for_read(explicit_pass)?;
            blackbook_core::scrypt_dek(pass.as_bytes(), &env.salt)
                .map_err(|e| AppError::Crypto(format!("kdf: {e}")))
        }
    }
}

/// Open an external envelope to plaintext, using the session + optional passphrase.
fn external_open(env: &ExtEnvelope, session: &client::Session, explicit_pass: Option<String>) -> Result<Vec<u8>> {
    let kek = external_kek(env, session, explicit_pass)?;
    let dek = Zeroizing::new(blackbook_core::aead_open(&env.wrapped_dek, kek.as_slice())
        .map_err(|_| AppError::Crypto("wrong key/passphrase or corrupt envelope (DEK unwrap failed)".into()))?);
    blackbook_core::aead_open(&env.ciphertext, &dek)
        .map_err(|_| AppError::Crypto("decryption failed (wrong key/passphrase or corrupt data)".into()))
}

// ---------------------------------------------------------------------------
// Resident files (Phase 4): the ciphertext lives on the *client's* disk; the
// server holds only a manifest + its half of the split file key.
//
//   Kf            = random 256-bit file key
//   ct            = AES-256-GCM(Kf, file)            → client stash
//   Kf_c          = random 256-bit client half
//   Kf_s          = Kf XOR Kf_c                      → sent to server (its half)
//   wrapped_c     = AES-256-GCM(client_kek, Kf_c)    → client stash header
//                   (client_kek = CMK or Argon2id(passphrase), as in v2)
// Neither side can rebuild Kf alone: the server never sees Kf_c; the client
// can't get Kf_s back without passing the server's auth/ACL/K-of-N/MFA gates.
// The stash file is: RESIDENT_MAGIC | header_len(4) | header_json | ct.
// ---------------------------------------------------------------------------

const RESIDENT_MAGIC: &[u8; 4] = b"BBKR";

#[derive(serde::Serialize, serde::Deserialize)]
struct ResidentHeader {
    /// Envelope mode for `wrapped_c`: 0 = CMK, 1 = Argon2id(passphrase).
    mode: u8,
    /// Argon2 salt (base64) when mode = 1.
    salt: String,
    m_cost: u32, t_cost: u32, p_cost: u32,
    /// `AES-256-GCM(client_kek, Kf_c)` (base64).
    wrapped_c: String,
    /// Original file name, for restore convenience.
    orig_name: String,
}

/// `~/.bbk/resident`.
fn resident_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| AppError::Config("no home directory".into()))?;
    Ok(home.join(".bbk").join("resident"))
}

/// Local index mapping `<domain>/<name>` → stash file id.
fn resident_index_path() -> Result<PathBuf> {
    Ok(resident_dir()?.join("index.json"))
}

fn resident_index_load() -> std::collections::BTreeMap<String, String> {
    resident_index_path().ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn resident_index_save(map: &std::collections::BTreeMap<String, String>) -> Result<()> {
    let dir = resident_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(resident_index_path()?, serde_json::to_vec_pretty(map)?)?;
    Ok(())
}

fn resident_key(domain: &str, name: &str) -> String { format!("{domain}/{name}") }

/// Seal a file for resident storage. Returns `(stash_bytes, key_component_b64,
/// mode_label)` where `key_component_b64` is the server half (`Kf_s`).
fn resident_seal(key: &ExtKey, plaintext: &[u8], orig_name: &str) -> Result<(Vec<u8>, String, &'static str)> {
    use rand::RngCore;
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut kf = [0u8; 32]; rand::thread_rng().fill_bytes(&mut kf);
    let mut kf_c = [0u8; 32]; rand::thread_rng().fill_bytes(&mut kf_c);
    let kf_s: Vec<u8> = kf.iter().zip(kf_c.iter()).map(|(a, b)| a ^ b).collect();

    let ct = blackbook_core::aead_seal(plaintext, &kf)
        .map_err(|e| AppError::Crypto(format!("seal: {e}")))?;

    let (mode, salt_b64, m, t, p, client_kek, label): (u8, String, u32, u32, u32, Zeroizing<[u8; 32]>, &'static str) = match key {
        ExtKey::Cmk(cmk) => (0, String::new(), 0, 0, 0, Zeroizing::new(*cmk), "CMK"),
        ExtKey::Passphrase(pass) => {
            let mut salt = [0u8; 16]; rand::thread_rng().fill_bytes(&mut salt);
            let (k, m, t, p) = credstore::argon2_key(pass, &salt)?;
            (1, b64.encode(salt), m, t, p, k, "passphrase")
        }
    };
    let wrapped_c = blackbook_core::aead_seal(kf_c.as_slice(), client_kek.as_slice())
        .map_err(|e| AppError::Crypto(format!("wrap client half: {e}")))?;

    let header = ResidentHeader {
        mode, salt: salt_b64, m_cost: m, t_cost: t, p_cost: p,
        wrapped_c: b64.encode(&wrapped_c), orig_name: orig_name.to_string(),
    };
    let hjson = serde_json::to_vec(&header)?;
    let mut stash = Vec::with_capacity(4 + 4 + hjson.len() + ct.len());
    stash.extend_from_slice(RESIDENT_MAGIC);
    stash.extend_from_slice(&(hjson.len() as u32).to_be_bytes());
    stash.extend_from_slice(&hjson);
    stash.extend_from_slice(&ct);
    Ok((stash, b64.encode(&kf_s), label))
}

/// The domain a client is scoped to, for keying the resident index.
fn domain_label(bb: &client::BlackbookClient) -> String { bb.domain().to_string() }

/// Extract just the ciphertext part of a stash (for the optional server copy).
fn resident_parts_from_stash(stash: &[u8]) -> Result<(ResidentHeader, Vec<u8>)> {
    resident_parse(stash)
}

/// Parse a resident stash file into (header, ciphertext).
fn resident_parse(stash: &[u8]) -> Result<(ResidentHeader, Vec<u8>)> {
    let bad = || AppError::Crypto("malformed resident stash file".into());
    if stash.len() < 8 || &stash[..4] != RESIDENT_MAGIC { return Err(bad()); }
    let hlen = u32::from_be_bytes(stash[4..8].try_into().unwrap()) as usize;
    if stash.len() < 8 + hlen { return Err(bad()); }
    let header: ResidentHeader = serde_json::from_slice(&stash[8..8 + hlen]).map_err(|_| bad())?;
    Ok((header, stash[8 + hlen..].to_vec()))
}

/// Open a resident stash given the server key-component half and the session
/// (for the CMK) / optional passphrase. Returns the file plaintext.
fn resident_open(
    header: &ResidentHeader, ciphertext: &[u8], kf_s_b64: &str,
    session: &client::Session, explicit_pass: Option<String>,
) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    // Recover the client half: unwrap Kf_c with CMK or Argon2id(passphrase).
    let client_kek: Zeroizing<[u8; 32]> = match header.mode {
        0 => session.cmk_bytes().map(Zeroizing::new).ok_or_else(|| AppError::Crypto(
            "resident file is sealed under the profile's client master key, but \
             the active profile has none".into()))?,
        _ => {
            // Passphrase-sealed resident file: request the passphrase on this
            // access (flag → env → prompt); never cached.
            let pass = resolve_external_passphrase_for_read(explicit_pass)?;
            let salt = b64.decode(&header.salt).map_err(|_| AppError::Crypto("bad salt".into()))?;
            credstore::argon2_key_with(&pass, &salt, header.m_cost, header.t_cost, header.p_cost)
                .map_err(|e| AppError::Crypto(format!("kdf: {e}")))?
        }
    };
    let wrapped_c = b64.decode(&header.wrapped_c).map_err(|_| AppError::Crypto("bad wrapped_c".into()))?;
    let kf_c = Zeroizing::new(blackbook_core::aead_open(&wrapped_c, client_kek.as_slice())
        .map_err(|_| AppError::Crypto("wrong key/passphrase (client half unwrap failed)".into()))?);
    let kf_s = Zeroizing::new(b64.decode(kf_s_b64).map_err(|_| AppError::Crypto("server key component not base64".into()))?);
    if kf_c.len() != 32 || kf_s.len() != 32 {
        return Err(AppError::Crypto("key halves must be 32 bytes".into()));
    }
    let kf: Zeroizing<Vec<u8>> = Zeroizing::new(kf_c.iter().zip(kf_s.iter()).map(|(a, b)| a ^ b).collect());
    blackbook_core::aead_open(ciphertext, &kf)
        .map_err(|_| AppError::Crypto("decryption failed (wrong key halves or corrupt data)".into()))
}

/// Unwrap just the client key-half (`Kf_c`) from a resident stash header using
/// its *current* key (CMK or passphrase). Used by `file rekey` — re-keying a
/// resident file only needs to rewrap this 32-byte half, not the ciphertext.
fn resident_unwrap_client_half(
    header: &ResidentHeader, session: &client::Session, explicit_pass: Option<String>,
) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let client_kek: Zeroizing<[u8; 32]> = match header.mode {
        0 => session.cmk_bytes().map(Zeroizing::new).ok_or_else(|| AppError::Crypto(
            "resident file is sealed under the profile's client master key, but the active profile has none".into()))?,
        _ => {
            let pass = resolve_external_passphrase_for_read(explicit_pass)?;
            let salt = b64.decode(&header.salt).map_err(|_| AppError::Crypto("bad salt".into()))?;
            credstore::argon2_key_with(&pass, &salt, header.m_cost, header.t_cost, header.p_cost)
                .map_err(|e| AppError::Crypto(format!("kdf: {e}")))?
        }
    };
    let wrapped_c = b64.decode(&header.wrapped_c).map_err(|_| AppError::Crypto("bad wrapped_c".into()))?;
    let kf_c = Zeroizing::new(blackbook_core::aead_open(&wrapped_c, client_kek.as_slice())
        .map_err(|_| AppError::Crypto("wrong key/passphrase (client half unwrap failed)".into()))?);
    if kf_c.len() != 32 { return Err(AppError::Crypto("client half must be 32 bytes".into())); }
    let mut out = [0u8; 32]; out.copy_from_slice(&kf_c); Ok(out)
}

/// Rebuild a resident stash, re-wrapping the (unchanged) client key-half under
/// `new_key` and keeping the (unchanged) ciphertext. The file key `Kf` and the
/// server's half `Kf_s` are untouched, so no server interaction is needed.
fn resident_rewrap(new_key: &ExtKey, kf_c: &[u8; 32], ciphertext: &[u8], orig_name: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    use rand::RngCore;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (mode, salt_b64, m, t, p, client_kek): (u8, String, u32, u32, u32, Zeroizing<[u8; 32]>) = match new_key {
        ExtKey::Cmk(cmk) => (0, String::new(), 0, 0, 0, Zeroizing::new(*cmk)),
        ExtKey::Passphrase(pass) => {
            let mut salt = [0u8; 16]; rand::thread_rng().fill_bytes(&mut salt);
            let (k, m, t, p) = credstore::argon2_key(pass, &salt)?;
            (1, b64.encode(salt), m, t, p, k)
        }
    };
    let wrapped_c = blackbook_core::aead_seal(kf_c, client_kek.as_slice())
        .map_err(|e| AppError::Crypto(format!("wrap client half: {e}")))?;
    let header = ResidentHeader {
        mode, salt: salt_b64, m_cost: m, t_cost: t, p_cost: p,
        wrapped_c: b64.encode(&wrapped_c), orig_name: orig_name.to_string(),
    };
    let hjson = serde_json::to_vec(&header)?;
    let mut stash = Vec::with_capacity(8 + hjson.len() + ciphertext.len());
    stash.extend_from_slice(RESIDENT_MAGIC);
    stash.extend_from_slice(&(hjson.len() as u32).to_be_bytes());
    stash.extend_from_slice(&hjson);
    stash.extend_from_slice(ciphertext);
    Ok(stash)
}

#[derive(serde::Deserialize)]
struct LoginBundle {
    server: Option<String>,
    token: Option<String>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    ca_pem: Option<String>,
    // The shape returned by `client create` also includes these — accept and ignore.
    #[serde(default)] name: Option<String>,
    #[serde(default)] role: Option<String>,
    #[serde(default)] expires_at: Option<String>,
}

async fn cmd_login(
    bundle: String,
    server_override: Option<String>,
    profile_override: Option<String>,
) -> Result<()> {
    let raw = if bundle == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else { std::fs::read_to_string(&bundle)? };
    let b: LoginBundle = serde_json::from_str(&raw)
        .map_err(|e| AppError::Config(format!("bundle: {e}")))?;

    let mut session = client::Session {
        server: b.server.unwrap_or_default(),
        token: b.token,
        cert_pem: b.cert_pem,
        key_pem: b.key_pem,
        ca_pem: b.ca_pem,
        cmk: None,
    };
    if let Some(s) = server_override { session.server = s; }

    // A full bundle is mandatory: the server rejects any request that doesn't
    // present both a client certificate and a matching bearer token. Catch an
    // incomplete bundle here with a precise message instead of a generic 401.
    let mut missing = Vec::new();
    if session.server.is_empty() { missing.push("server"); }
    if session.token.is_none()    { missing.push("token"); }
    if session.cert_pem.is_none() { missing.push("cert"); }
    if session.key_pem.is_none()  { missing.push("key"); }
    if session.ca_pem.is_none()   { missing.push("ca"); }
    if !missing.is_empty() {
        return Err(AppError::Config(format!(
            "incomplete credential bundle — missing: {}. Use a bundle from \
             `client create` or the first-run admin-bundle.json.",
            missing.join(", "))));
    }

    let bb = client::BlackbookClient::from_session(&session)?;
    let me = bb.whoami().await?;
    // Profile defaults to the authenticated identity's name; --profile/-P
    // (or $BLACKBOOK_PROFILE) overrides.
    let profile = profile_override.unwrap_or_else(|| me.name.clone());

    // Decide whether this is a *fresh* login (mint a new CMK + new passphrase)
    // or a *re-login* into an existing profile (carry the CMK forward, reuse
    // the existing passphrase) — the latter is what `client rotate` does, and
    // a fresh CMK there would orphan all prior CMK-sealed external data.
    let existing = client::Session::load_named(&profile).ok();
    let carried_cmk = existing.as_ref().and_then(|s| s.cmk.clone());
    let reuse = carried_cmk.is_some();

    let pass = if reuse {
        // Re-login: the user must prove the existing passphrase (no confirm).
        credstore::resolve_passphrase(
            None, &format!("Passphrase for existing profile '{profile}': "), false)
            .map_err(|e| AppError::Config(format!(
                "the existing profile is passphrase-protected: {e}")))?
    } else {
        credstore::resolve_passphrase(
            None, "Choose a passphrase to protect this profile: ", true)
            .map_err(|e| AppError::Config(format!(
                "a passphrase is required to protect local credentials: {e}")))?
    };

    // Carry the prior CMK forward; only mint one if there was none.
    session.cmk = carried_cmk;
    let minted = session.ensure_cmk();

    let path = session.save_encrypted(&profile, &pass)?;
    println!("Logged in to {} as {} ({}) via {}.", session.server, me.name, me.role, me.auth_method);
    println!("Saved encrypted profile '{profile}' ({}); it is now active and unlocked.", path.display());
    if reuse && !minted {
        println!("Carried the existing client master key forward — external data stays decryptable.");
    }
    // Default this profile to the identity's private user domain, so commands
    // land in the user's own namespace without needing -D. Only set it if the
    // user hasn't already chosen a default via `domain use` (explicit wins).
    if let Some(ud) = me.user_domain.as_deref() {
        if client::Session::read_domain_pref(&profile).is_none() {
            client::Session::write_domain_pref(&profile, ud)?;
            println!("Default domain for '{profile}' set to your user domain '{ud}' (change with `blackbook -P {profile} domain use NAME`).");
        }
    }
    println!("The profile is locked at rest — unlock future sessions with `blackbook -P {profile} unlock`.");
    Ok(())
}

async fn cmd_profile(cmd: ProfileCmd) -> Result<()> {
    match cmd {
        ProfileCmd::Ls => {
            let names = client::Session::list_profiles()?;
            if names.is_empty() { println!("(no profiles — run `blackbook login`)"); return Ok(()); }
            let active = client::active_profile();
            for n in names {
                let mark = if n == active { "*" } else { " " };
                println!("{mark} {n}");
            }
        }
        ProfileCmd::Use { name } => {
            // Make sure it exists before switching.
            client::Session::load_named(&name)
                .map_err(|_| AppError::Config(format!("no such profile '{name}'")))?;
            client::Session::write_active_pointer(&name)?;
            println!("active profile is now '{name}'");
        }
        ProfileCmd::Show { name } => {
            let profile = name.unwrap_or_else(client::active_profile);
            let session = client::Session::load_named(&profile)
                .map_err(|_| AppError::Config(format!("no such profile '{profile}'")))?;
            let bb = client::BlackbookClient::from_session(&session)?;
            match bb.whoami().await {
                Ok(me) => println!("profile '{profile}': {} ({}) @ {} — auth: {}",
                                   me.name, me.role, session.server, me.auth_method),
                Err(e) => println!("profile '{profile}': {} (whoami failed: {e})", session.server),
            }
        }
        ProfileCmd::Rm { name, yes } => {
            if !yes {
                eprint!("Delete profile '{name}'? [y/N]: ");
                if read_stdin_line().to_lowercase() != "y" { println!("aborted"); return Ok(()); }
            }
            if client::Session::clear_named(&name)? {
                println!("deleted profile '{name}'");
            } else {
                println!("no such profile '{name}'");
            }
        }
    }
    Ok(())
}

/// Build a session-backed client; attach domain + MFA code if supplied.
fn build_client(
    session: &client::Session,
    domain: Option<String>,
    mfa: Option<String>,
) -> Result<client::BlackbookClient> {
    let mut bb = client::BlackbookClient::from_session(session)?;
    if let Some(d) = domain { bb = bb.with_domain(d); }
    if let Some(c) = mfa { bb = bb.with_mfa(c); }
    Ok(bb)
}

async fn cmd_logout() -> Result<()> {
    let profile = client::active_profile();
    // Drop any cached unlock key first so the credential can't be reopened.
    credstore::agent_clear(&profile);
    if client::Session::clear()? { println!("Logged out of profile '{profile}'."); }
    else { println!("No saved session for profile '{profile}'."); }
    Ok(())
}

async fn cmd_unlock(ttl_minutes: u64) -> Result<()> {
    let profile = client::active_profile();
    let path = client::Session::path_for(&profile)
        .map_err(|e| AppError::Config(e.to_string()))?;
    let bytes = std::fs::read(&path)
        .map_err(|_| AppError::Config(format!("no such profile '{profile}' — run `blackbook login` first")))?;
    let env: credstore::EncryptedProfile = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Config(format!(
            "profile '{profile}' is not encrypted (legacy plaintext); re-run `blackbook login` to protect it")))?;
    let pass = credstore::resolve_passphrase(
        None, &format!("Passphrase for profile '{profile}': "), false)?;
    // Verify the passphrase actually opens the envelope before caching.
    let kek = env.derive_kek(&pass).map_err(|e| AppError::Config(e.to_string()))?;
    env.open_with_kek(kek.as_slice()).map_err(|_| AppError::Config(
        "wrong passphrase — profile not unlocked".into()))?;
    let ttl = ttl_minutes.saturating_mul(60);
    credstore::agent_store(&profile, kek.as_slice(), ttl)
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("Profile '{profile}' unlocked for {ttl_minutes} minute(s).");
    Ok(())
}

async fn cmd_lock() -> Result<()> {
    let profile = client::active_profile();
    if credstore::agent_clear(&profile) {
        println!("Profile '{profile}' locked (cached key cleared).");
    } else {
        println!("Profile '{profile}' was not unlocked.");
    }
    Ok(())
}

/// Change the passphrase on the active profile. Opens the encrypted envelope
/// with the current passphrase and re-seals the *same* inner bundle (session +
/// CMK) under a fresh Argon2id KEK from the new passphrase. The CMK is
/// preserved verbatim, so every CMK-sealed external item still decrypts; only
/// the on-disk wrapping changes.
async fn cmd_passphrase(old: Option<String>, new: Option<String>) -> Result<()> {
    let profile = client::active_profile();
    let path = client::Session::path_for(&profile)
        .map_err(|e| AppError::Config(e.to_string()))?;
    let bytes = std::fs::read(&path)
        .map_err(|_| AppError::Config(format!("no such profile '{profile}' — run `blackbook login` first")))?;
    let env: credstore::EncryptedProfile = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Config(format!(
            "profile '{profile}' is not an encrypted profile (legacy plaintext); re-run `blackbook login` to protect it")))?;

    // Current passphrase: flag → $BLACKBOOK_OLD_PASSPHRASE → $BLACKBOOK_PASSPHRASE → prompt.
    let old_pp: Zeroizing<String> = match old.filter(|s| !s.is_empty())
        .or_else(|| std::env::var("BLACKBOOK_OLD_PASSPHRASE").ok().filter(|s| !s.is_empty())) {
        Some(p) => Zeroizing::new(p),
        None => credstore::resolve_passphrase(None, &format!("Current passphrase for '{profile}': "), false)?,
    };
    let inner = env.open_with_passphrase(&old_pp)
        .map_err(|_| AppError::Config("current passphrase is incorrect".into()))?;

    // New passphrase: flag → $BLACKBOOK_NEW_PASSPHRASE → prompt (confirmed).
    let new_pp: Zeroizing<String> = match new.filter(|s| !s.is_empty())
        .or_else(|| std::env::var("BLACKBOOK_NEW_PASSPHRASE").ok().filter(|s| !s.is_empty())) {
        Some(p) => Zeroizing::new(p),
        None => credstore::resolve_passphrase(None, "New passphrase: ", true)?,
    };
    if *new_pp == *old_pp {
        return Err(AppError::Config("new passphrase is the same as the current one".into()));
    }

    // Re-seal the exact inner bundle under the new passphrase, write atomically,
    // and refresh the agent so the session stays unlocked.
    let sealed = credstore::seal_profile(&new_pp, &inner)
        .map_err(|e| AppError::Config(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&sealed)?)?;
    std::fs::rename(&tmp, &path)?;
    if let Ok(kek) = sealed.derive_kek(&new_pp) {
        let _ = credstore::agent_store(&profile, kek.as_slice(), credstore::DEFAULT_AGENT_TTL_SECS);
    }
    println!("✓ passphrase changed for profile '{profile}'. The client master key was preserved — all external data still decrypts.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Shell completions
//
// The completion "brain" is the hidden `__complete` subcommand: the shell
// passes it the words typed so far and it prints one candidate per line. It
// introspects clap's own command tree for command/flag *names* (so it can
// never drift from the real CLI) and reads local `~/.bbk` data for dynamic
// *values* (profile names, domains, resident files). It performs NO network
// I/O — server-side resource names are deliberately not completed (that would
// fire an authenticated request, hit the audit log, and leak names on every
// <Tab>).
// ---------------------------------------------------------------------------

/// Emit a shell completion script. The script registers a native completer
/// that calls back into this binary's `__complete`, so all logic stays in Rust.
fn cmd_completions(shell: &str) -> Result<()> {
    // Absolute path to this exe, so completion works without the binary on PATH.
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "bbk".to_string());
    // The command *name* to register completion for is this binary's basename
    // (normally `bbk`), derived from the exe so a renamed binary still works.
    let cmd = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "bbk".to_string());
    match shell.to_lowercase().as_str() {
        "powershell" | "pwsh" | "ps" => print!("{}", powershell_script(&exe, &cmd)),
        "bash" => print!("{}", bash_script(&exe, &cmd)),
        "zsh" => print!("{}", zsh_script(&exe, &cmd)),
        "fish" => print!("{}", fish_script(&exe, &cmd)),
        other => return Err(AppError::Config(format!(
            "unknown shell '{other}' — choose powershell, bash, zsh, or fish"))),
    }
    Ok(())
}

/// The completion brain. `words` is the full command line argv (`blackbook`,
/// then everything typed). Prints candidates, one per line.
fn cmd_complete(words: &[String]) {
    use std::io::Write;
    let cands = complete_candidates(words);
    let mut out = std::io::stdout().lock();
    for c in cands {
        let _ = writeln!(out, "{c}");
    }
}

/// Compute completion candidates for a command line. Pure + side-effect-free
/// apart from reading local `~/.bbk` files, so it's easy to reason about.
fn complete_candidates(words: &[String]) -> Vec<String> {
    // words[0] is the program name; the rest are real tokens. The final token
    // is the (possibly empty) word being completed.
    let args = if words.is_empty() { &[][..] } else { &words[1..] };
    let cur = args.last().cloned().unwrap_or_default();
    let prev = if args.len() >= 2 { args[args.len() - 2].clone() } else { String::new() };

    // 1) Value completion: if the previous token is a flag that takes a known
    //    local value, complete that value set regardless of position.
    if let Some(vals) = value_candidates_for_flag(&prev) {
        return filter_prefix(vals, &cur);
    }

    // 2) Positional value completion for a few verbs whose first argument is a
    //    locally-known name (e.g. `profile use <name>`, `file get <resident>`).
    if let Some(vals) = positional_value_candidates(args) {
        return filter_prefix(vals, &cur);
    }

    // 3) Otherwise complete command / subcommand / flag *names* by walking
    //    clap's command tree to the current subcommand context.
    let cmd = Cli::command();
    let ctx = resolve_subcommand(&cmd, args);
    let mut out: Vec<String> = Vec::new();
    // Subcommand names (only if the current word isn't a flag).
    if !cur.starts_with('-') {
        for sub in ctx.get_subcommands() {
            if sub.is_hide_set() { continue; }
            out.push(sub.get_name().to_string());
        }
    }
    // Flags valid in this context (long names; plus global flags from the root).
    for a in ctx.get_arguments().chain(cmd.get_arguments()) {
        if let Some(long) = a.get_long() {
            let f = format!("--{long}");
            if !out.contains(&f) { out.push(f); }
        }
    }
    filter_prefix(out, &cur)
}

/// Local value sets for flags that take a name we already know on this machine.
fn value_candidates_for_flag(flag: &str) -> Option<Vec<String>> {
    match flag {
        "-P" | "--profile" => Some(local_profiles()),
        "-D" | "--domain" => Some(local_domains()),
        _ => None,
    }
}

/// First-positional value completion for verbs whose argument is local.
fn positional_value_candidates(args: &[String]) -> Option<Vec<String>> {
    // Find the first non-flag token (the subcommand path), e.g. ["profile","use"].
    let path: Vec<&str> = args.iter()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'))
        .collect();
    match path.as_slice() {
        // `profile use|show|rm <name>` → known profiles
        ["profile", "use", ..] | ["profile", "show", ..] | ["profile", "rm", ..] =>
            Some(local_profiles()),
        // `domain use <name>` → known domains
        ["domain", "use", ..] => Some(local_domains()),
        // `file get|rm <name>` → resident files this machine actually holds
        ["file", "get", ..] | ["file", "rm", ..] => Some(local_resident_files()),
        _ => None,
    }
}

/// Walk the clap command tree following the subcommand tokens in `args`,
/// returning the deepest matched command (the completion context).
fn resolve_subcommand<'a>(root: &'a clap::Command, args: &[String]) -> &'a clap::Command {
    let mut ctx = root;
    for tok in args {
        if tok.starts_with('-') { continue; }
        match ctx.get_subcommands().find(|s| s.get_name() == tok
            || s.get_all_aliases().any(|a| a == tok)) {
            Some(sub) => ctx = sub,
            None => break,
        }
    }
    ctx
}

fn filter_prefix(mut v: Vec<String>, prefix: &str) -> Vec<String> {
    if !prefix.is_empty() && !prefix.starts_with('-') {
        v.retain(|c| c.starts_with(prefix));
    } else if prefix.starts_with('-') {
        v.retain(|c| c.starts_with(prefix));
    }
    v.sort();
    v.dedup();
    v
}

fn local_profiles() -> Vec<String> {
    client::Session::list_profiles().unwrap_or_default()
}

/// Domains we can infer locally: every profile's saved default-domain pref,
/// plus the always-present `default`. (No network — this is best-effort.)
fn local_domains() -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    set.insert("default".to_string());
    for p in local_profiles() {
        if let Some(d) = client::Session::read_domain_pref(&p) { set.insert(d); }
    }
    set.into_iter().collect()
}

/// Resident files this machine holds, from the local index (`<domain>/<name>`).
/// Returns the bare names.
fn local_resident_files() -> Vec<String> {
    resident_index_load().keys()
        .map(|k| k.rsplit('/').next().unwrap_or(k).to_string())
        .collect()
}

fn powershell_script(exe: &str, cmd: &str) -> String {
    format!(r#"# Blackbook PowerShell completion. Add to your $PROFILE:
#   {cmd} completions powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName {cmd} -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.ToString() }})
    # If the cursor is on a fresh trailing space, add an empty word to complete.
    if ($commandAst.CommandElements[-1].Extent.EndOffset -lt $cursorPosition) {{
        $words += ''
    }}
    & '{exe}' __complete -- @words 2>$null | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}
"#)
}

fn bash_script(exe: &str, cmd: &str) -> String {
    format!(r#"# Blackbook bash completion. Source it:  source <({cmd} completions bash)
_{cmd}() {{
    local IFS=$'\n'
    COMPREPLY=( $('{exe}' __complete -- "${{COMP_WORDS[@]}}" 2>/dev/null) )
}}
complete -F _{cmd} {cmd}
"#)
}

fn zsh_script(exe: &str, cmd: &str) -> String {
    format!(r#"# Blackbook zsh completion. Source it:  source <({cmd} completions zsh)
_{cmd}() {{
    local -a c
    c=(${{(f)"$('{exe}' __complete -- ${{words[@]}} 2>/dev/null)"}})
    compadd -- $c
}}
compdef _{cmd} {cmd}
"#)
}

fn fish_script(exe: &str, cmd: &str) -> String {
    format!(r#"# Blackbook fish completion. Source it:  {cmd} completions fish | source
complete -c {cmd} -f -a "({exe} __complete -- (commandline -opc) (commandline -ct) 2>/dev/null)"
"#)
}

async fn cmd_whoami() -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    let me = bb.whoami().await?;
    println!("{} ({}) — id {} — auth: {}", me.name, me.role, me.id, me.auth_method);
    println!("server: {}", session.server);
    if let Some(ud) = me.user_domain.as_deref() {
        println!("user domain: {ud}");
    }
    // Show this identity's client-certificate fingerprint as a visual
    // "randomart" (and a compact braille rendering) so it can be eyeballed
    // against what the server vouches — the way SSH shows key art.
    if let Some(cert_pem) = session.cert_pem.as_deref() {
        if let Ok(fp_hex) = tunnel_crypto::cert_fingerprint(cert_pem) {
            if let Ok(fp) = hex::decode(&fp_hex) {
                println!("cert fingerprint (SHA3-256): {}", &fp_hex[..32.min(fp_hex.len())]);
                println!("  braille: {}", presentation::braille(&fp));
                println!("{}", presentation::randomart(&fp, &me.name));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_put(
    name: String, value: Option<String>,
    mfa_required: bool, delete_on_read: bool, max_reads: Option<i64>,
    rotate_on_read: bool,
    quorum: Option<i32>, signatories: Vec<String>,
    overwrite: bool, preserve_on_cleanup: bool, no_overwrite: bool,
    ext: ExtFlags,
    domain: Option<String>, mfa: Option<String>,
) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    let value = value.unwrap_or_else(|| {
        eprint!("value (stdin): ");
        read_stdin_line()
    });
    // Secrets: data residency (--external-data / --external) is not available;
    // only the key axis applies. resolve_ext_spec enforces that.
    let spec = resolve_ext_spec(&ext, /* data_allowed = */ false)?;
    if spec.is_some() && rotate_on_read {
        return Err(AppError::Config(
            "--rotate-on-read is meaningless for client-side secrets (the server can't re-key what it can't read)".into()));
    }
    let flags = if mfa_required || delete_on_read || max_reads.is_some()
        || rotate_on_read || preserve_on_cleanup || no_overwrite {
        Some(client::ResourceFlagsRequest {
            mfa_required, delete_on_read, max_reads, rotate_on_read,
            preserve_on_cleanup, no_overwrite,
        })
    } else { None };
    let policy = match (quorum, signatories.is_empty()) {
        (Some(_), true) => return Err(AppError::Config(
            "--quorum requires --signatories <name,name,...>".into())),
        (None, false) => return Err(AppError::Config(
            "--signatories requires --quorum N".into())),
        (Some(k), false) => Some(client::AccessPolicyRequest {
            threshold_k: k, signatories,
        }),
        (None, true) => None,
    };
    let mut ext_mode_label = "";
    let resp = if let Some(spec) = spec {
        // Encrypt locally; the server only ever sees the opaque envelope.
        let key = ext_key_for_spec(&spec, &session, ext.passphrase)?;
        ext_mode_label = match key { ExtKey::Cmk(_) => " [external-key/managed]", ExtKey::Passphrase(_) => " [external-key/passphrase]" };
        let envelope = external_seal(&key, value.as_bytes())?;
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&envelope);
        bb.store_external(&name, &b64, flags.as_ref(), policy.as_ref(), overwrite).await?
    } else {
        bb.store(&name, &value, None, flags.as_ref(), policy.as_ref(), overwrite).await?
    };
    let tag = ext_mode_label;
    println!("{} {} ({}){}", resp.status, resp.resource_name, resp.resource_id, tag);
    Ok(())
}

async fn cmd_mfa(cmd: MfaCmd) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    match cmd {
        MfaCmd::Enroll => {
            let resp = bb.mfa_enroll().await?;
            println!("Provisioning URI:\n  {}\n", resp.provisioning_uri);
            println!("Or enter this base32 secret in your authenticator:\n  {}\n", resp.secret_base32);
            println!("{}", resp.instructions);
        }
        MfaCmd::Verify { code } => {
            bb.mfa_verify(&code).await?;
            println!("MFA verified.");
        }
    }
    Ok(())
}

async fn cmd_get(
    name: String, request_id: Option<String>,
    wait: bool, wait_timeout: u64, external_passphrase: Option<String>,
    domain: Option<String>, mfa: Option<String>,
) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    let resp = if !wait {
        bb.retrieve_with_request(&name, request_id.as_deref()).await?
    } else {
        // Block until the K-of-N request is approved (single call for automation).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_timeout);
        let mut announced = false;
        loop {
            match bb.retrieve_with_request(&name, request_id.as_deref()).await {
                Ok(r) => break r,
                Err(client::ClientError::Api { status: 412, message }) => {
                    if !announced { eprintln!("{message}"); eprintln!("waiting up to {wait_timeout}s for approval…"); announced = true; }
                    if std::time::Instant::now() >= deadline {
                        return Err(AppError::Client(format!("timed out after {wait_timeout}s waiting for approval")));
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    if resp.external {
        // Client-side secret: the server handed back an opaque envelope that
        // only our passphrase can open.
        let envelope_b64 = resp.envelope.ok_or_else(||
            AppError::Crypto("server marked secret external but returned no envelope".into()))?;
        use base64::Engine as _;
        let envelope = base64::engine::general_purpose::STANDARD.decode(&envelope_b64)
            .map_err(|_| AppError::Crypto("envelope is not valid base64".into()))?;
        let env = ext_decode(&envelope)?;
        let plain = external_open(&env, &session, external_passphrase)?;
        use std::io::Write;
        std::io::stdout().write_all(&plain)?;
        return Ok(());
    }
    println!("{}", resp.data);
    Ok(())
}

/// Resolve the *target* key for a rekey from the rekey flags. `--external-key`
/// → managed (CMK); `--external-passphrase` → a new user passphrase; neither →
/// default to managed (the natural "drop the passphrase" choice). The two are
/// mutually exclusive. Shared by `rekey` (secrets) and `file rekey`.
fn rekey_target_key(
    session: &client::Session, external_key: bool, new_passphrase: Option<String>,
) -> Result<ExtKey> {
    let pass = new_passphrase.filter(|s| !s.is_empty());
    if external_key && pass.is_some() {
        return Err(AppError::Config(
            "choose one target key: --external-key (managed) OR --external-passphrase (user).".into()));
    }
    match pass {
        Some(p) => Ok(ExtKey::Passphrase(p)),
        None => session.cmk_bytes().map(ExtKey::Cmk).ok_or_else(|| AppError::Config(
            "this profile has no managed key (CMK) to rekey to. Re-run `blackbook login`, \
             or pass --external-passphrase to set a user passphrase.".into())),
    }
}

fn ext_key_label(k: &ExtKey) -> &'static str {
    match k { ExtKey::Cmk(_) => "managed (CMK)", ExtKey::Passphrase(_) => "passphrase" }
}

/// Change the client-side key on an external secret. Fetches the opaque
/// envelope, decrypts it with the current key (old passphrase / CMK), and
/// re-seals the *same plaintext* under the new key, then stores it back with
/// `overwrite`. Only the wrapping changes.
async fn cmd_rekey(
    name: String, old_external_passphrase: Option<String>,
    external_key: bool, external_passphrase: Option<String>,
    domain: Option<String>, mfa: Option<String>,
) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    let resp = bb.retrieve_with_request(&name, None).await?;
    if !resp.external {
        return Err(AppError::Config(format!(
            "'{name}' is a normal (server-side) secret, not client-side — there is no external key to change.")));
    }
    let envelope_b64 = resp.envelope.ok_or_else(||
        AppError::Crypto("server marked secret external but returned no envelope".into()))?;
    use base64::Engine as _;
    let envelope = base64::engine::general_purpose::STANDARD.decode(&envelope_b64)
        .map_err(|_| AppError::Crypto("envelope is not valid base64".into()))?;
    let env = ext_decode(&envelope)?;
    // Decrypt with the *current* key.
    let plain = external_open(&env, &session, old_external_passphrase)?;
    // Re-seal under the *new* key and store back.
    let new_key = rekey_target_key(&session, external_key, external_passphrase)?;
    let new_env = external_seal(&new_key, &plain)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&new_env);
    bb.store_external(&name, &b64, None, None, /* overwrite = */ true).await?;
    println!("✓ rekeyed secret '{name}' → {}.", ext_key_label(&new_key));
    Ok(())
}

async fn cmd_approve(request_id: String) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    let v = bb.approve_request(&request_id).await?;
    println!("approved — total approvers: {}",
             v.get("approvers").and_then(|x| x.as_u64()).unwrap_or(0));
    Ok(())
}

async fn cmd_requests(id: Option<String>, verbose: bool) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;

    // Detail view for a single request: who can approve, and who has.
    if let Some(id) = id {
        let r = bb.get_access_request(&id).await?;
        println!("Request {}", r.id);
        println!("  resource : {} ({}) in domain {}", r.resource_name, r.resource_kind, r.domain);
        println!("  requester: {}", r.requester);
        println!("  threshold: {} of {} signatories", r.threshold_k, r.signatories.len());
        println!("  status   : {}", r.status);
        println!("  created  : {}", r.created_at);
        println!("  expires  : {}", r.expires_at);
        println!("  signatories (who can approve this request):");
        for s in &r.signatories {
            let mark = if r.approvers.contains(s) { "[approved]" } else { "[ pending]" };
            println!("    {mark}  {s}");
        }
        if r.approvers.iter().any(|a| !r.signatories.contains(a)) {
            // Defensive: approvers not in the signatory list (shouldn't happen).
            println!("  other approvers: {}", r.approvers.join(", "));
        }
        return Ok(());
    }

    let list = bb.list_access_requests().await?;
    if list.count == 0 { println!("(no access requests)"); return Ok(()); }
    println!("{:<14}  {:<10}  {:<14}  {:<24}  {:<6}  {:<10}  STATUS",
             "ID", "DOMAIN", "REQUESTER", "RESOURCE", "K", "APPROVERS");
    println!("{}", "-".repeat(110));
    for r in list.requests {
        println!("{:<14}  {:<10}  {:<14}  {:<24}  {:<6}  {:<10}  {}",
                 r.id, r.domain, r.requester, r.resource_name,
                 r.threshold_k,
                 format!("{}/{}", r.approvers.len(), r.signatories.len()),
                 r.status);
        if verbose {
            println!("      can approve : {}", r.signatories.join(", "));
            println!("      approved by : {}",
                     if r.approvers.is_empty() { "(none yet)".to_string() } else { r.approvers.join(", ") });
        }
    }
    if !verbose {
        println!("\nTip: `blackbook requests <ID>` (or `-v`) shows who can approve each request.");
    }
    Ok(())
}

async fn cmd_grants(cmd: GrantsCmd, domain: Option<String>) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, None)?;
    match cmd {
        GrantsCmd::Add { grantee, pattern, kind, max_uses, ttl_hours, expires_at, not_before } => {
            if ttl_hours.is_none() && expires_at.is_none() {
                return Err(AppError::Config(
                    "a time limit is required: pass --ttl-hours H or --expires-at RFC3339".into()));
            }
            if kind != "secret" && kind != "file" {
                return Err(AppError::Config("--kind must be 'secret' or 'file'".into()));
            }
            let opts = client::GrantAddOpts {
                resource_kind: kind, max_uses, ttl_hours, expires_at, not_before,
            };
            let v = bb.create_access_grant(&grantee, &pattern, &opts).await?;
            let gid = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
            let exp = v.get("expires_at").and_then(|x| x.as_str()).unwrap_or("?");
            let cap = max_uses.map(|m| format!("{m} use(s)")).unwrap_or_else(|| "unlimited uses".into());
            println!("pre-approved {grantee} for '{pattern}' ({cap}, expires {exp}) — grant {gid}");
        }
        GrantsCmd::Ls => {
            let list = bb.list_access_grants().await?;
            if list.count == 0 { println!("(no advance grants)"); return Ok(()); }
            println!("{:<14}  {:<12}  {:<12}  {:<7}  {:<22}  {:<8}  {:<24}  STATUS",
                     "ID", "SIGNATORY", "GRANTEE", "KIND", "PATTERN", "USE", "EXPIRES");
            println!("{}", "-".repeat(120));
            for g in list.grants {
                let use_disp = match g.max_uses {
                    Some(m) => format!("{}/{}", g.use_count, m),
                    None => format!("{}", g.use_count),
                };
                let status = if g.revoked { "revoked" } else { "active" };
                println!("{:<14}  {:<12}  {:<12}  {:<7}  {:<22}  {:<8}  {:<24}  {}",
                         g.id, g.signatory, g.grantee, g.resource_kind,
                         g.pattern, use_disp, g.expires_at, status);
            }
        }
        GrantsCmd::Rm { id, yes } => {
            if !yes {
                eprint!("Revoke advance grant '{id}'? [y/N]: ");
                if read_stdin_line().to_lowercase() != "y" { println!("aborted"); return Ok(()); }
            }
            bb.revoke_access_grant(&id).await?;
            println!("revoked grant '{id}'");
        }
    }
    Ok(())
}

/// Compact, human-readable summary of a resource's enforced rules for list
/// views — e.g. `mfa, max-reads 3/5, quorum 2-of-3, immutable`. Returns "-"
/// when nothing special is set.
fn rules_summary(flags: &client::ResourceFlagsView, read_count: i64,
                 threshold_k: Option<i64>, signatory_count: Option<usize>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if flags.mfa_required { parts.push("mfa".into()); }
    if flags.delete_on_read { parts.push("burn-after-read".into()); }
    if let Some(max) = flags.max_reads {
        parts.push(format!("max-reads {}/{}", read_count, max));
    } else if read_count > 0 {
        parts.push(format!("reads {read_count}"));
    }
    if flags.rotate_on_read { parts.push("rotate-on-read".into()); }
    if flags.no_overwrite { parts.push("immutable".into()); }
    if flags.preserve_on_cleanup { parts.push("preserve".into()); }
    if let (Some(k), Some(n)) = (threshold_k, signatory_count) {
        parts.push(format!("quorum {k}-of-{n}"));
    }
    if parts.is_empty() { "-".into() } else { parts.join(", ") }
}

async fn cmd_ls(domain: Option<String>, mfa: Option<String>, json: bool) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    let resp = bb.list().await?;
    if json {
        println!("{}", serde_json::to_string(&resp)?);
        return Ok(());
    }
    if resp.count == 0 { println!("(no secrets)"); return Ok(()); }
    println!("{:<28}  {:<8}  {:<10}  {:<24}  {}", "NAME", "KIND", "STATUS", "UPDATED", "RULES");
    println!("{}", "-".repeat(118));
    for r in resp.resources {
        let kind = if r.external { "external" } else { "server" };
        let status = match r.exhausted_at {
            Some(_) => "exhausted",
            None => "active",
        };
        let rules = rules_summary(&r.flags, r.read_count, r.threshold_k, r.signatory_count);
        println!("{:<28}  {:<8}  {:<10}  {:<24}  {}",
                 r.resource_name, kind, status, r.updated_at, rules);
    }
    Ok(())
}

async fn cmd_cleanup(domain: Option<String>) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, None)?;
    let resp = bb.cleanup().await?;
    if resp.deleted == 0 && resp.preserved == 0 {
        println!("no tombstoned resources to clean up");
    } else {
        println!("purged {} tombstoned resource(s) ({} secret(s), {} file(s)); kept {} preserved",
                 resp.deleted, resp.secrets_deleted, resp.files_deleted, resp.preserved);
        for n in resp.names {
            println!("  - {n}");
        }
    }
    Ok(())
}

async fn cmd_rm(name: String, yes: bool, domain: Option<String>, mfa: Option<String>) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    if !yes {
        eprint!("Delete '{name}'? [y/N]: ");
        if read_stdin_line().to_lowercase() != "y" { println!("aborted"); return Ok(()); }
    }
    let resp = bb.delete(&name).await?;
    println!("deleted {} at {}", resp.resource_id, resp.deleted_at);
    Ok(())
}

async fn cmd_tunnel(cmd: TunnelCmd) -> Result<()> {
    use tunnel_client::Proto;
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    let me = bb.whoami().await?;
    let my_name = me.name.clone();
    let my_cert = session.cert_pem.clone()
        .ok_or_else(|| AppError::Config("profile has no client certificate".into()))?;
    let my_key = session.key_pem.clone()
        .ok_or_else(|| AppError::Config("profile has no client key".into()))?;

    match cmd {
        TunnelCmd::Ls => {
            let v = bb.tunnel_list().await?;
            let tunnels = v.get("tunnels").and_then(|x| x.as_array()).cloned().unwrap_or_default();
            if tunnels.is_empty() { println!("(no active tunnels)"); return Ok(()); }
            println!("{:<26}  {:<14}  {:<14}  {}", "ID", "OFFERER", "TARGET", "STATE");
            println!("{}", "-".repeat(70));
            for t in tunnels {
                println!("{:<26}  {:<14}  {:<14}  {}",
                    t.get("id").and_then(|x| x.as_str()).unwrap_or("?"),
                    t.get("offerer").and_then(|x| x.as_str()).unwrap_or("?"),
                    t.get("target").and_then(|x| x.as_str()).unwrap_or("?"),
                    t.get("state").and_then(|x| x.as_str()).unwrap_or("?"));
            }
            Ok(())
        }
        TunnelCmd::Forward { peer, listen, target, udp } => {
            let proto = if udp { Proto::Udp } else { Proto::Tcp };
            // Offer the tunnel, then connect and run the handshake.
            let tid = bb.tunnel_offer(&peer).await?;
            println!("🔌 offered tunnel {tid} to '{peer}'. Waiting for them to `tunnel accept`…");
            let mut ws = bb.tunnel_connect_ws(&tid).await
                .map_err(|e| AppError::Client(e.to_string()))?;
            let (sess, vouch) = tunnel_client::handshake(&mut ws, &my_name, &my_cert, &my_key).await
                .map_err(|e| AppError::Config(format!("tunnel handshake: {e}")))?;
            println!("🔒 secured E2E with '{}' (cert {}…) — server cannot read this tunnel.",
                     vouch.peer_name, &vouch.peer_fingerprint[..16.min(vouch.peer_fingerprint.len())]);
            println!("➡️  forwarding {} {listen} → {}:{target}",
                     if udp { "udp" } else { "tcp" }, vouch.peer_name);
            tunnel_client::run_listener(ws, sess, proto, listen, target).await
                .map_err(|e| AppError::Config(format!("tunnel: {e}")))?;
            Ok(())
        }
        TunnelCmd::Accept { from, wait_timeout } => {
            // Poll for an offer addressed to us, then connect + serve dials.
            println!("👂 waiting for a tunnel offer{}…",
                     from.as_deref().map(|f| format!(" from '{f}'")).unwrap_or_default());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_timeout);
            let tid = loop {
                let v = bb.tunnel_list().await?;
                let found = v.get("tunnels").and_then(|x| x.as_array()).and_then(|arr| {
                    arr.iter().find(|t| {
                        t.get("target").and_then(|x| x.as_str()) == Some(my_name.as_str())
                        && t.get("state").and_then(|x| x.as_str()) != Some("connected")
                        && from.as_deref().map_or(true, |f| t.get("offerer").and_then(|x| x.as_str()) == Some(f))
                    }).and_then(|t| t.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                });
                if let Some(id) = found { break id; }
                if std::time::Instant::now() >= deadline {
                    return Err(AppError::Config(format!("no tunnel offer within {wait_timeout}s")));
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            };
            let mut ws = bb.tunnel_connect_ws(&tid).await
                .map_err(|e| AppError::Client(e.to_string()))?;
            let (sess, vouch) = tunnel_client::handshake(&mut ws, &my_name, &my_cert, &my_key).await
                .map_err(|e| AppError::Config(format!("tunnel handshake: {e}")))?;
            println!("🔒 secured E2E with '{}' (cert {}…) — serving their dial requests.",
                     vouch.peer_name, &vouch.peer_fingerprint[..16.min(vouch.peer_fingerprint.len())]);
            tunnel_client::run_target(ws, sess).await
                .map_err(|e| AppError::Config(format!("tunnel: {e}")))?;
            Ok(())
        }
    }
}

async fn cmd_file(cmd: FileCmd, domain: Option<String>, mfa: Option<String>) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, domain, mfa)?;
    match cmd {
        FileCmd::Put { path, name, mime, mfa_required, delete_on_read, max_reads,
                       rotate_on_read, quorum, signatories, overwrite,
                       preserve_on_cleanup, no_overwrite, external_key, external_passphrase,
                       external, external_data, server_copy, shred, external_passphrase_env } => {
            let body = std::fs::read(&path)?;
            let name = name.unwrap_or_else(|| {
                path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default()
            });
            if name.is_empty() { return Err(AppError::Config("could not derive --name from path".into())); }
            // Files allow both axes. resolve_ext_spec validates key/data combos.
            let ext = ExtFlags { external, external_key, external_data, passphrase: external_passphrase, passphrase_from_env: external_passphrase_env };
            let spec = resolve_ext_spec(&ext, /* data_allowed = */ true)?;
            let resident = matches!(spec, Some(ExtSpec { data: DataLoc::Resident, .. }));
            if spec.is_some() && rotate_on_read {
                return Err(AppError::Config(
                    "--rotate-on-read is meaningless for client-side files (the server can't re-key what it can't read)".into()));
            }
            if !resident && (server_copy || shred) {
                return Err(AppError::Config("--server-copy and --shred require --external-data (resident)".into()));
            }
            match (quorum, signatories.is_empty()) {
                (Some(_), true) => return Err(AppError::Config(
                    "--quorum requires --signatories <name,name,...>".into())),
                (None, false) => return Err(AppError::Config(
                    "--signatories requires --quorum N".into())),
                _ => {}
            }
            let dom = domain_label(&bb);

            if resident {
                // Encrypt locally, stash the ciphertext on this machine, and
                // upload only the manifest + the server's key-component half.
                let key = ext_key_for_spec(spec.as_ref().unwrap(), &session, ext.passphrase.clone())?;
                let label = match key { ExtKey::Cmk(_) => "managed", ExtKey::Passphrase(_) => "passphrase" };
                let (stash, kc_b64, _) = resident_seal(&key, &body, &name)?;
                // Persist the stash file under ~/.bbk/resident/<id>.bbkr.
                let stash_id = format!("{}.bbkr", blackbook_core::Id::new(16).to_hex());
                let stash_path = resident_dir()?.join(&stash_id);
                std::fs::create_dir_all(resident_dir()?)?;
                std::fs::write(&stash_path, &stash)?;
                // The body uploaded to the server is the client ciphertext only
                // when a server backup is requested; otherwise it's a 1-byte
                // placeholder (the server requires a non-empty body but discards
                // it for resident-no-copy).
                let upload_body: Vec<u8> = if server_copy {
                    let (_, ct) = resident_parts_from_stash(&stash)?; ct
                } else { vec![0u8] };
                let opts = client::FilePutOpts {
                    mime: mime.as_deref(),
                    mfa_required, delete_on_read, max_reads, rotate_on_read: false,
                    preserve_on_cleanup, no_overwrite, overwrite,
                    quorum, signatories,
                    external: false, external_meta: None,
                    resident: true, key_component: Some(kc_b64), server_copy,
                };
                match bb.file_put(&name, upload_body, &opts).await {
                    Ok(resp) => {
                        // Record the stash location locally.
                        let mut idx = resident_index_load();
                        idx.insert(resident_key(&dom, &name), stash_id);
                        resident_index_save(&idx)?;
                        // --shred: overwrite the original plaintext before
                        // unlinking, so the cleartext isn't trivially recoverable
                        // from freed blocks (best-effort; see secure_delete docs).
                        if shred { let _ = credstore::secure_delete(&path); }
                        let copy = if server_copy { " + server backup" } else { "" };
                        let shred_note = if shred { "; original shredded (overwritten)" } else { "" };
                        println!("registered resident {} (stash {}, sha3:{}…) [resident/{}{}]{}",
                                 resp.name, stash_path.display(), &resp.content_hash[..16], label, copy, shred_note);
                    }
                    Err(e) => {
                        // Roll back the local stash so we don't leave an orphan;
                        // the stash holds ciphertext + a wrapped key, so scrub it.
                        let _ = credstore::secure_delete(&stash_path);
                        return Err(e.into());
                    }
                }
            } else {
                // Data-in-server: either external-key (encrypt locally, server
                // stores the opaque envelope) or normal (server-side encryption).
                let mut file_ext_label = "";
                let (upload_body, external_meta) = if let Some(spec) = spec.as_ref() {
                    let key = ext_key_for_spec(spec, &session, ext.passphrase.clone())?;
                    file_ext_label = match key { ExtKey::Cmk(_) => " [external-key/managed]", ExtKey::Passphrase(_) => " [external-key/passphrase]" };
                    let (meta, ct) = external_seal_parts(&key, &body)?;
                    use base64::Engine as _;
                    (ct, Some(base64::engine::general_purpose::STANDARD.encode(&meta)))
                } else {
                    (body, None)
                };
                let opts = client::FilePutOpts {
                    mime: mime.as_deref(),
                    mfa_required, delete_on_read, max_reads, rotate_on_read,
                    preserve_on_cleanup, no_overwrite, overwrite,
                    quorum, signatories,
                    external: external_meta.is_some(), external_meta,
                    resident: false, key_component: None, server_copy: false,
                };
                let resp = bb.file_put(&name, upload_body, &opts).await?;
                println!("uploaded {} ({} bytes stored, sha3:{}…){}", resp.name, resp.size, &resp.content_hash[..16], file_ext_label);
            }
        }
        FileCmd::Get { name, path, request_id, wait, wait_timeout, external_passphrase } => {
            let dl = if wait {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_timeout);
                let mut announced = false;
                loop {
                    match bb.file_get_download(&name, request_id.as_deref()).await {
                        Ok(b) => break b,
                        Err(client::ClientError::Api { status: 412, message }) => {
                            if !announced { eprintln!("{message}"); eprintln!("waiting up to {wait_timeout}s for approval…"); announced = true; }
                            if std::time::Instant::now() >= deadline {
                                return Err(AppError::Client(format!("timed out after {wait_timeout}s waiting for approval")));
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                bb.file_get_download(&name, request_id.as_deref()).await?
            };
            let bytes = if dl.resident {
                // Resident file: the server returned only its key-component half.
                // Find the local stash, recombine, decrypt locally.
                let dom = domain_label(&bb);
                let kc = dl.key_component.ok_or_else(|| AppError::Crypto(
                    "server flagged file resident but returned no key component".into()))?;
                let idx = resident_index_load();
                let stash_id = idx.get(&resident_key(&dom, &name)).ok_or_else(|| AppError::Config(
                    format!("no local stash for resident file '{name}' in domain '{dom}' — \
                             this machine doesn't hold the ciphertext")))?;
                let stash = std::fs::read(resident_dir()?.join(stash_id))
                    .map_err(|e| AppError::Config(format!("reading resident stash: {e}")))?;
                let (header, ct) = resident_parse(&stash)?;
                resident_open(&header, &ct, &kc, &session, external_passphrase)?
            } else if let Some(meta_b64) = dl.external_meta {
                // External-key files: `bytes` is the client ciphertext; the row
                // carried the envelope header meta. `meta ++ ct` reconstitutes
                // the full envelope, opened with the CMK or passphrase.
                use base64::Engine as _;
                let mut envelope = base64::engine::general_purpose::STANDARD.decode(&meta_b64)
                    .map_err(|_| AppError::Crypto("external meta is not valid base64".into()))?;
                envelope.extend_from_slice(&dl.bytes);
                let env = ext_decode(&envelope)?;
                external_open(&env, &session, external_passphrase)?
            } else {
                dl.bytes
            };
            match path.as_deref().and_then(|p| p.to_str()) {
                Some("-") => {
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                }
                Some(p) => { std::fs::write(p, &bytes)?; eprintln!("wrote {} bytes to {}", bytes.len(), p); }
                None => {
                    let out = PathBuf::from(&name);
                    std::fs::write(&out, &bytes)?;
                    eprintln!("wrote {} bytes to {}", bytes.len(), out.display());
                }
            }
        }
        FileCmd::Ls { json } => {
            let list = bb.file_list().await?;
            if json {
                println!("{}", serde_json::to_string(&list)?);
                return Ok(());
            }
            if list.count == 0 { println!("(no files)"); return Ok(()); }
            println!("{:<32}  {:>9}  {:<14}  {:<16}  {}", "NAME", "SIZE", "OWNER", "KIND", "RULES");
            println!("{}", "-".repeat(120));
            for f in list.files {
                let kind = match f.external.as_str() {
                    "key" => "external-key",
                    "resident" => "resident",
                    _ => "server",
                };
                let kind = if f.exhausted_at.is_some() { format!("{kind} (exhausted)") } else { kind.to_string() };
                let rules = rules_summary(&f.flags, f.read_count, f.threshold_k, f.signatory_count);
                println!("{:<32}  {:>9}  {:<14}  {:<16}  {}",
                         f.name, f.size, f.owner, kind, rules);
            }
        }
        FileCmd::Rm { name, yes } => {
            if !yes {
                eprint!("Delete file '{name}'? [y/N]: ");
                if read_stdin_line().to_lowercase() != "y" { println!("aborted"); return Ok(()); }
            }
            bb.file_delete(&name).await?;
            println!("deleted '{name}'");
        }
        FileCmd::Rotate { name } => {
            bb.file_rotate(&name).await?;
            println!("rotated DEK for '{name}'");
        }
        FileCmd::Rekey { name, old_external_passphrase, external_key, external_passphrase } => {
            let dom = domain_label(&bb);
            let new_key = rekey_target_key(&session, external_key, external_passphrase)?;
            // Resident file? Then the ciphertext + server key-half never change —
            // we only rewrap the client-half (Kf_c) in the local stash header.
            // Detect locally (the stash is what we'd rewrap) without a download.
            let idx = resident_index_load();
            if let Some(stash_id) = idx.get(&resident_key(&dom, &name)).cloned() {
                let stash_path = resident_dir()?.join(&stash_id);
                let stash = std::fs::read(&stash_path)
                    .map_err(|e| AppError::Config(format!("reading resident stash: {e}")))?;
                let (header, ct) = resident_parse(&stash)?;
                // Unwrap Kf_c with the current key.
                let kf_c = resident_unwrap_client_half(&header, &session, old_external_passphrase)?;
                // Re-wrap Kf_c under the new key, rewrite the stash header in place.
                let new_stash = resident_rewrap(&new_key, &kf_c, &ct, &header.orig_name)?;
                let tmp = stash_path.with_extension("bbkr.tmp");
                std::fs::write(&tmp, &new_stash)?;
                std::fs::rename(&tmp, &stash_path)?;
                println!("✓ rekeyed resident file '{name}' → {} (local stash only; no re-upload).", ext_key_label(&new_key));
            } else {
                // External-key file: fetch, decrypt, re-seal, re-upload the envelope.
                let dl = bb.file_get_download(&name, None).await?;
                if dl.resident {
                    return Err(AppError::Config(format!(
                        "'{name}' is resident but this machine has no local stash for it — rekey must run where the stash lives.")));
                }
                let meta_b64 = dl.external_meta.ok_or_else(|| AppError::Config(format!(
                    "'{name}' is a normal (server-side) file, not client-side — there is no external key to change.")))?;
                use base64::Engine as _;
                let mut envelope = base64::engine::general_purpose::STANDARD.decode(&meta_b64)
                    .map_err(|_| AppError::Crypto("external meta is not valid base64".into()))?;
                envelope.extend_from_slice(&dl.bytes);
                let env = ext_decode(&envelope)?;
                let plain = external_open(&env, &session, old_external_passphrase)?;
                let (meta, ct) = external_seal_parts(&new_key, &plain)?;
                let opts = client::FilePutOpts {
                    mime: dl.content_type.as_deref(),
                    mfa_required: false, delete_on_read: false, max_reads: None, rotate_on_read: false,
                    preserve_on_cleanup: false, no_overwrite: false, overwrite: true,
                    quorum: None, signatories: vec![],
                    external: true,
                    external_meta: Some(base64::engine::general_purpose::STANDARD.encode(&meta)),
                    resident: false, key_component: None, server_copy: false,
                };
                bb.file_put(&name, ct, &opts).await?;
                println!("✓ rekeyed external-key file '{name}' → {}.", ext_key_label(&new_key));
            }
        }
    }
    Ok(())
}

async fn cmd_client(cmd: ClientCmd) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    match cmd {
        ClientCmd::Create { name, role, ttl_days, out } => {
            let new = bb.create_client(&name, &role, ttl_days).await?;
            let bundle = serde_json::json!({
                "server": session.server,
                "token": new.token,
                "cert_pem": new.cert_pem,
                "key_pem": new.key_pem,
                "ca_pem": session.ca_pem,
                "name": new.name,
                "role": new.role,
                "expires_at": new.expires_at,
            });
            let pretty = serde_json::to_string_pretty(&bundle)?;
            if let Some(path) = out {
                std::fs::write(&path, &pretty)?;
                eprintln!("Bundle written to {} — share with {} via a secure channel.", path.display(), new.name);
            } else {
                println!("{pretty}");
                eprintln!();
                eprintln!("Save the JSON above and run `blackbook login --bundle PATH` on the client.");
                eprintln!("This is the ONLY time the cert/key/token appear in plaintext.");
            }
        }
        ClientCmd::Rotate { name, ttl_days, out } => {
            let new = bb.rotate_my_or_client(&name, ttl_days).await?;
            let bundle = serde_json::json!({
                "server": session.server,
                "token": new.token,
                "cert_pem": new.cert_pem,
                "key_pem": new.key_pem,
                "ca_pem": session.ca_pem,
                "name": new.name,
                "role": new.role,
                "expires_at": new.expires_at,
            });
            let pretty = serde_json::to_string_pretty(&bundle)?;
            if let Some(path) = out {
                std::fs::write(&path, &pretty)?;
                eprintln!("New bundle for '{}' written to {}.", new.name, path.display());
            } else {
                println!("{pretty}");
                eprintln!();
                eprintln!("Old credentials are now invalid. Rebox to {} with `blackbook login --bundle PATH`.", new.name);
            }
        }
        ClientCmd::Ls => {
            let list = bb.list_clients().await?;
            if list.count == 0 { println!("(no clients)"); return Ok(()); }
            println!("{:<24}  {:<8}  {:<24}  {:<24}  {}", "NAME", "ROLE", "CREATED", "EXPIRES", "REVOKED");
            println!("{}", "-".repeat(112));
            for c in list.clients {
                println!("{:<24}  {:<8}  {:<24}  {:<24}  {}",
                         c.name, c.role, c.created_at,
                         c.expires_at.as_deref().unwrap_or("never"),
                         c.revoked_at.as_deref().unwrap_or("-"));
            }
        }
        ClientCmd::Revoke { name, yes } => {
            if !yes {
                eprint!("Revoke '{name}'? Its token and cert stop working immediately. [y/N]: ");
                if read_stdin_line().to_lowercase() != "y" { println!("aborted"); return Ok(()); }
            }
            bb.revoke_client(&name).await?;
            println!("revoked '{name}'");
        }
    }
    Ok(())
}

/// Parse a rate string `N/PERIOD` → (max, period_secs). PERIOD is a number with
/// an optional unit suffix `s`/`m`/`h`/`d` (a bare number means seconds).
fn parse_rate(s: &str) -> Result<(i32, i32)> {
    let (n, period) = s.split_once('/').ok_or_else(|| AppError::Config(
        format!("rate must be N/PERIOD, e.g. 10/1h — got '{s}'")))?;
    let max: i32 = n.trim().parse().map_err(|_| AppError::Config(format!("bad rate count '{n}'")))?;
    let p = period.trim();
    let split = p.find(|c: char| c.is_alphabetic()).unwrap_or(p.len());
    let (num, unit) = p.split_at(split);
    let num: i64 = num.parse().map_err(|_| AppError::Config(format!("bad rate period '{p}'")))?;
    let secs = match unit {
        "" | "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86_400,
        other => return Err(AppError::Config(format!("unknown period unit '{other}' (use s/m/h/d)"))),
    };
    if max <= 0 || secs <= 0 {
        return Err(AppError::Config("rate count and period must be positive".into()));
    }
    Ok((max, secs as i32))
}

/// Render a period in whole seconds back to the most natural unit.
fn fmt_period(secs: i32) -> String {
    let s = secs as i64;
    if s % 86_400 == 0 { format!("{}d", s / 86_400) }
    else if s % 3600 == 0 { format!("{}h", s / 3600) }
    else if s % 60 == 0 { format!("{}m", s / 60) }
    else { format!("{s}s") }
}

async fn cmd_acl(cmd: AclCmd, domain: Option<String>) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    match cmd {
        AclCmd::Grant {
            subject, pattern,
            create, read, update, delete,
            expires_at, not_before, max_uses, rate, schedule,
        } => {
            // The rule's domain comes from the global --domain (default).
            let domain = domain.unwrap_or_else(|| "default".to_string());
            let mut actions: Vec<&str> = Vec::new();
            if create { actions.push("create"); }
            if read   { actions.push("read"); }
            if update { actions.push("update"); }
            if delete { actions.push("delete"); }
            if actions.is_empty() {
                return Err(AppError::Config("at least one of --create/--read/--update/--delete required".into()));
            }
            let (rate_max, rate_period_secs) = match rate.as_deref() {
                Some(s) => { let (m, p) = parse_rate(s)?; (Some(m), Some(p)) }
                None => (None, None),
            };
            let (client_name, group_domain) = match subject.strip_prefix('@') {
                Some(g) => (None, Some(g.to_string())),
                None    => (Some(subject.clone()), None),
            };
            let opts = client::GrantOpts {
                client_name, group_domain,
                domain: Some(domain.clone()),
                expires_at, not_before, max_uses,
                rate_max, rate_period_secs, schedule: schedule.clone(),
            };
            bb.grant_acl(&pattern, &actions, opts).await?;
            let extra = [
                rate.as_ref().map(|r| format!("rate={r}")),
                schedule.as_ref().map(|s| format!("schedule='{s}'")),
            ].into_iter().flatten().collect::<Vec<_>>().join(", ");
            println!("granted {} on '{pattern}' to {} (domain={domain}){}",
                     actions.join("+"), subject,
                     if extra.is_empty() { String::new() } else { format!(" [{extra}]") });
        }
        AclCmd::Ls => {
            let list = bb.list_acl().await?;
            if list.count == 0 { println!("(no acl entries)"); return Ok(()); }
            println!("{:<14}  {:<10}  {:<20}  {:<24}  {:<10}  {:<8}  {}",
                     "ID", "DOMAIN", "SUBJECT", "PATTERN", "ACTIONS", "USE", "LIMITS");
            println!("{}", "-".repeat(140));
            for e in list.entries {
                let subject = e.client_name
                    .or_else(|| e.group_domain.map(|g| format!("@{g}")))
                    .unwrap_or_else(|| "?".into());
                let use_disp = match (e.max_uses, e.use_count) {
                    (Some(m), c) => format!("{c}/{m}"),
                    (None, c) => format!("{c}"),
                };
                // Compact limits column: rate, schedule, expiry.
                let mut limits: Vec<String> = Vec::new();
                if let (Some(m), Some(p)) = (e.rate_max, e.rate_period_secs) {
                    limits.push(format!("rate {m}/{}", fmt_period(p)));
                }
                if let Some(s) = &e.schedule { limits.push(format!("cron \"{s}\"")); }
                if let Some(x) = &e.expires_at { limits.push(format!("exp {}", &x[..x.len().min(10)])); }
                println!("{:<14}  {:<10}  {:<20}  {:<24}  {:<10}  {:<8}  {}",
                         e.id, e.domain, subject, e.resource_pattern,
                         e.actions.join(","), use_disp,
                         if limits.is_empty() { "-".into() } else { limits.join(", ") });
            }
        }
        AclCmd::Revoke { id } => {
            bb.revoke_acl(&id).await?;
            println!("revoked acl '{id}'");
        }
    }
    Ok(())
}

async fn cmd_domain(cmd: DomainCmd) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;
    match cmd {
        DomainCmd::Create { name, description } => {
            bb.create_domain(&name, description.as_deref()).await?;
            println!("created domain '{name}'");
        }
        DomainCmd::Ls => {
            let list = bb.list_domains().await?;
            if list.count == 0 { println!("(no domains visible)"); return Ok(()); }
            println!("{:<24}  {:<24}  {}", "NAME", "CREATED", "DESCRIPTION");
            println!("{}", "-".repeat(80));
            for d in list.domains {
                println!("{:<24}  {:<24}  {}", d.name, d.created_at,
                         d.description.as_deref().unwrap_or(""));
            }
        }
        DomainCmd::Use { name, clear } => {
            let profile = client::active_profile();
            if clear {
                if client::Session::clear_domain_pref(&profile)? {
                    println!("cleared default domain for profile '{profile}' (now 'default')");
                } else {
                    println!("profile '{profile}' had no domain preference");
                }
            } else if let Some(name) = name {
                client::Session::write_domain_pref(&profile, &name)?;
                println!("profile '{profile}' now defaults to domain '{name}' (override per-command with -D)");
            } else {
                match client::Session::read_domain_pref(&profile) {
                    Some(d) => println!("profile '{profile}' default domain: {d}"),
                    None => println!("profile '{profile}' default domain: default (none set)"),
                }
            }
        }
        DomainCmd::Members { domain } => {
            let list = bb.list_domain_members(&domain).await?;
            if list.count == 0 { println!("(no members)"); return Ok(()); }
            println!("{:<24}  {:<8}  {}", "CLIENT", "ROLE", "ADDED");
            println!("{}", "-".repeat(64));
            for m in list.members {
                println!("{:<24}  {:<8}  {}", m.client_name, m.role, m.added_at);
            }
        }
        DomainCmd::AddMember { domain, client: cname, role } => {
            bb.add_domain_member(&domain, &cname, &role).await?;
            println!("added '{cname}' to '{domain}' as {role}");
        }
        DomainCmd::RmMember { domain, client: cname } => {
            bb.remove_domain_member(&domain, &cname).await?;
            println!("removed '{cname}' from '{domain}'");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_audit(
    limit: i64, verify: bool, archive: bool, keep_last: Option<i64>, before: Option<String>,
    prune: bool, verify_archive: Option<String>, list_archives: bool,
) -> Result<()> {
    let session = client::Session::load()?;
    let bb = build_client(&session, None, None)?;

    if let Some(file) = verify_archive {
        let v = bb.audit_archive_verify(&file).await?;
        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        if ok {
            println!("archive '{file}' OK — verified {} row(s) (id {}..{})",
                     v.get("verified").and_then(|x| x.as_i64()).unwrap_or(0),
                     v.get("first_id").and_then(|x| x.as_i64()).unwrap_or(0),
                     v.get("last_id").and_then(|x| x.as_i64()).unwrap_or(0));
        } else {
            println!("archive '{file}' BROKEN — {}", v.get("reason").and_then(|x| x.as_str()).unwrap_or("unknown"));
        }
        return Ok(());
    }
    if list_archives {
        let v = bb.audit_archives().await?;
        let empty = vec![];
        let arr = v.get("archives").and_then(|x| x.as_array()).unwrap_or(&empty);
        if arr.is_empty() { println!("(no archives)"); return Ok(()); }
        println!("{:<44}  {}", "FILE", "SIZE");
        println!("{}", "-".repeat(60));
        for a in arr {
            println!("{:<44}  {}", a.get("file").and_then(|x| x.as_str()).unwrap_or("?"),
                     a.get("size_bytes").and_then(|x| x.as_u64()).unwrap_or(0));
        }
        return Ok(());
    }
    if archive {
        if keep_last.is_none() && before.is_none() {
            return Err(AppError::Config("specify --keep-last N or --before TIMESTAMP".into()));
        }
        let v = bb.audit_archive(keep_last, before.as_deref(), prune).await?;
        let n = v.get("archived").and_then(|x| x.as_i64()).unwrap_or(0);
        if n == 0 {
            println!("nothing archived — {}", v.get("message").and_then(|x| x.as_str()).unwrap_or(""));
        } else {
            println!("archived {n} row(s) (id {}..{}) → {} ({} bytes); pruned {}",
                     v.get("first_id").and_then(|x| x.as_i64()).unwrap_or(0),
                     v.get("last_id").and_then(|x| x.as_i64()).unwrap_or(0),
                     v.get("file").and_then(|x| x.as_str()).unwrap_or("?"),
                     v.get("size_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                     v.get("pruned").and_then(|x| x.as_u64()).unwrap_or(0));
        }
        return Ok(());
    }

    if verify {
        let v = bb.audit_verify().await?;
        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        let through = v.get("verified_through").and_then(|x| x.as_i64()).unwrap_or(0);
        if ok {
            println!("audit chain OK — verified {through} row(s)");
        } else {
            let bad = v.get("first_bad_id").and_then(|x| x.as_i64()).unwrap_or(-1);
            let reason = v.get("reason").and_then(|x| x.as_str()).unwrap_or("unknown");
            println!("audit chain BROKEN after {through} verified row(s): first bad id {bad} — {reason}");
        }
        return Ok(());
    }
    let list = bb.audit(limit).await?;
    if list.count == 0 { println!("(no audit entries)"); return Ok(()); }
    println!("{:<26}  {:<14}  {:<16}  {:<10}  {}", "TS", "CLIENT", "ACTION", "STATUS", "RESOURCE");
    println!("{}", "-".repeat(96));
    for e in list.entries {
        println!("{:<26}  {:<14}  {:<16}  {:<10}  {}",
                 e.ts,
                 e.client_name.as_deref().unwrap_or("-"),
                 e.action, e.status,
                 e.resource.as_deref().unwrap_or("-"));
    }
    Ok(())
}

/// Insert the `default` domain if it doesn't already exist. Required at
/// boot because secrets / files / ACL rows have a `NOT NULL` FK to
/// `blackbook_domains(id)` and the API defaults the `?domain=` query param
/// to `"default"`. The row's name is AEAD-encrypted just like any other
/// domain — no plaintext "default" string ends up in the DB.
async fn ensure_default_domain(
    pool: &Pool<Postgres>, metadata_enc_key: &[u8], name_index_key: &[u8],
) -> Result<()> {
    let name_id = server::domain_name_id_hex(name_index_key, "default");
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM blackbook_domains WHERE name_id = $1",
    ).bind(&name_id).fetch_optional(pool).await?;
    if exists.is_some() { return Ok(()); }
    let id = "default".to_string();
    let name_enc = server::enc_str(metadata_enc_key, "default")
        .map_err(|e| AppError::Config(format!("encrypt default domain name: {e}")))?;
    let desc_enc = server::enc_str(metadata_enc_key, "Default domain")
        .map_err(|e| AppError::Config(format!("encrypt default domain description: {e}")))?;
    sqlx::query(
        "INSERT INTO blackbook_domains (id, name_enc, name_id, description_enc)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING",
    ).bind(&id).bind(&name_enc).bind(&name_id).bind(&desc_enc)
    .execute(pool).await?;
    log::info!("provisioned default domain");
    Ok(())
}

fn server_sans(bind: &str) -> Vec<String> {
    let mut sans: Vec<String> = std::env::var("BLACKBOOK_SERVER_SANS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    if sans.is_empty() {
        sans = vec![
            "localhost".into(), "127.0.0.1".into(),
            "blackbook".into(), "blackbook-app".into(),
        ];
        // Plus whatever host was on the bind line if it isn't 0.0.0.0.
        if let Some(host) = bind.rsplit_once(':').map(|(h, _)| h) {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if !host.is_empty() && host != "0.0.0.0" && host != "::" && !sans.iter().any(|s| s == host) {
                sans.push(host.to_string());
            }
        }
    }
    sans
}

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

/// Best-effort OS hardening for the long-lived server, applied before any key
/// material is loaded. Two protections, both targeting "secrets must stay in
/// RAM, never disk":
///   1. **No core dumps** — a crash must not spill the master key / DEK to a
///      core file. We zero `RLIMIT_CORE` *and* set `PR_SET_DUMPABLE=0` (which
///      also blocks same-uid `ptrace` snooping).
///   2. **No swap** — `mlockall` pins current and future pages in RAM so secret
///      bytes can't be paged out to disk.
///
/// Every step is best-effort: in a hardened container `mlockall` can fail on a
/// low `RLIMIT_MEMLOCK`, so we log and continue rather than refuse to boot.
#[cfg(target_os = "linux")]
fn harden_process() {
    // SAFETY: plain libc calls with valid arguments; we only read their return
    // codes and never dereference anything we didn't allocate on the stack.
    unsafe {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
            log::warn!("hardening: could not disable core dumps (RLIMIT_CORE)");
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            log::warn!("hardening: could not set PR_SET_DUMPABLE=0");
        }
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            log::warn!("hardening: mlockall() failed (RLIMIT_MEMLOCK too low under this \
                        container/cgroup?) — secret pages may be swappable. Raise the \
                        memlock limit or disable swap on the host for full protection.");
        } else {
            log::info!("hardening: core dumps disabled and process memory locked (no swap).");
        }
    }
}

/// On non-Linux hosts the syscalls above aren't available; the server still
/// runs, just without these OS-level guarantees.
#[cfg(not(target_os = "linux"))]
fn harden_process() {
    log::info!("hardening: core-dump/swap locking is Linux-only; skipped on this platform.");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_default_env()
        .filter_level(cli.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .init();

    // Resolve which credential profile this invocation uses, in precedence
    // order: explicit --profile/-P (or $BLACKBOOK_PROFILE, via clap `env`) →
    // the persisted `~/.bbk/active` pointer → `default`. Stashed once so every
    // Session::load() in this process targets the same profile.
    let resolved_profile = cli.profile.clone()
        .or_else(|| client::Session::read_active_pointer().ok().flatten())
        .unwrap_or_else(|| "default".to_string());
    client::set_active_profile(resolved_profile.clone());

    // Resolve the effective domain in precedence order: explicit -D/--domain
    // (or $BLACKBOOK_DOMAIN, via clap `env`) → the profile's saved default
    // (`domain use`) → None (the server treats absence as `default`). Computed
    // once so no command needs `-D` when a profile default is set.
    let effective_domain: Option<String> = cli.domain.clone()
        .or_else(|| client::Session::read_domain_pref(&resolved_profile));

    match cli.command {
        Commands::Health => {
            let db_url = cli.database_url.ok_or_else(|| AppError::Config("DATABASE_URL not provided".into()))?;
            let db = Database::new(&db_url).await?;
            match db.health_check().await {
                Ok(_) => println!("ok"),
                Err(e) => { eprintln!("db unhealthy: {e}"); std::process::exit(1); }
            }
        }

        Commands::RekeyDek => {
            let data_dir = std::env::var("BLACKBOOK_DATA_DIR")
                .unwrap_or_else(|_| "/opt/blackbook/data".to_string());
            let paths = persistence::DataPaths::under(&data_dir);
            let provider = persistence::DekProvider::from_env()
                .map_err(|e| AppError::Config(format!("master key: {e}")))?;
            persistence::rekey_master_dek(&paths, &provider)
                .map_err(|e| AppError::Config(format!("rekey: {e}")))?;
            println!("✓ master DEK rotated under the '{}' provider (master key unchanged; \
                      restart the server if you also rotated the keyfile).", provider.kind());
        }

        Commands::Web { bind } => {
            webui::run_web(&bind).await.map_err(|e| AppError::Config(e.to_string()))?;
        }

        Commands::Server { bind } => {
            // Lock the process down before any key material is loaded into RAM.
            harden_process();
            let db_url = cli.database_url.ok_or_else(|| AppError::Config("DATABASE_URL not provided".into()))?;
            log::info!("Initializing Blackbook server...");
            let db = Database::new(&db_url).await?;
            db.initialize().await?;

            let pool = PgPoolOptions::new()
                .max_connections(20)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&db_url).await?;

            let data_dir = std::env::var("BLACKBOOK_DATA_DIR")
                .unwrap_or_else(|_| "/opt/blackbook/data".to_string());
            let paths = persistence::DataPaths::under(&data_dir);

            // CA + server cert (auto-generated on first boot).
            let (ca, ca_new) = persistence::load_or_init_ca(&paths)
                .map_err(|e| AppError::Config(format!("persistence/ca: {e}")))?;
            log::info!("CA {} ({})",
                       if ca_new { "generated" } else { "loaded" },
                       paths.ca_cert.display());
            let sans = server_sans(&bind);
            let server_cert_new = persistence::load_or_init_server_cert(&paths, &ca, &sans)
                .map_err(|e| AppError::Config(format!("persistence/server-cert: {e}")))?;
            log::info!("Server cert {} ({}) SAN={:?}",
                       if server_cert_new { "issued" } else { "loaded" },
                       paths.server_cert.display(), sans);
            let ca_shared: tls::SharedCa = Arc::new(ca);

            // DEK + master key. The outermost key is produced by a provider
            // (user passphrase, or a locally-wrapped keyfile) and never stored
            // raw on disk. Fail closed: no provider → refuse to start.
            let provider = persistence::DekProvider::from_env()
                .map_err(|e| AppError::Config(format!("master key: {e}")))?;
            log::info!("master DEK provider: {}", provider.kind());
            let dek = persistence::resolve_dek(&paths, &provider)
                .map_err(|e| AppError::Config(format!("persistence/DEK: {e}")))?;
            drop(provider); // wipe the passphrase (if any) as soon as the DEK is resolved.
            let (keys, keys_new) = persistence::load_or_init_master(&paths, &dek)
                .map_err(|e| AppError::Config(format!("persistence/master: {e}")))?;
            drop(dek); // DEK is no longer needed; wipe it now rather than at scope end.
            log::info!("Master key {} at {}",
                       if keys_new { "generated" } else { "loaded" },
                       paths.master_key.display());

            // Bootstrap admin (token + cert). The metadata keys are needed
            // because the admin row's name lives encrypted (`name_enc`) and
            // is looked up via the HMAC `name_id`.
            let metadata_enc_key_b = keys.index.handle_with_info(b"metadata-enc/v1")
                .map_err(|e| AppError::Config(format!("derive metadata-enc key: {e}")))?;
            let name_index_key_b = keys.index.handle()
                .map_err(|e| AppError::Config(format!("derive name index key: {e}")))?;
            // URL the operator's CLI will connect to. The server can't know
            // its own published address, so default to the docker-local
            // mapping and let $BLACKBOOK_PUBLIC_URL override.
            let public_url = std::env::var("BLACKBOOK_PUBLIC_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
            match auth::bootstrap_admin_if_needed(
                &pool, &ca_shared, &metadata_enc_key_b, &name_index_key_b,
            ).await {
                Ok(Some((token, cert))) => {
                    if let Err(e) = persistence::write_admin_bundle(
                        &paths, &token, &cert, &ca_shared.cert_pem, &public_url,
                    ) {
                        log::warn!("could not write admin bundle: {e}");
                    }
                    // The token is deliberately NOT logged: container/journald
                    // logs persist on disk (and are often shipped off-host), so
                    // emitting the bearer token there would defeat its secrecy.
                    // It lives only in the 0600 bundle on the data volume.
                    let _ = &token; // consumed by write_admin_bundle above
                    log::warn!("================================================================");
                    log::warn!("BLACKBOOK FIRST-RUN ADMIN BUNDLE  --  RETRIEVE IT NOW");
                    log::warn!("");
                    log::warn!("    Bundle : {}  (mode 0600, contains the token)", paths.admin_bundle.display());
                    log::warn!("");
                    log::warn!("    docker cp blackbook-app:/opt/blackbook/data/admin-bundle.json .");
                    log::warn!("    blackbook login admin-bundle.json      # saves to profile 'admin'");
                    log::warn!("");
                    log::warn!("    (The bundle's server URL defaults to {public_url};");
                    log::warn!("     override at login with `-s https://your-host:8443`.)");
                    log::warn!("    Treat the bundle as a secret: copy it over a secure channel,");
                    log::warn!("    then delete it from the volume. The token is NOT written to");
                    log::warn!("    logs — only to the bundle file.");
                    log::warn!("================================================================");
                }
                Ok(None) => log::info!("Admin client already provisioned; not bootstrapping."),
                Err(e) => return Err(AppError::Config(e.to_string())),
            }

            // Derive the audit MAC and name-index HMAC keys once. These
            // are stable for the lifetime of the BlackbookKey bundle (which
            // does not rotate yet); audit() and the name_id helpers read
            // them on every request.
            let audit_hmac_key = std::sync::Arc::new(
                keys.hmac.handle()
                    .map_err(|e| AppError::Config(format!("derive audit hmac key: {e}")))?,
            );
            let name_index_key = std::sync::Arc::new(
                keys.index.handle()
                    .map_err(|e| AppError::Config(format!("derive name index key: {e}")))?,
            );
            // Per-field AEAD key for at-rest encryption of every user-supplied
            // identifier (resource/client/domain names, ACL patterns, audit
            // resource/message, file metadata). Same root, distinct info tag.
            let metadata_enc_key = std::sync::Arc::new(
                keys.index.handle_with_info(b"metadata-enc/v1")
                    .map_err(|e| AppError::Config(format!("derive metadata-enc key: {e}")))?,
            );

            // Auto-provision the `default` domain on first boot so secrets /
            // files / ACL rows (which have a NOT NULL FK to blackbook_domains)
            // can be created against the default `?domain=` query parameter.
            ensure_default_domain(&pool, metadata_enc_key.as_slice(), name_index_key.as_slice()).await?;

            let app_state = server::AppState {
                keys: std::sync::Arc::new(tokio::sync::RwLock::new(keys)),
                db: pool,
                start_time: std::time::SystemTime::now(),
                ca: ca_shared,
                data_dir: PathBuf::from(&data_dir),
                audit_hmac_key,
                name_index_key,
                metadata_enc_key,
                tunnels: tunnel_relay::TunnelHub::new(),
            };

            server::run_server(
                app_state,
                &bind,
                paths.server_cert.to_str().ok_or_else(|| AppError::Config("non-utf8 server_cert path".into()))?,
                paths.server_key.to_str().ok_or_else(|| AppError::Config("non-utf8 server_key path".into()))?,
                paths.ca_cert.to_str().ok_or_else(|| AppError::Config("non-utf8 ca_cert path".into()))?,
            ).await?;
        }

        Commands::Login { bundle, server } =>
            cmd_login(bundle, server, cli.profile.clone()).await?,
        Commands::Logout => cmd_logout().await?,
        Commands::Unlock { ttl_minutes } => cmd_unlock(ttl_minutes).await?,
        Commands::Lock => cmd_lock().await?,
        Commands::Passphrase { old, new } => cmd_passphrase(old, new).await?,
        Commands::Completions { shell } => cmd_completions(&shell)?,
        Commands::Complete { words } => cmd_complete(&words),
        Commands::Profile(cmd) => cmd_profile(cmd).await?,
        Commands::Whoami => cmd_whoami().await?,
        Commands::Put { name, value, mfa_required, delete_on_read, max_reads, rotate_on_read, quorum, signatories, overwrite, preserve_on_cleanup, no_overwrite, external_key, external_passphrase, external, external_data, external_passphrase_env } =>
            cmd_put(name, value, mfa_required, delete_on_read, max_reads, rotate_on_read,
                    quorum, signatories, overwrite, preserve_on_cleanup, no_overwrite,
                    ExtFlags { external, external_key, external_data, passphrase: external_passphrase, passphrase_from_env: external_passphrase_env },
                    effective_domain.clone(), cli.mfa.clone()).await?,
        Commands::Get { name, request_id, wait, wait_timeout, external_passphrase } =>
            cmd_get(name, request_id, wait, wait_timeout, external_passphrase, effective_domain.clone(), cli.mfa.clone()).await?,
        Commands::Ls { json } => cmd_ls(effective_domain.clone(), cli.mfa.clone(), json).await?,
        Commands::Rm { name, yes } => cmd_rm(name, yes, effective_domain.clone(), cli.mfa.clone()).await?,
        Commands::Rekey { name, old_external_passphrase, external_key, external_passphrase } =>
            cmd_rekey(name, old_external_passphrase, external_key, external_passphrase,
                      effective_domain.clone(), cli.mfa.clone()).await?,
        Commands::File(cmd) => cmd_file(cmd, effective_domain.clone(), cli.mfa.clone()).await?,
        Commands::Tunnel(cmd) => cmd_tunnel(cmd).await?,
        Commands::Client(cmd) => cmd_client(cmd).await?,
        Commands::Acl(cmd) => cmd_acl(cmd, effective_domain.clone()).await?,
        Commands::Domain(cmd) => cmd_domain(cmd).await?,
        Commands::Mfa(cmd) => cmd_mfa(cmd).await?,
        Commands::Approve { request_id } => cmd_approve(request_id).await?,
        Commands::Requests { id, verbose } => cmd_requests(id, verbose).await?,
        Commands::Grants(cmd) => cmd_grants(cmd, effective_domain.clone()).await?,
        Commands::Audit { limit, verify, archive, keep_last, before, prune, verify_archive, list_archives } =>
            cmd_audit(limit, verify, archive, keep_last, before, prune, verify_archive, list_archives).await?,
        Commands::Cleanup => cmd_cleanup(effective_domain.clone()).await?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> ExtFlags {
        ExtFlags {
            external: false, external_key: false, external_data: false,
            passphrase: None, passphrase_from_env: false,
        }
    }

    // These cases are deliberately independent of $BLACKBOOK_EXTERNAL_PASSPHRASE:
    // each resolves before (or without) consulting the env, so they're stable
    // regardless of the runner's environment.

    #[test]
    fn no_external_flags_means_normal_storage() {
        // A plain put must never become client-side encrypted, even if the env
        // var happens to be set — opt-in is explicit only.
        assert!(resolve_ext_spec(&flags(), false).unwrap().is_none());
    }

    #[test]
    fn external_key_selects_managed_in_server() {
        let f = ExtFlags { external_key: true, ..flags() };
        let spec = resolve_ext_spec(&f, false).unwrap().expect("external");
        assert!(matches!(spec.key, KeySource::Managed));
        assert!(matches!(spec.data, DataLoc::InServer));
    }

    #[test]
    fn passphrase_env_opt_in_selects_passphrase_mode() {
        // The env-sourced opt-in chooses the user-key path even though no argv
        // passphrase value was supplied (the value is sourced later, in
        // ext_key_for_spec). This is what lets the web console create a
        // passphrase-sealed secret without the passphrase touching argv.
        let f = ExtFlags { passphrase_from_env: true, ..flags() };
        let spec = resolve_ext_spec(&f, false).unwrap().expect("external");
        assert!(matches!(spec.key, KeySource::Passphrase));
        assert!(matches!(spec.data, DataLoc::InServer));
    }

    #[test]
    fn passphrase_env_plus_managed_is_rejected() {
        // Managed key and a passphrase opt-in are contradictory — must be a
        // clear error, not a silent pick.
        let f = ExtFlags { passphrase_from_env: true, external_key: true, ..flags() };
        assert!(resolve_ext_spec(&f, false).is_err());
    }
}