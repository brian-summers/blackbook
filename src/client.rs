//! Blackbook HTTP client and on-disk session.
//!
//! Credentials live in named **profiles** so one machine can hold several
//! identities. Each profile is a JSON file at `~/.bbk/profiles/<name>.json`
//! holding:
//! - `server` URL
//! - `token` — bearer token (required: the server demands cert *and* token)
//! - `cert_pem` / `key_pem` — client cert + private key (PEM) for mTLS
//! - `ca_pem` — Blackbook CA cert (PEM) so the CLI can pin the server.
//!
//! `~/.bbk/active` records which profile is used when no `--profile`/`-P`
//! flag or `$BLACKBOOK_PROFILE` is given. The active profile for the current
//! process is resolved once in `main()` and stashed via
//! [`set_active_profile`]; every [`Session::load`] then targets it.
//!
//! A legacy single-session file at `~/.bbk/session.json` is still read as the
//! `default` profile if no `profiles/default.json` exists yet.

use reqwest::{Client, Identity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Active profile name for this process, resolved once in `main()`.
static ACTIVE_PROFILE: OnceLock<String> = OnceLock::new();

/// Record the profile this invocation should use. Called once from `main()`
/// after resolving `--profile`/`-P`, `$BLACKBOOK_PROFILE`, the `~/.bbk/active`
/// pointer, and the `default` fallback, in that order.
pub fn set_active_profile(name: String) {
    let _ = ACTIVE_PROFILE.set(name);
}

/// The active profile name (or `"default"` if `set_active_profile` was never
/// called — e.g. very early errors).
pub fn active_profile() -> String {
    ACTIVE_PROFILE.get().cloned().unwrap_or_else(|| "default".to_string())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not logged in — run `blackbook login --server URL --token TOKEN` first")]
    NoSession,

    #[error("session file at {path}: {detail}")]
    SessionIo { path: String, detail: String },

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("tls config: {0}")]
    TlsConfig(String),

    #[error("{0}")]
    Cred(#[from] crate::credstore::CredError),
}

pub type Result<T> = std::result::Result<T, ClientError>;

// ---------------------------------------------------------------------------
// Session: on-disk record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub server: String,
    /// Bearer token. Required in practice — the server rejects any request
    /// that doesn't present both a client cert and a matching token.
    pub token: Option<String>,
    /// Client certificate (PEM). Required for mTLS.
    pub cert_pem: Option<String>,
    /// Client private key (PEM). Required for mTLS.
    pub key_pem: Option<String>,
    /// Blackbook CA certificate (PEM). The CLI pins the server's chain to
    /// this CA — anything else, the HTTPS handshake fails.
    pub ca_pem: Option<String>,
    /// Rotation-stable Client Master Key (32 bytes, base64). Minted at login,
    /// sealed inside the encrypted profile. Used by "external" client-side
    /// storage to wrap data keys *by default* (no separate passphrase), and
    /// independent of token/cert so credential rotation never destroys data.
    /// `None` for legacy plaintext profiles created before Phase 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmk: Option<String>,
}

impl Session {
    /// `~/.bbk`.
    fn bbk_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| ClientError::SessionIo {
            path: "~/.bbk".into(),
            detail: "could not resolve home directory".into(),
        })?;
        Ok(home.join(".bbk"))
    }

    /// `~/.bbk/profiles/<profile>.json`.
    pub fn path_for(profile: &str) -> Result<PathBuf> {
        Ok(Self::bbk_dir()?.join("profiles").join(format!("{profile}.json")))
    }

    /// Legacy single-session path, read as the `default` profile if no
    /// `profiles/default.json` exists.
    fn legacy_path() -> Result<PathBuf> {
        Ok(Self::bbk_dir()?.join("session.json"))
    }

    /// `~/.bbk/active` — names the profile used when no `-P`/env is given.
    fn active_pointer_path() -> Result<PathBuf> {
        Ok(Self::bbk_dir()?.join("active"))
    }

    /// Read the persisted active-profile pointer, if any.
    pub fn read_active_pointer() -> Result<Option<String>> {
        let path = Self::active_pointer_path()?;
        if !path.exists() { return Ok(None); }
        let s = fs::read_to_string(&path)?;
        let s = s.trim();
        Ok(if s.is_empty() { None } else { Some(s.to_string()) })
    }

    /// Persist the active-profile pointer.
    pub fn write_active_pointer(name: &str) -> Result<()> {
        let path = Self::active_pointer_path()?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(&path, name)?;
        Ok(())
    }

    /// `~/.bbk/domains/<profile>` — the default domain for a given profile, so
    /// the user doesn't have to pass `-D` on every command. Per-profile so
    /// different identities can default to different domains. Stored as a
    /// plaintext pointer (the domain name is not a secret; the credentials it
    /// gates remain in the encrypted profile).
    fn domain_pointer_path(profile: &str) -> Result<PathBuf> {
        Ok(Self::bbk_dir()?.join("domains").join(profile))
    }

    /// Read a profile's saved default domain, if any.
    pub fn read_domain_pref(profile: &str) -> Option<String> {
        let path = Self::domain_pointer_path(profile).ok()?;
        let s = fs::read_to_string(&path).ok()?;
        let s = s.trim();
        if s.is_empty() { None } else { Some(s.to_string()) }
    }

    /// Persist a profile's default domain.
    pub fn write_domain_pref(profile: &str, domain: &str) -> Result<()> {
        let path = Self::domain_pointer_path(profile)?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(&path, domain)?;
        Ok(())
    }

    /// Remove a profile's default-domain preference (revert to `default`).
    pub fn clear_domain_pref(profile: &str) -> Result<bool> {
        let path = Self::domain_pointer_path(profile)?;
        if path.exists() { fs::remove_file(&path)?; Ok(true) } else { Ok(false) }
    }

    /// Names of all saved profiles (files in `~/.bbk/profiles`), plus the
    /// legacy `default` if only `session.json` exists.
    pub fn list_profiles() -> Result<Vec<String>> {
        let mut names = Vec::new();
        let dir = Self::bbk_dir()?.join("profiles");
        if dir.exists() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        names.push(stem.to_string());
                    }
                }
            }
        }
        // Legacy session.json surfaces as `default` if not already present.
        if Self::legacy_path()?.exists() && !names.iter().any(|n| n == "default") {
            names.push("default".to_string());
        }
        names.sort();
        Ok(names)
    }

    /// Load the active profile (see [`active_profile`]).
    pub fn load() -> Result<Self> {
        Self::load_named(&active_profile())
    }

    /// Load a specific profile by name. Falls back to the legacy
    /// `session.json` for the `default` profile if no profile file exists.
    ///
    /// Transparently handles both the encrypted `v2` envelope (Phase 2) and
    /// legacy plaintext profiles. For encrypted profiles the unlock key comes
    /// from (in order) the unlock agent's cached KEK, then `$BLACKBOOK_PASSPHRASE`
    /// or an interactive prompt — see [`credstore`].
    pub fn load_named(profile: &str) -> Result<Self> {
        let path = Self::path_for(profile)?;
        if path.exists() {
            let bytes = fs::read(&path).map_err(|e| ClientError::SessionIo {
                path: path.display().to_string(), detail: e.to_string(),
            })?;
            return Self::from_profile_bytes(profile, &bytes);
        }
        if profile == "default" {
            let legacy = Self::legacy_path()?;
            if legacy.exists() {
                let bytes = fs::read(&legacy).map_err(|e| ClientError::SessionIo {
                    path: legacy.display().to_string(), detail: e.to_string(),
                })?;
                return Self::from_profile_bytes(profile, &bytes);
            }
        }
        Err(ClientError::NoSession)
    }

    /// Parse raw profile bytes that may be either a `v2` encrypted envelope
    /// or a legacy plaintext `Session`. Encrypted profiles are decrypted using
    /// the unlock agent or an available passphrase.
    fn from_profile_bytes(profile: &str, bytes: &[u8]) -> Result<Self> {
        // Try the encrypted envelope first; fall back to plaintext.
        if let Ok(env) = serde_json::from_slice::<crate::credstore::EncryptedProfile>(bytes) {
            if env.v >= 2 {
                // 1) cached KEK from the agent (no prompt, no Argon2id re-run).
                if let Some(kek) = crate::credstore::agent_get(profile) {
                    if let Ok(inner) = env.open_with_kek(&kek) {
                        return Ok(serde_json::from_slice(&inner)?);
                    }
                    // Stale/rotated KEK: fall through to passphrase.
                }
                // 2) passphrase (env var or interactive prompt). Refresh the
                //    agent so subsequent commands in the TTL don't re-prompt.
                let pass = crate::credstore::resolve_passphrase(
                    None, &format!("Passphrase for profile '{profile}': "), false)?;
                let kek = env.derive_kek(&pass)?;
                let inner = env.open_with_kek(&kek)?;
                let _ = crate::credstore::agent_store(
                    profile, &kek, crate::credstore::DEFAULT_AGENT_TTL_SECS);
                return Ok(serde_json::from_slice(&inner)?);
            }
        }
        // Legacy plaintext profile.
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Generate a fresh random Client Master Key if this session doesn't have
    /// one yet, returning whether a new one was minted. Called at login so
    /// every encrypted profile carries a rotation-stable CMK.
    pub fn ensure_cmk(&mut self) -> bool {
        if self.cmk.is_some() { return false; }
        use base64::Engine as _;
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        self.cmk = Some(base64::engine::general_purpose::STANDARD.encode(k));
        true
    }

    /// Decode the 32-byte CMK, if present.
    pub fn cmk_bytes(&self) -> Option<[u8; 32]> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.cmk.as_ref()?).ok()?;
        if raw.len() != 32 { return None; }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Some(out)
    }

    /// Encrypt + save into a named profile under `passphrase`, seed the unlock
    /// agent so the next command doesn't re-prompt, and mark the profile
    /// active. This is the Phase 2 login path — credentials are never written
    /// to disk in the clear.
    pub fn save_encrypted(&self, profile: &str, passphrase: &str) -> Result<PathBuf> {
        let inner = serde_json::to_vec(self)?;
        let env = crate::credstore::seal_profile(passphrase, &inner)?;
        let kek = env.derive_kek(passphrase)?;
        let path = Self::path_for(profile)?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(&path, serde_json::to_vec_pretty(&env)?)?;
        Self::harden(&path)?;
        let _ = crate::credstore::agent_store(
            profile, &kek, crate::credstore::DEFAULT_AGENT_TTL_SECS);
        Self::write_active_pointer(profile)?;
        Ok(path)
    }

    /// Save into the active profile and mark it active (plaintext — legacy /
    /// internal use only; the login path uses [`save_encrypted`]).
    pub fn save(&self) -> Result<PathBuf> {
        self.save_named(&active_profile())
    }

    /// Save into a named profile as plaintext and persist it as the active
    /// pointer. Retained for back-compat; new logins use [`save_encrypted`].
    pub fn save_named(&self, profile: &str) -> Result<PathBuf> {
        let path = Self::path_for(profile)?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        Self::harden(&path)?;
        Self::write_active_pointer(profile)?;
        Ok(path)
    }

    /// Best-effort `0600` on POSIX; no-op elsewhere.
    fn harden(path: &std::path::Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        #[cfg(not(unix))]
        { let _ = path; }
        Ok(())
    }

    /// Delete the active profile's file. Returns whether anything was removed.
    pub fn clear() -> Result<bool> {
        Self::clear_named(&active_profile())
    }

    /// Delete a named profile's file (and legacy file if `default`).
    pub fn clear_named(profile: &str) -> Result<bool> {
        let mut removed = false;
        let path = Self::path_for(profile)?;
        if path.exists() { fs::remove_file(&path)?; removed = true; }
        if profile == "default" {
            let legacy = Self::legacy_path()?;
            if legacy.exists() { fs::remove_file(&legacy)?; removed = true; }
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// API response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Whoami { pub id: String, pub name: String, pub role: String, pub auth_method: String }

#[derive(Debug, Deserialize)]
pub struct StoreResponse {
    pub resource_id: String, pub resource_name: String,
    pub created_at: String, pub encryption_method: String, pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct RetrieveResponse {
    pub resource_id: String, pub resource_name: String, pub data: String,
    pub created_at: String, pub updated_at: String,
    /// True for client-side ("external") secrets: `data` is empty and
    /// `envelope` carries the base64 opaque blob to decrypt locally.
    #[serde(default)] pub external: bool,
    #[serde(default)] pub envelope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteResponse { pub deleted: bool, pub resource_id: String, pub deleted_at: String }

/// Resource policy flags as returned in list views. Mirrors
/// `auth::ResourceFlags`; all optional so older servers still deserialize.
#[derive(Debug, Default, Deserialize)]
pub struct ResourceFlagsView {
    #[serde(default)] pub mfa_required: bool,
    #[serde(default)] pub delete_on_read: bool,
    #[serde(default)] pub max_reads: Option<i64>,
    #[serde(default)] pub rotate_on_read: bool,
    #[serde(default)] pub preserve_on_cleanup: bool,
    #[serde(default)] pub no_overwrite: bool,
}

#[derive(Debug, Deserialize)]
pub struct ResourceSummary {
    pub resource_id: String, pub resource_name: String,
    pub created_at: String, pub updated_at: String,
    /// Populated when the secret was tombstoned by `max_reads` exhaustion;
    /// its crypto material is gone but the name slot is still occupied.
    #[serde(default)]
    pub exhausted_at: Option<String>,
    /// True for client-side ("external") secrets — the server can't read it.
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub read_count: i64,
    #[serde(default)]
    pub flags: ResourceFlagsView,
    /// K-of-N threshold (if any) + how many signatories are configured.
    #[serde(default)]
    pub threshold_k: Option<i64>,
    #[serde(default)]
    pub signatory_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ListResources { pub resources: Vec<ResourceSummary>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct CleanupResponse {
    pub deleted: usize,
    #[serde(default)] pub secrets_deleted: usize,
    #[serde(default)] pub files_deleted: usize,
    pub preserved: i64,
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Health { pub status: String, pub database: String, pub version: String, pub uptime: u64 }

#[derive(Debug, Deserialize)]
pub struct NewClient {
    pub id: String, pub name: String, pub role: String,
    pub token: String,
    pub cert_pem: String, pub key_pem: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientSummary {
    pub id: String, pub name: String, pub role: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientList { pub clients: Vec<ClientSummary>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct AclSummary {
    pub id: String,
    pub domain: String,
    pub client_name: Option<String>,
    pub group_domain: Option<String>,
    pub resource_pattern: String,
    pub actions: Vec<String>,
    pub granted_at: String,
    pub expires_at: Option<String>,
    pub not_before: Option<String>,
    pub max_uses: Option<i32>,
    pub use_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct AclList { pub entries: Vec<AclSummary>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct AuditEntry {
    pub id: i64, pub ts: String,
    pub client_id: Option<String>, pub client_name: Option<String>,
    pub action: String, pub resource: Option<String>,
    pub status: String, pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditList { pub entries: Vec<AuditEntry>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct FileSummary {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub size: i64,
    pub mime_type: Option<String>,
    pub content_hash: String,
    pub created_at: String,
    pub updated_at: String,
    /// Client-side storage kind: "" (normal), "key" (external-key), "resident".
    #[serde(default)]
    pub external: String,
    #[serde(default)]
    pub read_count: i64,
    #[serde(default)]
    pub flags: ResourceFlagsView,
    #[serde(default)]
    pub exhausted_at: Option<String>,
    #[serde(default)]
    pub threshold_k: Option<i64>,
    #[serde(default)]
    pub signatory_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct FileList { pub files: Vec<FileSummary>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct ApiError { pub error: String, pub message: String }

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

pub struct BlackbookClient {
    http: Client,
    server: String,
    token: Option<String>,
    /// Current working domain; passed as `?domain=` on every resource call.
    /// Defaults to `default`.
    domain: String,
    /// Optional TOTP code for the current request batch; sent as
    /// `X-Blackbook-MFA` on every call when set.
    mfa: Option<String>,
}

/// Per-resource flag bag sent on `put`. Mirrors `auth::ResourceFlags`.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ResourceFlagsRequest {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mfa_required: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub delete_on_read: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_reads: Option<i64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rotate_on_read: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub preserve_on_cleanup: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_overwrite: bool,
}

/// K-of-N approval policy attached to a resource at store-time.
#[derive(Debug, Clone, Serialize)]
pub struct AccessPolicyRequest {
    pub threshold_k: i32,
    pub signatories: Vec<String>,
}

/// Options for `file_put` — mirrors the secret `put` policy surface. Sent as
/// query parameters since the request body carries the raw file bytes.
#[derive(Debug, Default)]
pub struct FilePutOpts<'a> {
    pub mime: Option<&'a str>,
    pub mfa_required: bool,
    pub delete_on_read: bool,
    pub max_reads: Option<i64>,
    pub rotate_on_read: bool,
    pub preserve_on_cleanup: bool,
    pub no_overwrite: bool,
    pub overwrite: bool,
    pub quorum: Option<i32>,
    pub signatories: Vec<String>,
    /// Client-side ("external") upload: `body` is already the client's
    /// ciphertext and `external_meta` is the base64 {salt, wrapped_dek}.
    pub external: bool,
    pub external_meta: Option<String>,
    /// Resident (Phase 4): the ciphertext stays on the client; `body` is empty
    /// unless `server_copy` is set. `key_component` is the base64 server half
    /// of the split file key.
    pub resident: bool,
    pub key_component: Option<String>,
    pub server_copy: bool,
}

/// Full result of a file download. `bytes` is the body (client ciphertext for
/// external files, plaintext for normal, empty for resident-no-copy). For a
/// resident file `key_component` carries the server's half of the split key.
#[derive(Debug)]
pub struct FileDownload {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub external_meta: Option<String>,
    pub key_component: Option<String>,
    pub resident: bool,
}

#[derive(Debug, Deserialize)]
pub struct AccessRequestSummary {
    pub id: String,
    pub requester: String,
    pub resource_kind: String,
    pub domain: String,
    pub resource_name: String,
    pub threshold_k: i32,
    pub signatories: Vec<String>,
    pub approvers: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct AccessRequestList {
    pub requests: Vec<AccessRequestSummary>,
    pub count: usize,
}

#[derive(Debug, Deserialize)]
pub struct AccessGrantSummary {
    pub id: String,
    pub signatory: String,
    pub grantee: String,
    pub domain: String,
    pub resource_kind: String,
    pub pattern: String,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    #[serde(default)] pub not_before: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct AccessGrantList {
    pub grants: Vec<AccessGrantSummary>,
    pub count: usize,
}

/// Options for creating an advance-approval grant.
#[derive(Debug, Default)]
pub struct GrantAddOpts {
    pub resource_kind: String,      // "secret" | "file"
    pub max_uses: Option<i32>,
    pub ttl_hours: Option<i64>,
    pub expires_at: Option<String>, // RFC3339
    pub not_before: Option<String>, // RFC3339
}

#[derive(Debug, Deserialize)]
pub struct MfaEnrollResponse {
    pub provisioning_uri: String,
    pub secret_base32: String,
    pub instructions: String,
}

/// Options for the ACL grant command. Subject is exactly one of
/// `client_name` (direct grant) or `group_domain` (group grant).
#[derive(Debug, Default)]
pub struct GrantOpts {
    pub client_name: Option<String>,
    pub group_domain: Option<String>,
    pub domain: Option<String>,
    pub expires_at: Option<String>,
    pub not_before: Option<String>,
    pub max_uses: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct DomainSummary {
    pub id: String, pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DomainList { pub domains: Vec<DomainSummary>, pub count: usize }

#[derive(Debug, Deserialize)]
pub struct MemberSummary {
    pub client_name: String,
    pub role: String,
    pub added_at: String,
}

#[derive(Debug, Deserialize)]
pub struct MemberList { pub members: Vec<MemberSummary>, pub count: usize }

impl BlackbookClient {
    pub fn from_session(session: &Session) -> Result<Self> {
        let mut builder = reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(60))
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3);

        // Pin to the Blackbook CA if available; otherwise fall back to
        // accept-invalid (only used during the very first `login` against
        // a fresh server with self-signed certs).
        if let Some(ca_pem) = &session.ca_pem {
            let ca_cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())
                .map_err(|e| ClientError::TlsConfig(format!("ca cert: {e}")))?;
            builder = builder
                .add_root_certificate(ca_cert)
                .tls_built_in_root_certs(false);
        } else {
            // First contact — operator has the CA, we don't yet. Allow the
            // session to be created; the CA gets pinned on subsequent calls
            // if the operator passes --ca to `login`.
            builder = builder.danger_accept_invalid_certs(true);
        }

        // mTLS client identity, if we have one.
        if let (Some(cert), Some(key)) = (&session.cert_pem, &session.key_pem) {
            // reqwest's rustls backend wants a single PEM containing cert + key.
            let combined = format!("{cert}\n{key}");
            let identity = Identity::from_pem(combined.as_bytes())
                .map_err(|e| ClientError::TlsConfig(format!("client identity: {e}")))?;
            builder = builder.identity(identity);
        }

        let http = builder.build()?;
        Ok(Self {
            http,
            server: session.server.trim_end_matches('/').to_string(),
            token: session.token.clone(),
            domain: "default".to_string(),
            mfa: None,
        })
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into(); self
    }
    /// The domain this client is scoped to (`default` if unset).
    pub fn domain(&self) -> &str { &self.domain }
    pub fn with_mfa(mut self, code: impl Into<String>) -> Self {
        self.mfa = Some(code.into()); self
    }

    async fn handle<T: serde::de::DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() { return Ok(resp.json::<T>().await?); }
        let body = resp.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiError>(&body).map(|e| e.message).unwrap_or(body);
        Err(ClientError::Api { status: status.as_u16(), message })
    }

    /// Returns (bytes, content_type, external_meta_b64). The third is set when
    /// the server flags the download as a client-side ("external") file via
    /// `X-Blackbook-External: 1` + `X-Blackbook-External-Meta`.
    async fn handle_bytes(&self, resp: reqwest::Response) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
        let d = self.handle_download(resp).await?;
        Ok((d.bytes, d.content_type, d.external_meta))
    }

    /// Full download result, including the Phase 4 resident key component.
    async fn handle_download(&self, resp: reqwest::Response) -> Result<FileDownload> {
        let status = resp.status();
        let ct = resp.headers().get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let ext_meta = if resp.headers().get("X-Blackbook-External").is_some() {
            resp.headers().get("X-Blackbook-External-Meta")
                .and_then(|v| v.to_str().ok()).map(|s| s.to_string())
                .or(Some(String::new()))
        } else { None };
        let key_component = resp.headers().get("X-Blackbook-Key-Component")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let resident = resp.headers().get("X-Blackbook-Resident").is_some();
        if status.is_success() {
            return Ok(FileDownload {
                bytes: resp.bytes().await?.to_vec(),
                content_type: ct, external_meta: ext_meta, key_component, resident,
            });
        }
        let body = resp.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiError>(&body).map(|e| e.message).unwrap_or(body);
        Err(ClientError::Api { status: status.as_u16(), message })
    }

    fn url(&self, path: &str) -> String { format!("{}{}", self.server, path) }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut rb = self.http.request(method, self.url(path));
        if let Some(t) = &self.token { rb = rb.bearer_auth(t); }
        if let Some(c) = &self.mfa { rb = rb.header("X-Blackbook-MFA", c); }
        rb
    }

    /// Append `?domain=` if the current domain isn't `default`.
    fn req_in_domain(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        if self.domain == "default" {
            self.req(method, path)
        } else {
            let sep = if path.contains('?') { '&' } else { '?' };
            let url = format!("{}{}{}domain={}", self.server, path, sep, urlencoding_simple(&self.domain));
            let mut rb = self.http.request(method, url);
            if let Some(t) = &self.token { rb = rb.bearer_auth(t); }
            if let Some(c) = &self.mfa { rb = rb.header("X-Blackbook-MFA", c); }
            rb
        }
    }

    pub async fn health(&self) -> Result<Health> {
        let resp = self.req(reqwest::Method::GET, "/health").send().await?;
        self.handle(resp).await
    }

    pub async fn whoami(&self) -> Result<Whoami> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/whoami").send().await?;
        self.handle(resp).await
    }

    pub async fn store(
        &self, name: &str, data: &str,
        description: Option<&str>,
        flags: Option<&ResourceFlagsRequest>,
        policy: Option<&AccessPolicyRequest>,
        overwrite: bool,
    ) -> Result<StoreResponse> {
        self.store_inner(name, data, description, flags, policy, overwrite, None).await
    }

    /// Store a client-side ("external") secret: `envelope_b64` is the opaque
    /// blob the server keeps but can't open. `data` is empty/ignored.
    pub async fn store_external(
        &self, name: &str, envelope_b64: &str,
        flags: Option<&ResourceFlagsRequest>,
        policy: Option<&AccessPolicyRequest>,
        overwrite: bool,
    ) -> Result<StoreResponse> {
        self.store_inner(name, "", None, flags, policy, overwrite, Some(envelope_b64)).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_inner(
        &self, name: &str, data: &str,
        description: Option<&str>,
        flags: Option<&ResourceFlagsRequest>,
        policy: Option<&AccessPolicyRequest>,
        overwrite: bool,
        external: Option<&str>,
    ) -> Result<StoreResponse> {
        let body = serde_json::json!({
            "resource_name": name,
            "data": data,
            "description": description,
            "flags": flags,
            "access_policy": policy,
            "overwrite": overwrite,
            "external": external,
        });
        let resp = self.req_in_domain(reqwest::Method::POST, "/api/v1/store").json(&body).send().await?;
        self.handle(resp).await
    }

    /// Retrieve, optionally presenting an approved access-request id via
    /// the `X-Blackbook-Request-Id` header.
    pub async fn retrieve_with_request(
        &self, id_or_name: &str, request_id: Option<&str>,
    ) -> Result<RetrieveResponse> {
        let body = serde_json::json!({"resource_id": id_or_name});
        let mut rb = self.req_in_domain(reqwest::Method::POST, "/api/v1/retrieve").json(&body);
        if let Some(rid) = request_id {
            rb = rb.header("X-Blackbook-Request-Id", rid);
        }
        let resp = rb.send().await?;
        self.handle(resp).await
    }

    /// Approve someone else's pending access request.
    pub async fn approve_request(&self, id: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/access-requests/{}/approve", urlencoding_simple(id));
        let resp = self.req(reqwest::Method::POST, &url).send().await?;
        self.handle(resp).await
    }

    /// List access requests visible to the caller (theirs + ones they sign).
    pub async fn list_access_requests(&self) -> Result<AccessRequestList> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/access-requests").send().await?;
        self.handle(resp).await
    }

    /// Fetch a single access request by id (caller must be requester,
    /// signatory, or admin).
    pub async fn get_access_request(&self, id: &str) -> Result<AccessRequestSummary> {
        let url = format!("/api/v1/access-requests/{}", urlencoding_simple(id));
        let resp = self.req(reqwest::Method::GET, &url).send().await?;
        self.handle(resp).await
    }

    /// Create an advance-approval grant (caller is the signatory).
    pub async fn create_access_grant(
        &self, grantee: &str, pattern: &str, opts: &GrantAddOpts,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "grantee": grantee,
            "pattern": pattern,
            "resource_kind": if opts.resource_kind.is_empty() { "secret" } else { &opts.resource_kind },
            "max_uses": opts.max_uses,
            "ttl_hours": opts.ttl_hours,
            "expires_at": opts.expires_at,
            "not_before": opts.not_before,
        });
        let resp = self.req_in_domain(reqwest::Method::POST, "/api/v1/access-grants").json(&body).send().await?;
        self.handle(resp).await
    }

    /// List advance grants the caller created or benefits from.
    pub async fn list_access_grants(&self) -> Result<AccessGrantList> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/access-grants").send().await?;
        self.handle(resp).await
    }

    /// Revoke an advance grant by id.
    pub async fn revoke_access_grant(&self, id: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/access-grants/{}", urlencoding_simple(id));
        let resp = self.req(reqwest::Method::DELETE, &url).send().await?;
        self.handle(resp).await
    }

    pub async fn mfa_enroll(&self) -> Result<MfaEnrollResponse> {
        let resp = self.req(reqwest::Method::POST, "/api/v1/mfa/enroll").send().await?;
        self.handle(resp).await
    }

    pub async fn mfa_verify(&self, code: &str) -> Result<serde_json::Value> {
        let body = serde_json::json!({"code": code});
        let resp = self.req(reqwest::Method::POST, "/api/v1/mfa/verify").json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn retrieve(&self, id_or_name: &str) -> Result<RetrieveResponse> {
        let body = serde_json::json!({"resource_id": id_or_name});
        let resp = self.req_in_domain(reqwest::Method::POST, "/api/v1/retrieve").json(&body).send().await?;
        self.handle(resp).await
    }

    /// Admin-only: purge tombstoned secrets in the current domain. Returns
    /// the count deleted, the count of preserve_on_cleanup rows that were
    /// kept, and the names of every row that was removed.
    pub async fn cleanup(&self) -> Result<CleanupResponse> {
        let resp = self.req_in_domain(reqwest::Method::POST, "/api/v1/cleanup").send().await?;
        self.handle(resp).await
    }

    pub async fn delete(&self, id_or_name: &str) -> Result<DeleteResponse> {
        let body = serde_json::json!({"resource_id": id_or_name, "confirm": true});
        let resp = self.req_in_domain(reqwest::Method::POST, "/api/v1/delete").json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn list(&self) -> Result<ListResources> {
        let resp = self.req_in_domain(reqwest::Method::GET, "/api/v1/list").send().await?;
        self.handle(resp).await
    }

    // Files

    pub async fn file_put(&self, name: &str, body: Vec<u8>, opts: &FilePutOpts<'_>) -> Result<FileSummary> {
        let url = format!("/api/v1/files/{}", urlencoding_simple(name));
        // Flags + K-of-N ride as query params (the body is the raw file).
        let mut qs: Vec<(String, String)> = Vec::new();
        if self.domain != "default" { qs.push(("domain".into(), self.domain.clone())); }
        if opts.mfa_required { qs.push(("mfa_required".into(), "true".into())); }
        if opts.delete_on_read { qs.push(("delete_on_read".into(), "true".into())); }
        if let Some(n) = opts.max_reads { qs.push(("max_reads".into(), n.to_string())); }
        if opts.rotate_on_read { qs.push(("rotate_on_read".into(), "true".into())); }
        if opts.preserve_on_cleanup { qs.push(("preserve_on_cleanup".into(), "true".into())); }
        if opts.no_overwrite { qs.push(("no_overwrite".into(), "true".into())); }
        if opts.overwrite { qs.push(("overwrite".into(), "true".into())); }
        if let Some(k) = opts.quorum { qs.push(("quorum".into(), k.to_string())); }
        if !opts.signatories.is_empty() { qs.push(("signatories".into(), opts.signatories.join(","))); }
        if opts.external { qs.push(("external".into(), "true".into())); }
        if let Some(m) = &opts.external_meta { qs.push(("meta".into(), m.clone())); }
        if opts.resident { qs.push(("resident".into(), "true".into())); }
        if let Some(kc) = &opts.key_component { qs.push(("key_component".into(), kc.clone())); }
        if opts.server_copy { qs.push(("server_copy".into(), "true".into())); }
        let mut rb = self.req(reqwest::Method::PUT, &url).query(&qs).body(body);
        if let Some(m) = opts.mime { rb = rb.header(reqwest::header::CONTENT_TYPE, m); }
        let resp = rb.send().await?;
        self.handle(resp).await
    }

    pub async fn file_get(&self, name: &str) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
        self.file_get_with_request(name, None).await
    }

    /// Download a file, optionally presenting an approved K-of-N request id.
    /// Returns (bytes, content_type, external_meta_b64) — the last is set for
    /// client-side ("external") files.
    pub async fn file_get_with_request(
        &self, name: &str, request_id: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
        let url = format!("/api/v1/files/{}", urlencoding_simple(name));
        let mut rb = self.req_in_domain(reqwest::Method::GET, &url);
        if let Some(rid) = request_id {
            rb = rb.header("X-Blackbook-Request-Id", rid);
        }
        let resp = rb.send().await?;
        self.handle_bytes(resp).await
    }

    /// Like [`file_get_with_request`] but returns the full [`FileDownload`],
    /// including the resident key component. Used by the resident-file path.
    pub async fn file_get_download(
        &self, name: &str, request_id: Option<&str>,
    ) -> Result<FileDownload> {
        let url = format!("/api/v1/files/{}", urlencoding_simple(name));
        let mut rb = self.req_in_domain(reqwest::Method::GET, &url);
        if let Some(rid) = request_id {
            rb = rb.header("X-Blackbook-Request-Id", rid);
        }
        let resp = rb.send().await?;
        self.handle_download(resp).await
    }

    pub async fn file_delete(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/files/{}", urlencoding_simple(name));
        let resp = self.req_in_domain(reqwest::Method::DELETE, &url).send().await?;
        self.handle(resp).await
    }

    pub async fn file_list(&self) -> Result<FileList> {
        let resp = self.req_in_domain(reqwest::Method::GET, "/api/v1/files").send().await?;
        self.handle(resp).await
    }

    pub async fn file_rotate(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/files/{}/rotate", urlencoding_simple(name));
        let resp = self.req_in_domain(reqwest::Method::POST, &url).send().await?;
        self.handle(resp).await
    }

    // Domains

    pub async fn create_domain(&self, name: &str, description: Option<&str>) -> Result<serde_json::Value> {
        let body = serde_json::json!({"name": name, "description": description});
        let resp = self.req(reqwest::Method::POST, "/api/v1/domains").json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn list_domains(&self) -> Result<DomainList> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/domains").send().await?;
        self.handle(resp).await
    }

    pub async fn add_domain_member(&self, domain: &str, client_name: &str, role: &str) -> Result<serde_json::Value> {
        let body = serde_json::json!({"client_name": client_name, "role": role});
        let url = format!("/api/v1/domains/{}/members", urlencoding_simple(domain));
        let resp = self.req(reqwest::Method::POST, &url).json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn list_domain_members(&self, domain: &str) -> Result<MemberList> {
        let url = format!("/api/v1/domains/{}/members", urlencoding_simple(domain));
        let resp = self.req(reqwest::Method::GET, &url).send().await?;
        self.handle(resp).await
    }

    pub async fn remove_domain_member(&self, domain: &str, client_name: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/domains/{}/members/{}", urlencoding_simple(domain), urlencoding_simple(client_name));
        let resp = self.req(reqwest::Method::DELETE, &url).send().await?;
        self.handle(resp).await
    }

    // Clients / ACL / Audit

    pub async fn create_client(&self, name: &str, role: &str, ttl_days: Option<i64>) -> Result<NewClient> {
        let body = serde_json::json!({"name": name, "role": role, "ttl_days": ttl_days});
        let resp = self.req(reqwest::Method::POST, "/api/v1/clients").json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn rotate_my_or_client(&self, name: &str, ttl_days: Option<i64>) -> Result<NewClient> {
        let url = format!("/api/v1/clients/{}/rotate", urlencoding_simple(name));
        let body = serde_json::json!({"ttl_days": ttl_days});
        let resp = self.req(reqwest::Method::POST, &url).json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn list_clients(&self) -> Result<ClientList> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/clients").send().await?;
        self.handle(resp).await
    }

    pub async fn revoke_client(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/clients/{}/revoke", urlencoding_simple(name));
        let resp = self.req(reqwest::Method::POST, &url).send().await?;
        self.handle(resp).await
    }

    pub async fn grant_acl(&self, pattern: &str, actions: &[&str], opts: GrantOpts) -> Result<serde_json::Value> {
        let actions: Vec<String> = actions.iter().map(|s| (*s).to_string()).collect();
        let body = serde_json::json!({
            "client_name":     opts.client_name,
            "group_domain":    opts.group_domain,
            "domain":          opts.domain,
            "resource_pattern": pattern,
            "actions":         actions,
            "expires_at":      opts.expires_at,
            "not_before":      opts.not_before,
            "max_uses":        opts.max_uses,
        });
        let resp = self.req(reqwest::Method::POST, "/api/v1/acl").json(&body).send().await?;
        self.handle(resp).await
    }

    pub async fn list_acl(&self) -> Result<AclList> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/acl").send().await?;
        self.handle(resp).await
    }

    pub async fn revoke_acl(&self, id: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/acl/{id}");
        let resp = self.req(reqwest::Method::DELETE, &url).send().await?;
        self.handle(resp).await
    }

    pub async fn audit(&self, limit: i64) -> Result<AuditList> {
        let url = format!("/api/v1/audit?limit={limit}");
        let resp = self.req(reqwest::Method::GET, &url).send().await?;
        self.handle(resp).await
    }

    /// Verify the audit log hash chain. Returns the server's verdict as a
    /// raw JSON value: `{ok: true, verified_through: N}` or
    /// `{ok: false, verified_through: N, first_bad_id: M, reason: "…"}`.
    pub async fn audit_verify(&self) -> Result<serde_json::Value> {
        let resp = self.req(reqwest::Method::GET, "/api/v1/audit/verify").send().await?;
        self.handle(resp).await
    }
}

/// Percent-encode a path segment (handles spaces, slashes-in-name, etc.).
/// Pulled in-line to avoid yet another crate.
fn urlencoding_simple(s: &str) -> String {
    const ALLOWED: &[u8] = b"-_.~";
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || ALLOWED.contains(b) {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
