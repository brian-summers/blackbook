// Blackbook Server Module
// HTTPS-only REST API with bearer-token + mTLS auth, per-resource ACLs, an
// append-only audit log, and file storage backed by encrypted blobs on disk.

use actix_web::http::StatusCode;
use actix_web::{middleware, web, App, HttpResponse, HttpServer, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::auth::{
    self, acl_check, acl_record_use, action_name, audit, AclDecision, AuditStatus,
    AuthenticatedClient, PeerCertInfo, ResourceFlags,
};
use sqlx::types::Json as SqlxJson;
use crate::blackbook_core::{
    aead_open, aead_seal, decrypt_aes_gcm, encrypt_aes_gcm, AclAction, BlackbookKey, Id,
};
use crate::audit_archive;
use crate::tls::SharedCa;

// ---------------------------------------------------------------------------
// Request / response shapes (secrets — unchanged from prior round)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoreRequest {
    pub resource_name: String,
    pub description: Option<String>,
    pub data: String,
    /// Optional resource-policy flags — see [`auth::ResourceFlags`].
    #[serde(default)]
    pub flags: Option<auth::ResourceFlags>,
    /// Optional K-of-N approval policy. When set, reads require an open
    /// access-request with at least `threshold_k` distinct approvers from
    /// the named signatories.
    #[serde(default)]
    pub access_policy: Option<AccessPolicy>,
    /// If `false` (the default), storing a secret whose name already exists
    /// returns 409 Conflict. Set to `true` to intentionally replace the
    /// existing value; the caller must also hold `update` permission.
    #[serde(default)]
    pub overwrite: bool,
    /// Client-side ("external") storage: a base64 opaque envelope the client
    /// produced ({salt, wrapped_dek, ciphertext}). When set, the server stores
    /// it verbatim and never sees the plaintext or the data key — `data` is
    /// ignored. Decryption requires the client passphrase, which never leaves
    /// the client.
    #[serde(default)]
    pub external: Option<String>,
}

/// K-of-N approval policy attached to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Number of distinct signatories whose approval is required before the
    /// resource can be read. Must be 1..=signatories.len().
    pub threshold_k: i32,
    /// Client *names* allowed to approve. The server resolves these to ids
    /// at enforcement time so client renames don't silently invalidate
    /// policies.
    pub signatories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    pub status: String,  // "pending" | "ready" | "consumed" | "expired"
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoreResponse {
    pub resource_id: String,
    pub resource_name: String,
    pub created_at: String,
    pub encryption_method: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRequest { pub resource_id: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveResponse {
    pub resource_id: String,
    pub resource_name: String,
    pub data: String,
    pub created_at: String,
    pub updated_at: String,
    /// True when this is a client-side ("external") secret: `data` is empty
    /// and `envelope` carries the base64 opaque blob for the client to
    /// decrypt with its passphrase.
    #[serde(default)]
    pub external: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeleteRequest { pub resource_id: String, pub confirm: bool }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeleteResponse { pub deleted: bool, pub resource_id: String, pub deleted_at: String }

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String, pub database: String,
    pub version: String, pub uptime: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoamiResponse {
    pub id: String, pub name: String, pub role: String,
    pub auth_method: String,
    /// The caller's private user domain (`~<name>`), if it exists. Lets the CLI
    /// default a fresh profile to the user's own domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default = "default_user_role")]
    pub role: String,
    pub ttl_days: Option<i64>,
}
fn default_user_role() -> String { "user".into() }

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateClientRequest {
    pub ttl_days: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientSummary {
    pub id: String, pub name: String, pub role: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrantAclRequest {
    /// Either a client name (direct grant) or `null` if `group_domain` is set.
    pub client_name: Option<String>,
    /// Either a domain name (group grant — applies to every member of that
    /// domain) or `null` if `client_name` is set.
    pub group_domain: Option<String>,
    /// Which domain this grant lives in (i.e. where the protected resources
    /// are). Defaults to `default`.
    #[serde(default)]
    pub domain: Option<String>,
    pub resource_pattern: String,
    pub actions: Vec<String>,
    /// Optional RFC3339 expiry. NULL = never.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Optional RFC3339 activation time. NULL = active immediately.
    #[serde(default)]
    pub not_before: Option<String>,
    /// Cap on the number of times this grant can authorize an action.
    #[serde(default)]
    pub max_uses: Option<i32>,
    /// Rate limit: at most `rate_max` authorizations per `rate_period_secs`
    /// (fixed window). Both must be set together, or neither.
    #[serde(default)]
    pub rate_max: Option<i32>,
    #[serde(default)]
    pub rate_period_secs: Option<i32>,
    /// 5-field cron schedule of allowed-access windows (mask semantics).
    /// NULL = always allowed. e.g. `* 9-17 * * 1-5` = weekdays 9–5.
    #[serde(default)]
    pub schedule: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_max: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_period_secs: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

// Domains

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub client_name: String,
    #[serde(default = "default_member_role")]
    pub role: String,
}
fn default_member_role() -> String { "user".to_string() }

#[derive(Debug, Serialize, Deserialize)]
pub struct MemberSummary {
    pub client_name: String,
    pub role: String,
    pub added_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64, pub ts: String,
    pub client_id: Option<String>, pub client_name: Option<String>,
    pub action: String, pub resource: Option<String>,
    pub status: String, pub message: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileSummary {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub size: i64,
    pub mime_type: Option<String>,
    pub content_hash: String,
    pub created_at: String,
    pub updated_at: String,
    /// Client-side storage kind: "" (normal), "key" (external-key), or
    /// "resident". Only populated by list views.
    #[serde(default)]
    pub external: String,
    #[serde(default)]
    pub read_count: i64,
    #[serde(default)]
    pub flags: ResourceFlags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exhausted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_k: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatory_count: Option<usize>,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<RwLock<BlackbookKey>>,
    pub db: PgPool,
    pub start_time: std::time::SystemTime,
    pub ca: SharedCa,
    pub data_dir: PathBuf,
    /// 32-byte key derived from `BlackbookKey::hmac` at boot. Used to MAC
    /// the audit log hash chain. Kept on the AppState (not re-derived on
    /// every call) because audit writes happen on every request and the
    /// scrypt-derived handle is non-trivial to recompute.
    pub audit_hmac_key: Arc<Vec<u8>>,
    /// 32-byte key derived from `BlackbookKey::index` at boot. Used to
    /// HMAC resource names into opaque `name_id` lookup ids so the
    /// plaintext name doesn't appear in WHERE clauses or query logs.
    pub name_index_key: Arc<Vec<u8>>,
    /// 32-byte AES key derived from `BlackbookKey::index.handle_with_info(
    /// b"metadata-enc/v1")`. Used to encrypt *all* user-supplied metadata at
    /// rest (resource names, client/domain names, ACL patterns, audit
    /// resource/message, file mime/hash/size, …) via `enc_field` /
    /// `dec_field`. A DB-only attacker without this key sees only opaque
    /// IDs, ciphertext, and timestamps.
    pub metadata_enc_key: Arc<Vec<u8>>,
    /// In-memory registry of live client↔client tunnels (the relay pairs two
    /// mTLS-authenticated clients and forwards opaque E2E frames). Ephemeral —
    /// no DB row; see [`crate::tunnel_relay`].
    pub tunnels: crate::tunnel_relay::TunnelHub,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn request_id() -> String { uuid::Uuid::new_v4().to_string() }

/// Length-prefixed keyed SHA3-256 used for every deterministic lookup id
/// in the database. The `scope` string is a domain-separation tag so that
/// e.g. a resource-name id and a client-name id derived from the same key
/// can never collide. Output is 64 hex chars (32 bytes).
pub fn hmac_id(index_key: &[u8], scope: &[u8], parts: &[&[u8]]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(scope);
    h.update(&[0u8]);
    h.update(&(index_key.len() as u32).to_be_bytes());
    h.update(index_key);
    for p in parts {
        h.update(&(p.len() as u32).to_be_bytes());
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// HMAC a resource (secret/file) name into the opaque `name_id` used for DB
/// lookups. Deterministic for a given `(domain_id, name)` so the same name
/// in the same domain always maps to the same id — but the plaintext name
/// never appears in a `WHERE` clause or query log.
pub fn name_id_hex(index_key: &[u8], domain_id: &str, name: &str) -> String {
    hmac_id(index_key, b"blackbook-name-id/v1",
            &[domain_id.as_bytes(), name.as_bytes()])
}

/// HMAC a client name into the opaque `clients.name_id` used for lookup.
pub fn client_name_id_hex(index_key: &[u8], name: &str) -> String {
    hmac_id(index_key, b"blackbook-client-name-id/v1", &[name.as_bytes()])
}

/// HMAC a domain name into the opaque `domains.name_id` used for lookup.
pub fn domain_name_id_hex(index_key: &[u8], name: &str) -> String {
    hmac_id(index_key, b"blackbook-domain-name-id/v1", &[name.as_bytes()])
}

/// HMAC a file's plaintext SHA3 content hash. The encrypted content-on-disk
/// path still binds to the original hash for integrity checks (decrypt →
/// rehash → compare HMAC), but the column itself reveals nothing to a DB
/// thief — they can no longer ask "do you have file with SHA3 X?".
pub fn file_hash_id_hex(index_key: &[u8], plaintext_hash_hex: &str) -> String {
    hmac_id(index_key, b"blackbook-file-hash-id/v1", &[plaintext_hash_hex.as_bytes()])
}

/// Deterministically map a string to a 64-bit key for Postgres advisory
/// locks (`pg_advisory_xact_lock`). Used to serialize find-or-create on the
/// access-request dedup tuple without a unique constraint that would need a
/// nullable-aware partial index to also cover the consumed/expired cases.
fn advisory_key(s: &str) -> i64 {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    i64::from_be_bytes(d[..8].try_into().unwrap())
}

/// AEAD-encrypt one piece of metadata under the master `metadata_enc` key.
/// Random 12-byte nonce is prepended; output is `nonce || ciphertext || tag`.
/// Two encryptions of the same plaintext produce *different* ciphertexts —
/// equality / sort / filter on the resulting BYTEA column is not possible
/// by design, which is why every column we encrypt is paired with a
/// deterministic `*_id` HMAC for the lookup paths that need one.
pub fn enc_field(metadata_enc_key: &[u8], plaintext: &[u8]) -> std::result::Result<Vec<u8>, String> {
    aead_seal(plaintext, metadata_enc_key)
        .map_err(|e| format!("metadata encrypt: {e}"))
}

/// Inverse of `enc_field`. Returns plaintext bytes.
pub fn dec_field(metadata_enc_key: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, String> {
    aead_open(ciphertext, metadata_enc_key)
        .map_err(|e| format!("metadata decrypt: {e}"))
}

/// Encrypt a UTF-8 string with `enc_field` and return the ciphertext bytes.
pub fn enc_str(metadata_enc_key: &[u8], s: &str) -> std::result::Result<Vec<u8>, String> {
    enc_field(metadata_enc_key, s.as_bytes())
}

/// Decrypt a ciphertext to a UTF-8 string. Errors if the bytes aren't valid
/// UTF-8 — which would mean the column was overwritten with non-text data.
pub fn dec_str(metadata_enc_key: &[u8], ciphertext: &[u8]) -> std::result::Result<String, String> {
    let bytes = dec_field(metadata_enc_key, ciphertext)?;
    String::from_utf8(bytes).map_err(|e| format!("metadata decrypt: not utf-8: {e}"))
}

/// Query-string `?domain=NAME` that resource endpoints accept. Defaults to
/// the `default` domain so existing flows keep working without flags.
#[derive(Debug, Deserialize, Default)]
pub struct DomainQuery {
    #[serde(default)]
    pub domain: Option<String>,
}

impl DomainQuery {
    pub fn name(&self) -> &str { self.domain.as_deref().unwrap_or("default") }
}

/// Policy parameters accepted on `file put` as query-string fields (the body
/// is the raw file bytes, so flags can't ride in a JSON body the way they do
/// for secrets). Parsed alongside `DomainQuery` — each `web::Query` extractor
/// ignores fields it doesn't declare. Mirrors the secret `put` flags + K-of-N.
#[derive(Debug, Deserialize, Default)]
pub struct FilePolicyQuery {
    #[serde(default)] pub mfa_required: Option<bool>,
    #[serde(default)] pub delete_on_read: Option<bool>,
    #[serde(default)] pub max_reads: Option<i64>,
    #[serde(default)] pub rotate_on_read: Option<bool>,
    #[serde(default)] pub preserve_on_cleanup: Option<bool>,
    #[serde(default)] pub no_overwrite: Option<bool>,
    #[serde(default)] pub overwrite: Option<bool>,
    /// K-of-N threshold. Requires `signatories`.
    #[serde(default)] pub quorum: Option<i32>,
    /// Comma-separated client names allowed to approve.
    #[serde(default)] pub signatories: Option<String>,
    /// Client-side ("external") storage: the request body is already the
    /// client's ciphertext; the server stores it verbatim and keeps the
    /// base64 `meta` (salt + wrapped DEK) alongside.
    #[serde(default)] pub external: Option<bool>,
    /// base64 of the external meta ({salt, wrapped_dek}); required when
    /// `external=true`.
    #[serde(default)] pub meta: Option<String>,
    /// Phase 4 "resident" file: the ciphertext lives on the *client's* disk;
    /// the server stores only a manifest + the client-supplied `key_component`
    /// (the server's half of the split file key). Body is the client ciphertext
    /// only when `server_copy=true` (an opt-in encrypted backup); otherwise the
    /// body is discarded after hashing.
    #[serde(default)] pub resident: Option<bool>,
    /// base64 of the server's key-component half (`Kf_s`); required when
    /// `resident=true`. Stored wrapped under `file_dek_kek` at rest.
    #[serde(default)] pub key_component: Option<String>,
    /// Keep an encrypted backup copy of the client ciphertext server-side.
    #[serde(default)] pub server_copy: Option<bool>,
}

impl FilePolicyQuery {
    /// Build the `ResourceFlags` this upload should persist.
    fn flags(&self) -> ResourceFlags {
        ResourceFlags {
            mfa_required: self.mfa_required.unwrap_or(false),
            delete_on_read: self.delete_on_read.unwrap_or(false),
            max_reads: self.max_reads,
            rotate_on_read: self.rotate_on_read.unwrap_or(false),
            preserve_on_cleanup: self.preserve_on_cleanup.unwrap_or(false),
            no_overwrite: self.no_overwrite.unwrap_or(false),
        }
    }
    /// Parse the K-of-N policy (threshold + signatory names), if requested.
    fn access_policy(&self) -> std::result::Result<Option<AccessPolicy>, String> {
        match (self.quorum, self.signatories.as_deref()) {
            (None, None) | (None, Some("")) => Ok(None),
            (Some(_), None) | (Some(_), Some("")) =>
                Err("quorum requires signatories".into()),
            (None, Some(_)) =>
                Err("signatories requires quorum".into()),
            (Some(k), Some(s)) => {
                let sigs: Vec<String> = s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect();
                Ok(Some(AccessPolicy { threshold_k: k, signatories: sigs }))
            }
        }
    }
}

/// Resolve the domain or return a 404 response. Also enforces membership for
/// non-global-admins (admins skip this check).
async fn resolve_and_gate_domain(
    state: &AppState, client: &AuthenticatedClient, q: &DomainQuery,
) -> std::result::Result<(String, String), HttpResponse> {
    let domain_name = q.name();
    let id = match auth::resolve_domain(&state.db, &state.name_index_key, domain_name).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(err(StatusCode::NOT_FOUND, "no_such_domain",
                                  format!("domain '{}' does not exist", domain_name))),
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())),
    };
    let allowed = auth::domain_member(&state.db, client, &id).await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;
    if !allowed {
        return Err(err(StatusCode::FORBIDDEN, "not_member",
                      format!("not a member of domain '{}'", domain_name)));
    }
    Ok((id, domain_name.to_string()))
}

fn err(status: StatusCode, code: &str, message: impl Into<String>) -> HttpResponse {
    HttpResponse::build(status).json(ErrorResponse {
        error: code.into(), message: message.into(), request_id: request_id(),
    })
}

fn parse_actions(actions: &[String]) -> std::result::Result<i32, String> {
    let mut mask = 0i32;
    for a in actions {
        match a.to_ascii_lowercase().as_str() {
            "create" => mask |= auth::action_bit(AclAction::Create),
            "read"   => mask |= auth::action_bit(AclAction::Read),
            "update" => mask |= auth::action_bit(AclAction::Update),
            "delete" => mask |= auth::action_bit(AclAction::Delete),
            other => return Err(format!("unknown action '{other}'")),
        }
    }
    if mask == 0 { return Err("at least one action required".into()); }
    Ok(mask)
}

fn actions_from_mask(mask: i32) -> Vec<String> {
    let mut out = Vec::new();
    if mask & auth::action_bit(AclAction::Create) != 0 { out.push("create".into()); }
    if mask & auth::action_bit(AclAction::Read)   != 0 { out.push("read".into()); }
    if mask & auth::action_bit(AclAction::Update) != 0 { out.push("update".into()); }
    if mask & auth::action_bit(AclAction::Delete) != 0 { out.push("delete".into()); }
    out
}

/// Extract `(threshold_k, signatory_count)` from a stored `access_policy`
/// JSONB blob, for list views. Returns `(None, None)` when there's no K-of-N
/// policy. The signatory *ids* are never exposed — only the count — so the
/// list reveals that a quorum is required without leaking who can approve.
fn policy_threshold(policy: Option<&SqlxJson<serde_json::Value>>) -> (Option<i64>, Option<usize>) {
    match policy {
        None => (None, None),
        Some(SqlxJson(v)) => {
            let k = v.get("threshold_k").and_then(|x| x.as_i64());
            let n = v.get("signatories").and_then(|x| x.as_array()).map(|a| a.len());
            (k, n)
        }
    }
}

fn require_admin(client: &AuthenticatedClient) -> std::result::Result<(), HttpResponse> {
    if client.is_admin() { Ok(()) } else {
        Err(err(StatusCode::FORBIDDEN, "forbidden", "admin role required"))
    }
}

/// Authorize a domain-scoped management action (ACL/member ops). Passes for a
/// global admin or an admin of `domain_id`. Domain admins are confined to
/// their own domain — this grants no global privilege.
async fn require_domain_admin(
    db: &PgPool, client: &AuthenticatedClient, domain_id: &str,
) -> std::result::Result<(), HttpResponse> {
    match auth::domain_admin(db, client, domain_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(err(StatusCode::FORBIDDEN, "forbidden",
                             "domain-admin role required for this domain")),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())),
    }
}

fn auth_method_str(m: auth::AuthMethod) -> &'static str {
    match m {
        auth::AuthMethod::MutualTlsAndToken => "mtls+token",
    }
}

// ---------------------------------------------------------------------------
// Public endpoint
// ---------------------------------------------------------------------------

pub async fn health_check(state: web::Data<AppState>) -> Result<HttpResponse> {
    let uptime = state.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let db_healthy = state.db.acquire().await.is_ok();
    Ok(HttpResponse::Ok().json(HealthResponse {
        status: if db_healthy { "healthy" } else { "degraded" }.into(),
        database: if db_healthy { "connected" } else { "disconnected" }.into(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime,
    }))
}

pub async fn whoami(
    state: web::Data<AppState>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let method = auth_method_str(client.auth_method);
    // Report the caller's private user domain (`~<name>`) when it exists, so the
    // CLI can default a fresh profile to it.
    let dname = auth::user_domain_name(&client.name);
    let dname_id = domain_name_id_hex(&state.name_index_key, &dname);
    let has_user_domain: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM blackbook_domains d
         JOIN blackbook_domain_members m ON m.domain_id = d.id
         WHERE d.name_id = $1 AND d.archived_at IS NULL AND m.client_id = $2 LIMIT 1",
    ).bind(&dname_id).bind(&client.id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(WhoamiResponse {
        id: client.id, name: client.name, role: client.role,
        auth_method: method.into(),
        user_domain: has_user_domain.map(|_| dname),
    }))
}

// ---------------------------------------------------------------------------
// Secrets endpoints (string secrets via blackbook_secrets)
// ---------------------------------------------------------------------------

pub async fn store_data(
    state: web::Data<AppState>,
    req: web::Json<StoreRequest>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    if req.resource_name.is_empty() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "store", None, AuditStatus::Error,
              Some("empty resource_name")).await;
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "resource_name cannot be empty"));
    }
    // Client-side ("external") storage: the value rides as an opaque base64
    // envelope the server can't open. When present, `data` is ignored.
    let external_blob: Option<Vec<u8>> = match req.external.as_deref() {
        Some(b64) => {
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64)
                .map_err(|_| actix_web::error::ErrorBadRequest("external envelope is not valid base64"))?;
            if bytes.is_empty() {
                return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "external envelope cannot be empty"));
            }
            Some(bytes)
        }
        None => None,
    };
    if external_blob.is_none() && req.data.is_empty() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "store", Some(&req.resource_name),
              AuditStatus::Error, Some("empty data")).await;
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "data cannot be empty"));
    }

    let (domain_id, _domain_name) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };

    let req_name_id = name_id_hex(&state.name_index_key, &domain_id, &req.resource_name);
    let existed: Option<(String, SqlxJson<ResourceFlags>)> = sqlx::query_as(
        "SELECT resource_id, flags FROM blackbook_secrets WHERE domain_id = $1 AND name_id = $2",
    )
    .bind(&domain_id).bind(&req_name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    if let Some((_, SqlxJson(existing_flags))) = &existed {
        // Immutable resources can never be replaced, even with overwrite=true.
        if existing_flags.no_overwrite {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "create", Some(&req.resource_name),
                  AuditStatus::Denied, Some("immutable: no_overwrite set")).await;
            return Ok(err(StatusCode::CONFLICT, "immutable",
                         format!("'{}' is immutable (no_overwrite) and cannot be replaced; delete it first",
                                 req.resource_name)));
        }
        if !req.overwrite {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "create", Some(&req.resource_name),
                  AuditStatus::Denied, Some("already exists; overwrite not requested")).await;
            return Ok(err(StatusCode::CONFLICT, "already_exists",
                         format!("'{}' already exists; set overwrite=true to replace it",
                                 req.resource_name)));
        }
    }

    let action = if existed.is_some() { AclAction::Update } else { AclAction::Create };

    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &req.resource_name, action).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), action_name(action),
              Some(&req.resource_name), AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to {} '{}'", action_name(action), req.resource_name)));
    }

    // For external secrets the server performs no *content* encryption — it
    // cannot, lacking the client key/passphrase. It still wraps the opaque
    // client envelope in its own at-rest AEAD below (see `external_at_rest`),
    // so a stolen database is worthless without the server's BlackbookKey.
    // Otherwise it applies the usual two-layer server-side envelope.
    let (layer1, layer2, wrapped): (Vec<u8>, Vec<u8>, String) = if external_blob.is_some() {
        (Vec::new(), Vec::new(), String::new())
    } else {
        let keys = state.keys.read().await;
        let primary = keys.secret_layer1.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let secondary = keys.secret_layer2.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let l1 = encrypt_aes_gcm(req.data.as_bytes(), &primary)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let l2 = encrypt_aes_gcm(&l1, &secondary)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let w = keys.serialize()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        (l1, l2, w)
    };
    let is_external = external_blob.is_some();
    // Defense in depth: wrap the already-client-encrypted envelope in the
    // server's metadata AEAD before it touches the DB. The server still can't
    // read the plaintext (it lacks the client factor), but a DB-only thief now
    // also needs the server's BlackbookKey to recover even the opaque envelope.
    let external_at_rest: Option<Vec<u8>> = match external_blob.as_deref() {
        Some(b) => Some(enc_field(&state.metadata_enc_key, b)
            .map_err(actix_web::error::ErrorInternalServerError)?),
        None => None,
    };
    let enc_method = if is_external { "client-side (external) + server at-rest" } else { "AES-256-GCM (2-layer)" };

    let now = chrono::Utc::now();
    let response = if let Some((existing_id, _)) = existed {
        sqlx::query(
            "UPDATE blackbook_secrets
             SET data_layer1 = $1, data_layer2 = $2, wrapped_key = $3,
                 is_external = $4, external_envelope = $5, encryption_method = $6, updated_at = $7
             WHERE resource_id = $8",
        )
        .bind(&layer1).bind(&layer2).bind(&wrapped)
        .bind(is_external).bind(external_at_rest.as_deref()).bind(enc_method).bind(now).bind(&existing_id)
        .execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        StoreResponse {
            resource_id: existing_id, resource_name: req.resource_name.clone(),
            created_at: now.to_rfc3339(),
            encryption_method: enc_method.into(),
            status: "updated".into(),
        }
    } else {
        let new_id = Id::new(32).to_hex();
        let flags_value = SqlxJson(req.flags.clone().unwrap_or_default());
        // Validate access policy if provided.
        if let Some(p) = &req.access_policy {
            if p.threshold_k < 1 || (p.threshold_k as usize) > p.signatories.len() {
                return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                             "threshold_k must be 1..=signatories.len()"));
            }
            if p.signatories.is_empty() {
                return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                             "signatories list must not be empty"));
            }
        }
        // Translate signatories (caller-supplied client *names*) into opaque
        // client ids before persisting, so the access_policy JSONB never
        // holds plaintext identifiers.
        let policy_value = match req.access_policy.as_ref() {
            None => None,
            Some(p) => {
                let mut ids: Vec<String> = Vec::with_capacity(p.signatories.len());
                for name in &p.signatories {
                    let row: Option<(String,)> = sqlx::query_as(
                        "SELECT id FROM blackbook_clients WHERE name_id = $1",
                    )
                    .bind(client_name_id_hex(&state.name_index_key, name))
                    .fetch_optional(&state.db).await
                    .map_err(actix_web::error::ErrorInternalServerError)?;
                    match row {
                        Some((cid,)) => ids.push(cid),
                        None => return Ok(err(StatusCode::BAD_REQUEST, "unknown_signatory",
                                              format!("signatory '{name}' is not a known client"))),
                    }
                }
                Some(SqlxJson(serde_json::json!({
                    "threshold_k": p.threshold_k,
                    "signatories": ids,
                })))
            }
        };
        let resource_name_enc = enc_str(&state.metadata_enc_key, &req.resource_name)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        sqlx::query(
            "INSERT INTO blackbook_secrets
             (resource_id, resource_name_enc, name_id, data_layer1, data_layer2, wrapped_key,
              is_external, external_envelope,
              created_at, updated_at, encryption_method, domain_id, flags, access_policy)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(&new_id).bind(&resource_name_enc).bind(&req_name_id).bind(&layer1).bind(&layer2)
        .bind(&wrapped).bind(is_external).bind(external_at_rest.as_deref())
        .bind(now).bind(now).bind(enc_method).bind(&domain_id)
        .bind(flags_value).bind(policy_value)
        .execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        StoreResponse {
            resource_id: new_id, resource_name: req.resource_name.clone(),
            created_at: now.to_rfc3339(),
            encryption_method: enc_method.into(),
            status: "stored".into(),
        }
    };
    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), action_name(action),
          Some(&req.resource_name), AuditStatus::Ok, None).await;
    Ok(HttpResponse::Created().json(response))
}

pub async fn retrieve_data(
    state: web::Data<AppState>,
    req: web::Json<RetrieveRequest>,
    q: web::Query<DomainQuery>,
    http_req: actix_web::HttpRequest,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    // Look up by resource_id or by the HMAC of the name — the plaintext
    // name never enters the WHERE clause (see name_id_hex).
    let lookup_name_id = name_id_hex(&state.name_index_key, &domain_id, &req.resource_id);
    let row: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>, String, String, String, SqlxJson<ResourceFlags>, i64, Option<SqlxJson<AccessPolicy>>, Option<chrono::NaiveDateTime>, bool, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT resource_id, resource_name_enc, data_layer1, data_layer2, wrapped_key,
                created_at::text, updated_at::text, flags, read_count, access_policy, exhausted_at,
                is_external, external_envelope
         FROM blackbook_secrets
         WHERE domain_id = $1 AND (resource_id = $2 OR name_id = $3)",
    )
    .bind(&domain_id).bind(&req.resource_id).bind(&lookup_name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((res_id, name_enc, _l1, data_l2, _wrapped, created, updated, SqlxJson(flags), read_count, policy_opt, exhausted_at, is_external, external_envelope)) = row else {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&req.resource_id),
              AuditStatus::NotFound, None).await;
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "resource not found"));
    };
    let res_name = dec_str(&state.metadata_enc_key, &name_enc)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &res_name, AclAction::Read).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
              AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to read '{res_name}'")));
    }

    // Tombstone: a previous read exhausted max_reads and scrubbed the crypto
    // material. The row is kept so the name slot remains occupied; reads
    // return 410 Gone (not 404 — the resource is *known* to have existed).
    if let Some(ts) = exhausted_at {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
              AuditStatus::Denied, Some("tombstoned: data was scrubbed at exhaustion")).await;
        return Ok(err(StatusCode::GONE, "exhausted",
                     format!("'{res_name}' was exhausted at {} and its data has been scrubbed",
                             ts.format("%Y-%m-%dT%H:%M:%SZ"))));
    }

    // Fast soft-reject if the stale snapshot already shows the limit reached
    // — avoids consuming a K-of-N approval / advance-grant use for a read that
    // the atomic claim below would refuse anyway. Not the enforcement point.
    if let Some(max) = flags.max_reads {
        if read_count >= max {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
                  AuditStatus::Denied, Some("max_reads exhausted")).await;
            return Ok(err(StatusCode::FORBIDDEN, "max_reads",
                         format!("'{res_name}' has reached its max_reads ({max})")));
        }
    }
    let _ = read_count; // superseded by the atomic claim below
    // K-of-N threshold gate (live approvals ∪ advance grants).
    if let Some(SqlxJson(policy)) = policy_opt.as_ref() {
        let request_id_hdr = http_req.headers().get("X-Blackbook-Request-Id")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        if let Some(resp) = threshold_gate(&state, &client, "secret", &domain_id, &res_name, policy, request_id_hdr).await? {
            return Ok(resp);
        }
    }

    if flags.mfa_required {
        let code = http_req.headers().get("X-Blackbook-MFA")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let Some(code) = code else {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
                  AuditStatus::Denied, Some("missing MFA")).await;
            return Ok(err(StatusCode::UNAUTHORIZED, "mfa_required",
                         "this resource requires X-Blackbook-MFA <code>"));
        };
        let kek_bytes = state.keys.read().await.mfa_secret_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let ok = auth::verify_totp(&state.db, &kek_bytes, &client.id, &code).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        if !ok {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
                  AuditStatus::Denied, Some("MFA verification failed")).await;
            return Ok(err(StatusCode::UNAUTHORIZED, "mfa_failed", "invalid TOTP code"));
        }
    }

    // Atomically claim this read BEFORE decrypting/serving, so concurrent
    // requests can't bypass max_reads / delete_on_read. The cap is the
    // tightest of max_reads and (1 for delete_on_read). The conditional
    // UPDATE … RETURNING either claims a slot (row returned) or refuses
    // (no row → already at the cap, or tombstoned in a race). An uncapped
    // resource just bumps the counter for stats.
    let cap: Option<i64> = match (flags.max_reads, flags.delete_on_read) {
        (Some(m), true) => Some(m.min(1)),
        (Some(m), false) => Some(m),
        (None, true) => Some(1),
        (None, false) => None,
    };
    let new_count: Option<i64> = if let Some(cap) = cap {
        let claimed: Option<(i64,)> = sqlx::query_as(
            "UPDATE blackbook_secrets SET read_count = read_count + 1
             WHERE resource_id = $1 AND exhausted_at IS NULL AND read_count < $2
             RETURNING read_count",
        ).bind(&res_id).bind(cap).fetch_optional(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        match claimed {
            Some((c,)) => Some(c),
            None => {
                audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name),
                      AuditStatus::Denied, Some("read limit reached (atomic claim)")).await;
                return Ok(err(StatusCode::FORBIDDEN, "max_reads",
                             format!("'{res_name}' has reached its read limit")));
            }
        }
    } else {
        let _ = sqlx::query("UPDATE blackbook_secrets SET read_count = read_count + 1 WHERE resource_id = $1")
            .bind(&res_id).execute(&state.db).await;
        None
    };

    // Produce the served payload. External secrets are returned as the opaque
    // client envelope (base64). The server peels only its own at-rest AEAD
    // (added in store_data) — it still cannot read the client's plaintext.
    // Normal secrets are peeled through the two server-side layers here.
    let (data_out, envelope_out): (String, Option<String>) = if is_external {
        use base64::Engine as _;
        let at_rest = external_envelope.clone().unwrap_or_default();
        let env = dec_field(&state.metadata_enc_key, &at_rest)
            .map_err(actix_web::error::ErrorInternalServerError)?;
        (String::new(), Some(base64::engine::general_purpose::STANDARD.encode(&env)))
    } else {
        let keys = state.keys.read().await;
        let primary = keys.secret_layer1.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let secondary = keys.secret_layer2.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let dec_l2 = decrypt_aes_gcm(&data_l2, &secondary)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let plain = decrypt_aes_gcm(&dec_l2, &primary)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let plain = String::from_utf8(plain)
            .map_err(|_| actix_web::error::ErrorInternalServerError("decrypted data is not UTF-8"))?;
        (plain, None)
    };

    // Post-read effects. The read slot is already claimed (counter bumped);
    // here we only tear down. delete_on_read wins over tombstoning.
    let reached_max = flags.max_reads
        .map(|m| new_count.map(|c| c >= m).unwrap_or(false))
        .unwrap_or(false);
    let post_note: Option<&'static str> = if flags.delete_on_read {
        let _ = sqlx::query("DELETE FROM blackbook_secrets WHERE resource_id = $1")
            .bind(&res_id).execute(&state.db).await;
        log::info!("delete_on_read consumed resource {res_name} (id {res_id})");
        Some("consumed by delete_on_read")
    } else if reached_max {
        // Final allowed read: scrub all crypto material in place — including
        // the external envelope — so nothing recoverable remains.
        let _ = sqlx::query(
            "UPDATE blackbook_secrets
             SET data_layer1 = ''::bytea, data_layer2 = ''::bytea, wrapped_key = '',
                 external_envelope = NULL, exhausted_at = NOW()
             WHERE resource_id = $1",
        ).bind(&res_id).execute(&state.db).await;
        log::info!("max_reads exhausted; tombstoned resource {res_name} (id {res_id})");
        Some("tombstoned: max_reads reached on this read")
    } else {
        None
    };

    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "read", Some(&res_name), AuditStatus::Ok,
          post_note).await;
    Ok(HttpResponse::Ok().json(RetrieveResponse {
        resource_id: res_id, resource_name: res_name,
        data: data_out, created_at: created, updated_at: updated,
        external: is_external, envelope: envelope_out,
    }))
}

pub async fn delete_data(
    state: web::Data<AppState>,
    req: web::Json<DeleteRequest>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    if !req.confirm {
        return Ok(err(StatusCode::BAD_REQUEST, "confirmation_required", "set confirm=true to delete"));
    }
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let lookup_name_id = name_id_hex(&state.name_index_key, &domain_id, &req.resource_id);
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT resource_id, resource_name_enc FROM blackbook_secrets
         WHERE domain_id = $1 AND (resource_id = $2 OR name_id = $3)",
    )
    .bind(&domain_id).bind(&req.resource_id).bind(&lookup_name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((res_id, name_enc)) = row else {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "delete", Some(&req.resource_id),
              AuditStatus::NotFound, None).await;
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "resource not found"));
    };
    let resource_name = dec_str(&state.metadata_enc_key, &name_enc)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &resource_name, AclAction::Delete).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "delete", Some(&resource_name),
              AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to delete '{resource_name}'")));
    }
    sqlx::query("DELETE FROM blackbook_secrets WHERE resource_id = $1")
        .bind(&res_id).execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "delete", Some(&resource_name),
          AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(DeleteResponse {
        deleted: true, resource_id: req.resource_id.clone(),
        deleted_at: chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn list_resources(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let rows: Vec<(String, Vec<u8>, String, String, Option<chrono::NaiveDateTime>, SqlxJson<ResourceFlags>, i64, Option<SqlxJson<serde_json::Value>>, bool)> = sqlx::query_as(
        "SELECT resource_id, resource_name_enc, created_at::text, updated_at::text, exhausted_at,
                flags, read_count, access_policy, is_external
         FROM blackbook_secrets WHERE domain_id = $1
         ORDER BY created_at DESC LIMIT 500",
    )
    .bind(&domain_id)
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let mut items = Vec::new();
    for (id, name_enc, created, updated, exhausted, SqlxJson(flags), read_count, policy_opt, is_external) in rows {
        let name = match dec_str(&state.metadata_enc_key, &name_enc) {
            Ok(n) => n,
            Err(e) => {
                log::warn!("list_resources: decrypt failed for {id}: {e}");
                continue;
            }
        };
        if !client.is_admin() {
            let dec = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Read).await
                .map_err(actix_web::error::ErrorInternalServerError)?;
            if !dec.is_allowed() { continue; }
        }
        let exhausted_str = exhausted.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let (threshold_k, signatory_count) = policy_threshold(policy_opt.as_ref());
        items.push(serde_json::json!({
            "resource_id": id, "resource_name": name,
            "created_at": created, "updated_at": updated,
            "exhausted_at": exhausted_str,
            "external": is_external,
            "read_count": read_count,
            "flags": flags,
            "threshold_k": threshold_k,
            "signatory_count": signatory_count,
        }));
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "list", None, AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "resources": items, "count": items.len(),
    })))
}

/// Admin-only purge of tombstoned secrets (those whose `max_reads` was hit
/// and whose crypto material has already been scrubbed). Rows whose `flags`
/// JSONB has `preserve_on_cleanup: true` are kept regardless. Each removal is
/// recorded in the audit log.
pub async fn cleanup_secrets(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&client) { return Ok(resp); }
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };

    // Tombstoned rows in this domain: exhausted_at set + crypto scrubbed.
    // We additionally filter out anything flagged preserve_on_cleanup so that
    // forensic-retention rows survive even a "cleanup everything" call.
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT resource_id, resource_name_enc
         FROM blackbook_secrets
         WHERE domain_id = $1
           AND exhausted_at IS NOT NULL
           AND COALESCE((flags->>'preserve_on_cleanup')::boolean, false) = false",
    )
    .bind(&domain_id)
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let preserved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM blackbook_secrets
         WHERE domain_id = $1
           AND exhausted_at IS NOT NULL
           AND COALESCE((flags->>'preserve_on_cleanup')::boolean, false) = true",
    )
    .bind(&domain_id)
    .fetch_one(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let mut deleted_names: Vec<String> = Vec::with_capacity(rows.len());
    for (id, name_enc) in rows {
        let name = dec_str(&state.metadata_enc_key, &name_enc)
            .unwrap_or_else(|_| format!("<encrypted:{id}>"));
        let _ = sqlx::query("DELETE FROM blackbook_secrets WHERE resource_id = $1")
            .bind(&id).execute(&state.db).await;
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "cleanup", Some(&name),
              AuditStatus::Ok, Some("tombstoned secret purged")).await;
        deleted_names.push(name);
    }

    // Tombstoned files: purge the page + its content row + on-disk blob.
    // Deleting the content row CASCADE-deletes the page; the blob file (already
    // scrubbed at exhaustion) is removed best-effort.
    let file_rows: Vec<(String, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT p.id, p.name_enc, p.content_id, c.storage_path
         FROM blackbook_pages p JOIN blackbook_contents c ON c.id = p.content_id
         WHERE p.domain_id = $1
           AND p.exhausted_at IS NOT NULL
           AND COALESCE((p.flags->>'preserve_on_cleanup')::boolean, false) = false",
    )
    .bind(&domain_id)
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let files_preserved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM blackbook_pages
         WHERE domain_id = $1
           AND exhausted_at IS NOT NULL
           AND COALESCE((flags->>'preserve_on_cleanup')::boolean, false) = true",
    )
    .bind(&domain_id)
    .fetch_one(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let mut deleted_files: Vec<String> = Vec::with_capacity(file_rows.len());
    for (id, name_enc, content_id, storage_path) in file_rows {
        let name = dec_str(&state.metadata_enc_key, &name_enc)
            .unwrap_or_else(|_| format!("<encrypted:{id}>"));
        let _ = sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
            .bind(&content_id).execute(&state.db).await;
        let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&storage_path)).await;
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "cleanup", Some(&name),
              AuditStatus::Ok, Some("tombstoned file purged")).await;
        deleted_files.push(name);
    }

    let total_preserved = preserved + files_preserved;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "cleanup.summary", None, AuditStatus::Ok,
          Some(&format!("secrets_deleted={} files_deleted={} preserved={}",
                        deleted_names.len(), deleted_files.len(), total_preserved))).await;
    let mut all_names = deleted_names.clone();
    all_names.extend(deleted_files.iter().map(|n| format!("file:{n}")));
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "deleted": deleted_names.len() + deleted_files.len(),
        "secrets_deleted": deleted_names.len(),
        "files_deleted": deleted_files.len(),
        "preserved": total_preserved,
        "names": all_names,
    })))
}

// ---------------------------------------------------------------------------
// File endpoints (pages + contents)
// ---------------------------------------------------------------------------

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

pub async fn upload_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Bytes,
    req: actix_web::HttpRequest,
    q: web::Query<DomainQuery>,
    pol: web::Query<FilePolicyQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                     "file name must be non-empty and may not contain '/' or '..'"));
    }
    if body.len() > MAX_FILE_BYTES {
        return Ok(err(StatusCode::PAYLOAD_TOO_LARGE, "too_large",
                     format!("file exceeds {} bytes", MAX_FILE_BYTES)));
    }
    if body.is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "empty body"));
    }
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };

    let name_id = name_id_hex(&state.name_index_key, &domain_id, &name);
    let existing: Option<(String, String, SqlxJson<ResourceFlags>)> = sqlx::query_as(
        "SELECT id, content_id, flags FROM blackbook_pages WHERE domain_id = $1 AND name_id = $2",
    )
    .bind(&domain_id).bind(&name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // Read-only-by-default + immutability, matching secrets.
    if let Some((_, _, SqlxJson(existing_flags))) = &existing {
        if existing_flags.no_overwrite {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.create",
                  Some(&name), AuditStatus::Denied, Some("immutable: no_overwrite set")).await;
            return Ok(err(StatusCode::CONFLICT, "immutable",
                         format!("'{name}' is immutable (no_overwrite) and cannot be replaced; delete it first")));
        }
        if !pol.overwrite.unwrap_or(false) {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.create",
                  Some(&name), AuditStatus::Denied, Some("already exists; overwrite not requested")).await;
            return Ok(err(StatusCode::CONFLICT, "already_exists",
                         format!("'{name}' already exists; pass overwrite=true to replace it")));
        }
    }
    let action = if existing.is_some() { AclAction::Update } else { AclAction::Create };

    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, action).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), &format!("file.{}", action_name(action)),
              Some(&name), AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to {} '{}'", action_name(action), name)));
    }

    // Build flags + K-of-N policy (only applied on create; overwrite keeps the
    // resource's existing policy, like secrets).
    let flags = pol.flags();
    let access_policy = pol.access_policy()
        .map_err(|e| actix_web::error::ErrorBadRequest(e))?;
    if let Some(p) = &access_policy {
        if p.threshold_k < 1 || (p.threshold_k as usize) > p.signatories.len() {
            return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                         "threshold_k must be 1..=signatories.len()"));
        }
    }

    // Storage mode. Three kinds:
    //   external-key (kind 1): body is the client ciphertext, stored verbatim;
    //     the server keeps the client's {salt, wrapped_dek} meta. (Phase 3.)
    //   resident     (kind 2): the ciphertext lives on the *client's* disk; the
    //     server keeps only the manifest + the server's half of the split file
    //     key (`server_key_component`, wrapped under file_dek_kek). The body is
    //     either empty or (with server_copy) an encrypted backup of the client
    //     ciphertext. (Phase 4.)
    //   normal       (kind 0): server-side encrypted as usual.
    let is_resident = pol.resident.unwrap_or(false);
    let is_external = !is_resident && pol.external.unwrap_or(false);
    let want_server_copy = is_resident && pol.server_copy.unwrap_or(false);

    let external_meta: Option<Vec<u8>> = if is_external {
        let m = pol.meta.as_deref().ok_or_else(||
            actix_web::error::ErrorBadRequest("external upload requires the `meta` query parameter"))?;
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(m)
            .map_err(|_| actix_web::error::ErrorBadRequest("external meta is not valid base64"))?;
        if bytes.is_empty() {
            return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "external meta cannot be empty"));
        }
        Some(bytes)
    } else { None };

    // For a resident file, decode + wrap the server's key-component half now,
    // so a DB thief can't read it without the server's file_dek_kek.
    let server_key_component_wrapped: Option<Vec<u8>> = if is_resident {
        use base64::Engine as _;
        let kc_b64 = pol.key_component.as_deref().ok_or_else(||
            actix_web::error::ErrorBadRequest("resident upload requires the `key_component` query parameter"))?;
        let kc = base64::engine::general_purpose::STANDARD.decode(kc_b64)
            .map_err(|_| actix_web::error::ErrorBadRequest("key_component is not valid base64"))?;
        if kc.len() != 32 {
            return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "key_component must be 32 bytes"));
        }
        let keys = state.keys.read().await;
        let kek = keys.file_dek_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let wrapped = encrypt_aes_gcm(&kc, &kek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        Some(wrapped)
    } else { None };
    let external_kind: i16 = if is_resident { 2 } else if is_external { 1 } else { 0 };

    // Integrity hash is always over the *stored* bytes (plaintext for normal
    // files, ciphertext for external) so download can verify at-rest integrity
    // without needing to decrypt external blobs.
    let plaintext_hash = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(&body);
        hex::encode(h.finalize())
    };
    let plaintext_size = body.len() as i64;
    let mime_type = req.headers().get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()).map(|s| s.to_string())
        .or_else(|| mime_guess::from_path(&name).first().map(|m| m.to_string()));

    let (stored_bytes, wrapped_dek): (Vec<u8>, Vec<u8>) = if is_external {
        (body.to_vec(), Vec::new())
    } else if is_resident && !want_server_copy {
        // Resident, no backup: the server keeps no blob at all. An empty
        // content row preserves the FK so all the existing JOINs keep working.
        (Vec::new(), Vec::new())
    } else if is_resident && want_server_copy {
        // Opt-in backup: re-encrypt the client ciphertext under a fresh server
        // file DEK, exactly like a normal file. The server still can't read the
        // *plaintext* — `body` is already the client ciphertext (sealed under
        // Kf, which the server never holds whole).
        use rand::RngCore;
        let mut dek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dek);
        let backup = aead_seal(&body, &dek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let keys = state.keys.read().await;
        let kek = keys.file_dek_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let wd = encrypt_aes_gcm(&dek, &kek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        (backup, wd)
    } else {
        use rand::RngCore;
        let mut dek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dek);
        let ciphertext = aead_seal(&body, &dek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let keys = state.keys.read().await;
        let kek = keys.file_dek_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let wd = encrypt_aes_gcm(&dek, &kek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        (ciphertext, wd)
    };
    let ciphertext = stored_bytes;

    // Persist the blob.
    let new_content_id = Id::new(32).to_hex();
    let storage_relpath = format!("{}", new_content_id);
    let storage_full = state.data_dir.join("contents").join(&storage_relpath);
    tokio::fs::write(&storage_full, &ciphertext).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let ciphertext_size = ciphertext.len() as i64;

    // Update DB. Replace-or-insert with old-blob cleanup.
    let now = chrono::Utc::now();
    let response = if let Some((page_id, old_content_id, _)) = existing {
        let mut tx = state.db.begin().await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        sqlx::query(
            "INSERT INTO blackbook_contents (id, storage_path, ciphertext_size) VALUES ($1, $2, $3)",
        )
        .bind(&new_content_id).bind(&storage_relpath).bind(ciphertext_size)
        .execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        let mime_enc = match &mime_type {
            Some(m) => Some(enc_str(&state.metadata_enc_key, m)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?),
            None => None,
        };
        let size_enc = enc_field(&state.metadata_enc_key, &plaintext_size.to_be_bytes())
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let hash_id = file_hash_id_hex(&state.name_index_key, &plaintext_hash);
        sqlx::query(
            "UPDATE blackbook_pages
             SET content_id = $1, wrapped_dek = $2, plaintext_hash_id = $3,
                 plaintext_size_enc = $4, mime_type_enc = $5,
                 is_external = $6, external_meta = $7,
                 external_kind = $8, server_key_component = $9, has_server_copy = $10,
                 updated_at = $11
             WHERE id = $12",
        )
        .bind(&new_content_id).bind(&wrapped_dek).bind(&hash_id)
        .bind(&size_enc).bind(mime_enc.as_deref())
        .bind(is_external).bind(external_meta.as_deref())
        .bind(external_kind).bind(server_key_component_wrapped.as_deref()).bind(want_server_copy)
        .bind(now).bind(&page_id)
        .execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
            .bind(&old_content_id).execute(&mut *tx).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;
        // Best-effort old blob removal.
        let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&old_content_id)).await;
        FileSummary {
            id: page_id, name: name.clone(), owner: client.name.clone(),
            size: plaintext_size, mime_type,
            content_hash: plaintext_hash,
            created_at: now.to_rfc3339(), updated_at: now.to_rfc3339(),
            ..Default::default()
        }
    } else {
        let page_id = Id::new(16).encode();
        let mut tx = state.db.begin().await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        sqlx::query(
            "INSERT INTO blackbook_contents (id, storage_path, ciphertext_size) VALUES ($1, $2, $3)",
        )
        .bind(&new_content_id).bind(&storage_relpath).bind(ciphertext_size)
        .execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        // Encrypt every user-supplied field; only opaque ids and the
        // wrapped DEK go in plaintext.
        let name_enc = enc_str(&state.metadata_enc_key, &name)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let mime_enc = match &mime_type {
            Some(m) => Some(enc_str(&state.metadata_enc_key, m)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?),
            None => None,
        };
        let size_enc = enc_field(&state.metadata_enc_key, &plaintext_size.to_be_bytes())
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let hash_id = file_hash_id_hex(&state.name_index_key, &plaintext_hash);
        // Translate K-of-N signatory names → opaque client ids before storing,
        // so the access_policy JSONB never holds plaintext identifiers.
        let policy_value = match &access_policy {
            None => None,
            Some(p) => {
                let mut ids: Vec<String> = Vec::with_capacity(p.signatories.len());
                for sig in &p.signatories {
                    let row: Option<(String,)> = sqlx::query_as(
                        "SELECT id FROM blackbook_clients WHERE name_id = $1",
                    )
                    .bind(client_name_id_hex(&state.name_index_key, sig))
                    .fetch_optional(&mut *tx).await
                    .map_err(actix_web::error::ErrorInternalServerError)?;
                    match row {
                        Some((cid,)) => ids.push(cid),
                        None => return Ok(err(StatusCode::BAD_REQUEST, "unknown_signatory",
                                              format!("signatory '{sig}' is not a known client"))),
                    }
                }
                Some(SqlxJson(serde_json::json!({
                    "threshold_k": p.threshold_k, "signatories": ids,
                })))
            }
        };
        sqlx::query(
            "INSERT INTO blackbook_pages
                (id, name_enc, name_id, owner_id, content_id, wrapped_dek,
                 plaintext_hash_id, plaintext_size_enc, mime_type_enc, domain_id,
                 is_external, external_meta, external_kind, server_key_component,
                 has_server_copy, flags, access_policy)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(&page_id).bind(&name_enc).bind(&name_id).bind(&client.id).bind(&new_content_id)
        .bind(&wrapped_dek).bind(&hash_id).bind(&size_enc).bind(mime_enc.as_deref())
        .bind(&domain_id).bind(is_external).bind(external_meta.as_deref())
        .bind(external_kind).bind(server_key_component_wrapped.as_deref()).bind(want_server_copy)
        .bind(SqlxJson(&flags)).bind(policy_value)
        .execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;
        FileSummary {
            id: page_id, name: name.clone(), owner: client.name.clone(),
            size: plaintext_size, mime_type,
            content_hash: plaintext_hash,
            created_at: now.to_rfc3339(), updated_at: now.to_rfc3339(),
            ..Default::default()
        }
    };

    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), &format!("file.{}", action_name(action)),
          Some(&name), AuditStatus::Ok, Some(&format!("{}b", plaintext_size))).await;
    Ok(HttpResponse::Created().json(response))
}

pub async fn download_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    q: web::Query<DomainQuery>,
    http_req: actix_web::HttpRequest,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let name_id = name_id_hex(&state.name_index_key, &domain_id, &name);
    // Page row first (policy + metadata); the blob is fetched only after every
    // gate passes. Tombstoned files have a scrubbed DEK and a removed blob but
    // the page row survives, so we don't JOIN contents here.
    let row: Option<(String, String, Vec<u8>, String, Vec<u8>, Option<Vec<u8>>, SqlxJson<ResourceFlags>, i64, Option<SqlxJson<AccessPolicy>>, Option<chrono::NaiveDateTime>, bool, Option<Vec<u8>>, i16, Option<Vec<u8>>, bool)> = sqlx::query_as(
        "SELECT id, content_id, wrapped_dek, plaintext_hash_id, plaintext_size_enc,
                mime_type_enc, flags, read_count, access_policy, exhausted_at,
                is_external, external_meta, external_kind, server_key_component, has_server_copy
         FROM blackbook_pages
         WHERE domain_id = $1 AND name_id = $2",
    )
    .bind(&domain_id).bind(&name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((page_id, content_id, wrapped_dek, expected_hash_id, size_enc, mime_enc, SqlxJson(flags), read_count, policy_opt, exhausted_at, is_external, external_meta, external_kind, server_key_component, has_server_copy)) = row else {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
              AuditStatus::NotFound, None).await;
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "file not found"));
    };
    let size_bytes = dec_field(&state.metadata_enc_key, &size_enc)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    if size_bytes.len() != 8 {
        return Err(actix_web::error::ErrorInternalServerError("decrypted plaintext_size has wrong length"));
    }
    let mut sb = [0u8; 8]; sb.copy_from_slice(&size_bytes);
    let plaintext_size = i64::from_be_bytes(sb);
    let mime: Option<String> = match mime_enc {
        Some(b) => Some(dec_str(&state.metadata_enc_key, &b)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?),
        None => None,
    };
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Read).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
              AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to read '{name}'")));
    }

    // Tombstone: a prior read exhausted max_reads and scrubbed the blob+DEK.
    if let Some(ts) = exhausted_at {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
              AuditStatus::Denied, Some("tombstoned: blob was scrubbed at exhaustion")).await;
        return Ok(err(StatusCode::GONE, "exhausted",
                     format!("'{name}' was exhausted at {} and its blob has been scrubbed",
                             ts.format("%Y-%m-%dT%H:%M:%SZ"))));
    }
    // Fast soft-reject (not the enforcement point — the atomic claim below is).
    if let Some(max) = flags.max_reads {
        if read_count >= max {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                  AuditStatus::Denied, Some("max_reads exhausted")).await;
            return Ok(err(StatusCode::FORBIDDEN, "max_reads",
                         format!("'{name}' has reached its max_reads ({max})")));
        }
    }
    let _ = read_count; // superseded by the atomic claim below
    // K-of-N threshold gate (live approvals ∪ advance grants), kind = "file".
    if let Some(SqlxJson(policy)) = policy_opt.as_ref() {
        let request_id_hdr = http_req.headers().get("X-Blackbook-Request-Id")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        if let Some(resp) = threshold_gate(&state, &client, "file", &domain_id, &name, policy, request_id_hdr).await? {
            return Ok(resp);
        }
    }
    // mfa_required.
    if flags.mfa_required {
        let code = http_req.headers().get("X-Blackbook-MFA")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let Some(code) = code else {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                  AuditStatus::Denied, Some("missing MFA")).await;
            return Ok(err(StatusCode::UNAUTHORIZED, "mfa_required",
                         "this resource requires X-Blackbook-MFA <code>"));
        };
        let kek_bytes = state.keys.read().await.mfa_secret_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let ok = auth::verify_totp(&state.db, &kek_bytes, &client.id, &code).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        if !ok {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                  AuditStatus::Denied, Some("MFA verification failed")).await;
            return Ok(err(StatusCode::UNAUTHORIZED, "mfa_failed", "invalid TOTP code"));
        }
    }

    // Atomically claim this read before fetching the blob, so concurrent
    // downloads can't bypass max_reads / delete_on_read (same scheme as
    // secrets). Cap = tightest of max_reads and (1 for delete_on_read).
    let cap: Option<i64> = match (flags.max_reads, flags.delete_on_read) {
        (Some(m), true) => Some(m.min(1)),
        (Some(m), false) => Some(m),
        (None, true) => Some(1),
        (None, false) => None,
    };
    let new_count: Option<i64> = if let Some(cap) = cap {
        let claimed: Option<(i64,)> = sqlx::query_as(
            "UPDATE blackbook_pages SET read_count = read_count + 1
             WHERE id = $1 AND exhausted_at IS NULL AND read_count < $2
             RETURNING read_count",
        ).bind(&page_id).bind(cap).fetch_optional(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        match claimed {
            Some((c,)) => Some(c),
            None => {
                audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                      AuditStatus::Denied, Some("read limit reached (atomic claim)")).await;
                return Ok(err(StatusCode::FORBIDDEN, "max_reads",
                             format!("'{name}' has reached its read limit")));
            }
        }
    } else {
        let _ = sqlx::query("UPDATE blackbook_pages SET read_count = read_count + 1 WHERE id = $1")
            .bind(&page_id).execute(&state.db).await;
        None
    };

    // Resident file (kind 2): the ciphertext lives on the client. We return
    // only the server's key-component half (unwrapped from file_dek_kek); the
    // client recombines it with its own half to rebuild the file key and
    // decrypts its local copy. No blob is read here (unless a server backup
    // copy exists, which the client can fetch via the normal path on demand —
    // not part of this response). Post-read effects still apply below by id.
    if external_kind == 2 {
        let wrapped = server_key_component.ok_or_else(|| actix_web::error::ErrorInternalServerError(
            "resident file is missing its server key component"))?;
        let keys = state.keys.read().await;
        let kek = keys.file_dek_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let kc = decrypt_aes_gcm(&wrapped, &kek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

        // Post-read effects for resident files: delete_on_read / max_reads
        // tombstone clear the key component (so the file becomes permanently
        // unrecoverable) and drop any backup blob. rotate-on-read is N/A.
        let reached_max = flags.max_reads
            .map(|m| new_count.map(|c| c >= m).unwrap_or(false))
            .unwrap_or(false);
        let post_note: Option<&'static str> = if flags.delete_on_read {
            // Read the blob path before deleting the content row, then remove
            // both the row (CASCADE drops the page) and any backup file.
            if has_server_copy {
                let sp: Option<(String,)> = sqlx::query_as("SELECT storage_path FROM blackbook_contents WHERE id = $1")
                    .bind(&content_id).fetch_optional(&state.db).await.ok().flatten();
                if let Some((p,)) = sp { let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&p)).await; }
            }
            let _ = sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
                .bind(&content_id).execute(&state.db).await;
            Some("consumed by delete_on_read")
        } else if reached_max {
            let _ = sqlx::query(
                "UPDATE blackbook_pages SET server_key_component = NULL, exhausted_at = NOW() WHERE id = $1",
            ).bind(&page_id).execute(&state.db).await;
            log::info!("max_reads exhausted; tombstoned resident file {name} (page {page_id})");
            Some("tombstoned: max_reads reached on this read")
        } else {
            None
        };

        acl_record_use(&state.db, &decision).await;
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
              AuditStatus::Ok, post_note.or(Some("read (resident key component)"))).await;
        use base64::Engine as _;
        let kc_b64 = base64::engine::general_purpose::STANDARD.encode(&kc);
        let mut resp = HttpResponse::Ok();
        resp.insert_header(("X-Blackbook-Resident", "1"));
        resp.insert_header(("X-Blackbook-Key-Component", kc_b64));
        if has_server_copy { resp.insert_header(("X-Blackbook-Server-Copy", "1")); }
        return Ok(resp.body(Vec::new()));
    }

    // Fetch the blob. For external files it's the client's ciphertext and we
    // return it verbatim; otherwise we unwrap the per-file DEK and decrypt.
    let storage_path: (String,) = sqlx::query_as("SELECT storage_path FROM blackbook_contents WHERE id = $1")
        .bind(&content_id).fetch_one(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let storage_path = storage_path.0;
    let stored = tokio::fs::read(state.data_dir.join("contents").join(&storage_path)).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    use sha3::{Digest, Sha3_256};
    // Integrity is always checked over the stored bytes (= ciphertext for
    // external, plaintext for normal — the hash was taken over the same bytes
    // at upload), so a tampered blob on disk is caught either way.
    let mut h = Sha3_256::new(); h.update(&stored);
    let stored_hash_id = file_hash_id_hex(&state.name_index_key, &hex::encode(h.finalize()));
    // `served` is what we hand back; `kek_opt` is kept only for rotate-on-read.
    let (served, kek_opt): (Vec<u8>, Option<Vec<u8>>) = if is_external {
        if stored_hash_id != expected_hash_id {
            log::error!("stored ciphertext hash mismatch for external file {name}");
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                  AuditStatus::Error, Some("hash mismatch")).await;
            return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "integrity_error", "stored blob does not match"));
        }
        (stored, None)
    } else {
        let keys = state.keys.read().await;
        let kek = keys.file_dek_kek.handle()
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        drop(keys);
        let dek = decrypt_aes_gcm(&wrapped_dek, &kek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let plain = aead_open(&stored, &dek)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let mut hp = Sha3_256::new(); hp.update(&plain);
        let got_hash_id = file_hash_id_hex(&state.name_index_key, &hex::encode(hp.finalize()));
        if got_hash_id != expected_hash_id {
            log::error!("plaintext hash mismatch for {name}");
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
                  AuditStatus::Error, Some("hash mismatch")).await;
            return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "integrity_error", "stored hash does not match"));
        }
        if plain.len() as i64 != plaintext_size {
            log::error!("plaintext size mismatch for {name}");
            return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "integrity_error", "stored size does not match"));
        }
        (plain, Some(kek))
    };

    // Post-read effects. The read slot is already claimed (counter bumped);
    // here we only tear down / re-key. delete_on_read > tombstone(max_reads) >
    // rotate_on_read.
    let reached_max = flags.max_reads
        .map(|m| new_count.map(|c| c >= m).unwrap_or(false))
        .unwrap_or(false);
    let post_note: Option<&'static str> = if flags.delete_on_read {
        // Deleting the content row CASCADE-deletes the page row; then drop the blob.
        let _ = sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
            .bind(&content_id).execute(&state.db).await;
        let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&storage_path)).await;
        log::info!("delete_on_read consumed file {name} (page {page_id})");
        Some("consumed by delete_on_read")
    } else if reached_max {
        // Tombstone: scrub the DEK + remove the blob, keep the page row (and
        // its name slot) with exhausted_at set (counter already incremented by
        // the claim). Content row kept so the FK holds; `cleanup` purges both.
        let _ = sqlx::query(
            "UPDATE blackbook_pages SET wrapped_dek = ''::bytea, exhausted_at = NOW() WHERE id = $1",
        ).bind(&page_id).execute(&state.db).await;
        let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&storage_path)).await;
        log::info!("max_reads exhausted; tombstoned file {name} (page {page_id})");
        Some("tombstoned: max_reads reached on this read")
    } else if flags.rotate_on_read && !is_external {
        // Re-key the per-file DEK (counter already incremented by the claim).
        // Not applicable to external files — the server can't re-key what it
        // can't read; the client owns that key.
        if let (Some(kek),) = (kek_opt.as_ref(),) {
            if let Err(e) = rekey_file_dek(&state, &page_id, &content_id, &storage_path, &served, kek).await {
                log::warn!("rotate_on_read re-key failed for {name}: {e}");
            }
        }
        Some("dek rotated on read")
    } else {
        None
    };

    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.read", Some(&name),
          AuditStatus::Ok, post_note.or(Some("read"))).await;
    let mut resp = HttpResponse::Ok();
    if let Some(m) = mime { resp.content_type(m); }
    if is_external {
        // Hand the client its {salt, wrapped_dek} so it can derive the DEK
        // from its passphrase. The body is the client ciphertext.
        use base64::Engine as _;
        let meta_b64 = base64::engine::general_purpose::STANDARD
            .encode(external_meta.as_deref().unwrap_or_default());
        resp.insert_header(("X-Blackbook-External", "1"));
        resp.insert_header(("X-Blackbook-External-Meta", meta_b64));
    }
    Ok(resp.body(served))
}

/// Re-encrypt a file's plaintext under a freshly generated per-file DEK and
/// rebind the page to a new content row + blob, deleting the old blob. Used by
/// `rotate_on_read` and shares the mechanism with the explicit `file rotate`.
async fn rekey_file_dek(
    state: &AppState, page_id: &str, old_content_id: &str, old_storage: &str,
    plain: &[u8], kek: &[u8],
) -> std::result::Result<(), String> {
    use rand::RngCore;
    let mut new_dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_dek);
    let new_ct = aead_seal(plain, &new_dek).map_err(|e| e.to_string())?;
    let new_wrapped = encrypt_aes_gcm(&new_dek, kek).map_err(|e| e.to_string())?;
    let new_content_id = Id::new(32).to_hex();
    let new_storage = new_content_id.clone();
    tokio::fs::write(state.data_dir.join("contents").join(&new_storage), &new_ct).await
        .map_err(|e| e.to_string())?;
    let mut tx = state.db.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO blackbook_contents (id, storage_path, ciphertext_size) VALUES ($1, $2, $3)")
        .bind(&new_content_id).bind(&new_storage).bind(new_ct.len() as i64)
        .execute(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("UPDATE blackbook_pages SET content_id = $1, wrapped_dek = $2 WHERE id = $3")
        .bind(&new_content_id).bind(&new_wrapped).bind(page_id)
        .execute(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
        .bind(old_content_id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(old_storage)).await;
    Ok(())
}

pub async fn delete_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let name_id = name_id_hex(&state.name_index_key, &domain_id, &name);
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT p.id, c.storage_path
         FROM blackbook_pages p JOIN blackbook_contents c ON c.id = p.content_id
         WHERE p.domain_id = $1 AND p.name_id = $2",
    )
    .bind(&domain_id).bind(&name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((page_id, storage_path)) = row else {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.delete", Some(&name),
              AuditStatus::NotFound, None).await;
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "file not found"));
    };
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Delete).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.delete", Some(&name),
              AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to delete '{name}'")));
    }
    sqlx::query("DELETE FROM blackbook_pages WHERE id = $1")
        .bind(&page_id).execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&storage_path)).await;
    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.delete", Some(&name),
          AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"deleted": true, "name": name})))
}

pub async fn list_files(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let rows: Vec<(String, Vec<u8>, Vec<u8>, String, Vec<u8>, Option<Vec<u8>>, String, String, SqlxJson<ResourceFlags>, i64, Option<SqlxJson<serde_json::Value>>, Option<chrono::NaiveDateTime>, i16)> = sqlx::query_as(
        "SELECT p.id, p.name_enc, c.name_enc AS owner_enc, p.plaintext_hash_id, p.plaintext_size_enc,
                p.mime_type_enc, p.created_at::text, p.updated_at::text,
                p.flags, p.read_count, p.access_policy, p.exhausted_at, p.external_kind
         FROM blackbook_pages p JOIN blackbook_clients c ON c.id = p.owner_id
         WHERE p.domain_id = $1
         ORDER BY p.created_at DESC LIMIT 500",
    )
    .bind(&domain_id)
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let mut items = Vec::new();
    for (id, name_enc, owner_enc, content_hash_id, size_enc, mime_enc, created_at, updated_at, SqlxJson(flags), read_count, policy_opt, exhausted, external_kind) in rows {
        let name = match dec_str(key, &name_enc) {
            Ok(n) => n,
            Err(e) => { log::warn!("list_files decrypt name id={id}: {e}"); continue; }
        };
        let owner = dec_str(key, &owner_enc).unwrap_or_else(|_| "?".into());
        let size_bytes = dec_field(key, &size_enc).unwrap_or_default();
        let size = if size_bytes.len() == 8 {
            let mut b = [0u8; 8]; b.copy_from_slice(&size_bytes); i64::from_be_bytes(b)
        } else { 0 };
        let mime_type = mime_enc.and_then(|b| dec_str(key, &b).ok());
        if !client.is_admin() {
            let dec = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Read).await
                .map_err(actix_web::error::ErrorInternalServerError)?;
            if !dec.is_allowed() { continue; }
        }
        let exhausted_str = exhausted.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let (threshold_k, signatory_count) = policy_threshold(policy_opt.as_ref());
        let external = match external_kind { 1 => "key", 2 => "resident", _ => "" }.to_string();
        // content_hash on the response is the at-rest HMAC id — the raw
        // plaintext SHA3 is never recovered without first decrypting the
        // file, which `file get` does as a side effect of integrity check.
        items.push(FileSummary {
            id, name, owner, size, mime_type,
            content_hash: content_hash_id,
            created_at, updated_at,
            external, read_count, flags, exhausted_at: exhausted_str,
            threshold_k, signatory_count,
        });
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.list", None, AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"files": items, "count": items.len()})))
}

pub async fn rotate_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let name_id = name_id_hex(&state.name_index_key, &domain_id, &name);
    let row: Option<(String, String, Vec<u8>, String, Vec<u8>)> = sqlx::query_as(
        "SELECT p.id, c.storage_path, p.wrapped_dek, p.plaintext_hash_id, p.plaintext_size_enc
         FROM blackbook_pages p JOIN blackbook_contents c ON c.id = p.content_id
         WHERE p.domain_id = $1 AND p.name_id = $2",
    )
    .bind(&domain_id).bind(&name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((page_id, old_storage, wrapped_dek, expected_hash_id, size_enc)) = row else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "file not found"));
    };
    let size_bytes = dec_field(&state.metadata_enc_key, &size_enc)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    if size_bytes.len() != 8 {
        return Err(actix_web::error::ErrorInternalServerError("decrypted plaintext_size has wrong length"));
    }
    let mut sb = [0u8; 8]; sb.copy_from_slice(&size_bytes);
    let plaintext_size = i64::from_be_bytes(sb);
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Update).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.rotate", Some(&name),
              AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     format!("not permitted to update '{name}'")));
    }

    // Decrypt with current DEK.
    let old_ct = tokio::fs::read(state.data_dir.join("contents").join(&old_storage)).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let keys = state.keys.read().await;
    let kek = keys.file_dek_kek.handle()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    drop(keys);
    let old_dek = decrypt_aes_gcm(&wrapped_dek, &kek)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let plain = aead_open(&old_ct, &old_dek)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new(); h.update(&plain);
    let got_hash_id = file_hash_id_hex(&state.name_index_key, &hex::encode(h.finalize()));
    if got_hash_id != expected_hash_id {
        return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "integrity_error",
                     "plaintext hash mismatch — refusing to rotate"));
    }
    if plain.len() as i64 != plaintext_size {
        return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "integrity_error",
                     "plaintext size mismatch — refusing to rotate"));
    }

    // Re-encrypt with new DEK.
    use rand::RngCore;
    let mut new_dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_dek);
    let new_ct = aead_seal(&plain, &new_dek)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let new_wrapped = encrypt_aes_gcm(&new_dek, &kek)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let new_content_id = Id::new(32).to_hex();
    let new_storage = format!("{}", new_content_id);
    let new_path = state.data_dir.join("contents").join(&new_storage);
    tokio::fs::write(&new_path, &new_ct).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let now = chrono::Utc::now();
    let mut tx = state.db.begin().await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    sqlx::query(
        "INSERT INTO blackbook_contents (id, storage_path, ciphertext_size) VALUES ($1, $2, $3)",
    )
    .bind(&new_content_id).bind(&new_storage).bind(new_ct.len() as i64)
    .execute(&mut *tx).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    // Find old content_id to delete after page is rebound.
    let old_content_id: (String,) = sqlx::query_as(
        "SELECT content_id FROM blackbook_pages WHERE id = $1"
    ).bind(&page_id).fetch_one(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    sqlx::query(
        "UPDATE blackbook_pages
         SET content_id = $1, wrapped_dek = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(&new_content_id).bind(&new_wrapped).bind(now).bind(&page_id)
    .execute(&mut *tx).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    sqlx::query("DELETE FROM blackbook_contents WHERE id = $1")
        .bind(&old_content_id.0).execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let _ = tokio::fs::remove_file(state.data_dir.join("contents").join(&old_storage)).await;

    acl_record_use(&state.db, &decision).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "file.rotate", Some(&name),
          AuditStatus::Ok, Some(&format!("{} -> {}", &old_storage[..8.min(old_storage.len())], &new_storage[..8.min(new_storage.len())]))).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"rotated": true, "name": name})))
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

pub async fn create_client_endpoint(
    state: web::Data<AppState>,
    req: web::Json<CreateClientRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    if req.name.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "name is required"));
    }
    if !(req.role == "admin" || req.role == "user") {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                     "role must be 'admin' or 'user'"));
    }
    match auth::create_client(&state.db, &state.ca, &state.metadata_enc_key, &state.name_index_key,
                               &req.name, &req.role, req.ttl_days).await {
        Ok(new) => {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "client.create", Some(&req.name),
                  AuditStatus::Ok, Some(&format!("role={}", req.role))).await;
            Ok(HttpResponse::Created().json(new))
        }
        Err(auth::AuthOpError::Db(sqlx::Error::Database(dbe))) if dbe.code().as_deref() == Some("23505") => {
            Ok(err(StatusCode::CONFLICT, "conflict",
                  format!("client '{}' already exists", req.name)))
        }
        Err(auth::AuthOpError::Invalid(m)) => Ok(err(StatusCode::BAD_REQUEST, "validation_error", m)),
        Err(e) => Err(actix_web::error::ErrorInternalServerError(e.to_string())),
    }
}

pub async fn rotate_client_endpoint(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RotateClientRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let name = path.into_inner();
    match auth::rotate_client(&state.db, &state.ca, &state.name_index_key, &name, body.ttl_days).await {
        Ok(Some(new)) => {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "client.rotate", Some(&name),
                  AuditStatus::Ok, None).await;
            Ok(HttpResponse::Ok().json(new))
        }
        Ok(None) => Ok(err(StatusCode::NOT_FOUND, "not_found",
                          format!("no active client named '{name}'"))),
        Err(e) => Err(actix_web::error::ErrorInternalServerError(e.to_string())),
    }
}

pub async fn list_clients_endpoint(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let rows: Vec<(String, Vec<u8>, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, name_enc, role, created_at::text, expires_at::text, revoked_at::text
         FROM blackbook_clients ORDER BY created_at DESC",
    )
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let items: Vec<_> = rows.into_iter()
        .map(|(id, name_enc, role, created_at, expires_at, revoked_at)| ClientSummary {
            id,
            name: dec_str(key, &name_enc).unwrap_or_else(|_| "?".into()),
            role, created_at, expires_at, revoked_at,
        }).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({"clients": items, "count": items.len()})))
}

pub async fn revoke_client_endpoint(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let name = path.into_inner();
    if name == caller.name {
        return Ok(err(StatusCode::BAD_REQUEST, "self_revoke", "cannot revoke the calling client"));
    }
    let name_id = client_name_id_hex(&state.name_index_key, &name);
    let affected = sqlx::query(
        "UPDATE blackbook_clients SET revoked_at = NOW()
         WHERE name_id = $1 AND revoked_at IS NULL",
    )
    .bind(&name_id).execute(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?
    .rows_affected();
    if affected == 0 {
        return Ok(err(StatusCode::NOT_FOUND, "not_found",
                     format!("no active client named '{name}'")));
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "client.revoke", Some(&name),
          AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"revoked": true, "name": name})))
}

pub async fn grant_acl(
    state: web::Data<AppState>,
    req: web::Json<GrantAclRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let mask = match parse_actions(&req.actions) {
        Ok(m) => m,
        Err(msg) => return Ok(err(StatusCode::BAD_REQUEST, "validation_error", msg)),
    };
    if req.client_name.is_some() == req.group_domain.is_some() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                     "specify exactly one of client_name or group_domain"));
    }

    // Resolve the domain (where the grant lives — the resource's domain).
    let domain_name = req.domain.as_deref().unwrap_or("default");
    let domain_id = match auth::resolve_domain(&state.db, &state.name_index_key, domain_name).await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(id) => id,
        None => return Ok(err(StatusCode::NOT_FOUND, "no_such_domain",
                            format!("domain '{}' does not exist", domain_name))),
    };
    // Authority is scoped to *this* domain: a global admin or an admin of it.
    if let Err(resp) = require_domain_admin(&state.db, &caller, &domain_id).await {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "acl.grant",
              Some(&req.resource_pattern), AuditStatus::Denied, Some("not a domain admin")).await;
        return Ok(resp);
    }

    let (client_id, group_domain_id) = if let Some(name) = &req.client_name {
        let name_id = client_name_id_hex(&state.name_index_key, name);
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM blackbook_clients WHERE name_id = $1 AND revoked_at IS NULL",
        ).bind(&name_id).fetch_optional(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
        let Some((id,)) = row else {
            return Ok(err(StatusCode::NOT_FOUND, "not_found",
                         format!("no active client named '{name}'")));
        };
        (Some(id), None)
    } else {
        let gname = req.group_domain.as_deref().unwrap();
        let gid = match auth::resolve_domain(&state.db, &state.name_index_key, gname).await
            .map_err(actix_web::error::ErrorInternalServerError)?
        {
            Some(id) => id,
            None => return Ok(err(StatusCode::NOT_FOUND, "no_such_domain",
                                format!("group domain '{gname}' does not exist"))),
        };
        (None, Some(gid))
    };

    let expires_at = parse_rfc3339_opt(req.expires_at.as_deref())
        .map_err(|m| err(StatusCode::BAD_REQUEST, "validation_error", m));
    let not_before = parse_rfc3339_opt(req.not_before.as_deref())
        .map_err(|m| err(StatusCode::BAD_REQUEST, "validation_error", m));
    let (expires_at, not_before) = match (expires_at, not_before) {
        (Ok(e), Ok(n)) => (e, n),
        (Err(resp), _) | (_, Err(resp)) => return Ok(resp),
    };

    // Validate rate + schedule before persisting.
    if req.rate_max.is_some() != req.rate_period_secs.is_some() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
            "rate_max and rate_period_secs must be set together"));
    }
    if let Some(sched) = &req.schedule {
        // Validate against a reference time; a parse error means a bad schedule.
        if let Err(msg) = auth::cron_window_matches(sched, &chrono::Utc::now().naive_utc()) {
            return Ok(err(StatusCode::BAD_REQUEST, "validation_error", format!("bad schedule: {msg}")));
        }
    }

    let id = Id::new(12).encode();
    let pattern_enc = enc_str(&state.metadata_enc_key, &req.resource_pattern)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    sqlx::query(
        "INSERT INTO blackbook_acl
            (id, domain_id, client_id, group_domain_id, pattern_enc,
             actions, expires_at, not_before, max_uses, granted_by,
             rate_max, rate_period_secs, schedule)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(&id).bind(&domain_id).bind(&client_id).bind(&group_domain_id)
    .bind(&pattern_enc).bind(mask)
    .bind(expires_at).bind(not_before).bind(req.max_uses)
    .bind(&caller.id)
    .bind(req.rate_max).bind(req.rate_period_secs).bind(&req.schedule)
    .execute(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let target = req.client_name.clone()
        .map(|c| format!("client={c}"))
        .or_else(|| req.group_domain.clone().map(|g| format!("group={g}")))
        .unwrap_or_default();
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "acl.grant", Some(&req.resource_pattern),
          AuditStatus::Ok,
          Some(&format!("domain={} {} actions={}", domain_name, target, req.actions.join(",")))).await;
    Ok(HttpResponse::Created().json(serde_json::json!({"id": id})))
}

fn parse_rfc3339_opt(s: Option<&str>) -> std::result::Result<Option<chrono::NaiveDateTime>, String> {
    match s {
        None => Ok(None),
        Some(s) => {
            let dt = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("invalid RFC3339 timestamp '{s}': {e}"))?;
            Ok(Some(dt.naive_utc()))
        }
    }
}

pub async fn list_acl(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    // Global admins see every rule; domain admins see only rules in the
    // domains they administer; anyone else is forbidden.
    let admin_domains: Option<Vec<String>> = if caller.is_admin() {
        None // unrestricted
    } else {
        let ids = auth::admin_domain_ids(&state.db, &caller).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        if ids.is_empty() {
            return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                         "admin role required (global or domain)"));
        }
        Some(ids)
    };
    let rows: Vec<(
        String, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, i32,
        String, Option<String>, Option<String>, Option<i32>, i32,
        Option<i32>, Option<i32>, Option<String>,
    )> = sqlx::query_as(
        "SELECT a.id, d.name_enc, c.name_enc, g.name_enc, a.pattern_enc, a.actions,
                a.granted_at::text, a.expires_at::text, a.not_before::text,
                a.max_uses, a.use_count,
                a.rate_max, a.rate_period_secs, a.schedule
         FROM blackbook_acl a
         JOIN blackbook_domains d  ON d.id = a.domain_id
         LEFT JOIN blackbook_clients c ON c.id = a.client_id
         LEFT JOIN blackbook_domains g ON g.id = a.group_domain_id
         WHERE ($1::text[] IS NULL OR a.domain_id = ANY($1))
         ORDER BY a.granted_at DESC",
    ).bind(admin_domains.as_deref())
    .fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let items: Vec<_> = rows.into_iter()
        .map(|(id, domain_enc, client_name_enc, group_domain_enc, pattern_enc, actions, granted_at, expires_at, not_before, max_uses, use_count, rate_max, rate_period_secs, schedule)| AclSummary {
            id,
            domain: dec_str(key, &domain_enc).unwrap_or_else(|_| "?".into()),
            client_name: client_name_enc.and_then(|b| dec_str(key, &b).ok()),
            group_domain: group_domain_enc.and_then(|b| dec_str(key, &b).ok()),
            resource_pattern: dec_str(key, &pattern_enc).unwrap_or_else(|_| "?".into()),
            actions: actions_from_mask(actions),
            granted_at, expires_at, not_before, max_uses, use_count,
            rate_max, rate_period_secs, schedule,
        }).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({"entries": items, "count": items.len()})))
}

pub async fn revoke_acl(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    // Authorize against the *rule's own domain* so a domain admin can only
    // revoke rules in domains they administer (and can't reach across domains).
    let row: Option<(String,)> = sqlx::query_as("SELECT domain_id FROM blackbook_acl WHERE id = $1")
        .bind(&id).fetch_optional(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((domain_id,)) = row else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such acl entry"));
    };
    if let Err(resp) = require_domain_admin(&state.db, &caller, &domain_id).await {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "acl.revoke", Some(&id),
              AuditStatus::Denied, Some("not a domain admin")).await;
        return Ok(resp);
    }
    let affected = sqlx::query("DELETE FROM blackbook_acl WHERE id = $1")
        .bind(&id).execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .rows_affected();
    if affected == 0 {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such acl entry"));
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "acl.revoke", Some(&id),
          AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"revoked": true})))
}

// ---------------------------------------------------------------------------
// Domains: namespace + ACL group
// ---------------------------------------------------------------------------

pub async fn create_domain(
    state: web::Data<AppState>,
    req: web::Json<CreateDomainRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    if req.name.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "name is required"));
    }
    if req.name.starts_with(auth::USER_DOMAIN_PREFIX) {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
            format!("domain names may not start with '{}' (reserved for private user domains)", auth::USER_DOMAIN_PREFIX)));
    }
    let id = Id::new(12).encode();
    let name_enc = enc_str(&state.metadata_enc_key, &req.name)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let name_id = domain_name_id_hex(&state.name_index_key, &req.name);
    let desc_enc = match &req.description {
        Some(d) => Some(enc_str(&state.metadata_enc_key, d)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?),
        None => None,
    };
    let result = sqlx::query(
        "INSERT INTO blackbook_domains (id, name_enc, name_id, description_enc) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id).bind(&name_enc).bind(&name_id).bind(desc_enc.as_deref())
    .execute(&state.db).await;
    match result {
        Ok(_) => {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "domain.create",
                  Some(&req.name), AuditStatus::Ok, None).await;
            Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "name": req.name})))
        }
        Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => {
            Ok(err(StatusCode::CONFLICT, "conflict",
                  format!("domain '{}' already exists", req.name)))
        }
        Err(e) => Err(actix_web::error::ErrorInternalServerError(e.to_string())),
    }
}

pub async fn list_domains(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    // Anyone authenticated may list domains they're a member of; admins see all.
    let rows: Vec<(String, Vec<u8>, Option<Vec<u8>>, String)> = if caller.is_admin() {
        sqlx::query_as(
            "SELECT id, name_enc, description_enc, created_at::text
             FROM blackbook_domains WHERE archived_at IS NULL
             ORDER BY id",
        ).fetch_all(&state.db).await
    } else {
        sqlx::query_as(
            "SELECT d.id, d.name_enc, d.description_enc, d.created_at::text
             FROM blackbook_domains d
             JOIN blackbook_domain_members m ON m.domain_id = d.id
             WHERE d.archived_at IS NULL AND m.client_id = $1
             ORDER BY d.id",
        ).bind(&caller.id).fetch_all(&state.db).await
    }
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let items: Vec<_> = rows.into_iter().map(|(id, name_enc, description_enc, created_at)| DomainSummary {
        id,
        name: dec_str(key, &name_enc).unwrap_or_else(|_| "?".into()),
        description: description_enc.and_then(|b| dec_str(key, &b).ok()),
        created_at,
    }).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({"domains": items, "count": items.len()})))
}

pub async fn add_domain_member(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: web::Json<AddMemberRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let domain_name = path.into_inner();
    if !(req.role == "admin" || req.role == "user" || req.role == "guest") {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                     "role must be 'admin', 'user', or 'guest'"));
    }
    let domain_id = match auth::resolve_domain(&state.db, &state.name_index_key, &domain_name).await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(id) => id,
        None => return Ok(err(StatusCode::NOT_FOUND, "no_such_domain",
                            format!("domain '{domain_name}' does not exist"))),
    };
    // A domain admin may manage members (including delegating the in-domain
    // 'admin' role) only within their own domain. Note: the 'admin' role here
    // is purely domain-scoped — it never grants global admin.
    if let Err(resp) = require_domain_admin(&state.db, &caller, &domain_id).await {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "domain.add_member",
              Some(&domain_name), AuditStatus::Denied, Some("not a domain admin")).await;
        return Ok(resp);
    }
    let client_name_id = client_name_id_hex(&state.name_index_key, &req.client_name);
    let client_id: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM blackbook_clients WHERE name_id = $1 AND revoked_at IS NULL",
    ).bind(&client_name_id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((client_id,)) = client_id else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found",
                     format!("no active client named '{}'", req.client_name)));
    };
    sqlx::query(
        "INSERT INTO blackbook_domain_members (domain_id, client_id, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (domain_id, client_id) DO UPDATE SET role = EXCLUDED.role",
    ).bind(&domain_id).bind(&client_id).bind(&req.role)
    .execute(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "domain.add_member",
          Some(&domain_name), AuditStatus::Ok,
          Some(&format!("client={} role={}", req.client_name, req.role))).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "added": true, "domain": domain_name, "client": req.client_name, "role": req.role,
    })))
}

pub async fn remove_domain_member(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_name, client_name) = path.into_inner();
    let domain_id = match auth::resolve_domain(&state.db, &state.name_index_key, &domain_name).await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(id) => id,
        None => return Ok(err(StatusCode::NOT_FOUND, "no_such_domain",
                            format!("domain '{domain_name}' does not exist"))),
    };
    if let Err(resp) = require_domain_admin(&state.db, &caller, &domain_id).await {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "domain.remove_member",
              Some(&domain_name), AuditStatus::Denied, Some("not a domain admin")).await;
        return Ok(resp);
    }
    let client_nid = client_name_id_hex(&state.name_index_key, &client_name);
    let affected = sqlx::query(
        "DELETE FROM blackbook_domain_members
         WHERE domain_id  = $1
           AND client_id  = (SELECT id FROM blackbook_clients WHERE name_id = $2)",
    ).bind(&domain_id).bind(&client_nid)
    .execute(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?
    .rows_affected();
    if affected == 0 {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such membership"));
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "domain.remove_member",
          Some(&domain_name), AuditStatus::Ok, Some(&format!("client={client_name}"))).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"removed": true})))
}

// ---------------------------------------------------------------------------
// MFA (TOTP) endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MfaEnrollResponse {
    pub provisioning_uri: String,
    pub secret_base32: String,
    /// Reminder string — show to the user.
    pub instructions: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest { pub code: String }

/// Enroll the caller in TOTP. Generates a fresh secret, encrypts and stores
/// it. The provisioning URI is returned exactly once — the caller imports it
/// into an authenticator app, then proves possession by calling /mfa/verify.
pub async fn mfa_enroll(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let kek_bytes = state.keys.read().await.mfa_secret_kek.handle()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    match auth::enroll_totp(&state.db, &kek_bytes, &caller.id, &caller.name).await {
        Ok((uri, b32)) => {
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "mfa.enroll", None, AuditStatus::Ok, None).await;
            Ok(HttpResponse::Ok().json(MfaEnrollResponse {
                provisioning_uri: uri,
                secret_base32: b32,
                instructions: "Import the URI (or paste the base32 secret) into an authenticator app, then call /api/v1/mfa/verify with the displayed code to confirm enrollment.".to_string(),
            }))
        }
        Err(e) => Err(actix_web::error::ErrorInternalServerError(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Access requests (K-of-N approval workflow)
// ---------------------------------------------------------------------------

const REQUEST_TTL_HOURS: i64 = 24;

/// Create an access request for the given resource/policy. `policy.signatories`
/// holds opaque client ids (post the at-rest-encryption migration); revoked
/// signatories are dropped so the request reflects who could actually approve.
pub async fn create_access_request(
    db: &PgPool,
    metadata_enc_key: &[u8],
    name_index_key: &[u8],
    requester: &AuthenticatedClient,
    resource_kind: &str,
    domain_id: &str,
    resource_name: &str,
    policy: &AccessPolicy,
) -> std::result::Result<AccessRequestSummary, sqlx::Error> {
    let resource_name_id = name_id_hex(name_index_key, domain_id, resource_name);

    // Dedup: at most one OPEN (not consumed, not expired) request per
    // (requester, kind, domain, resource). A repeated `get` returns the
    // existing request — with its accumulated approvers — instead of spawning
    // a fresh one each time. We serialize the find-or-create with an advisory
    // lock keyed on the dedup tuple so two concurrent first reads can't both
    // insert.
    let mut tx = db.begin().await?;
    let lock_key = advisory_key(&format!(
        "accessreq:{}:{}:{}:{}", requester.id, resource_kind, domain_id, resource_name_id));
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(lock_key)
        .execute(&mut *tx).await?;

    let existing: Option<(String, i32, SqlxJson<Vec<String>>, chrono::NaiveDateTime, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT id, threshold_k, approvers, created_at, expires_at
         FROM blackbook_access_requests
         WHERE requester_id = $1 AND resource_kind = $2 AND domain_id = $3
           AND resource_name_id = $4
           AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&requester.id).bind(resource_kind).bind(domain_id).bind(&resource_name_id)
    .fetch_optional(&mut *tx).await?;

    if let Some((id, threshold_k, SqlxJson(approvers), created_at, expires_at)) = existing {
        // Reuse — surface current approver names + status.
        tx.commit().await?;
        let approver_names = ids_to_names(db, metadata_enc_key, &approvers).await;
        let status = if (approvers.len() as i32) >= threshold_k { "ready" } else { "pending" };
        return Ok(AccessRequestSummary {
            id,
            requester: requester.name.clone(),
            resource_kind: resource_kind.to_string(),
            domain: domain_id.to_string(),
            resource_name: resource_name.to_string(),
            threshold_k,
            signatories: policy.signatories.clone(),
            approvers: approver_names,
            created_at: created_at.and_utc().to_rfc3339(),
            expires_at: expires_at.and_utc().to_rfc3339(),
            consumed_at: None,
            status: status.to_string(),
        });
    }

    // Filter out revoked signatories. The list is already client ids
    // (written that way by `store_data`).
    let mut ids: Vec<String> = Vec::new();
    for id in &policy.signatories {
        if let Some((_,)) = sqlx::query_as::<_, (String,)>(
            "SELECT id FROM blackbook_clients WHERE id = $1 AND revoked_at IS NULL",
        ).bind(id).fetch_optional(&mut *tx).await? {
            ids.push(id.clone());
        }
    }
    let id = Id::new(12).encode();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(REQUEST_TTL_HOURS)).naive_utc();
    let resource_name_enc = aead_seal(resource_name.as_bytes(), metadata_enc_key)
        .map_err(|_| sqlx::Error::Configuration("metadata encrypt: aead_seal failed".into()))?;
    sqlx::query(
        "INSERT INTO blackbook_access_requests
            (id, requester_id, resource_kind, domain_id, resource_name_enc,
             resource_name_id, threshold_k, signatory_ids, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id).bind(&requester.id).bind(resource_kind).bind(domain_id)
    .bind(&resource_name_enc).bind(&resource_name_id).bind(policy.threshold_k)
    .bind(SqlxJson(&ids)).bind(expires_at)
    .execute(&mut *tx).await?;
    tx.commit().await?;

    Ok(AccessRequestSummary {
        id,
        requester: requester.name.clone(),
        resource_kind: resource_kind.to_string(),
        domain: domain_id.to_string(),
        resource_name: resource_name.to_string(),
        threshold_k: policy.threshold_k,
        signatories: policy.signatories.clone(),
        approvers: vec![],
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: expires_at.and_utc().to_rfc3339(),
        consumed_at: None,
        status: "pending".to_string(),
    })
}

/// Atomically check & mark-consumed an access request. Returns true iff:
///   - the request matches the resource being read,
///   - the requester is the caller,
///   - it's not expired or already consumed,
///   - approvers.len() >= threshold_k.
/// Distinct signatories who have an *active advance grant* covering this read,
/// restricted to the resource's own signatory set. Returns `(signatory_id,
/// grant_id)` — one usable grant per signatory. A grant counts only if it's
/// in-window, not revoked, under its use cap, and its encrypted pattern
/// matches the resource name.
async fn advance_approvers(
    state: &AppState, grantee_id: &str, kind: &str, domain_id: &str,
    resource_name: &str, policy_sigs: &[String],
) -> sqlx::Result<Vec<(String, String)>> {
    let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, signatory_id, pattern_enc
         FROM blackbook_access_grants
         WHERE grantee_id = $1 AND domain_id = $2 AND resource_kind = $3
           AND revoked_at IS NULL
           AND (not_before IS NULL OR not_before <= CURRENT_TIMESTAMP)
           AND expires_at > CURRENT_TIMESTAMP
           AND (max_uses IS NULL OR use_count < max_uses)
         ORDER BY created_at ASC",
    )
    .bind(grantee_id).bind(domain_id).bind(kind)
    .fetch_all(&state.db).await?;
    let sigset: std::collections::HashSet<&String> = policy_sigs.iter().collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (gid, sig, pat_enc) in rows {
        if !sigset.contains(&sig) || seen.contains(&sig) { continue; }
        let pat = match aead_open(&pat_enc, &state.metadata_enc_key) {
            Ok(b) => String::from_utf8(b).unwrap_or_default(),
            Err(_) => continue,
        };
        if auth::sql_like_match(&pat, resource_name) {
            seen.insert(sig.clone());
            out.push((sig, gid));
        }
    }
    Ok(out)
}

/// Increment `use_count` on each named advance grant (best-effort).
async fn consume_grant_uses(db: &PgPool, grant_ids: &[String]) {
    for id in grant_ids {
        if let Err(e) = sqlx::query(
            "UPDATE blackbook_access_grants SET use_count = use_count + 1 WHERE id = $1",
        ).bind(id).execute(db).await {
            log::warn!("advance-grant use_count bump failed for {id}: {e}");
        }
    }
}

/// The unified K-of-N gate for a read, shared by secrets and files.
///
/// Approval credit is the union of (a) distinct live approvers on an open
/// per-request request and (b) distinct signatories with a matching advance
/// grant. If that union reaches `threshold_k` the read proceeds; advance
/// grants relied upon have a use consumed.
///
/// Returns `Ok(None)` to proceed with the read, or `Ok(Some(resp))` to
/// short-circuit (412 / 404 / etc.). `request_id_hdr` carries the optional
/// `X-Blackbook-Request-Id`.
async fn threshold_gate(
    state: &AppState,
    client: &AuthenticatedClient,
    kind: &str,
    domain_id: &str,
    resource_name: &str,
    policy: &AccessPolicy,
    request_id_hdr: Option<String>,
) -> Result<Option<HttpResponse>> {
    let k = policy.threshold_k;
    let audit_action = if kind == "file" { "file.read" } else { "read" };
    let advance = advance_approvers(state, &client.id, kind, domain_id, resource_name, &policy.signatories)
        .await.map_err(actix_web::error::ErrorInternalServerError)?;

    match request_id_hdr {
        Some(rid) => {
            let row: Option<(String, String, Vec<u8>, i32, SqlxJson<Vec<String>>, chrono::NaiveDateTime, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
                "SELECT requester_id, resource_kind, resource_name_enc, threshold_k, approvers, expires_at, consumed_at
                 FROM blackbook_access_requests WHERE id = $1",
            ).bind(&rid).fetch_optional(&state.db).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
            let Some((requester_id, rkind, rname_enc, tk, SqlxJson(approvers), expires_at, consumed_at)) = row else {
                return Ok(Some(err(StatusCode::PRECONDITION_FAILED, "approval_pending",
                                   "request is not yet fully approved (or expired/consumed)")));
            };
            let rname = aead_open(&rname_enc, &state.metadata_enc_key)
                .ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
            let valid = consumed_at.is_none()
                && requester_id == client.id
                && rkind == kind && rname == resource_name
                && expires_at > chrono::Utc::now().naive_utc();
            if !valid {
                audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), audit_action, Some(resource_name),
                      AuditStatus::Denied, Some("approval request not ready")).await;
                return Ok(Some(err(StatusCode::PRECONDITION_FAILED, "approval_pending",
                                   "request is not yet fully approved (or expired/consumed)")));
            }
            let mut approver_set: std::collections::HashSet<String> = approvers.into_iter().collect();
            let advance_used: Vec<String> = advance.iter()
                .filter(|(sig, _)| !approver_set.contains(sig))
                .map(|(_, gid)| gid.clone()).collect();
            for (sig, _) in &advance { approver_set.insert(sig.clone()); }
            if (approver_set.len() as i32) < tk {
                audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), audit_action, Some(resource_name),
                      AuditStatus::Denied, Some("approval request not ready")).await;
                return Ok(Some(err(StatusCode::PRECONDITION_FAILED, "approval_pending",
                                   "request is not yet fully approved (or expired/consumed)")));
            }
            let affected = sqlx::query(
                "UPDATE blackbook_access_requests SET consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND consumed_at IS NULL",
            ).bind(&rid).execute(&state.db).await
            .map_err(actix_web::error::ErrorInternalServerError)?.rows_affected();
            if affected == 0 {
                return Ok(Some(err(StatusCode::PRECONDITION_FAILED, "approval_pending",
                                   "request was already consumed")));
            }
            consume_grant_uses(&state.db, &advance_used).await;
            Ok(None)
        }
        None => {
            // Advance grants alone satisfy the threshold → no request, no wait.
            if (advance.len() as i32) >= k {
                let used: Vec<String> = advance.iter().take(k as usize).map(|(_, g)| g.clone()).collect();
                consume_grant_uses(&state.db, &used).await;
                audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), audit_action, Some(resource_name),
                      AuditStatus::Ok, Some("approved via advance grants")).await;
                return Ok(None);
            }
            // Otherwise find-or-create the live request; advance grants give
            // partial credit toward its threshold.
            let req = match create_access_request(
                &state.db, &state.metadata_enc_key, &state.name_index_key,
                client, kind, domain_id, resource_name, policy,
            ).await {
                Ok(s) => s,
                Err(e) => return Err(actix_web::error::ErrorInternalServerError(e.to_string())),
            };
            let approver_ids: (SqlxJson<Vec<String>>,) = sqlx::query_as(
                "SELECT approvers FROM blackbook_access_requests WHERE id = $1",
            ).bind(&req.id).fetch_one(&state.db).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
            let mut set: std::collections::HashSet<String> = approver_ids.0.0.into_iter().collect();
            let advance_used: Vec<String> = advance.iter()
                .filter(|(sig, _)| !set.contains(sig))
                .map(|(_, gid)| gid.clone()).collect();
            for (sig, _) in &advance { set.insert(sig.clone()); }
            if (set.len() as i32) >= k {
                let affected = sqlx::query(
                    "UPDATE blackbook_access_requests SET consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND consumed_at IS NULL",
                ).bind(&req.id).execute(&state.db).await
                .map_err(actix_web::error::ErrorInternalServerError)?.rows_affected();
                if affected > 0 {
                    consume_grant_uses(&state.db, &advance_used).await;
                    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), audit_action, Some(resource_name),
                          AuditStatus::Ok, Some("approved via advance grants + live approvals")).await;
                    return Ok(None);
                }
            }
            let effective = set.len();
            let message = if (effective as i32) >= k {
                format!("request {} is approved ({}/{}) — retry with --request-id {}",
                        req.id, effective, k, req.id)
            } else {
                format!("threshold {} of {} required — request {} has {} approval(s) (incl. advance grants); approvers run `blackbook approve {}`",
                        k, policy.signatories.len(), req.id, effective, req.id)
            };
            audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), audit_action, Some(resource_name),
                  AuditStatus::Denied,
                  Some(&format!("threshold {}: request {} ({}/{})", k, req.id, effective, k))).await;
            Ok(Some(HttpResponse::build(StatusCode::PRECONDITION_FAILED).json(serde_json::json!({
                "error": "approval_required",
                "message": message,
                "request": req,
            }))))
        }
    }
}

pub async fn approve_access_request(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let request_id = path.into_inner();

    // Serialize concurrent approvals on the same request: lock the row with
    // SELECT ... FOR UPDATE, re-check state, append, and commit inside one
    // transaction so two signatories approving at once can't clobber each
    // other's entry.
    let mut tx = state.db.begin().await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let row: Option<(SqlxJson<Vec<String>>, SqlxJson<Vec<String>>, chrono::NaiveDateTime, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
        "SELECT signatory_ids, approvers, expires_at, consumed_at
         FROM blackbook_access_requests WHERE id = $1 FOR UPDATE",
    ).bind(&request_id).fetch_optional(&mut *tx).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((SqlxJson(signatories), SqlxJson(mut approvers), expires_at, consumed_at)) = row else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such request"));
    };
    if consumed_at.is_some() {
        return Ok(err(StatusCode::CONFLICT, "consumed", "request already consumed"));
    }
    if expires_at <= chrono::Utc::now().naive_utc() {
        return Ok(err(StatusCode::GONE, "expired", "request expired"));
    }
    if !signatories.contains(&caller.id) {
        audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "approval", Some(&request_id),
              AuditStatus::Denied, Some("not a signatory")).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden",
                     "you are not a signatory on this request"));
    }
    if approvers.contains(&caller.id) {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "approved": true, "already_recorded": true, "approvers": approvers.len(),
        })));
    }
    approvers.push(caller.id.clone());
    sqlx::query("UPDATE blackbook_access_requests SET approvers = $1 WHERE id = $2")
        .bind(SqlxJson(&approvers)).bind(&request_id)
        .execute(&mut *tx).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "approval", Some(&request_id),
          AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "approved": true,
        "approvers": approvers.len(),
    })))
}

pub async fn list_access_requests(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    // Show requests where the caller is either the requester or a listed
    // signatory. Admins see all.
    let rows: Vec<(String, Vec<u8>, String, Option<Vec<u8>>, Vec<u8>, String, i32, SqlxJson<Vec<String>>, SqlxJson<Vec<String>>, String, String, Option<String>)> = if caller.is_admin() {
        sqlx::query_as(
            "SELECT r.id, c.name_enc, r.resource_kind, d.name_enc, r.resource_name_enc,
                    r.threshold_k::text, r.threshold_k, r.signatory_ids, r.approvers,
                    r.created_at::text, r.expires_at::text, r.consumed_at::text
             FROM blackbook_access_requests r
             JOIN blackbook_clients c ON c.id = r.requester_id
             LEFT JOIN blackbook_domains d ON d.id = r.domain_id
             ORDER BY r.created_at DESC LIMIT 200",
        ).fetch_all(&state.db).await
    } else {
        sqlx::query_as(
            "SELECT r.id, c.name_enc, r.resource_kind, d.name_enc, r.resource_name_enc,
                    r.threshold_k::text, r.threshold_k, r.signatory_ids, r.approvers,
                    r.created_at::text, r.expires_at::text, r.consumed_at::text
             FROM blackbook_access_requests r
             JOIN blackbook_clients c ON c.id = r.requester_id
             LEFT JOIN blackbook_domains d ON d.id = r.domain_id
             WHERE r.requester_id = $1
                OR r.signatory_ids @> to_jsonb(ARRAY[$1::text])
             ORDER BY r.created_at DESC LIMIT 200",
        ).bind(&caller.id).fetch_all(&state.db).await
    }
    .map_err(actix_web::error::ErrorInternalServerError)?;

    // Resolve signatory/approver client ids → names for display.
    let key = state.metadata_enc_key.as_slice();
    let mut items = Vec::new();
    for (id, requester_enc, kind, domain_enc, rname_enc, _k_txt, threshold_k, SqlxJson(sig_ids), SqlxJson(app_ids), created_at, expires_at, consumed_at) in rows {
        let requester = dec_str(key, &requester_enc).unwrap_or_else(|_| "?".into());
        let domain = domain_enc.and_then(|b| dec_str(key, &b).ok()).unwrap_or_default();
        let resource_name = dec_str(key, &rname_enc).unwrap_or_else(|_| "?".into());
        let signatories = ids_to_names(&state.db, key, &sig_ids).await;
        let approvers = ids_to_names(&state.db, key, &app_ids).await;
        let status = if consumed_at.is_some() { "consumed" }
                     else if expires_at < chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S%.f").to_string() { "expired" }
                     else if (app_ids.len() as i32) >= threshold_k { "ready" }
                     else { "pending" };
        items.push(AccessRequestSummary {
            id, requester, resource_kind: kind, domain, resource_name,
            threshold_k, signatories, approvers,
            created_at, expires_at, consumed_at,
            status: status.into(),
        });
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({"requests": items, "count": items.len()})))
}

async fn ids_to_names(db: &PgPool, metadata_enc_key: &[u8], ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        if let Ok(Some((b,))) = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT name_enc FROM blackbook_clients WHERE id = $1",
        ).bind(id).fetch_optional(db).await {
            out.push(dec_str(metadata_enc_key, &b).unwrap_or_else(|_| id.clone()));
        } else {
            out.push(id.clone());
        }
    }
    out
}

/// Single access request by id, for the detail view. Authorized for the
/// requester, any listed signatory, or an admin — so a signatory can see a
/// request they're able to approve (including who else can approve it).
pub async fn get_access_request(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let row: Option<(String, String, Vec<u8>, String, Option<Vec<u8>>, Vec<u8>, i32, SqlxJson<Vec<String>>, SqlxJson<Vec<String>>, String, String, Option<String>)> = sqlx::query_as(
        "SELECT r.id, r.requester_id, c.name_enc, r.resource_kind, d.name_enc, r.resource_name_enc,
                r.threshold_k, r.signatory_ids, r.approvers,
                r.created_at::text, r.expires_at::text, r.consumed_at::text
         FROM blackbook_access_requests r
         JOIN blackbook_clients c ON c.id = r.requester_id
         LEFT JOIN blackbook_domains d ON d.id = r.domain_id
         WHERE r.id = $1",
    ).bind(&id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((id, requester_id, requester_enc, kind, domain_enc, rname_enc, threshold_k, SqlxJson(sig_ids), SqlxJson(app_ids), created_at, expires_at, consumed_at)) = row else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such request"));
    };
    if !caller.is_admin() && caller.id != requester_id && !sig_ids.contains(&caller.id) {
        return Ok(err(StatusCode::FORBIDDEN, "forbidden", "not your request and you are not a signatory"));
    }
    let key = state.metadata_enc_key.as_slice();
    let requester = dec_str(key, &requester_enc).unwrap_or_else(|_| "?".into());
    let domain = domain_enc.and_then(|b| dec_str(key, &b).ok()).unwrap_or_default();
    let resource_name = dec_str(key, &rname_enc).unwrap_or_else(|_| "?".into());
    let signatories = ids_to_names(&state.db, key, &sig_ids).await;
    let approvers = ids_to_names(&state.db, key, &app_ids).await;
    let status = if consumed_at.is_some() { "consumed" }
                 else if expires_at < chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S%.f").to_string() { "expired" }
                 else if (app_ids.len() as i32) >= threshold_k { "ready" }
                 else { "pending" };
    Ok(HttpResponse::Ok().json(AccessRequestSummary {
        id, requester, resource_kind: kind, domain, resource_name,
        threshold_k, signatories, approvers, created_at, expires_at, consumed_at,
        status: status.into(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    /// Reader being pre-authorized (client name).
    pub grantee: String,
    /// Resource pattern (`*`/`_` globbing, same as ACL).
    pub pattern: String,
    #[serde(default = "default_grant_kind")]
    pub resource_kind: String,
    pub max_uses: Option<i32>,
    /// RFC3339 expiry. Either this or `ttl_hours` is required.
    pub expires_at: Option<String>,
    pub ttl_hours: Option<i64>,
    pub not_before: Option<String>,
}
fn default_grant_kind() -> String { "secret".into() }

#[derive(Debug, Serialize)]
pub struct AccessGrantSummary {
    pub id: String,
    pub signatory: String,
    pub grantee: String,
    pub domain: String,
    pub resource_kind: String,
    pub pattern: String,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub not_before: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub revoked: bool,
}

/// Create an advance-approval grant. The caller is the signatory; the grant
/// only counts toward a resource's threshold where the caller is actually one
/// of that resource's signatories, so creating one is always safe.
pub async fn create_access_grant(
    state: web::Data<AppState>,
    body: web::Json<CreateGrantRequest>,
    q: web::Query<DomainQuery>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_id, domain_name) = match resolve_and_gate_domain(&state, &caller, &q).await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    if body.resource_kind != "secret" && body.resource_kind != "file" {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "resource_kind must be 'secret' or 'file'"));
    }
    if body.pattern.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "pattern is required"));
    }
    // Resolve grantee name → id.
    let grantee_id: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM blackbook_clients WHERE name_id = $1 AND revoked_at IS NULL",
    ).bind(client_name_id_hex(&state.name_index_key, &body.grantee))
    .fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((grantee_id,)) = grantee_id else {
        return Ok(err(StatusCode::BAD_REQUEST, "unknown_grantee", format!("'{}' is not a known client", body.grantee)));
    };
    // Resolve expiry: explicit RFC3339 wins, else now + ttl_hours. Required.
    let expires_at = match (&body.expires_at, body.ttl_hours) {
        (Some(s), _) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("expires_at: {e}")))?
            .naive_utc(),
        (None, Some(h)) if h > 0 => (chrono::Utc::now() + chrono::Duration::hours(h)).naive_utc(),
        _ => return Ok(err(StatusCode::BAD_REQUEST, "validation_error",
                          "a time limit is required: pass expires_at (RFC3339) or ttl_hours > 0")),
    };
    let not_before = match &body.not_before {
        Some(s) => Some(chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("not_before: {e}")))?
            .naive_utc()),
        None => None,
    };
    if let Some(m) = body.max_uses { if m < 1 {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "max_uses must be >= 1"));
    }}
    let id = Id::new(12).encode();
    let pattern_enc = enc_str(&state.metadata_enc_key, &body.pattern)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    sqlx::query(
        "INSERT INTO blackbook_access_grants
            (id, signatory_id, grantee_id, domain_id, resource_kind, pattern_enc,
             max_uses, not_before, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id).bind(&caller.id).bind(&grantee_id).bind(&domain_id)
    .bind(&body.resource_kind).bind(&pattern_enc).bind(body.max_uses)
    .bind(not_before).bind(expires_at)
    .execute(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "grant.create",
          Some(&body.pattern), AuditStatus::Ok,
          Some(&format!("grantee={} domain={} kind={}", body.grantee, domain_name, body.resource_kind))).await;
    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "signatory": caller.name,
        "grantee": body.grantee,
        "domain": domain_name,
        "resource_kind": body.resource_kind,
        "pattern": body.pattern,
        "max_uses": body.max_uses,
        "expires_at": expires_at.and_utc().to_rfc3339(),
    })))
}

/// List advance grants the caller created (as signatory) or benefits from (as
/// grantee). Admins see all.
pub async fn list_access_grants(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let rows: Vec<(String, Vec<u8>, Vec<u8>, Option<Vec<u8>>, String, Vec<u8>, Option<i32>, i32, Option<String>, String, String, Option<String>)> = if caller.is_admin() {
        sqlx::query_as(
            "SELECT g.id, s.name_enc, gr.name_enc, d.name_enc, g.resource_kind, g.pattern_enc,
                    g.max_uses, g.use_count, g.not_before::text, g.expires_at::text, g.created_at::text, g.revoked_at::text
             FROM blackbook_access_grants g
             JOIN blackbook_clients s ON s.id = g.signatory_id
             JOIN blackbook_clients gr ON gr.id = g.grantee_id
             LEFT JOIN blackbook_domains d ON d.id = g.domain_id
             ORDER BY g.created_at DESC LIMIT 200",
        ).fetch_all(&state.db).await
    } else {
        sqlx::query_as(
            "SELECT g.id, s.name_enc, gr.name_enc, d.name_enc, g.resource_kind, g.pattern_enc,
                    g.max_uses, g.use_count, g.not_before::text, g.expires_at::text, g.created_at::text, g.revoked_at::text
             FROM blackbook_access_grants g
             JOIN blackbook_clients s ON s.id = g.signatory_id
             JOIN blackbook_clients gr ON gr.id = g.grantee_id
             LEFT JOIN blackbook_domains d ON d.id = g.domain_id
             WHERE g.signatory_id = $1 OR g.grantee_id = $1
             ORDER BY g.created_at DESC LIMIT 200",
        ).bind(&caller.id).fetch_all(&state.db).await
    }
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let mut items = Vec::new();
    for (id, sig_enc, grantee_enc, domain_enc, kind, pat_enc, max_uses, use_count, not_before, expires_at, created_at, revoked_at) in rows {
        items.push(AccessGrantSummary {
            id,
            signatory: dec_str(key, &sig_enc).unwrap_or_else(|_| "?".into()),
            grantee: dec_str(key, &grantee_enc).unwrap_or_else(|_| "?".into()),
            domain: domain_enc.and_then(|b| dec_str(key, &b).ok()).unwrap_or_default(),
            resource_kind: kind,
            pattern: dec_str(key, &pat_enc).unwrap_or_else(|_| "?".into()),
            max_uses, use_count,
            not_before, expires_at, created_at,
            revoked: revoked_at.is_some(),
        });
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({"grants": items, "count": items.len()})))
}

/// Revoke an advance grant. Only the signatory who created it (or an admin)
/// may revoke it.
pub async fn revoke_access_grant(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT signatory_id FROM blackbook_access_grants WHERE id = $1 AND revoked_at IS NULL",
    ).bind(&id).fetch_optional(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some((signatory_id,)) = row else {
        return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such (active) grant"));
    };
    if !caller.is_admin() && caller.id != signatory_id {
        return Ok(err(StatusCode::FORBIDDEN, "forbidden", "only the granting signatory (or an admin) may revoke"));
    }
    sqlx::query("UPDATE blackbook_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(&id).execute(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "grant.revoke",
          Some(&id), AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"revoked": true, "id": id})))
}

pub async fn mfa_verify(
    state: web::Data<AppState>,
    req: web::Json<MfaVerifyRequest>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let kek_bytes = state.keys.read().await.mfa_secret_kek.handle()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let ok = auth::verify_totp(&state.db, &kek_bytes, &caller.id, &req.code).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "mfa.verify", None,
          if ok { AuditStatus::Ok } else { AuditStatus::Denied }, None).await;
    if ok {
        Ok(HttpResponse::Ok().json(serde_json::json!({"verified": true})))
    } else {
        Ok(err(StatusCode::UNAUTHORIZED, "mfa_failed", "invalid TOTP code"))
    }
}

pub async fn list_domain_members(
    state: web::Data<AppState>,
    path: web::Path<String>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    let domain_name = path.into_inner();
    let domain_id = match auth::resolve_domain(&state.db, &state.name_index_key, &domain_name).await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        Some(id) => id,
        None => return Ok(err(StatusCode::NOT_FOUND, "no_such_domain",
                            format!("domain '{domain_name}' does not exist"))),
    };
    // Non-admins must be members of the domain themselves.
    if !caller.is_admin() {
        let is_member = auth::domain_member(&state.db, &caller, &domain_id).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        if !is_member {
            return Ok(err(StatusCode::FORBIDDEN, "forbidden", "not a member of this domain"));
        }
    }
    let rows: Vec<(Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT c.name_enc, m.role, m.added_at::text
         FROM blackbook_domain_members m
         JOIN blackbook_clients c ON c.id = m.client_id
         WHERE m.domain_id = $1
         ORDER BY m.added_at",
    ).bind(&domain_id).fetch_all(&state.db).await
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let key = state.metadata_enc_key.as_slice();
    let items: Vec<_> = rows.into_iter()
        .map(|(name_enc, role, added_at)| MemberSummary {
            client_name: dec_str(key, &name_enc).unwrap_or_else(|_| "?".into()),
            role, added_at,
        })
        .collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({"members": items, "count": items.len()})))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
}
fn default_audit_limit() -> i64 { 100 }

pub async fn list_audit(
    state: web::Data<AppState>,
    q: web::Query<AuditQuery>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let limit = q.limit.clamp(1, 1000);
    let rows: Vec<(i64, String, Option<String>, Option<Vec<u8>>, String, Option<Vec<u8>>, String, Option<Vec<u8>>)> =
        sqlx::query_as(
            "SELECT a.id, a.ts::text, a.client_id, c.name_enc, a.action, a.resource_enc, a.status, a.message_enc
             FROM blackbook_audit a LEFT JOIN blackbook_clients c ON c.id = a.client_id
             ORDER BY a.ts DESC LIMIT $1",
        ).bind(limit).fetch_all(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    // Decrypt the per-row fields. A decryption failure on any row means the
    // master key changed or the row was corrupted — surface "-" so the rest
    // of the page is still readable, but log it.
    let key = state.metadata_enc_key.as_slice();
    let dec = |b: Option<Vec<u8>>| -> Option<String> {
        b.and_then(|bytes| dec_str(key, &bytes).ok())
    };
    let items: Vec<_> = rows.into_iter()
        .map(|(id, ts, client_id, client_name_enc, action, resource_enc, status, message_enc)| AuditEntry {
            id, ts, client_id,
            client_name: dec(client_name_enc),
            action,
            resource: dec(resource_enc),
            status,
            message: dec(message_enc),
        }).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({"entries": items, "count": items.len()})))
}

/// Recompute the audit hash chain from the genesis row forward and report
/// the first row (if any) whose stored `row_hash` disagrees with the
/// recomputed value — i.e. the earliest point at which the log was tampered,
/// truncated, or reordered. Admin only.
pub async fn verify_audit(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let rows: Vec<(i64, chrono::NaiveDateTime, Option<String>, String, Option<Vec<u8>>, String, Option<Vec<u8>>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT id, ts, client_id, action, resource_enc, status, message_enc, prev_hash, row_hash
             FROM blackbook_audit ORDER BY id ASC",
        ).fetch_all(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let key = state.audit_hmac_key.as_slice();
    // Resume from the latest archive anchor (if old rows were archived+pruned)
    // so the first surviving row's prev_hash chains correctly; else genesis.
    let mut prev = match latest_audit_anchor(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)? {
        Some((_id, h)) => h,
        None => [0u8; 32],
    };
    let mut verified: i64 = 0;
    for (id, ts, client_id, action, resource_enc, status, message_enc, stored_prev, stored_row) in rows {
        // Decrypt the encrypted columns back to plaintext for hashing —
        // the chain is over canonical content, not over the storage
        // representation (random IV would otherwise make the hash unstable).
        let resource: Option<String> = match resource_enc {
            Some(b) => match dec_str(&state.metadata_enc_key, &b) {
                Ok(s) => Some(s),
                Err(_) => {
                    return Ok(HttpResponse::Ok().json(serde_json::json!({
                        "ok": false, "verified_through": verified, "first_bad_id": id,
                        "reason": "resource_enc failed to decrypt",
                    })));
                }
            },
            None => None,
        };
        let message: Option<String> = match message_enc {
            Some(b) => match dec_str(&state.metadata_enc_key, &b) {
                Ok(s) => Some(s),
                Err(_) => {
                    return Ok(HttpResponse::Ok().json(serde_json::json!({
                        "ok": false, "verified_through": verified, "first_bad_id": id,
                        "reason": "message_enc failed to decrypt",
                    })));
                }
            },
            None => None,
        };
        // A row with no row_hash never went through the chained writer and
        // wasn't backfilled — treat it as the first broken link.
        let Some(stored_row) = stored_row else {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "ok": false, "verified_through": verified, "first_bad_id": id,
                "reason": "row has no row_hash (unchained insert?)",
            })));
        };
        // prev_hash on the row must equal the running chain value.
        let expected_prev_hex = hex::encode(prev);
        if stored_prev.as_deref() != Some(expected_prev_hex.as_str()) {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "ok": false, "verified_through": verified, "first_bad_id": id,
                "reason": "prev_hash does not match the preceding row (deletion or reorder?)",
            })));
        }
        let computed = auth::compute_audit_hash(
            key, &prev, ts.and_utc().timestamp_micros(),
            client_id.as_deref(), &action, resource.as_deref(), &status, message.as_deref(),
        );
        if hex::encode(computed) != stored_row {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "ok": false, "verified_through": verified, "first_bad_id": id,
                "reason": "row_hash mismatch (row contents were altered?)",
            })));
        }
        let mut next = [0u8; 32];
        if hex::decode_to_slice(&stored_row, &mut next).is_err() {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "ok": false, "verified_through": verified, "first_bad_id": id,
                "reason": "row_hash is not valid hex",
            })));
        }
        prev = next;
        verified += 1;
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id), "audit.verify", None,
          AuditStatus::Ok, Some(&format!("verified {verified} rows"))).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "ok": true, "verified_through": verified,
    })))
}

// ---------------------------------------------------------------------------
// Audit-log archival (compress + encrypt + chain-verify old rows off the DB)
// ---------------------------------------------------------------------------

/// The latest archive anchor: `(archived_through_id, final_row_hash)` of the
/// most recent prune, or `None` if nothing has been pruned.
async fn latest_audit_anchor(db: &PgPool) -> sqlx::Result<Option<(i64, [u8; 32])>> {
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT archived_through_id, final_row_hash FROM blackbook_audit_anchors
         ORDER BY archived_through_id DESC LIMIT 1",
    ).fetch_optional(db).await?;
    Ok(row.and_then(|(id, h)| {
        let mut buf = [0u8; 32];
        hex::decode_to_slice(&h, &mut buf).ok().map(|_| (id, buf))
    }))
}

/// Dedicated AES key for encrypting archive files — domain-separated from the
/// metadata key and the audit MAC key.
fn audit_archive_enc_key(keys: &BlackbookKey) -> std::result::Result<Vec<u8>, String> {
    keys.index.handle_with_info(b"audit-archive-enc/v1").map_err(|e| e.to_string())
}

/// Best-effort timestamp parse for the `before` cutoff.
fn parse_audit_ts(s: &str) -> Option<chrono::NaiveDateTime> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) { return Some(dt.naive_utc()); }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) { return Some(dt); }
        if fmt == "%Y-%m-%d" {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, fmt) { return d.and_hms_opt(0,0,0); }
        }
    }
    None
}

/// Reject path traversal: an archive name must be a bare `*.bbka` filename.
fn safe_archive_name(name: &str) -> bool {
    !name.is_empty() && name.ends_with(".bbka")
        && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

#[derive(Debug, Deserialize)]
pub struct ArchiveQuery {
    /// Archive rows older than this timestamp (RFC3339 / `YYYY-MM-DD[ HH:MM:SS]`).
    pub before: Option<String>,
    /// Keep the most recent N rows un-archived (mutually exclusive with `before`).
    pub keep_last: Option<i64>,
    /// Delete the archived rows from the DB and record a chain anchor.
    #[serde(default)]
    pub prune: bool,
}

/// Export the oldest contiguous run of audit rows to a compressed, encrypted,
/// chain-verifiable archive on the data volume; optionally prune them. Admin.
/// At least one row is always kept live so the running chain head stays a real
/// row.
pub async fn audit_archive_create(
    state: web::Data<AppState>,
    q: web::Query<ArchiveQuery>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let (anchor_id, genesis_prev) = latest_audit_anchor(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .unwrap_or((0i64, [0u8; 32]));

    let rows: Vec<(i64, chrono::NaiveDateTime, Option<String>, String, Option<Vec<u8>>, String, Option<Vec<u8>>, Option<String>, String)> =
        sqlx::query_as(
            "SELECT id, ts, client_id, action, resource_enc, status, message_enc, prev_hash, row_hash
             FROM blackbook_audit WHERE id > $1 ORDER BY id ASC",
        ).bind(anchor_id).fetch_all(&state.db).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let total = rows.len();
    if total <= 1 {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "archived": 0, "message": "fewer than 2 live rows — nothing to archive"})));
    }

    // How many of the oldest rows to archive. Always keep >= 1 row live.
    let mut cutoff = if let Some(keep) = q.keep_last {
        total.saturating_sub(keep.max(0) as usize)
    } else if let Some(before) = &q.before {
        match parse_audit_ts(before) {
            Some(b) => rows.iter().take_while(|r| r.1 < b).count(),
            None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error":"unparseable 'before' timestamp"}))),
        }
    } else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error":"specify 'keep_last' (keep N most recent) or 'before' (timestamp)"})));
    };
    cutoff = cutoff.min(total - 1); // never archive the very last live row
    if cutoff == 0 {
        return Ok(HttpResponse::Ok().json(serde_json::json!({"archived":0,"message":"nothing matched the cutoff"})));
    }

    let mut arows = Vec::with_capacity(cutoff);
    for (id, ts, client_id, action, resource_enc, status, message_enc, prev_hash, row_hash) in rows.iter().take(cutoff) {
        let dec = |b: &Option<Vec<u8>>| -> std::result::Result<Option<String>, actix_web::Error> {
            match b { Some(x) => Ok(Some(dec_str(&state.metadata_enc_key, x)
                .map_err(actix_web::error::ErrorInternalServerError)?)), None => Ok(None) }
        };
        arows.push(audit_archive::ArchivedRow {
            id: *id, ts_micros: ts.and_utc().timestamp_micros(),
            client_id: client_id.clone(), action: action.clone(), status: status.clone(),
            resource: dec(resource_enc)?, message: dec(message_enc)?,
            prev_hash: prev_hash.clone().unwrap_or_default(), row_hash: row_hash.clone(),
        });
    }
    let first_id = arows.first().unwrap().id;
    let last_id = arows.last().unwrap().id;
    let final_row_hash = arows.last().unwrap().row_hash.clone();
    let archive = audit_archive::AuditArchive {
        v: audit_archive::ARCHIVE_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        count: arows.len(), first_id, last_id,
        genesis_prev: hex::encode(genesis_prev), final_row_hash: final_row_hash.clone(),
        rows: arows,
    };
    // Refuse to archive if the live chain over this range doesn't verify.
    let v = audit_archive::verify_archive(&state.audit_hmac_key, &archive);
    if !v.ok {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error":"the live audit chain does not verify over the selected range; refusing to archive",
            "detail": v})));
    }
    let enc_key = { let keys = state.keys.read().await; audit_archive_enc_key(&keys) }
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let blob = audit_archive::build_archive(&enc_key, &archive)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let dir = state.data_dir.join("audit-archives");
    tokio::fs::create_dir_all(&dir).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let fname = format!("audit-{first_id:010}-{last_id:010}-{}.bbka",
                        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
    tokio::fs::write(dir.join(&fname), &blob).await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let mut pruned = 0u64;
    if q.prune {
        let res = sqlx::query("DELETE FROM blackbook_audit WHERE id > $1 AND id <= $2")
            .bind(anchor_id).bind(last_id).execute(&state.db).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
        pruned = res.rows_affected();
        sqlx::query("INSERT INTO blackbook_audit_anchors (archived_through_id, final_row_hash, archive_file)
                     VALUES ($1, $2, $3)")
            .bind(last_id).bind(&final_row_hash).bind(&fname).execute(&state.db).await
            .map_err(actix_web::error::ErrorInternalServerError)?;
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&caller.id),
          "audit.archive", Some(&fname), AuditStatus::Ok,
          Some(&format!("archived {} rows (id {first_id}..{last_id}); pruned {pruned}", archive.count))).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "archived": archive.count, "first_id": first_id, "last_id": last_id,
        "file": fname, "pruned": pruned, "size_bytes": blob.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct VerifyArchiveQuery { pub file: String }

/// Decrypt + decompress a named archive and recompute its hash chain end to
/// end with the master MAC key. Admin.
pub async fn audit_archive_verify(
    state: web::Data<AppState>,
    q: web::Query<VerifyArchiveQuery>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    if !safe_archive_name(&q.file) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error":"invalid archive name"})));
    }
    let path = state.data_dir.join("audit-archives").join(&q.file);
    let blob = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error":"no such archive"}))),
    };
    let enc_key = { let keys = state.keys.read().await; audit_archive_enc_key(&keys) }
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let archive = match audit_archive::open_archive(&enc_key, &blob) {
        Ok(a) => a,
        Err(e) => return Ok(HttpResponse::Ok().json(serde_json::json!({"ok":false,"reason":e.to_string()}))),
    };
    let v = audit_archive::verify_archive(&state.audit_hmac_key, &archive);
    Ok(HttpResponse::Ok().json(v))
}

/// List archive files on the data volume. Admin.
pub async fn audit_archive_list(
    state: web::Data<AppState>,
    caller: AuthenticatedClient,
) -> Result<HttpResponse> {
    if let Err(resp) = require_admin(&caller) { return Ok(resp); }
    let dir = state.data_dir.join("audit-archives");
    let mut files: Vec<serde_json::Value> = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".bbka") { continue; }
            let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
            files.push(serde_json::json!({"file": name, "size_bytes": size}));
        }
    }
    files.sort_by(|a, b| a["file"].as_str().cmp(&b["file"].as_str()));
    Ok(HttpResponse::Ok().json(serde_json::json!({"archives": files, "count": files.len()})))
}

// ---------------------------------------------------------------------------
// TLS / mTLS bootstrap
// ---------------------------------------------------------------------------

/// Build the OpenSSL acceptor for the API server.
///
/// - Pins to TLS 1.3 (no SSLv3/TLS1.0/1.1/1.2 fallback).
/// - Loads the auto-generated server cert + key.
/// - Trusts only our internal CA for client cert verification.
/// - Accepts client certs (`SslVerifyMode::PEER`) but does NOT require them
///   at the TLS layer — the app layer decides between cert-or-token paths.
fn build_ssl_acceptor(
    cert_path: &str, key_path: &str, ca_path: &str,
) -> std::io::Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion};

    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    acceptor.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_RENEGOTIATION);

    acceptor.set_certificate_chain_file(cert_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    acceptor.set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    acceptor.check_private_key()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    acceptor.set_ca_file(ca_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    // PEER alone = request and validate cert if presented; no failure if absent.
    // The app layer then decides whether to accept token-only requests.
    acceptor.set_verify(SslVerifyMode::PEER);
    // actix-web's `bind_openssl` wants the builder, not the built acceptor.
    Ok(acceptor)
}

// ---------------------------------------------------------------------------
// Tunnels — relay opaque E2E frames between two mTLS-authenticated clients.
// The server pairs them and vouches each peer's name + cert fingerprint; it
// never sees the ephemeral keys, so it cannot read or forge the channel.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OfferTunnelRequest {
    /// Client name the offerer wants to reach.
    pub target: String,
}

/// Look up a client's current cert fingerprint by name (the value the relay
/// vouches to the peer). Returns None if no active client by that name.
async fn client_fingerprint(state: &AppState, name: &str) -> Option<String> {
    let name_id = client_name_id_hex(&state.name_index_key, name);
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT cert_fingerprint FROM blackbook_clients WHERE name_id = $1 AND revoked_at IS NULL",
    ).bind(&name_id).fetch_optional(&state.db).await.ok().flatten();
    row.map(|(fp,)| fp)
}

/// Offer a tunnel to another client. Returns a tunnel id the offerer then opens
/// a WebSocket on; the target joins the same id.
pub async fn offer_tunnel(
    state: web::Data<AppState>,
    req: web::Json<OfferTunnelRequest>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    if req.target.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "target is required"));
    }
    if req.target == client.name {
        return Ok(err(StatusCode::BAD_REQUEST, "validation_error", "cannot tunnel to yourself"));
    }
    // The target must exist (so the offerer gets a clear error, and so we don't
    // mint dangling offers). Its fingerprint is resolved at attach time.
    if client_fingerprint(&state, &req.target).await.is_none() {
        return Ok(err(StatusCode::NOT_FOUND, "not_found",
                      format!("no active client named '{}'", req.target)));
    }
    let my_fp = match client_fingerprint(&state, &client.name).await {
        Some(fp) => fp,
        None => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "own fingerprint not found")),
    };
    let id = state.tunnels.offer(&client.name, &my_fp, &req.target).await;
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id), "tunnel.offer",
          Some(&req.target), AuditStatus::Ok, None).await;
    Ok(HttpResponse::Created().json(serde_json::json!({ "tunnel_id": id, "target": req.target })))
}

/// List tunnels this client offered or is the target of.
pub async fn list_tunnels(
    state: web::Data<AppState>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let items = state.tunnels.list_for(&client.name).await;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "tunnels": items, "count": items.len() })))
}

/// WebSocket endpoint: both peers connect here with the tunnel id. The server
/// pairs them, vouches each to the other, then relays opaque binary frames.
pub async fn tunnel_ws(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    body: web::Payload,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let tunnel_id = path.into_inner();
    use crate::tunnel_relay::{RelayMsg, Vouch};
    use futures_util::StreamExt as _;

    // Identify this caller's role within the tunnel and reject anyone who isn't
    // one of the two authorized parties.
    let role = state.tunnels.with_lock(|map| {
        map.get(&tunnel_id).map(|t| {
            if t.offerer_name == client.name { Some(true) }       // offerer/initiator
            else if t.target_name == client.name { Some(false) }  // target/answerer
            else { None }
        })
    }).await;
    let is_initiator = match role {
        Some(Some(r)) => r,
        Some(None) => return Ok(err(StatusCode::FORBIDDEN, "forbidden", "not a party to this tunnel")),
        None => return Ok(err(StatusCode::NOT_FOUND, "not_found", "no such tunnel")),
    };

    let (resp, ws_session, mut msg_stream) = actix_ws::handle(&req, body)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Channel the *peer's* WS task uses to push frames toward us.
    let (my_tx, mut my_rx) = mpsc::unbounded_channel::<RelayMsg>();

    // Register our side and, if the peer is already attached, capture both
    // vouches + the peer's sender so we can wire the pair.
    let my_name = client.name.clone();
    let my_fp = client_fingerprint(&state, &client.name).await.unwrap_or_default();
    let tunnels = state.tunnels.clone();
    let tid = tunnel_id.clone();

    struct Wiring {
        peer_tx: Option<mpsc::UnboundedSender<RelayMsg>>,
        my_vouch: Option<Vouch>,
        peer_vouch_and_tx: Option<(Vouch, mpsc::UnboundedSender<RelayMsg>)>,
    }
    let wiring = tunnels.with_lock(|map| {
        let Some(t) = map.get_mut(&tid) else {
            return Wiring { peer_tx: None, my_vouch: None, peer_vouch_and_tx: None };
        };
        if is_initiator {
            t.offerer_name = my_name.clone();
            t.offerer_fp = my_fp.clone();
            t.to_offerer = Some(my_tx.clone());
        } else {
            t.answerer_name = Some(my_name.clone());
            t.answerer_fp = Some(my_fp.clone());
            t.to_answerer = Some(my_tx.clone());
        }
        // If both sides are now present, produce both vouches.
        if t.to_offerer.is_some() && t.to_answerer.is_some() {
            let off_v = Vouch {
                you_are_initiator: true, tunnel_id: tid.clone(),
                peer_name: t.answerer_name.clone().unwrap_or_default(),
                peer_fingerprint: t.answerer_fp.clone().unwrap_or_default(),
            };
            let ans_v = Vouch {
                you_are_initiator: false, tunnel_id: tid.clone(),
                peer_name: t.offerer_name.clone(),
                peer_fingerprint: t.offerer_fp.clone(),
            };
            // "my" vouch describes the peer to me; "peer" vouch goes to them.
            let (my_vouch, peer_vouch, peer_tx) = if is_initiator {
                (off_v, ans_v, t.to_answerer.clone().unwrap())
            } else {
                (ans_v, off_v, t.to_offerer.clone().unwrap())
            };
            Wiring {
                peer_tx: Some(peer_tx.clone()),
                my_vouch: Some(my_vouch),
                peer_vouch_and_tx: Some((peer_vouch, peer_tx)),
            }
        } else {
            Wiring { peer_tx: None, my_vouch: None, peer_vouch_and_tx: None }
        }
    }).await;

    // If we completed the pair, deliver both vouches now (mine into my own
    // queue, the peer's into theirs). If we're first, the second arrival does it.
    let peer_tx_for_frames = wiring.peer_tx.clone();
    if let Some(v) = wiring.my_vouch { let _ = my_tx.send(RelayMsg::Vouch(v)); }
    if let Some((v, ptx)) = wiring.peer_vouch_and_tx { let _ = ptx.send(RelayMsg::Vouch(v)); }

    // Outbound pump: RelayMsg → this WebSocket.
    let mut out = ws_session.clone();
    actix_web::rt::spawn(async move {
        while let Some(msg) = my_rx.recv().await {
            match msg {
                RelayMsg::Vouch(v) => {
                    let json = serde_json::to_string(&v).unwrap_or_default();
                    if out.text(json).await.is_err() { break; }
                }
                RelayMsg::Frame(bytes) => {
                    if out.binary(bytes).await.is_err() { break; }
                }
                RelayMsg::PeerGone => { let _ = out.close(None).await; break; }
            }
        }
    });

    // Inbound pump: this WebSocket → peer's queue. Resolve the peer sender
    // lazily (the peer may attach after us) by re-reading the hub on first frame.
    let tunnels2 = state.tunnels.clone();
    let tid2 = tunnel_id.clone();
    actix_web::rt::spawn(async move {
        let mut peer_tx = peer_tx_for_frames;
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                actix_ws::Message::Binary(b) => {
                    if peer_tx.is_none() {
                        peer_tx = tunnels2.with_lock(|map| {
                            map.get(&tid2).and_then(|t| {
                                if is_initiator { t.to_answerer.clone() } else { t.to_offerer.clone() }
                            })
                        }).await;
                    }
                    if let Some(tx) = &peer_tx {
                        if tx.send(RelayMsg::Frame(b.to_vec())).is_err() { break; }
                    }
                }
                actix_ws::Message::Ping(p) => { let _ = ws_session.clone().pong(&p).await; }
                actix_ws::Message::Close(_) => break,
                _ => {}
            }
        }
        // Teardown: tell the peer and drop the tunnel.
        let peer = tunnels2.with_lock(|map| {
            let peer = map.get(&tid2).and_then(|t| {
                if is_initiator { t.to_answerer.clone() } else { t.to_offerer.clone() }
            });
            map.remove(&tid2);
            peer
        }).await;
        if let Some(tx) = peer { let _ = tx.send(RelayMsg::PeerGone); }
    });

    Ok(resp)
}

/// Rate-limit key for a request: the mTLS client-cert CN if present (every
/// request is mTLS-authenticated), else the peer IP.
fn net_client_key(req: &actix_web::dev::ServiceRequest) -> String {
    if let Some(p) = req.conn_data::<crate::auth::PeerCertInfo>() {
        if !p.common_name.is_empty() { return format!("cn:{}", p.common_name); }
    }
    let ci = req.connection_info();
    let ip = ci.realip_remote_addr().unwrap_or("?").to_string();
    format!("ip:{ip}")
}

pub async fn run_server(
    state: AppState,
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> std::io::Result<()> {
    log::info!("Starting Blackbook HTTPS server on {bind_addr}");
    let acceptor = build_ssl_acceptor(cert_path, key_path, ca_path)?;

    // Tier 1: one shared, loose per-client network rate limiter across workers.
    let net_limiter = std::sync::Arc::new(crate::net_ratelimit::NetRateLimiter::from_env());

    HttpServer::new(move || {
        let nl = net_limiter.clone();
        App::new()
            .app_data(web::Data::new(state.clone()))
            // Generous-ish payload limit so file uploads work; per-route guard
            // also enforces MAX_FILE_BYTES.
            .app_data(web::PayloadConfig::new(MAX_FILE_BYTES))
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            // Coarse anti-DoS gate before anything else runs.
            .wrap_fn(move |req, srv| {
                use actix_web::dev::Service as _;
                use futures_util::future::FutureExt as _;
                if nl.allow(&net_client_key(&req)) {
                    srv.call(req).map(|r| r.map(|sr| sr.map_into_boxed_body())).boxed_local()
                } else {
                    let resp = req.into_response(HttpResponse::TooManyRequests()
                        .json(serde_json::json!({
                            "error": "rate_limited",
                            "message": "too many requests from this client; slow down",
                        })))
                        .map_into_boxed_body();
                    async move { Ok(resp) }.boxed_local()
                }
            })
            // Public
            .route("/health", web::get().to(health_check))
            // Authenticated user-level
            .route("/api/v1/whoami", web::get().to(whoami))
            // Secrets
            .route("/api/v1/store", web::post().to(store_data))
            .route("/api/v1/retrieve", web::post().to(retrieve_data))
            .route("/api/v1/delete", web::post().to(delete_data))
            .route("/api/v1/list", web::get().to(list_resources))
            .route("/api/v1/cleanup", web::post().to(cleanup_secrets))
            // Files
            .route("/api/v1/files", web::get().to(list_files))
            .route("/api/v1/files/{name}", web::put().to(upload_file))
            .route("/api/v1/files/{name}", web::get().to(download_file))
            .route("/api/v1/files/{name}", web::delete().to(delete_file))
            .route("/api/v1/files/{name}/rotate", web::post().to(rotate_file))
            // Admin
            .route("/api/v1/clients", web::post().to(create_client_endpoint))
            .route("/api/v1/clients", web::get().to(list_clients_endpoint))
            .route("/api/v1/clients/{name}/revoke", web::post().to(revoke_client_endpoint))
            .route("/api/v1/clients/{name}/rotate", web::post().to(rotate_client_endpoint))
            .route("/api/v1/acl", web::post().to(grant_acl))
            .route("/api/v1/acl", web::get().to(list_acl))
            .route("/api/v1/acl/{id}", web::delete().to(revoke_acl))
            // MFA
            .route("/api/v1/mfa/enroll", web::post().to(mfa_enroll))
            .route("/api/v1/mfa/verify", web::post().to(mfa_verify))
            // Threshold approvals
            .route("/api/v1/access-requests", web::get().to(list_access_requests))
            .route("/api/v1/access-requests/{id}/approve", web::post().to(approve_access_request))
            .route("/api/v1/access-requests/{id}", web::get().to(get_access_request))
            .route("/api/v1/access-grants", web::post().to(create_access_grant))
            .route("/api/v1/access-grants", web::get().to(list_access_grants))
            .route("/api/v1/access-grants/{id}", web::delete().to(revoke_access_grant))
            // Domains + memberships
            .route("/api/v1/domains", web::post().to(create_domain))
            .route("/api/v1/domains", web::get().to(list_domains))
            .route("/api/v1/domains/{name}/members", web::post().to(add_domain_member))
            .route("/api/v1/domains/{name}/members", web::get().to(list_domain_members))
            .route("/api/v1/domains/{name}/members/{client}", web::delete().to(remove_domain_member))
            .route("/api/v1/audit", web::get().to(list_audit))
            .route("/api/v1/audit/verify", web::get().to(verify_audit))
            .route("/api/v1/audit/archive", web::post().to(audit_archive_create))
            .route("/api/v1/audit/archive/verify", web::get().to(audit_archive_verify))
            .route("/api/v1/audit/archives", web::get().to(audit_archive_list))
            // Tunnels — client↔client E2E relay
            .route("/api/v1/tunnels", web::post().to(offer_tunnel))
            .route("/api/v1/tunnels", web::get().to(list_tunnels))
            .route("/api/v1/tunnels/{id}/ws", web::get().to(tunnel_ws))
    })
    // Hand the OpenSSL stream's peer cert info to per-request extractors.
    // actix-tls's `TlsStream<IO>` derefs to the inner `SslStream<IO>` via its
    // `Deref` impl, so we can call `.ssl()` directly on the wrapper.
    .on_connect(|conn, ext| {
        use actix_tls::accept::openssl::TlsStream;
        if let Some(stream) = conn.downcast_ref::<TlsStream<tokio::net::TcpStream>>() {
            if let Some(cert) = stream.ssl().peer_certificate() {
                let der = cert.to_der().unwrap_or_default();
                use sha3::Digest;
                let mut h = sha3::Sha3_256::new();
                h.update(&der);
                let fingerprint = hex::encode(h.finalize());
                if let Some(cn) = cert
                    .subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .next()
                    .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
                {
                    ext.insert(PeerCertInfo { common_name: cn, fingerprint });
                }
            }
        }
    })
    .bind_openssl(bind_addr, acceptor)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::name_id_hex;

    #[test]
    fn name_id_is_deterministic_and_hex64() {
        let key = b"index-key-32-bytes-xxxxxxxxxxxxxx";
        let a = name_id_hex(key, "default", "api-key");
        let b = name_id_hex(key, "default", "api-key");
        assert_eq!(a, b, "same (domain,name) must map to the same id");
        assert_eq!(a.len(), 64, "name_id must be 64 hex chars to fit CHAR(64)");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn name_id_separates_domain_and_name() {
        let key = b"index-key-32-bytes-xxxxxxxxxxxxxx";
        // Same name, different domain → different id (no cross-domain collision).
        assert_ne!(name_id_hex(key, "default", "api-key"),
                   name_id_hex(key, "eng", "api-key"));
        // Different name, same domain → different id.
        assert_ne!(name_id_hex(key, "default", "api-key"),
                   name_id_hex(key, "default", "db-key"));
        // Length-prefix framing: ("ab","c") must not collide with ("a","bc").
        assert_ne!(name_id_hex(key, "ab", "c"), name_id_hex(key, "a", "bc"));
    }

    #[test]
    fn name_id_depends_on_key() {
        assert_ne!(
            name_id_hex(b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "default", "api-key"),
            name_id_hex(b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "default", "api-key"));
    }
}
