//! Authentication, authorization, and auditing for the Blackbook HTTP API.
//!
//! **Every request must satisfy *both* factors — there is no lesser path.**
//!
//! 1. **mTLS** — the client presents a certificate signed by Blackbook's CA.
//!    The TLS handshake validates the chain; the server's [`PeerCertInfo`]
//!    (populated by `on_connect` in `server.rs`) records the certificate's
//!    Common Name and SHA3-256 fingerprint. The client is looked up by the
//!    HMAC of its name and the row's `cert_fingerprint` must match.
//!
//! 2. **Bearer token** — the client sends `Authorization: Bearer <token>`.
//!    SHA3-256 of the token is matched against `blackbook_clients.token_hash`.
//!
//! Both must be present, both must resolve to a non-revoked, non-expired
//! client, and both must resolve to **the same** client row. A request with
//! only a certificate, only a token, or with the two disagreeing is rejected
//! with 401. This means possession of a full credential bundle (cert + key +
//! token, all pinned to one identity) is required — a leaked token alone or a
//! copied certificate alone is useless.

use actix_web::dev::Payload;
use actix_web::http::header;
use actix_web::{error as actix_error, FromRequest, HttpRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, NaiveDateTime, Utc};
use futures_util::future::LocalBoxFuture;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use sqlx::PgPool;

use crate::blackbook_core::{AclAction, Id};
use crate::tls::{self, CertBundle, SharedCa, ADMIN_CLIENT_TTL_DAYS, DEFAULT_CLIENT_TTL_DAYS};

pub const TOKEN_PREFIX: &str = "bbk_";

/// CN extracted from the peer's TLS certificate, stashed in per-connection
/// extensions by `server.rs::run_server`'s `on_connect` callback.
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    pub common_name: String,
    pub fingerprint: String,
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn hash_token(token: &str) -> String {
    let mut h = Sha3_256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn action_bit(action: AclAction) -> i32 {
    match action {
        AclAction::Create => 1,
        AclAction::Read => 2,
        AclAction::Update => 4,
        AclAction::Delete => 8,
    }
}

pub fn action_name(action: AclAction) -> &'static str {
    match action {
        AclAction::Create => "create",
        AclAction::Read => "read",
        AclAction::Update => "update",
        AclAction::Delete => "delete",
    }
}

/// Default cert/token TTL in days for a given role.
pub fn default_ttl_days(role: &str) -> i64 {
    match role {
        "admin" => ADMIN_CLIENT_TTL_DAYS,
        _ => DEFAULT_CLIENT_TTL_DAYS,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedClient {
    pub id: String,
    pub name: String,
    pub role: String,
    /// How the request authenticated. Only one value is ever produced —
    /// [`AuthMethod::MutualTlsAndToken`] — because both factors are
    /// mandatory. Retained as an enum so audit/whoami output stays stable
    /// and a future factor could extend it.
    pub auth_method: AuthMethod,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    /// The only accepted state: a valid client certificate *and* a valid
    /// bearer token that resolve to the same client.
    MutualTlsAndToken,
}

impl AuthenticatedClient {
    pub fn is_admin(&self) -> bool { self.role == "admin" }
}

impl FromRequest for AuthenticatedClient {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, actix_web::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = req
            .app_data::<actix_web::web::Data<crate::server::AppState>>()
            .cloned();
        let token_value = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()));
        let peer = req.conn_data::<PeerCertInfo>().cloned();

        Box::pin(async move {
            let state = state.ok_or_else(|| {
                actix_error::ErrorInternalServerError("app state missing")
            })?;
            let by_cert = if let Some(p) = peer.as_ref() {
                lookup_by_cn(&state.db, &state.metadata_enc_key, &state.name_index_key,
                             &p.common_name, &p.fingerprint).await
                    .map_err(|e| actix_error::ErrorInternalServerError(e.to_string()))?
            } else { None };
            let by_token = if let Some(t) = token_value.as_ref() {
                lookup_by_token(&state.db, &state.metadata_enc_key, t).await
                    .map_err(|e| actix_error::ErrorInternalServerError(e.to_string()))?
            } else { None };

            // Both factors are mandatory and must agree. No cert-only or
            // token-only path exists — a full bundle (cert + key + token,
            // all bound to one identity) is the only accepted credential.
            match (by_cert, by_token) {
                (Some(c), Some(t)) if c.id == t.id => {
                    let mut x = c; x.auth_method = AuthMethod::MutualTlsAndToken; Ok(x)
                }
                (Some(_), Some(_)) => Err(actix_error::ErrorUnauthorized(
                    "client certificate and bearer token identify different clients")),
                (Some(_), None) => Err(actix_error::ErrorUnauthorized(
                    "a bearer token is required in addition to the client certificate")),
                (None, Some(_)) => Err(actix_error::ErrorUnauthorized(
                    "a client certificate is required in addition to the bearer token")),
                (None, None) => Err(actix_error::ErrorUnauthorized(
                    "both a client certificate and a bearer token are required")),
            }
        })
    }
}

// `expires_at` is stored as `TIMESTAMP` (no timezone). We treat the stored
// value as UTC — every writer in this codebase uses `Utc::now()` and
// `Utc::now() + Duration::days(...)` then `.naive_utc()` for the bind.
//
// The fingerprint match means rotation invalidates the OLD cert — a rotated
// client cannot replay the previous cert because its fingerprint no longer
// matches the row.
async fn lookup_by_cn(
    db: &PgPool, metadata_enc_key: &[u8], name_index_key: &[u8],
    cn: &str, fingerprint: &str,
) -> sqlx::Result<Option<AuthenticatedClient>> {
    let name_id = crate::server::client_name_id_hex(name_index_key, cn);
    let row: Option<(String, Vec<u8>, String, Option<NaiveDateTime>)> = sqlx::query_as(
        "SELECT id, name_enc, role, expires_at FROM blackbook_clients
         WHERE name_id = $1 AND cert_fingerprint = $2 AND revoked_at IS NULL",
    )
    .bind(&name_id)
    .bind(fingerprint)
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(id, name_enc, role, exp)| {
        if exp.map(|e| e <= Utc::now().naive_utc()).unwrap_or(false) { return None; }
        let name = crate::server::dec_str(metadata_enc_key, &name_enc).ok()?;
        Some(AuthenticatedClient { id, name, role, auth_method: AuthMethod::MutualTlsAndToken })
    }))
}

async fn lookup_by_token(
    db: &PgPool, metadata_enc_key: &[u8], token: &str,
) -> sqlx::Result<Option<AuthenticatedClient>> {
    let hash = hash_token(token);
    let row: Option<(String, Vec<u8>, String, Option<NaiveDateTime>)> = sqlx::query_as(
        "SELECT id, name_enc, role, expires_at FROM blackbook_clients
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(id, name_enc, role, exp)| {
        if exp.map(|e| e <= Utc::now().naive_utc()).unwrap_or(false) { return None; }
        let name = crate::server::dec_str(metadata_enc_key, &name_enc).ok()?;
        Some(AuthenticatedClient { id, name, role, auth_method: AuthMethod::MutualTlsAndToken })
    }))
}

/// Outcome of an ACL check. `Allowed(acl_id)` returns the row that matched
/// so the caller can increment `use_count` after a successful action.
#[derive(Debug, Clone)]
pub enum AclDecision {
    AllowedAdmin,
    AllowedDomainAdmin,
    Allowed(String),
    Denied,
}

impl AclDecision {
    pub fn is_allowed(&self) -> bool { !matches!(self, AclDecision::Denied) }
}

/// Decide whether `client` may perform `action` on `resource_name` in
/// `domain_id`. Resolution order:
///   1. Global admin → allow.
///   2. Domain admin of `domain_id` → allow.
///   3. Direct or inherited ACL row that's in-window and unspent.
pub async fn acl_check(
    db: &PgPool,
    metadata_enc_key: &[u8],
    client: &AuthenticatedClient,
    domain_id: &str,
    resource_name: &str,
    action: AclAction,
) -> sqlx::Result<AclDecision> {
    if client.is_admin() { return Ok(AclDecision::AllowedAdmin); }

    let domain_admin: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM blackbook_domain_members
         WHERE client_id = $1 AND domain_id = $2 AND role = 'admin'
         LIMIT 1",
    )
    .bind(&client.id).bind(domain_id)
    .fetch_optional(db).await?;
    if domain_admin.is_some() { return Ok(AclDecision::AllowedDomainAdmin); }

    // Patterns are AEAD-encrypted at rest, so SQL can't do the LIKE match
    // anymore. Pull every candidate grant that matches everything *but* the
    // pattern, then decrypt + match in Rust. Candidate set is small per
    // (client, domain, action) so this is fine.
    let candidates: Vec<(String, Vec<u8>, Option<String>, Option<i32>, Option<i32>, i32, Option<NaiveDateTime>)> = sqlx::query_as(
        "SELECT a.id, a.pattern_enc, a.schedule, a.rate_max, a.rate_period_secs, a.rate_count, a.rate_window_start
         FROM blackbook_acl a
         WHERE a.domain_id = $1
           AND (
                a.client_id = $2
             OR a.group_domain_id IN (
                  SELECT domain_id FROM blackbook_domain_members WHERE client_id = $2
                )
           )
           AND (a.actions & $3) <> 0
           AND (a.expires_at IS NULL OR a.expires_at >  CURRENT_TIMESTAMP)
           AND (a.not_before IS NULL OR a.not_before <= CURRENT_TIMESTAMP)
           AND (a.max_uses   IS NULL OR a.use_count  <  a.max_uses)
         ORDER BY a.granted_at DESC",
    )
    .bind(domain_id).bind(&client.id).bind(action_bit(action))
    .fetch_all(db).await?;
    for (id, pattern_enc, schedule, rate_max, rate_period, rate_count, rate_window) in candidates {
        let pattern = match crate::blackbook_core::aead_open(&pattern_enc, metadata_enc_key) {
            Ok(b) => match String::from_utf8(b) { Ok(s) => s, Err(_) => continue },
            Err(_) => continue,
        };
        if !sql_like_match(&pattern, resource_name) { continue; }
        let now = Utc::now().naive_utc();
        // Cron-style allowed-access window. A malformed schedule fails closed.
        if let Some(sched) = &schedule {
            if !cron_window_matches(sched, &now).unwrap_or(false) { continue; }
        }
        // Per-rule fixed-window rate limit.
        if !rate_ok(rate_max, rate_period, rate_count, rate_window, now) { continue; }
        return Ok(AclDecision::Allowed(id));
    }
    Ok(AclDecision::Denied)
}

/// Glob match with the Blackbook convention that `*` means "any sequence"
/// and `_` means "exactly one char"; everything else is literal. Used by
/// `acl_check` and the advance-grant gate, where the pattern is decrypted
/// in-process and SQL can't do the match for us.
///
/// Implemented as an iterative two-pointer matcher with star backtracking —
/// O(pattern · text) worst case. This is deliberately NOT the natural
/// recursive form, which backtracks exponentially on adversarial inputs like
/// `*a*a*a…*b` against a long `aaaa…` string. Advance-grant patterns are
/// attacker-supplied (any signatory can set one) and matched against
/// caller-chosen resource names, so a super-linear matcher would be a CPU
/// denial-of-service vector that stalls an async worker.
pub fn sql_like_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);          // i over text, j over pattern
    let mut star: Option<usize> = None;             // index in p of the last '*'
    let mut mark = 0usize;                           // text index when '*' was seen
    while i < t.len() {
        if j < p.len() && (p[j] == '_' || p[j] == t[i]) {
            i += 1; j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some(j); mark = i; j += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last '*' absorb one more text char.
            j = s + 1; mark += 1; i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == '*' { j += 1; }
    j == p.len()
}

/// Whether `now` falls inside the access window described by a 5-field cron
/// expression (`minute hour day-of-month month day-of-week`), interpreted as a
/// **mask**: access is permitted whenever each field of `now` is a member of the
/// corresponding field's allowed set. So `* 9-17 * * 1-5` = weekdays 09:00–17:59.
/// Supports `*`, `a`, `a-b`, lists `a,b,c`, and steps `*/n` / `a-b/n`. Day-of-week
/// is Sunday=0 (7 also accepted as Sunday). A malformed expression returns an
/// error (the caller treats it as "deny", failing closed).
pub fn cron_window_matches(expr: &str, now: &NaiveDateTime) -> Result<bool, String> {
    use chrono::{Datelike, Timelike};
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 {
        return Err(format!("cron schedule must have 5 fields, got {}", f.len()));
    }
    let dow = now.weekday().num_days_from_sunday(); // 0=Sun..6=Sat
    Ok(cron_field(f[0], now.minute(), 0, 59)?
        && cron_field(f[1], now.hour(), 0, 23)?
        && cron_field(f[2], now.day(), 1, 31)?
        && cron_field(f[3], now.month(), 1, 12)?
        && (cron_field(f[4], dow, 0, 6)? || (dow == 0 && cron_field(f[4], 7, 0, 7)?)))
}

fn cron_field(field: &str, val: u32, min: u32, max: u32) -> Result<bool, String> {
    for term in field.split(',') {
        let (range, step) = match term.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().map_err(|_| format!("bad step '{s}'"))?),
            None => (term, 1),
        };
        if step == 0 { return Err("step may not be 0".into()); }
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (a.parse().map_err(|_| format!("bad range '{range}'"))?,
             b.parse().map_err(|_| format!("bad range '{range}'"))?)
        } else {
            let v: u32 = range.parse().map_err(|_| format!("bad value '{range}'"))?;
            (v, v)
        };
        if val >= lo && val <= hi && (val - lo) % step == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Fixed-window rate check: given a rule's limit and current window state, is
/// another access allowed *now*? `None` for `max`/`period` means "no limit".
pub fn rate_ok(
    rate_max: Option<i32>, rate_period_secs: Option<i32>,
    rate_count: i32, window_start: Option<NaiveDateTime>, now: NaiveDateTime,
) -> bool {
    let (Some(max), Some(period)) = (rate_max, rate_period_secs) else { return true };
    if max <= 0 || period <= 0 { return true; }
    match window_start {
        // No window yet, or the current window has fully elapsed → fresh budget.
        None => true,
        Some(ws) => {
            if now.signed_duration_since(ws) >= Duration::seconds(period as i64) {
                true
            } else {
                rate_count < max
            }
        }
    }
}

/// Best-effort: bump the ACL row's `use_count` after a successful action, and
/// advance the fixed-window rate counter (rolling the window if it elapsed).
pub async fn acl_record_use(db: &PgPool, decision: &AclDecision) {
    if let AclDecision::Allowed(id) = decision {
        if let Err(e) = sqlx::query(
            "UPDATE blackbook_acl SET
               use_count = use_count + 1,
               rate_window_start = CASE
                 WHEN rate_period_secs IS NULL THEN rate_window_start
                 WHEN rate_window_start IS NULL
                   OR rate_window_start + (rate_period_secs * INTERVAL '1 second') <= CURRENT_TIMESTAMP
                 THEN CURRENT_TIMESTAMP ELSE rate_window_start END,
               rate_count = CASE
                 WHEN rate_period_secs IS NULL THEN rate_count
                 WHEN rate_window_start IS NULL
                   OR rate_window_start + (rate_period_secs * INTERVAL '1 second') <= CURRENT_TIMESTAMP
                 THEN 1 ELSE rate_count + 1 END
             WHERE id = $1",
        ).bind(id).execute(db).await {
            log::warn!("ACL use_count/rate bump failed for {id}: {e}");
        }
    }
}

/// Resolve a friendly domain name to its row id. `Ok(None)` if the domain
/// doesn't exist or is archived.
pub async fn resolve_domain(
    db: &PgPool, name_index_key: &[u8], name: &str,
) -> sqlx::Result<Option<String>> {
    let name_id = crate::server::domain_name_id_hex(name_index_key, name);
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM blackbook_domains WHERE name_id = $1 AND archived_at IS NULL",
    )
    .bind(&name_id)
    .fetch_optional(db).await
}

/// Is the client allowed to touch the given domain at all? Global admins
/// pass unconditionally; otherwise they must have a membership row.
pub async fn domain_member(
    db: &PgPool, client: &AuthenticatedClient, domain_id: &str,
) -> sqlx::Result<bool> {
    if client.is_admin() { return Ok(true); }
    let row: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM blackbook_domain_members WHERE client_id = $1 AND domain_id = $2 LIMIT 1",
    )
    .bind(&client.id).bind(domain_id)
    .fetch_optional(db).await?;
    Ok(row.is_some())
}

/// Is the client an *administrator* of the given domain? True for a global
/// admin, or a member of that domain whose in-domain role is 'admin'. This is
/// the authority for managing ACLs and members *within* a domain — it confers
/// no global privilege (client provisioning, audit, cross-domain ops stay
/// reserved for global admins).
pub async fn domain_admin(
    db: &PgPool, client: &AuthenticatedClient, domain_id: &str,
) -> sqlx::Result<bool> {
    if client.is_admin() { return Ok(true); }
    let row: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM blackbook_domain_members
         WHERE client_id = $1 AND domain_id = $2 AND role = 'admin' LIMIT 1",
    )
    .bind(&client.id).bind(domain_id)
    .fetch_optional(db).await?;
    Ok(row.is_some())
}

/// The set of domain ids the client administers (for scoping list views).
/// Empty for non-admins with no domain-admin role; global admins should be
/// handled separately (they see everything).
pub async fn admin_domain_ids(
    db: &PgPool, client: &AuthenticatedClient,
) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT domain_id FROM blackbook_domain_members
         WHERE client_id = $1 AND role = 'admin'",
    )
    .bind(&client.id)
    .fetch_all(db).await?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}

/// Append a row to the audit log with hash-chain tamper-evidence.
///
/// Each row's `row_hash` is a keyed SHA3-256 over `(audit_hmac_key,
/// prev_row_hash, ts, client_id, action, resource, status, message)`, so
/// any tampering with a past row — content *or* deletion *or* reordering —
/// breaks the chain at and after the affected row. The MAC key never lands
/// in the DB; only a process that can read the master `BlackbookKey` can
/// forge or repair the chain.
///
/// Writes are serialized via a Postgres transaction-scoped advisory lock so
/// concurrent callers can't race on the chain head. The serialization point
/// is acceptable today; if audit throughput becomes a bottleneck we can move
/// to a Merkle tree per epoch.
pub async fn audit(
    db: &PgPool,
    hmac_key: &[u8],
    metadata_enc_key: &[u8],
    client_id: Option<&str>,
    action: &str,
    resource: Option<&str>,
    status: AuditStatus,
    message: Option<&str>,
) {
    let ts = chrono::Utc::now();
    // Encrypt user-supplied fields before they enter the DB. The hash chain
    // still binds to *plaintext* content so the row is tamper-evident over
    // what was actually written, not over the storage representation.
    let enc_resource: Option<Vec<u8>> = match resource {
        Some(r) => match crate::blackbook_core::aead_seal(r.as_bytes(), metadata_enc_key) {
            Ok(b) => Some(b),
            Err(e) => {
                log::warn!("audit encrypt resource failed: {e}; skipping audit row");
                return;
            }
        },
        None => None,
    };
    let enc_message: Option<Vec<u8>> = match message {
        Some(m) => match crate::blackbook_core::aead_seal(m.as_bytes(), metadata_enc_key) {
            Ok(b) => Some(b),
            Err(e) => {
                log::warn!("audit encrypt message failed: {e}; skipping audit row");
                return;
            }
        },
        None => None,
    };
    let result: std::result::Result<(), sqlx::Error> = async {
        let mut tx = db.begin().await?;
        // Constant key for the audit chain's advisory lock — arbitrary, just
        // needs to be unique within Blackbook. Released on COMMIT/ROLLBACK.
        sqlx::query("SELECT pg_advisory_xact_lock(7919001)")
            .execute(&mut *tx).await?;
        let prev: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT row_hash FROM blackbook_audit ORDER BY id DESC LIMIT 1",
        ).fetch_optional(&mut *tx).await?;
        let prev_hash_bytes: [u8; 32] = match prev.and_then(|(opt,)| opt) {
            Some(hex_str) => {
                let mut buf = [0u8; 32];
                if hex::decode_to_slice(&hex_str, &mut buf).is_ok() { buf }
                else { [0u8; 32] }
            }
            None => [0u8; 32],
        };
        let row_hash = compute_audit_hash(
            hmac_key, &prev_hash_bytes,
            ts.timestamp_micros(),
            client_id, action, resource, status.as_str(), message,
        );
        let prev_hash_hex = hex::encode(prev_hash_bytes);
        let row_hash_hex  = hex::encode(row_hash);
        sqlx::query(
            "INSERT INTO blackbook_audit
             (ts, client_id, action, status, resource_enc, message_enc, prev_hash, row_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ts.naive_utc())
        .bind(client_id)
        .bind(action)
        .bind(status.as_str())
        .bind(enc_resource.as_deref())
        .bind(enc_message.as_deref())
        .bind(&prev_hash_hex)
        .bind(&row_hash_hex)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }.await;
    if let Err(e) = result {
        log::warn!("audit insert failed (action={action}, status={status:?}): {e}");
    }
}

/// Compute the keyed SHA3-256 row hash for an audit row. Length-prefixes
/// every field so distinct inputs cannot produce the same digest by
/// concatenation ambiguity. `None` fields are encoded as `u32::MAX` length
/// to keep them distinguishable from an empty string.
pub fn compute_audit_hash(
    hmac_key: &[u8],
    prev_hash: &[u8; 32],
    ts_micros: i64,
    client_id: Option<&str>,
    action: &str,
    resource: Option<&str>,
    status: &str,
    message: Option<&str>,
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    // Domain-separation tag — defends against cross-context collisions
    // if the same key ever gets reused for another keyed-hash purpose.
    h.update(b"blackbook-audit-row/v1\0");
    h.update(&(hmac_key.len() as u32).to_be_bytes());
    h.update(hmac_key);
    h.update(prev_hash);
    h.update(&ts_micros.to_be_bytes());
    write_audit_opt(&mut h, client_id);
    write_audit_req(&mut h, action);
    write_audit_opt(&mut h, resource);
    write_audit_req(&mut h, status);
    write_audit_opt(&mut h, message);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn write_audit_req<D: sha3::Digest>(h: &mut D, s: &str) {
    h.update(&(s.len() as u32).to_be_bytes());
    h.update(s.as_bytes());
}
fn write_audit_opt<D: sha3::Digest>(h: &mut D, s: Option<&str>) {
    match s {
        None => h.update(&u32::MAX.to_be_bytes()),
        Some(s) => write_audit_req(h, s),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuditStatus { Ok, Denied, NotFound, Error }
impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditStatus::Ok => "ok",
            AuditStatus::Denied => "denied",
            AuditStatus::NotFound => "not_found",
            AuditStatus::Error => "error",
        }
    }
}

/// Provision the very first admin client. Returns the raw token and cert
/// bundle (only time they're exposed end-to-end).
pub async fn bootstrap_admin_if_needed(
    db: &PgPool,
    ca: &SharedCa,
    metadata_enc_key: &[u8],
    name_index_key: &[u8],
) -> Result<Option<(String, CertBundle)>, AuthOpError> {
    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS(
            SELECT 1 FROM blackbook_clients
            WHERE role = 'admin' AND revoked_at IS NULL
        )",
    )
    .fetch_one(db)
    .await?;
    if exists.0 { return Ok(None); }

    let token = generate_token();
    let token_hash = hash_token(&token);
    let id = Id::new(16).encode();
    let ttl = default_ttl_days("admin");
    let expires_dt = Utc::now() + Duration::days(ttl);
    let cert = tls::issue_client_cert(ca, "admin", ttl)?;
    let name_enc = crate::blackbook_core::aead_seal(b"admin", metadata_enc_key)
        .map_err(AuthOpError::Crypto)?;
    let name_id = crate::server::client_name_id_hex(name_index_key, "admin");

    sqlx::query(
        "INSERT INTO blackbook_clients
            (id, name_enc, name_id, token_hash, role, expires_at, cert_fingerprint)
         VALUES ($1, $2, $3, $4, 'admin', $5, $6)",
    )
    .bind(&id)
    .bind(&name_enc)
    .bind(&name_id)
    .bind(&token_hash)
    .bind(expires_dt.naive_utc())
    .bind(&cert.fingerprint)
    .execute(db)
    .await?;
    // The admin gets a private user domain too, like any other client.
    let _ = ensure_user_domain(db, metadata_enc_key, name_index_key, &id, "admin").await?;
    Ok(Some((token, cert)))
}

#[derive(Debug, thiserror::Error)]
pub enum AuthOpError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("tls: {0}")]
    Tls(#[from] crate::tls::TlsError),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::blackbook_core::CryptoError),
    #[error("totp: {0}")]
    Totp(String),
    #[error("{0}")]
    Invalid(String),
}

/// Prefix marking a private, per-client "user domain". Reserved: regular
/// domain names must not start with it. Each client gets `~<name>` as a private
/// namespace they fully administer.
pub const USER_DOMAIN_PREFIX: &str = "~";

/// The user-domain name for a client.
pub fn user_domain_name(client_name: &str) -> String {
    format!("{USER_DOMAIN_PREFIX}{client_name}")
}

/// Create the client's private user domain (`~<name>`) if absent and make the
/// client its in-domain admin, so it has full features there. Idempotent.
/// Returns the user-domain name. Shared by `create_client` and the admin
/// bootstrap so every identity gets one consistently.
pub async fn ensure_user_domain(
    db: &PgPool, metadata_enc_key: &[u8], name_index_key: &[u8],
    client_id: &str, client_name: &str,
) -> Result<String, AuthOpError> {
    let dname = user_domain_name(client_name);
    let name_id = crate::server::domain_name_id_hex(name_index_key, &dname);
    // Find or create the domain.
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM blackbook_domains WHERE name_id = $1 AND archived_at IS NULL",
    ).bind(&name_id).fetch_optional(db).await?;
    let domain_id = match existing {
        Some((id,)) => id,
        None => {
            let id = Id::new(12).encode();
            let name_enc = crate::blackbook_core::aead_seal(dname.as_bytes(), metadata_enc_key)
                .map_err(AuthOpError::Crypto)?;
            let desc_enc = crate::blackbook_core::aead_seal(
                format!("Private user domain for {client_name}").as_bytes(), metadata_enc_key)
                .map_err(AuthOpError::Crypto)?;
            sqlx::query(
                "INSERT INTO blackbook_domains (id, name_enc, name_id, description_enc)
                 VALUES ($1, $2, $3, $4) ON CONFLICT (name_id) DO NOTHING",
            ).bind(&id).bind(&name_enc).bind(&name_id).bind(&desc_enc)
            .execute(db).await?;
            // Re-read in case a concurrent create won the ON CONFLICT race.
            let (id,): (String,) = sqlx::query_as(
                "SELECT id FROM blackbook_domains WHERE name_id = $1",
            ).bind(&name_id).fetch_one(db).await?;
            id
        }
    };
    // Make the client an admin of its own domain (full features).
    sqlx::query(
        "INSERT INTO blackbook_domain_members (domain_id, client_id, role)
         VALUES ($1, $2, 'admin') ON CONFLICT (domain_id, client_id) DO UPDATE SET role = 'admin'",
    ).bind(&domain_id).bind(client_id).execute(db).await?;
    Ok(dname)
}

pub async fn create_client(
    db: &PgPool,
    ca: &SharedCa,
    metadata_enc_key: &[u8],
    name_index_key: &[u8],
    name: &str,
    role: &str,
    ttl_days: Option<i64>,
) -> Result<NewClient, AuthOpError> {
    // Reserve the user-domain prefix so a client can't shadow the namespace.
    if name.starts_with(USER_DOMAIN_PREFIX) {
        return Err(AuthOpError::Invalid(format!(
            "client name may not start with '{USER_DOMAIN_PREFIX}' (reserved for private user domains)")));
    }
    let token = generate_token();
    let token_hash = hash_token(&token);
    let id = Id::new(16).encode();
    let ttl = ttl_days.unwrap_or_else(|| default_ttl_days(role));
    let expires_dt = Utc::now() + Duration::days(ttl);
    let cert = tls::issue_client_cert(ca, name, ttl)?;
    let name_enc = crate::blackbook_core::aead_seal(name.as_bytes(), metadata_enc_key)
        .map_err(AuthOpError::Crypto)?;
    let name_id = crate::server::client_name_id_hex(name_index_key, name);

    sqlx::query(
        "INSERT INTO blackbook_clients
            (id, name_enc, name_id, token_hash, role, expires_at, cert_fingerprint)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&name_enc)
    .bind(&name_id)
    .bind(&token_hash)
    .bind(role)
    .bind(expires_dt.naive_utc())
    .bind(&cert.fingerprint)
    .execute(db)
    .await?;

    // Every new client automatically joins the `default` domain so basic CRUD
    // works out of the box. Admins can move/expand membership later.
    let default_name_id = crate::server::domain_name_id_hex(name_index_key, "default");
    let default_id: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM blackbook_domains WHERE name_id = $1 AND archived_at IS NULL",
    ).bind(&default_name_id).fetch_optional(db).await?;
    if let Some((domain_id,)) = default_id {
        let _ = sqlx::query(
            "INSERT INTO blackbook_domain_members (domain_id, client_id, role)
             VALUES ($1, $2, 'user') ON CONFLICT DO NOTHING",
        ).bind(&domain_id).bind(&id).execute(db).await;
    }

    // Give the client its own private, fully-administered user domain (`~name`).
    let user_domain = ensure_user_domain(db, metadata_enc_key, name_index_key, &id, name).await?;

    Ok(NewClient {
        id, name: name.to_string(), role: role.to_string(),
        token,
        cert_pem: cert.cert_pem,
        key_pem: cert.key_pem,
        expires_at: expires_dt.to_rfc3339(),
        user_domain,
    })
}

/// Issue a new token + cert for an existing client, replacing the old hash
/// and fingerprint atomically. Returns the new credentials.
pub async fn rotate_client(
    db: &PgPool,
    ca: &SharedCa,
    name_index_key: &[u8],
    name: &str,
    ttl_days: Option<i64>,
) -> Result<Option<NewClient>, AuthOpError> {
    let name_id = crate::server::client_name_id_hex(name_index_key, name);
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT id, role FROM blackbook_clients WHERE name_id = $1 AND revoked_at IS NULL",
    )
    .bind(&name_id)
    .fetch_optional(db)
    .await?;
    let Some((id, role)) = existing else { return Ok(None); };

    let token = generate_token();
    let token_hash = hash_token(&token);
    let ttl = ttl_days.unwrap_or_else(|| default_ttl_days(&role));
    let expires_dt = Utc::now() + Duration::days(ttl);
    let cert = tls::issue_client_cert(ca, name, ttl)?;

    sqlx::query(
        "UPDATE blackbook_clients
         SET token_hash = $1, expires_at = $2, cert_fingerprint = $3
         WHERE id = $4",
    )
    .bind(&token_hash)
    .bind(expires_dt.naive_utc())
    .bind(&cert.fingerprint)
    .bind(&id)
    .execute(db)
    .await?;

    Ok(Some(NewClient {
        user_domain: user_domain_name(&name),
        id, name: name.to_string(), role,
        token,
        cert_pem: cert.cert_pem,
        key_pem: cert.key_pem,
        expires_at: expires_dt.to_rfc3339(),
    }))
}

// ---------------------------------------------------------------------------
// Resource flags (JSONB column on secrets/pages)
// ---------------------------------------------------------------------------

/// Per-resource policy flags. Stored as a JSONB column; all fields carry
/// `#[serde(default)]` so records written before a new flag was introduced
/// continue to deserialize cleanly. Unknown field names are **rejected** at
/// the API boundary — a caller that misspells a flag name receives a 400
/// error rather than having the typo silently ignored. Every flag must have
/// explicit server-side enforcement; no flag enables anything by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceFlags {
    /// If true, every read must include a valid TOTP code in
    /// `X-Blackbook-MFA` (or be from an admin-enrolled session that just
    /// re-verified).
    #[serde(default)]
    pub mfa_required: bool,
    /// If true, the resource is deleted server-side immediately after the
    /// first successful read.
    #[serde(default)]
    pub delete_on_read: bool,
    /// If set, deny reads once `read_count >= max_reads`. The counter is
    /// incremented in the same transaction as the read.
    #[serde(default)]
    pub max_reads: Option<i64>,
    /// If true, the per-file DEK (for files) or the encryption envelope
    /// (for secrets) is rotated on every successful read.
    #[serde(default)]
    pub rotate_on_read: bool,
    /// If true, this resource is exempt from `cleanup` even after it has been
    /// tombstoned (e.g. by `max_reads` exhaustion). The forensic record
    /// — name, created_at, exhausted_at — is preserved indefinitely.
    #[serde(default)]
    pub preserve_on_cleanup: bool,
    /// If true, this resource is **immutable**: once created it can never be
    /// overwritten, even with an explicit `overwrite=true`. Set only at
    /// creation. To replace such a resource you must delete it first (subject
    /// to the `delete` ACL). Applies to both secrets and files.
    #[serde(default)]
    pub no_overwrite: bool,
}

// ---------------------------------------------------------------------------
// TOTP / MFA
// ---------------------------------------------------------------------------

/// Generate a fresh TOTP secret for `client_id`, encrypt it under
/// `kek_bytes` (the master's `mfa_secret_kek`), persist, and return the
/// provisioning URI + the base32 string for manual entry.
pub async fn enroll_totp(
    db: &PgPool,
    kek_bytes: &[u8],
    client_id: &str,
    client_name: &str,
) -> Result<(String, String), AuthOpError> {
    use rand::RngCore;
    let mut secret = vec![0u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    let enc = crate::blackbook_core::encrypt_aes_gcm(&secret, kek_bytes)?;
    sqlx::query(
        "UPDATE blackbook_clients
         SET totp_secret_enc = $1, totp_enrolled = FALSE
         WHERE id = $2",
    )
    .bind(&enc).bind(client_id)
    .execute(db).await?;

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30, secret.clone(),
        Some("Blackbook".to_string()),
        client_name.to_string(),
    ).map_err(|e| AuthOpError::Totp(format!("{e:?}")))?;
    let uri = totp.get_url();
    let b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret);
    Ok((uri, b32))
}

/// Verify a 6-digit TOTP code against the client's stored secret. After the
/// first successful verify, flips `totp_enrolled = true`.
pub async fn verify_totp(
    db: &PgPool,
    kek_bytes: &[u8],
    client_id: &str,
    code: &str,
) -> Result<bool, AuthOpError> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT totp_secret_enc FROM blackbook_clients
         WHERE id = $1 AND totp_secret_enc IS NOT NULL",
    )
    .bind(client_id).fetch_optional(db).await?;
    let Some((enc,)) = row else { return Ok(false); };
    let secret = crate::blackbook_core::decrypt_aes_gcm(&enc, kek_bytes)?;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1, 6, 1, 30, secret,
        Some("Blackbook".to_string()),
        client_id.to_string(),
    ).map_err(|e| AuthOpError::Totp(format!("{e:?}")))?;
    let ok = totp.check_current(code)
        .map_err(|e| AuthOpError::Totp(format!("{e:?}")))?;
    if ok {
        let _ = sqlx::query("UPDATE blackbook_clients SET totp_enrolled = TRUE WHERE id = $1")
            .bind(client_id).execute(db).await;
    }
    Ok(ok)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewClient {
    pub id: String,
    pub name: String,
    pub role: String,
    pub token: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_at: String,
    /// The client's private user domain (`~<name>`), which it fully administers.
    #[serde(default)]
    pub user_domain: String,
}

#[cfg(test)]
mod tests {
    use super::{ResourceFlags, compute_audit_hash, sql_like_match, cron_window_matches, rate_ok};
    use chrono::{NaiveDate, NaiveDateTime};

    fn dt(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn cron_business_hours_window() {
        // "* 9-17 * * 1-5" = weekdays 09:00–17:59.
        let sched = "* 9-17 * * 1-5";
        assert!(cron_window_matches(sched, &dt("2026-06-19 10:30:00")).unwrap());  // Fri 10:30
        assert!(cron_window_matches(sched, &dt("2026-06-19 17:59:00")).unwrap());  // Fri 17:59
        assert!(!cron_window_matches(sched, &dt("2026-06-19 18:00:00")).unwrap()); // Fri 18:00 (out)
        assert!(!cron_window_matches(sched, &dt("2026-06-19 08:59:00")).unwrap()); // Fri 08:59 (out)
        assert!(!cron_window_matches(sched, &dt("2026-06-20 10:30:00")).unwrap()); // Sat (out)
    }

    #[test]
    fn cron_steps_lists_and_sunday() {
        assert!(cron_window_matches("*/15 * * * *", &dt("2026-06-19 10:30:00")).unwrap()); // 30 % 15 == 0
        assert!(!cron_window_matches("*/15 * * * *", &dt("2026-06-19 10:31:00")).unwrap());
        assert!(cron_window_matches("0 0 1,15 * *", &dt("2026-06-15 00:00:00")).unwrap()); // 15th midnight
        // Sunday accepted as both 0 and 7.
        assert!(cron_window_matches("* * * * 0", &dt("2026-06-21 12:00:00")).unwrap()); // Sun
        assert!(cron_window_matches("* * * * 7", &dt("2026-06-21 12:00:00")).unwrap());
    }

    #[test]
    fn cron_malformed_is_error() {
        assert!(cron_window_matches("only four fields here", &dt("2026-06-19 10:00:00")).is_err());
        assert!(cron_window_matches("* * * * *", &dt("2026-06-19 10:00:00")).unwrap()); // always
    }

    #[test]
    fn rate_fixed_window() {
        let now = dt("2026-06-19 12:00:00");
        // No limit configured.
        assert!(rate_ok(None, None, 999, Some(now), now));
        // 5 per 60s: within budget.
        assert!(rate_ok(Some(5), Some(60), 4, Some(now), now));
        // At the cap inside the window → denied.
        assert!(!rate_ok(Some(5), Some(60), 5, Some(now), now));
        // At the cap but the window has elapsed → fresh budget.
        let later = now + chrono::Duration::seconds(61);
        assert!(rate_ok(Some(5), Some(60), 5, Some(now), later));
        // No window yet → allowed.
        assert!(rate_ok(Some(1), Some(60), 0, None, now));
    }

    #[test]
    fn glob_basic_semantics() {
        assert!(sql_like_match("monthly-report-*", "monthly-report-june"));
        assert!(sql_like_match("*", "anything"));
        assert!(sql_like_match("*", ""));
        assert!(sql_like_match("prod-_", "prod-x"));
        assert!(!sql_like_match("prod-_", "prod-xy"));        // _ is exactly one
        assert!(!sql_like_match("monthly-report-*", "weekly-report-1"));
        assert!(sql_like_match("a*b*c", "axxbyyc"));
        assert!(!sql_like_match("a*b*c", "axxbyy"));          // missing trailing c
        assert!(sql_like_match("exact", "exact"));
        assert!(!sql_like_match("exact", "exactly"));
        assert!(sql_like_match("**a", "a"));                  // redundant stars
    }

    #[test]
    fn glob_adversarial_input_is_linear_not_exponential() {
        // The recursive form would take ~2^30 steps here; the iterative one
        // returns effectively instantly. Correctness check doubles as a
        // regression guard against reintroducing exponential backtracking.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(64);
        let start = std::time::Instant::now();
        assert!(!sql_like_match(pattern, &text));
        assert!(start.elapsed().as_millis() < 100, "glob match took too long — exponential backtracking?");
    }

    #[test]
    fn audit_hash_is_deterministic() {
        let key = b"test-key-32-bytes-xxxxxxxxxxxxxxx";
        let prev = [7u8; 32];
        let a = compute_audit_hash(key, &prev, 1_700_000_000_000_000,
            Some("client-1"), "read", Some("res-a"), "ok", None);
        let b = compute_audit_hash(key, &prev, 1_700_000_000_000_000,
            Some("client-1"), "read", Some("res-a"), "ok", None);
        assert_eq!(a, b, "same inputs must produce the same hash");
    }

    #[test]
    fn audit_hash_changes_when_any_field_changes() {
        let key = b"test-key-32-bytes-xxxxxxxxxxxxxxx";
        let prev = [0u8; 32];
        let base = compute_audit_hash(key, &prev, 100,
            Some("c"), "read", Some("r"), "ok", Some("m"));
        // Each variant flips exactly one field; all must differ from base.
        assert_ne!(base, compute_audit_hash(key, &[1u8;32], 100, Some("c"), "read", Some("r"), "ok", Some("m")), "prev_hash");
        assert_ne!(base, compute_audit_hash(key, &prev, 101, Some("c"), "read", Some("r"), "ok", Some("m")), "ts");
        assert_ne!(base, compute_audit_hash(key, &prev, 100, Some("d"), "read", Some("r"), "ok", Some("m")), "client");
        assert_ne!(base, compute_audit_hash(key, &prev, 100, Some("c"), "delete", Some("r"), "ok", Some("m")), "action");
        assert_ne!(base, compute_audit_hash(key, &prev, 100, Some("c"), "read", Some("x"), "ok", Some("m")), "resource");
        assert_ne!(base, compute_audit_hash(key, &prev, 100, Some("c"), "read", Some("r"), "denied", Some("m")), "status");
        assert_ne!(base, compute_audit_hash(key, &prev, 100, Some("c"), "read", Some("r"), "ok", Some("n")), "message");
        // None vs empty-string must not collide (length-prefix sentinel).
        assert_ne!(
            compute_audit_hash(key, &prev, 100, None, "read", None, "ok", None),
            compute_audit_hash(key, &prev, 100, Some(""), "read", Some(""), "ok", Some("")),
            "None must be distinguishable from empty string");
    }

    #[test]
    fn audit_hash_depends_on_key() {
        let prev = [0u8; 32];
        let a = compute_audit_hash(b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &prev, 100, None, "read", None, "ok", None);
        let b = compute_audit_hash(b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &prev, 100, None, "read", None, "ok", None);
        assert_ne!(a, b, "a different MAC key must produce a different hash");
    }

    #[test]
    fn resource_flags_empty_object_gives_all_defaults() {
        let f: ResourceFlags = serde_json::from_str("{}").unwrap();
        assert!(!f.mfa_required);
        assert!(!f.delete_on_read);
        assert!(f.max_reads.is_none());
        assert!(!f.rotate_on_read);
        assert!(!f.preserve_on_cleanup);
        assert!(!f.no_overwrite);
    }

    #[test]
    fn resource_flags_known_fields_deserialize() {
        let json = r#"{"mfa_required":true,"delete_on_read":false,"max_reads":5,"rotate_on_read":true,"preserve_on_cleanup":true,"no_overwrite":true}"#;
        let f: ResourceFlags = serde_json::from_str(json).unwrap();
        assert!(f.mfa_required);
        assert!(!f.delete_on_read);
        assert_eq!(f.max_reads, Some(5));
        assert!(f.rotate_on_read);
        assert!(f.preserve_on_cleanup);
        assert!(f.no_overwrite);
    }

    #[test]
    fn resource_flags_partial_fields_use_defaults_for_remainder() {
        let f: ResourceFlags = serde_json::from_str(r#"{"mfa_required":true}"#).unwrap();
        assert!(f.mfa_required);
        assert!(!f.delete_on_read);
        assert!(f.max_reads.is_none());
        assert!(!f.rotate_on_read);
        assert!(!f.preserve_on_cleanup);
    }

    #[test]
    fn resource_flags_unknown_field_is_rejected() {
        // A misspelled flag name must produce an error, not silently do nothing.
        let result: Result<ResourceFlags, _> =
            serde_json::from_str(r#"{"delete_on_reaad": true}"#);
        assert!(result.is_err(), "expected error for unknown field, got {:?}", result);
    }

    #[test]
    fn resource_flags_db_format_roundtrip() {
        // Simulate what the server stores and then retrieves from JSONB:
        // all four fields present with their serialized names.
        let stored = r#"{"mfa_required":false,"delete_on_read":true,"max_reads":null,"rotate_on_read":false}"#;
        let f: ResourceFlags = serde_json::from_str(stored).unwrap();
        assert!(f.delete_on_read);
        // Re-serializing must produce stable JSON that round-trips cleanly.
        let reserialized = serde_json::to_string(&f).unwrap();
        let f2: ResourceFlags = serde_json::from_str(&reserialized).unwrap();
        assert!(f2.delete_on_read);
    }
}
