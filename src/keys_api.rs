// Managed keys — named, versioned cryptographic keys held by the server.
//
// A managed key lives in a domain like a secret or file, and is gated the
// same way: mTLS + token, domain membership, the per-name ACL, optional TOTP
// MFA, and an audit row for every operation. Unlike a secret, its material is
// never returned — callers send data in and get ciphertext / signatures /
// MACs / tokens back (encryption-as-a-service, Vault-transit style).
//
// ACL mapping (patterns match the key name, exactly as for secrets/files):
//   create → create a key (or import one)
//   read   → view metadata / public keys, and USE the key for any operation
//   update → rotate (add a new version)
//   delete → delete the key and every version (irreversible: anything it
//            encrypted becomes unrecoverable)
//
// At rest: the key row's name is AEAD-encrypted like every other identifier
// (`name_enc`, looked up by an HMAC `name_id`). Each version's material is
// AES-256-GCM-sealed under `AppState::managed_key_kek`, with the key id and
// version as associated data so a DB-level swap of one key's material into
// another row (or version) fails to decrypt instead of silently working.

use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::types::Json as SqlxJson;
use zeroize::Zeroizing;

use crate::auth::{self, acl_check, acl_record_use, audit, AuditStatus, AuthenticatedClient};
use crate::blackbook_core::{aead_open_aad, aead_seal_aad, AclAction, Id};
use crate::crypto_ops::{self, HashAlg, KeyType, TokenSigner, TokenVerifier};
use crate::server::{dec_str, enc_str, err, hmac_id, resolve_and_gate_domain, AppState, DomainQuery};

const MAX_KEY_NAME_LEN: usize = 200;
const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;

/// Per-key policy, stored as JSONB. Every field defaults off.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Require a TOTP code (`X-Blackbook-MFA`) for every operation that uses
    /// the key's *secret* material. Public-key operations (Ed25519 verify,
    /// JWKS, metadata) stay open to anyone with `read`.
    #[serde(default)]
    pub mfa_required: bool,
}

// ---------------------------------------------------------------------------
// Request bodies (binary fields are base64)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKeyRequest {
    pub name: String,
    /// `aes256-gcm` (default) | `ed25519` | `hmac`.
    #[serde(default)]
    pub key_type: Option<String>,
    #[serde(default)]
    pub mfa_required: bool,
    /// Bring-your-own-key: base64 of 32 bytes of existing material to import
    /// as version 1. Omit to have the server generate it.
    #[serde(default)]
    pub import_material: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptRequest {
    pub plaintext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptRequest {
    pub ciphertext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub input: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HmacRequest {
    pub input: String,
    /// `sha3-256` (default) | `sha3-512` | `sha256` | `sha512`.
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub input: String,
    /// `bbk:v<N>:…` from `sign` (Ed25519 keys) or `hmac` (HMAC keys).
    pub signature: String,
    /// HMAC keys only: the algorithm the MAC was made with.
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueTokenRequest {
    /// Extra claims to embed. `iat`/`exp`/`nbf`/`jti` are always set by the
    /// server and override anything given here.
    #[serde(default)]
    pub claims: Option<Map<String, Value>>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub not_before_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyTokenRequest {
    pub token: String,
    #[serde(default)]
    pub audience: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct KeyRow {
    id: String,
    name: String,
    key_type: KeyType,
    latest_version: i32,
    policy: KeyPolicy,
    created_at: String,
    updated_at: String,
}

fn internal(e: impl std::fmt::Display) -> HttpResponse {
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
}

fn bad_request(code: &str, msg: impl Into<String>) -> HttpResponse {
    err(StatusCode::BAD_REQUEST, code, msg)
}

/// HMAC of the key name for DB lookup, in its own scope so a key id can never
/// equal a secret/file `name_id` for the same name.
fn key_name_id(state: &AppState, domain_id: &str, name: &str) -> String {
    hmac_id(&state.name_index_key, b"blackbook-key-name-id/v1", &[domain_id.as_bytes(), name.as_bytes()])
}

fn validate_name(name: &str) -> std::result::Result<(), HttpResponse> {
    if name.is_empty() || name.len() > MAX_KEY_NAME_LEN || name.contains("..")
        || name.chars().any(|c| c.is_control() || c == '/')
    {
        return Err(bad_request("validation_error",
            format!("key name must be 1–{MAX_KEY_NAME_LEN} characters, without '/', '..' or control characters")));
    }
    Ok(())
}

fn b64_field(field: &str, value: &str) -> std::result::Result<Vec<u8>, HttpResponse> {
    B64.decode(value.trim()).map_err(|_| bad_request("validation_error", format!("'{field}' is not valid base64")))
}

fn aad_field(aad: Option<&str>) -> std::result::Result<Vec<u8>, HttpResponse> {
    aad.map(|a| b64_field("aad", a)).transpose().map(Option::unwrap_or_default)
}

/// AAD binding a sealed version to its key row and version number.
fn material_aad(key_id: &str, version: i32) -> Vec<u8> {
    let mut aad = b"blackbook/managed-key/v1\0".to_vec();
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

fn seal_material(state: &AppState, key_id: &str, version: i32, material: &[u8]) -> std::result::Result<Vec<u8>, HttpResponse> {
    aead_seal_aad(material, &state.managed_key_kek, &material_aad(key_id, version)).map_err(internal)
}

async fn audit_key(
    state: &AppState, client: &AuthenticatedClient, action: &str, name: &str,
    status: AuditStatus, message: Option<&str>,
) {
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id),
          action, Some(name), status, message).await;
}

async fn find_key(state: &AppState, domain_id: &str, name: &str) -> std::result::Result<Option<KeyRow>, HttpResponse> {
    let row: Option<(String, String, i32, SqlxJson<KeyPolicy>, String, String)> = sqlx::query_as(
        "SELECT id, key_type, latest_version, flags, created_at::text, updated_at::text
         FROM blackbook_keys WHERE domain_id = $1 AND name_id = $2",
    )
    .bind(domain_id).bind(key_name_id(state, domain_id, name))
    .fetch_optional(&state.db).await.map_err(internal)?;
    let Some((id, key_type, latest_version, SqlxJson(policy), created_at, updated_at)) = row else {
        return Ok(None);
    };
    Ok(Some(KeyRow {
        id, name: name.to_string(), key_type: KeyType::parse(&key_type).map_err(internal)?,
        latest_version, policy, created_at, updated_at,
    }))
}

/// Domain membership → key lookup → ACL. Returns the key and the ACL decision
/// (to record the grant's use once the operation succeeds).
async fn gate(
    state: &AppState, client: &AuthenticatedClient, q: &DomainQuery, name: &str,
    action: AclAction, audit_action: &str,
) -> std::result::Result<(KeyRow, auth::AclDecision), HttpResponse> {
    let (domain_id, domain_name) = resolve_and_gate_domain(state, client, q).await?;
    let Some(key) = find_key(state, &domain_id, name).await? else {
        audit_key(state, client, audit_action, name, AuditStatus::NotFound, None).await;
        return Err(err(StatusCode::NOT_FOUND, "not_found",
                       format!("no key named '{name}' in domain '{domain_name}'")));
    };
    let decision = acl_check(&state.db, &state.metadata_enc_key, client, &domain_id, name, action).await
        .map_err(internal)?;
    if !decision.is_allowed() {
        audit_key(state, client, audit_action, name, AuditStatus::Denied, None).await;
        return Err(err(StatusCode::FORBIDDEN, "forbidden",
                       format!("not permitted to {} key '{name}'", auth::action_name(action))));
    }
    Ok((key, decision))
}

fn require_type(key: &KeyRow, allowed: &[KeyType], op: &str) -> std::result::Result<(), HttpResponse> {
    if allowed.contains(&key.key_type) { return Ok(()); }
    Err(bad_request("wrong_key_type", format!(
        "'{op}' doesn't apply to {} key '{}' (it supports: {})",
        key.key_type.as_str(), key.name, key.key_type.operations())))
}

/// Enforce `mfa_required` before an operation that touches secret material.
async fn mfa_gate(
    state: &AppState, client: &AuthenticatedClient, http_req: &HttpRequest, key: &KeyRow, audit_action: &str,
) -> std::result::Result<(), HttpResponse> {
    if !key.policy.mfa_required { return Ok(()); }
    let code = http_req.headers().get("X-Blackbook-MFA").and_then(|v| v.to_str().ok()).map(str::to_string);
    let Some(code) = code else {
        audit_key(state, client, audit_action, &key.name, AuditStatus::Denied, Some("missing MFA")).await;
        return Err(err(StatusCode::UNAUTHORIZED, "mfa_required",
                       format!("key '{}' requires X-Blackbook-MFA <code>", key.name)));
    };
    let kek = Zeroizing::new(state.keys.read().await.mfa_secret_kek.handle().map_err(internal)?);
    let ok = auth::verify_totp(&state.db, &kek, &client.id, &code).await.map_err(internal)?;
    if !ok {
        audit_key(state, client, audit_action, &key.name, AuditStatus::Denied, Some("MFA verification failed")).await;
        return Err(err(StatusCode::UNAUTHORIZED, "mfa_failed", "invalid TOTP code"));
    }
    Ok(())
}

fn check_version(key: &KeyRow, version: i32) -> std::result::Result<(), HttpResponse> {
    if version < 1 || version > key.latest_version {
        return Err(bad_request("unknown_version", format!(
            "key '{}' has no version {version} (latest is v{})", key.name, key.latest_version)));
    }
    Ok(())
}

/// Unseal one version's secret material.
async fn load_material(state: &AppState, key: &KeyRow, version: i32) -> std::result::Result<Zeroizing<Vec<u8>>, HttpResponse> {
    check_version(key, version)?;
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT material_enc FROM blackbook_key_versions WHERE key_id = $1 AND version = $2",
    ).bind(&key.id).bind(version).fetch_optional(&state.db).await.map_err(internal)?;
    let (sealed,) = row.ok_or_else(|| internal(format!("key '{}' v{version} is missing its material", key.name)))?;
    aead_open_aad(&sealed, &state.managed_key_kek, &material_aad(&key.id, version))
        .map(Zeroizing::new)
        .map_err(|_| internal(format!("key '{}' v{version} failed its integrity check", key.name)))
}

/// One version's Ed25519 public key (stored in the clear — it's public).
async fn load_public(state: &AppState, key: &KeyRow, version: i32) -> std::result::Result<[u8; 32], HttpResponse> {
    check_version(key, version)?;
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT public_key FROM blackbook_key_versions WHERE key_id = $1 AND version = $2",
    ).bind(&key.id).bind(version).fetch_optional(&state.db).await.map_err(internal)?;
    row.and_then(|(pk,)| pk).and_then(|pk| pk.try_into().ok())
        .ok_or_else(|| internal(format!("key '{}' v{version} has no public key", key.name)))
}

/// Metadata view: versions, and for Ed25519 the public keys (latest also as PEM).
async fn summary(state: &AppState, key: &KeyRow) -> std::result::Result<Value, HttpResponse> {
    let rows: Vec<(i32, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT version, created_at::text, public_key FROM blackbook_key_versions
         WHERE key_id = $1 ORDER BY version",
    ).bind(&key.id).fetch_all(&state.db).await.map_err(internal)?;
    let mut latest_pk: Option<[u8; 32]> = None;
    let versions: Vec<Value> = rows.into_iter().map(|(version, created_at, pk)| {
        let pk: Option<[u8; 32]> = pk.and_then(|b| b.try_into().ok());
        if version == key.latest_version { latest_pk = pk; }
        json!({ "version": version, "created_at": created_at, "public_key": pk.map(|p| B64.encode(p)) })
    }).collect();
    let mut v = list_item(key);
    v["versions"] = json!(versions);
    if let Some(pk) = latest_pk {
        v["public_key"] = json!(B64.encode(pk));
        v["public_key_pem"] = json!(crypto_ops::ed25519_public_pem(&pk));
    }
    Ok(v)
}

fn list_item(key: &KeyRow) -> Value {
    json!({
        "name": key.name, "key_type": key.key_type.as_str(), "latest_version": key.latest_version,
        "mfa_required": key.policy.mfa_required,
        "created_at": key.created_at, "updated_at": key.updated_at,
    })
}

/// The version a token was issued under, from its `kid` (`<name>:v<N>`).
/// Tokens without a `kid` are checked against the latest version.
fn token_version(token: &str, key: &KeyRow) -> std::result::Result<i32, String> {
    let header = crypto_ops::token_header(token)?;
    let Some(kid) = header.get("kid").and_then(Value::as_str) else { return Ok(key.latest_version) };
    let (name, ver) = kid.rsplit_once(":v").ok_or("token 'kid' is not '<key>:v<N>'")?;
    if name != key.name { return Err(format!("token was issued by key '{name}', not '{}'", key.name)); }
    ver.parse().map_err(|_| "token 'kid' has a malformed version".into())
}

// ---------------------------------------------------------------------------
// Lifecycle endpoints
// ---------------------------------------------------------------------------

/// `POST /api/v1/keys` — create (or import) a managed key.
pub async fn create_key(
    state: web::Data<AppState>,
    req: web::Json<CreateKeyRequest>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let req = req.into_inner();
    if let Err(r) = validate_name(&req.name) { return Ok(r); }
    let key_type = match KeyType::parse(req.key_type.as_deref().unwrap_or("aes256-gcm")) {
        Ok(t) => t,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    let imported = req.import_material.is_some();
    let material = match req.import_material.as_deref() {
        Some(b64) => {
            let m = match b64_field("import_material", b64) { Ok(m) => Zeroizing::new(m), Err(r) => return Ok(r) };
            if let Err(e) = key_type.check_material(&m) { return Ok(bad_request("validation_error", e)); }
            m
        }
        None => KeyType::generate(),
    };
    let (domain_id, domain_name) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    match find_key(&state, &domain_id, &req.name).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            audit_key(&state, &client, "key.create", &req.name, AuditStatus::Denied, Some("already exists")).await;
            return Ok(err(StatusCode::CONFLICT, "already_exists",
                          format!("a key named '{}' already exists in '{domain_name}'", req.name)));
        }
        Err(r) => return Ok(r),
    }
    let decision = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &req.name, AclAction::Create).await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !decision.is_allowed() {
        audit_key(&state, &client, "key.create", &req.name, AuditStatus::Denied, None).await;
        return Ok(err(StatusCode::FORBIDDEN, "forbidden", format!("not permitted to create key '{}'", req.name)));
    }

    let id = Id::new(32).to_hex();
    let name_enc = enc_str(&state.metadata_enc_key, &req.name).map_err(actix_web::error::ErrorInternalServerError)?;
    let sealed = match seal_material(&state, &id, 1, &material) { Ok(s) => s, Err(r) => return Ok(r) };
    let public = key_type.public_key(&material);
    let policy = KeyPolicy { mfa_required: req.mfa_required };

    let mut tx = state.db.begin().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let inserted = sqlx::query(
        "INSERT INTO blackbook_keys (id, name_enc, name_id, domain_id, key_type, latest_version, flags)
         VALUES ($1, $2, $3, $4, $5, 1, $6)",
    )
    .bind(&id).bind(&name_enc).bind(key_name_id(&state, &domain_id, &req.name)).bind(&domain_id)
    .bind(key_type.as_str()).bind(SqlxJson(&policy))
    .execute(&mut *tx).await;
    if let Err(e) = inserted {
        // Lost a create race on UNIQUE (domain_id, name_id).
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Ok(err(StatusCode::CONFLICT, "already_exists",
                          format!("a key named '{}' already exists in '{domain_name}'", req.name)));
        }
        return Err(actix_web::error::ErrorInternalServerError(e));
    }
    sqlx::query(
        "INSERT INTO blackbook_key_versions (key_id, version, material_enc, public_key) VALUES ($1, 1, $2, $3)",
    )
    .bind(&id).bind(&sealed).bind(public.map(|p| p.to_vec()))
    .execute(&mut *tx).await.map_err(actix_web::error::ErrorInternalServerError)?;
    tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;

    acl_record_use(&state.db, &decision).await;
    audit_key(&state, &client, "key.create", &req.name, AuditStatus::Ok,
              Some(if imported { "imported" } else { "generated" })).await;
    let key = match find_key(&state, &domain_id, &req.name).await {
        Ok(Some(k)) => k,
        Ok(None) => return Ok(internal("key vanished after create")),
        Err(r) => return Ok(r),
    };
    Ok(match summary(&state, &key).await {
        Ok(v) => HttpResponse::Created().json(v),
        Err(r) => r,
    })
}

/// `GET /api/v1/keys` — keys in the domain the caller may read.
pub async fn list_keys(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (domain_id, _) = match resolve_and_gate_domain(&state, &client, &q).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let rows: Vec<(String, Vec<u8>, String, i32, SqlxJson<KeyPolicy>, String, String)> = sqlx::query_as(
        "SELECT id, name_enc, key_type, latest_version, flags, created_at::text, updated_at::text
         FROM blackbook_keys WHERE domain_id = $1 ORDER BY created_at DESC LIMIT 500",
    ).bind(&domain_id).fetch_all(&state.db).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let mut items = Vec::new();
    for (id, name_enc, key_type, latest_version, SqlxJson(policy), created_at, updated_at) in rows {
        let name = match dec_str(&state.metadata_enc_key, &name_enc) {
            Ok(n) => n,
            Err(e) => { log::warn!("list_keys: decrypt failed for {id}: {e}"); continue; }
        };
        if !client.is_admin() {
            let dec = acl_check(&state.db, &state.metadata_enc_key, &client, &domain_id, &name, AclAction::Read).await
                .map_err(actix_web::error::ErrorInternalServerError)?;
            if !dec.is_allowed() { continue; }
        }
        let Ok(key_type) = KeyType::parse(&key_type) else { continue };
        items.push(list_item(&KeyRow { id, name, key_type, latest_version, policy, created_at, updated_at }));
    }
    audit(&state.db, &state.audit_hmac_key, &state.metadata_enc_key, Some(&client.id),
          "key.list", None, AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(json!({ "keys": items, "count": items.len() })))
}

/// `GET /api/v1/keys/{name}` — metadata, versions, public keys.
pub async fn show_key(
    state: web::Data<AppState>, path: web::Path<String>, q: web::Query<DomainQuery>, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match gate(&state, &client, &q, &name, AclAction::Read, "key.read").await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let v = match summary(&state, &key).await { Ok(v) => v, Err(r) => return Ok(r) };
    acl_record_use(&state.db, &decision).await;
    audit_key(&state, &client, "key.read", &name, AuditStatus::Ok, None).await;
    Ok(HttpResponse::Ok().json(v))
}

/// `GET /api/v1/keys/{name}/jwks` — the Ed25519 public keys as an RFC 7517
/// JWK Set, so third parties can verify this key's tokens with any JWT library.
pub async fn key_jwks(
    state: web::Data<AppState>, path: web::Path<String>, q: web::Query<DomainQuery>, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match gate(&state, &client, &q, &name, AclAction::Read, "key.read").await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    if key.key_type != KeyType::Ed25519 {
        return Ok(bad_request("wrong_key_type", format!(
            "only Ed25519 keys have public keys; '{name}' is {} (verify its tokens through the API)",
            key.key_type.as_str())));
    }
    let rows: Vec<(i32, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT version, public_key FROM blackbook_key_versions WHERE key_id = $1 ORDER BY version DESC",
    ).bind(&key.id).fetch_all(&state.db).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let keys: Vec<Value> = rows.into_iter()
        .filter_map(|(v, pk)| pk.and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(|pk| crypto_ops::ed25519_jwk(&pk, &format!("{name}:v{v}"))))
        .collect();
    acl_record_use(&state.db, &decision).await;
    audit_key(&state, &client, "key.read", &name, AuditStatus::Ok, Some("jwks")).await;
    Ok(HttpResponse::Ok().json(json!({ "keys": keys })))
}

/// `POST /api/v1/keys/{name}/rotate` — add a fresh version; it becomes the
/// one used for new output, while older versions keep decrypting/verifying.
pub async fn rotate_key(
    state: web::Data<AppState>, path: web::Path<String>, q: web::Query<DomainQuery>, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match gate(&state, &client, &q, &name, AclAction::Update, "key.rotate").await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = KeyType::generate();
    let public = key.key_type.public_key(&material);
    let mut tx = state.db.begin().await.map_err(actix_web::error::ErrorInternalServerError)?;
    // Bumping the counter row-locks the key, so concurrent rotations serialize
    // and each gets a distinct version number.
    let (version,): (i32,) = sqlx::query_as(
        "UPDATE blackbook_keys SET latest_version = latest_version + 1, updated_at = NOW()
         WHERE id = $1 RETURNING latest_version",
    ).bind(&key.id).fetch_one(&mut *tx).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let sealed = match seal_material(&state, &key.id, version, &material) { Ok(s) => s, Err(r) => return Ok(r) };
    sqlx::query(
        "INSERT INTO blackbook_key_versions (key_id, version, material_enc, public_key) VALUES ($1, $2, $3, $4)",
    )
    .bind(&key.id).bind(version).bind(&sealed).bind(public.map(|p| p.to_vec()))
    .execute(&mut *tx).await.map_err(actix_web::error::ErrorInternalServerError)?;
    tx.commit().await.map_err(actix_web::error::ErrorInternalServerError)?;

    acl_record_use(&state.db, &decision).await;
    audit_key(&state, &client, "key.rotate", &name, AuditStatus::Ok, Some(&format!("now v{version}"))).await;
    let key = KeyRow { latest_version: version, ..key };
    Ok(match summary(&state, &key).await {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(r) => r,
    })
}

/// `DELETE /api/v1/keys/{name}` — destroy the key and every version.
pub async fn delete_key(
    state: web::Data<AppState>, path: web::Path<String>, q: web::Query<DomainQuery>, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match gate(&state, &client, &q, &name, AclAction::Delete, "key.delete").await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    sqlx::query("DELETE FROM blackbook_keys WHERE id = $1")
        .bind(&key.id).execute(&state.db).await.map_err(actix_web::error::ErrorInternalServerError)?;
    acl_record_use(&state.db, &decision).await;
    audit_key(&state, &client, "key.delete", &name, AuditStatus::Ok,
              Some(&format!("destroyed {} version(s)", key.latest_version))).await;
    Ok(HttpResponse::Ok().json(json!({
        "deleted": true, "name": name, "versions": key.latest_version,
        "deleted_at": chrono::Utc::now().to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Operation endpoints (all need `read` on the key)
// ---------------------------------------------------------------------------

/// Shared prologue for an operation: gate, type check, and (when the op uses
/// secret material) the MFA policy.
#[allow(clippy::too_many_arguments)]
async fn begin_op(
    state: &AppState, client: &AuthenticatedClient, http_req: &HttpRequest, q: &DomainQuery,
    name: &str, op: &str, allowed: &[KeyType], uses_secret: impl Fn(KeyType) -> bool,
) -> std::result::Result<(KeyRow, auth::AclDecision), HttpResponse> {
    let audit_action = format!("key.{op}");
    let (key, decision) = gate(state, client, q, name, AclAction::Read, &audit_action).await?;
    require_type(&key, allowed, op)?;
    if uses_secret(key.key_type) {
        mfa_gate(state, client, http_req, &key, &audit_action).await?;
    }
    Ok((key, decision))
}

async fn finish_op(
    state: &AppState, client: &AuthenticatedClient, decision: &auth::AclDecision, key: &KeyRow,
    op: &str, message: Option<&str>, body: Value,
) -> HttpResponse {
    acl_record_use(&state.db, decision).await;
    audit_key(state, client, &format!("key.{op}"), &key.name, AuditStatus::Ok, message).await;
    HttpResponse::Ok().json(body)
}

/// `POST /api/v1/keys/{name}/encrypt` → `{ciphertext: "bbk:v<N>:…"}`.
pub async fn encrypt(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<EncryptRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (plaintext, aad) = match (b64_field("plaintext", &req.plaintext), aad_field(req.aad.as_deref())) {
        (Ok(p), Ok(a)) => (Zeroizing::new(p), a),
        (Err(r), _) | (_, Err(r)) => return Ok(r),
    };
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "encrypt",
                                         &[KeyType::Aes256Gcm], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = match load_material(&state, &key, key.latest_version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let ct = aead_seal_aad(&plaintext, &material, &aad).map_err(actix_web::error::ErrorInternalServerError)?;
    let body = json!({ "ciphertext": crypto_ops::versioned(key.latest_version, &ct), "version": key.latest_version });
    Ok(finish_op(&state, &client, &decision, &key, "encrypt", None, body).await)
}

/// `POST /api/v1/keys/{name}/decrypt` → `{plaintext: base64}`. The version in
/// the ciphertext picks the key version, so data survives rotation.
pub async fn decrypt(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<DecryptRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (version, ct) = match crypto_ops::parse_versioned(&req.ciphertext) {
        Ok(x) => x,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    let aad = match aad_field(req.aad.as_deref()) { Ok(a) => a, Err(r) => return Ok(r) };
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "decrypt",
                                         &[KeyType::Aes256Gcm], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = match load_material(&state, &key, version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let Ok(plaintext) = aead_open_aad(&ct, &material, &aad).map(Zeroizing::new) else {
        audit_key(&state, &client, "key.decrypt", &name, AuditStatus::Error, Some("authentication failed")).await;
        return Ok(bad_request("decrypt_failed",
            "decryption failed — the ciphertext was made by a different key, with different associated data, or was modified"));
    };
    let body = json!({ "plaintext": B64.encode(plaintext.as_slice()), "version": version });
    Ok(finish_op(&state, &client, &decision, &key, "decrypt", None, body).await)
}

/// `POST /api/v1/keys/{name}/datakey` → a fresh 256-bit data key, both in the
/// clear (use it locally, then discard) and wrapped under the managed key
/// (store it beside your data; `decrypt` unwraps it later).
pub async fn datakey(
    state: web::Data<AppState>, path: web::Path<String>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "datakey",
                                         &[KeyType::Aes256Gcm], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = match load_material(&state, &key, key.latest_version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let dek = crypto_ops::random_bytes(32);
    let wrapped = aead_seal_aad(&dek, &material, &[]).map_err(actix_web::error::ErrorInternalServerError)?;
    let body = json!({
        "plaintext": B64.encode(dek.as_slice()),
        "ciphertext": crypto_ops::versioned(key.latest_version, &wrapped),
        "version": key.latest_version,
    });
    Ok(finish_op(&state, &client, &decision, &key, "datakey", None, body).await)
}

/// `POST /api/v1/keys/{name}/sign` → Ed25519 `{signature: "bbk:v<N>:…"}`.
pub async fn sign(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<SignRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let input = match b64_field("input", &req.input) { Ok(i) => i, Err(r) => return Ok(r) };
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "sign",
                                         &[KeyType::Ed25519], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = match load_material(&state, &key, key.latest_version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let sig = crypto_ops::ed25519_sign(&material, &input).map_err(actix_web::error::ErrorInternalServerError)?;
    let pk = crypto_ops::ed25519_public(&material).map_err(actix_web::error::ErrorInternalServerError)?;
    let body = json!({
        "signature": crypto_ops::versioned(key.latest_version, &sig),
        "version": key.latest_version,
        "public_key": B64.encode(pk),
    });
    Ok(finish_op(&state, &client, &decision, &key, "sign", None, body).await)
}

/// `POST /api/v1/keys/{name}/hmac` → `{hmac: "bbk:v<N>:…"}`.
pub async fn hmac(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<HmacRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let input = match b64_field("input", &req.input) { Ok(i) => i, Err(r) => return Ok(r) };
    let alg = match HashAlg::parse(req.algorithm.as_deref().unwrap_or("sha3-256")) {
        Ok(a) => a,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "hmac",
                                         &[KeyType::Hmac], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let material = match load_material(&state, &key, key.latest_version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let tag = crypto_ops::hmac(alg, &material, &input);
    let body = json!({
        "hmac": crypto_ops::versioned(key.latest_version, &tag),
        "algorithm": alg.as_str(),
        "version": key.latest_version,
    });
    Ok(finish_op(&state, &client, &decision, &key, "hmac", None, body).await)
}

/// `POST /api/v1/keys/{name}/verify` → `{valid: bool}` for an Ed25519
/// signature or an HMAC. An invalid signature is a normal 200 answer.
pub async fn verify(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<VerifyRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let input = match b64_field("input", &req.input) { Ok(i) => i, Err(r) => return Ok(r) };
    let (version, tag) = match crypto_ops::parse_versioned(&req.signature) {
        Ok(x) => x,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    let alg = match HashAlg::parse(req.algorithm.as_deref().unwrap_or("sha3-256")) {
        Ok(a) => a,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    // Ed25519 verification only needs the public key, so MFA doesn't apply.
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "verify",
                                         &[KeyType::Ed25519, KeyType::Hmac], |t| t == KeyType::Hmac).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let valid = match key.key_type {
        KeyType::Ed25519 => match load_public(&state, &key, version).await {
            Ok(pk) => crypto_ops::ed25519_verify(&pk, &input, &tag),
            Err(r) => return Ok(r),
        },
        _ => match load_material(&state, &key, version).await {
            Ok(m) => crypto_ops::hmac_verify(alg, &m, &input, &tag),
            Err(r) => return Ok(r),
        },
    };
    let body = json!({ "valid": valid, "version": version });
    Ok(finish_op(&state, &client, &decision, &key, "verify",
                 Some(if valid { "valid" } else { "invalid" }), body).await)
}

/// `POST /api/v1/keys/{name}/token` — issue a signed JWT (EdDSA for Ed25519
/// keys, HS256 for HMAC keys), `kid` = `<name>:v<N>`.
pub async fn issue_token(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<IssueTokenRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let req = req.into_inner();
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "token",
                                         &[KeyType::Ed25519, KeyType::Hmac], |_| true).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let claims = match crypto_ops::token_claims(crypto_ops::TokenRequest {
        claims: req.claims.unwrap_or_default(),
        subject: req.subject, audience: req.audience, issuer: req.issuer,
        ttl_secs: req.ttl_secs.unwrap_or(DEFAULT_TOKEN_TTL_SECS),
        not_before_secs: req.not_before_secs,
    }, crypto_ops::now_unix()) {
        Ok(c) => c,
        Err(e) => return Ok(bad_request("validation_error", e)),
    };
    let material = match load_material(&state, &key, key.latest_version).await { Ok(m) => m, Err(r) => return Ok(r) };
    let signer = match key.key_type {
        KeyType::Ed25519 => TokenSigner::Ed25519(&material),
        _ => TokenSigner::Hmac(&material),
    };
    let kid = format!("{name}:v{}", key.latest_version);
    let token = crypto_ops::token_issue(&signer, Some(&kid), &claims).map_err(actix_web::error::ErrorInternalServerError)?;
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or_default();
    let body = json!({ "token": token, "kid": kid, "expires_at": crypto_ops::fmt_unix(exp), "claims": claims });
    let note = claims.get("sub").and_then(Value::as_str).map(|s| format!("sub={s}"));
    Ok(finish_op(&state, &client, &decision, &key, "token", note.as_deref(), body).await)
}

/// `POST /api/v1/keys/{name}/token/verify` → `{valid, claims}` or
/// `{valid: false, reason}`. Checks signature, algorithm, `exp`, `nbf`, and
/// the audience when one is given.
pub async fn verify_token(
    state: web::Data<AppState>, path: web::Path<String>, req: web::Json<VerifyTokenRequest>,
    q: web::Query<DomainQuery>, http_req: HttpRequest, client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let name = path.into_inner();
    let (key, decision) = match begin_op(&state, &client, &http_req, &q, &name, "token.verify",
                                         &[KeyType::Ed25519, KeyType::Hmac], |t| t == KeyType::Hmac).await {
        Ok(x) => x,
        Err(r) => return Ok(r),
    };
    let invalid = |reason: String| json!({ "valid": false, "reason": reason });
    let version = match token_version(&req.token, &key) {
        Ok(v) if v >= 1 && v <= key.latest_version => v,
        Ok(v) => return Ok(finish_op(&state, &client, &decision, &key, "token.verify", Some("invalid"),
                                     invalid(format!("key '{name}' has no version {v}"))).await),
        Err(e) => return Ok(finish_op(&state, &client, &decision, &key, "token.verify", Some("invalid"),
                                      invalid(e)).await),
    };
    let now = crypto_ops::now_unix();
    let outcome = match key.key_type {
        KeyType::Ed25519 => match load_public(&state, &key, version).await {
            Ok(pk) => crypto_ops::token_verify(&req.token, &TokenVerifier::Ed25519(pk), now, req.audience.as_deref()),
            Err(r) => return Ok(r),
        },
        _ => match load_material(&state, &key, version).await {
            Ok(m) => crypto_ops::token_verify(&req.token, &TokenVerifier::Hmac(&m), now, req.audience.as_deref()),
            Err(r) => return Ok(r),
        },
    };
    let (body, note) = match outcome {
        Ok(claims) => (json!({ "valid": true, "kid": format!("{name}:v{version}"), "claims": claims }), "valid"),
        Err(reason) => (invalid(reason), "invalid"),
    };
    Ok(finish_op(&state, &client, &decision, &key, "token.verify", Some(note), body).await)
}
