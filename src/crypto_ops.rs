//! User-facing cryptographic operations — the "crypto toolkit" surface.
//!
//! Blackbook already relies on AES-256-GCM, Ed25519, HMAC / SHA-3, Argon2id
//! and scrypt internally. This module packages those same primitives as
//! operations users can call directly, from three places that must agree on
//! every byte format:
//!   * the server's managed-key API ([`crate::keys_api`]) — named, versioned
//!     keys whose secret material never leaves the server;
//!   * the `bbk key` / `bbk crypto` CLI ([`crate::crypto_cli`]) — managed keys
//!     via the server, plus local *unmanaged* keys (key files, the profile's
//!     client master key, passphrases);
//!   * the MCP tools ([`crate::mcp`]).
//!
//! Text formats (base64 is the standard alphabet unless noted):
//!
//! | Prefix          | Meaning                                                    |
//! |-----------------|------------------------------------------------------------|
//! | `bbk:v<N>:`     | output of managed-key version N (ciphertext, signature, MAC); the version selects the key on the way back in, so rotation never strands old data |
//! | `bbkd1:`        | envelope: a managed-key-wrapped data key + local AES-256-GCM |
//! | `bbkx1:`        | passphrase envelope: Argon2id → AES-256-GCM                 |
//! | `bbkc1:`        | profile-CMK envelope: HKDF-SHA256 subkey → AES-256-GCM      |
//! | `bbkk1:`        | raw-key envelope: plain AES-256-GCM, `nonce(12) ‖ ct ‖ tag` |
//! | JWT (RFC 7519)  | tokens, `EdDSA` (Ed25519, RFC 8037) or `HS256`              |

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use rand::RngCore;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::blackbook_core::{aead_open_aad, aead_seal_aad};
use crate::credstore;

/// Every key type uses 32 bytes of secret material (an AES-256 key, an
/// Ed25519 seed, or an HMAC key).
pub const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// AES-256-GCM: encrypt / decrypt / data keys.
    Aes256Gcm,
    /// Ed25519: sign / verify / EdDSA tokens. The public half is shareable.
    Ed25519,
    /// HMAC (SHA-3 or SHA-2, chosen per call): keyed hashes / HS256 tokens.
    Hmac,
}

impl KeyType {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "aes256-gcm" | "aes-256-gcm" | "aes256" | "aes" => Ok(Self::Aes256Gcm),
            "ed25519" => Ok(Self::Ed25519),
            "hmac" => Ok(Self::Hmac),
            other => Err(format!("unknown key type '{other}' (use aes256-gcm, ed25519 or hmac)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256-gcm",
            Self::Ed25519 => "ed25519",
            Self::Hmac => "hmac",
        }
    }

    /// The operations this key type supports, for error messages.
    pub fn operations(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "encrypt, decrypt, datakey",
            Self::Ed25519 => "sign, verify, token",
            Self::Hmac => "hmac, verify, token",
        }
    }

    /// Fresh CSPRNG secret material for this type.
    pub fn generate() -> Zeroizing<Vec<u8>> {
        let mut k = Zeroizing::new(vec![0u8; KEY_LEN]);
        rand::thread_rng().fill_bytes(k.as_mut_slice());
        k
    }

    pub fn check_material(self, material: &[u8]) -> Result<(), String> {
        if material.len() != KEY_LEN {
            return Err(format!("{} keys are {KEY_LEN} bytes; got {}", self.as_str(), material.len()));
        }
        Ok(())
    }

    /// The public half, for Ed25519 keys.
    pub fn public_key(self, material: &[u8]) -> Option<[u8; 32]> {
        match self {
            Self::Ed25519 => ed25519_public(material).ok(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

fn ed25519_signing_key(seed: &[u8]) -> Result<ed25519_dalek::SigningKey, String> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| "Ed25519 seeds are 32 bytes".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn ed25519_public(seed: &[u8]) -> Result<[u8; 32], String> {
    Ok(ed25519_signing_key(seed)?.verifying_key().to_bytes())
}

pub fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Result<[u8; 64], String> {
    use ed25519_dalek::Signer as _;
    Ok(ed25519_signing_key(seed)?.sign(msg).to_bytes())
}

/// Strict verification (rejects small-order keys and malleable signatures).
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok()
}

// ---------------------------------------------------------------------------
// Hashing and HMAC
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg { Sha3_256, Sha3_512, Sha256, Sha512 }

impl HashAlg {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "sha3-256" | "sha3_256" | "sha3" => Ok(Self::Sha3_256),
            "sha3-512" | "sha3_512" => Ok(Self::Sha3_512),
            "sha256" | "sha-256" | "sha2-256" => Ok(Self::Sha256),
            "sha512" | "sha-512" | "sha2-512" => Ok(Self::Sha512),
            other => Err(format!("unknown algorithm '{other}' (use sha3-256, sha3-512, sha256 or sha512)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_512 => "sha3-512",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

pub fn digest(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    match alg {
        HashAlg::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        HashAlg::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        HashAlg::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlg::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

/// Run `$body` with `$m` bound to a keyed HMAC instance for `$alg`.
macro_rules! with_hmac {
    ($alg:expr, $key:expr, |$m:ident| $body:expr) => {{
        use hmac::{Hmac, Mac};
        match $alg {
            HashAlg::Sha3_256 => { let mut $m = Hmac::<sha3::Sha3_256>::new_from_slice($key).expect("HMAC accepts any key length"); $body }
            HashAlg::Sha3_512 => { let mut $m = Hmac::<sha3::Sha3_512>::new_from_slice($key).expect("HMAC accepts any key length"); $body }
            HashAlg::Sha256 => { let mut $m = Hmac::<sha2::Sha256>::new_from_slice($key).expect("HMAC accepts any key length"); $body }
            HashAlg::Sha512 => { let mut $m = Hmac::<sha2::Sha512>::new_from_slice($key).expect("HMAC accepts any key length"); $body }
        }
    }};
}

pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    with_hmac!(alg, key, |m| { m.update(data); m.finalize().into_bytes().to_vec() })
}

/// Constant-time HMAC check.
pub fn hmac_verify(alg: HashAlg, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    with_hmac!(alg, key, |m| { m.update(data); m.verify_slice(tag).is_ok() })
}

// ---------------------------------------------------------------------------
// Managed-key output: `bbk:v<N>:<base64>`
// ---------------------------------------------------------------------------

pub const MANAGED_PREFIX: &str = "bbk:v";

pub fn versioned(version: i32, bytes: &[u8]) -> String {
    format!("{MANAGED_PREFIX}{version}:{}", B64.encode(bytes))
}

pub fn parse_versioned(s: &str) -> Result<(i32, Vec<u8>), String> {
    let bad = || "expected 'bbk:v<N>:<base64>' (output of a Blackbook managed key)".to_string();
    let rest = s.trim().strip_prefix(MANAGED_PREFIX).ok_or_else(bad)?;
    let (ver, body) = rest.split_once(':').ok_or_else(bad)?;
    let ver: i32 = ver.parse().map_err(|_| bad())?;
    if ver < 1 { return Err(bad()); }
    let bytes = B64.decode(body).map_err(|_| bad())?;
    Ok((ver, bytes))
}

// ---------------------------------------------------------------------------
// Local envelopes
// ---------------------------------------------------------------------------

pub const DATAKEY_PREFIX: &str = "bbkd1:";
pub const PASSPHRASE_PREFIX: &str = "bbkx1:";
pub const CMK_PREFIX: &str = "bbkc1:";
pub const RAWKEY_PREFIX: &str = "bbkk1:";

const DATAKEY_MAGIC: &[u8] = b"BBKD1";
const PASSPHRASE_MAGIC: &[u8] = b"BBKX1";
const PASSPHRASE_SALT_LEN: usize = 16;

/// What produced a piece of ciphertext text, judged by its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind { Managed, DataKey, Passphrase, Cmk, RawKey }

pub fn detect(s: &str) -> Option<EnvelopeKind> {
    let s = s.trim_start();
    if s.starts_with(MANAGED_PREFIX) { Some(EnvelopeKind::Managed) }
    else if s.starts_with(DATAKEY_PREFIX) { Some(EnvelopeKind::DataKey) }
    else if s.starts_with(PASSPHRASE_PREFIX) { Some(EnvelopeKind::Passphrase) }
    else if s.starts_with(CMK_PREFIX) { Some(EnvelopeKind::Cmk) }
    else if s.starts_with(RAWKEY_PREFIX) { Some(EnvelopeKind::RawKey) }
    else { None }
}

fn strip_b64(s: &str, prefix: &str) -> Result<Vec<u8>, String> {
    let body = s.trim().strip_prefix(prefix)
        .ok_or_else(|| format!("not a Blackbook envelope (expected a '{prefix}' prefix)"))?;
    B64.decode(body).map_err(|e| format!("envelope is not valid base64: {e}"))
}

fn open_err(_: crate::blackbook_core::CryptoError) -> String {
    "decryption failed — wrong key/passphrase, wrong associated data, or a corrupted envelope".into()
}

/// `bbkx1:` + base64(`BBKX1` ‖ salt(16) ‖ AES-256-GCM(Argon2id(pass, salt), pt)).
pub fn passphrase_seal(plaintext: &[u8], passphrase: &str, aad: &[u8]) -> Result<String, String> {
    let mut salt = [0u8; PASSPHRASE_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let (key, _, _, _) = credstore::argon2_key(passphrase, &salt).map_err(|e| e.to_string())?;
    let sealed = aead_seal_aad(plaintext, key.as_slice(), aad).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(PASSPHRASE_MAGIC.len() + salt.len() + sealed.len());
    buf.extend_from_slice(PASSPHRASE_MAGIC);
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&sealed);
    Ok(format!("{PASSPHRASE_PREFIX}{}", B64.encode(buf)))
}

pub fn passphrase_open(envelope: &str, passphrase: &str, aad: &[u8]) -> Result<Vec<u8>, String> {
    let buf = strip_b64(envelope, PASSPHRASE_PREFIX)?;
    let min = PASSPHRASE_MAGIC.len() + PASSPHRASE_SALT_LEN;
    if buf.len() <= min || &buf[..PASSPHRASE_MAGIC.len()] != PASSPHRASE_MAGIC {
        return Err("corrupted or truncated envelope".into());
    }
    let salt = &buf[PASSPHRASE_MAGIC.len()..min];
    let (key, _, _, _) = credstore::argon2_key(passphrase, salt).map_err(|e| e.to_string())?;
    aead_open_aad(&buf[min..], key.as_slice(), aad).map_err(open_err)
}

/// A purpose-bound subkey of the profile's client master key, so the CMK
/// that wraps external-secret data keys is never used directly on user data.
pub fn cmk_subkey(cmk: &[u8], purpose: &str) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, cmk);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(format!("blackbook/crypto/cmk/{purpose}/v1").as_bytes(), out.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// `bbkc1:` + base64(nonce ‖ AES-256-GCM(HKDF(cmk, "encrypt"), pt)).
pub fn cmk_seal(plaintext: &[u8], cmk: &[u8], aad: &[u8]) -> Result<String, String> {
    let k = cmk_subkey(cmk, "encrypt");
    let sealed = aead_seal_aad(plaintext, k.as_slice(), aad).map_err(|e| e.to_string())?;
    Ok(format!("{CMK_PREFIX}{}", B64.encode(sealed)))
}

pub fn cmk_open(envelope: &str, cmk: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let buf = strip_b64(envelope, CMK_PREFIX)?;
    let k = cmk_subkey(cmk, "encrypt");
    aead_open_aad(&buf, k.as_slice(), aad).map_err(open_err)
}

/// `bbkk1:` + base64(nonce ‖ ct ‖ tag) — plain AES-256-GCM under the caller's
/// own key with no KDF, so any AES-GCM library can open the decoded bytes.
pub fn rawkey_seal(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<String, String> {
    let sealed = aead_seal_aad(plaintext, key, aad).map_err(|e| e.to_string())?;
    Ok(format!("{RAWKEY_PREFIX}{}", B64.encode(sealed)))
}

pub fn rawkey_open(envelope: &str, key: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let buf = strip_b64(envelope, RAWKEY_PREFIX)?;
    aead_open_aad(&buf, key, aad).map_err(open_err)
}

/// `bbkd1:` + base64(`BBKD1` ‖ len(2) ‖ wrapped ‖ nonce ‖ ct ‖ tag), where
/// `wrapped` is the data key as ciphertext of a managed key (`bbk:v<N>:…`)
/// and the payload is sealed locally under the plaintext data key. The data
/// never reaches the server; only the 32-byte data key is ever unwrapped there.
pub fn datakey_seal(plaintext: &[u8], dek: &[u8], wrapped: &str, aad: &[u8]) -> Result<String, String> {
    let w = wrapped.as_bytes();
    let len = u16::try_from(w.len()).map_err(|_| "wrapped data key is too long".to_string())?;
    let sealed = aead_seal_aad(plaintext, dek, aad).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(DATAKEY_MAGIC.len() + 2 + w.len() + sealed.len());
    buf.extend_from_slice(DATAKEY_MAGIC);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(w);
    buf.extend_from_slice(&sealed);
    Ok(format!("{DATAKEY_PREFIX}{}", B64.encode(buf)))
}

/// Split a `bbkd1:` envelope into (wrapped data key, locally sealed payload).
pub fn datakey_parse(envelope: &str) -> Result<(String, Vec<u8>), String> {
    let buf = strip_b64(envelope, DATAKEY_PREFIX)?;
    let bad = || "corrupted or truncated envelope".to_string();
    let m = DATAKEY_MAGIC.len();
    if buf.len() < m + 2 || &buf[..m] != DATAKEY_MAGIC { return Err(bad()); }
    let len = u16::from_be_bytes([buf[m], buf[m + 1]]) as usize;
    let start = m + 2;
    if buf.len() < start + len { return Err(bad()); }
    let wrapped = String::from_utf8(buf[start..start + len].to_vec()).map_err(|_| bad())?;
    Ok((wrapped, buf[start + len..].to_vec()))
}

pub fn datakey_open(sealed: &[u8], dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    aead_open_aad(sealed, dek, aad).map_err(open_err)
}

// ---------------------------------------------------------------------------
// Tokens — compact JWS / JWT
// ---------------------------------------------------------------------------

/// Upper bound on a token's lifetime (10 years).
pub const TOKEN_MAX_TTL_SECS: i64 = 10 * 365 * 24 * 3600;
/// Clock-skew allowance when checking `exp` / `nbf`.
pub const TOKEN_LEEWAY_SECS: i64 = 60;

pub enum TokenSigner<'a> {
    Ed25519(&'a [u8]),
    Hmac(&'a [u8]),
}

pub enum TokenVerifier<'a> {
    Ed25519([u8; 32]),
    Hmac(&'a [u8]),
}

impl TokenVerifier<'_> {
    fn alg(&self) -> &'static str {
        match self { Self::Ed25519(_) => "EdDSA", Self::Hmac(_) => "HS256" }
    }
}

/// What the caller asks to put in a token. Reserved timing claims (`iat`,
/// `exp`, `nbf`, `jti`) are always set here, never taken from `claims`, so a
/// caller can't mint a token that outlives its requested TTL.
#[derive(Default)]
pub struct TokenRequest {
    pub claims: Map<String, Value>,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub issuer: Option<String>,
    pub ttl_secs: i64,
    pub not_before_secs: Option<i64>,
}

pub fn token_claims(req: TokenRequest, now: i64) -> Result<Map<String, Value>, String> {
    if req.ttl_secs < 1 || req.ttl_secs > TOKEN_MAX_TTL_SECS {
        return Err(format!("ttl must be between 1 second and {TOKEN_MAX_TTL_SECS} seconds"));
    }
    let mut c = req.claims;
    if let Some(s) = req.subject { c.insert("sub".into(), json!(s)); }
    if let Some(a) = req.audience { c.insert("aud".into(), json!(a)); }
    if let Some(i) = req.issuer { c.insert("iss".into(), json!(i)); }
    c.insert("iat".into(), json!(now));
    c.insert("exp".into(), json!(now + req.ttl_secs));
    match req.not_before_secs {
        Some(n) if n < 0 => return Err("not-before offset can't be negative".into()),
        Some(n) => { c.insert("nbf".into(), json!(now + n)); }
        None => { c.remove("nbf"); }
    }
    let mut jti = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti);
    c.insert("jti".into(), json!(B64URL.encode(jti)));
    Ok(c)
}

pub fn token_issue(signer: &TokenSigner, kid: Option<&str>, claims: &Map<String, Value>) -> Result<String, String> {
    let alg = match signer { TokenSigner::Ed25519(_) => "EdDSA", TokenSigner::Hmac(_) => "HS256" };
    let mut header = json!({ "alg": alg, "typ": "JWT" });
    if let Some(k) = kid { header["kid"] = json!(k); }
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?),
        B64URL.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?),
    );
    let sig = match signer {
        TokenSigner::Ed25519(seed) => ed25519_sign(seed, signing_input.as_bytes())?.to_vec(),
        TokenSigner::Hmac(key) => hmac(HashAlg::Sha256, key, signing_input.as_bytes()),
    };
    Ok(format!("{signing_input}.{}", B64URL.encode(sig)))
}

fn token_parts(token: &str) -> Result<(&str, &str, &str), String> {
    let mut it = token.trim().split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() => Ok((h, p, s)),
        _ => Err("malformed token (expected header.payload.signature)".into()),
    }
}

fn token_json(part: &str, what: &str) -> Result<Map<String, Value>, String> {
    let bytes = B64URL.decode(part).map_err(|_| format!("malformed token {what}"))?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(format!("malformed token {what}")),
    }
}

/// Decode a token's header without verifying anything (to read `kid`/`alg`).
pub fn token_header(token: &str) -> Result<Map<String, Value>, String> {
    let (h, _, _) = token_parts(token)?;
    token_json(h, "header")
}

/// Verify signature, algorithm, `exp`, `nbf` and (when given) audience.
/// Returns the claims on success, or the reason it's invalid.
pub fn token_verify(
    token: &str, verifier: &TokenVerifier, now: i64, audience: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let (h, p, s) = token_parts(token)?;
    let header = token_json(h, "header")?;
    // Only the algorithm that matches the key is accepted — never `none`, and
    // never an HMAC token checked against an Ed25519 public key or vice versa.
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != verifier.alg() {
        return Err(format!("algorithm mismatch: token is '{alg}' but this key verifies '{}'", verifier.alg()));
    }
    let sig = B64URL.decode(s).map_err(|_| "malformed token signature".to_string())?;
    let signing_input = &token.trim()[..h.len() + 1 + p.len()];
    let ok = match verifier {
        TokenVerifier::Ed25519(pk) => ed25519_verify(pk, signing_input.as_bytes(), &sig),
        TokenVerifier::Hmac(key) => hmac_verify(HashAlg::Sha256, key, signing_input.as_bytes(), &sig),
    };
    if !ok { return Err("bad signature".into()); }
    let claims = token_json(p, "payload")?;
    if let Some(exp) = claims.get("exp") {
        let exp = exp.as_i64().ok_or("malformed 'exp' claim")?;
        if now > exp + TOKEN_LEEWAY_SECS { return Err(format!("expired at {}", fmt_unix(exp))); }
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf.as_i64().ok_or("malformed 'nbf' claim")?;
        if now + TOKEN_LEEWAY_SECS < nbf { return Err(format!("not valid before {}", fmt_unix(nbf))); }
    }
    if let Some(want) = audience {
        let matches = match claims.get("aud") {
            Some(Value::String(a)) => a == want,
            Some(Value::Array(v)) => v.iter().any(|a| a.as_str() == Some(want)),
            _ => false,
        };
        if !matches { return Err(format!("audience mismatch: token is not for '{want}'")); }
    }
    Ok(claims)
}

pub fn now_unix() -> i64 { chrono::Utc::now().timestamp() }

pub fn fmt_unix(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| t.to_string())
}

// ---------------------------------------------------------------------------
// Key encodings: local key files, PEM, JWK
// ---------------------------------------------------------------------------

/// DER prefixes for Ed25519 keys (RFC 8410): SubjectPublicKeyInfo and a
/// PKCS#8 v1 PrivateKeyInfo; each is followed by the 32 raw key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
const ED25519_PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn pem_body(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = text[start..].find(&end)? + start;
    let body: String = text[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(body).ok()
}

pub fn ed25519_public_pem(public: &[u8; 32]) -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(public);
    pem_wrap("PUBLIC KEY", &der)
}

pub fn ed25519_private_pem(seed: &[u8]) -> String {
    let mut der = Zeroizing::new(ED25519_PKCS8_PREFIX.to_vec());
    der.extend_from_slice(seed);
    pem_wrap("PRIVATE KEY", &der)
}

/// RFC 8037 JSON Web Key for an Ed25519 public key.
pub fn ed25519_jwk(public: &[u8; 32], kid: &str) -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": B64URL.encode(public), "kid": kid, "alg": "EdDSA", "use": "sig" })
}

/// Short, stable identifier for a key (first 16 hex chars of SHA3-256).
pub fn key_fingerprint(bytes: &[u8]) -> String {
    hex::encode(digest(HashAlg::Sha3_256, bytes))[..16].to_string()
}

/// A local ("unmanaged") key loaded from a file the user holds.
pub struct LocalKey {
    pub key_type: KeyType,
    pub secret: Zeroizing<Vec<u8>>,
}

/// The JSON key-file format written by `bbk crypto keygen`.
pub fn local_key_json(key_type: KeyType, secret: &[u8]) -> Zeroizing<String> {
    let mut v = json!({ "blackbook_key": 1, "type": key_type.as_str(), "secret": B64.encode(secret) });
    if let Some(pk) = key_type.public_key(secret) {
        v["public"] = json!(B64.encode(pk));
    }
    Zeroizing::new(serde_json::to_string_pretty(&v).expect("JSON value serializes") + "\n")
}

/// Decode 32 key bytes written as hex or base64 text.
fn text_key_bytes(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.len() == 64 {
        if let Ok(b) = hex::decode(t) { return Some(b); }
    }
    B64.decode(t).ok().or_else(|| B64URL.decode(t.trim_end_matches('=')).ok())
        .filter(|b| b.len() == KEY_LEN)
}

/// Load a local key from file contents. Accepts the `keygen` JSON format, an
/// Ed25519 PKCS#8 PEM, 32 raw bytes, or 32 bytes as hex/base64 text. Raw
/// formats carry no type, so `hint` (or AES-256-GCM by default) decides.
pub fn parse_local_key(bytes: &[u8], hint: Option<KeyType>) -> Result<LocalKey, String> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(text) {
            let key_type = KeyType::parse(m.get("type").and_then(Value::as_str).unwrap_or(""))?;
            let secret = m.get("secret").and_then(Value::as_str)
                .ok_or("this key file has no secret (it may be a public key — use --public-key)")?;
            let secret = Zeroizing::new(B64.decode(secret).map_err(|_| "key file secret is not base64")?);
            key_type.check_material(&secret)?;
            return Ok(LocalKey { key_type, secret });
        }
        if let Some(der) = pem_body(text, "PRIVATE KEY") {
            let der = Zeroizing::new(der);
            if der.len() == ED25519_PKCS8_PREFIX.len() + KEY_LEN && der.starts_with(&ED25519_PKCS8_PREFIX) {
                let secret = Zeroizing::new(der[ED25519_PKCS8_PREFIX.len()..].to_vec());
                return Ok(LocalKey { key_type: KeyType::Ed25519, secret });
            }
            return Err("unsupported PEM private key (only Ed25519 PKCS#8 is supported)".into());
        }
        if let Some(b) = text_key_bytes(text) {
            return Ok(LocalKey { key_type: hint.unwrap_or(KeyType::Aes256Gcm), secret: Zeroizing::new(b) });
        }
    }
    if bytes.len() == KEY_LEN {
        return Ok(LocalKey { key_type: hint.unwrap_or(KeyType::Aes256Gcm), secret: Zeroizing::new(bytes.to_vec()) });
    }
    Err("unrecognized key file (expected a `bbk crypto keygen` file, an Ed25519 PEM, \
         or 32 raw / hex / base64 key bytes)".into())
}

/// Parse an Ed25519 public key from text: the `keygen` JSON (public or
/// private), a PEM public or private key, a JWK, or 32 bytes as base64/hex.
pub fn parse_public_key(text: &str) -> Result<[u8; 32], String> {
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(text) {
        if let Some(p) = m.get("public").and_then(Value::as_str) {
            return B64.decode(p).ok().and_then(|b| b.try_into().ok())
                .ok_or_else(|| "public key in file is not 32 base64 bytes".to_string());
        }
        if let Some(x) = m.get("x").and_then(Value::as_str) {
            return B64URL.decode(x).ok().and_then(|b| b.try_into().ok())
                .ok_or_else(|| "JWK 'x' is not a 32-byte Ed25519 key".to_string());
        }
    }
    if let Some(der) = pem_body(text, "PUBLIC KEY") {
        if der.len() == ED25519_SPKI_PREFIX.len() + 32 && der.starts_with(&ED25519_SPKI_PREFIX) {
            return Ok(der[ED25519_SPKI_PREFIX.len()..].try_into().expect("length checked"));
        }
        return Err("unsupported PEM public key (only Ed25519 is supported)".into());
    }
    // A PKCS#8 private key yields its public half (the keygen JSON already
    // carries `public`, handled above).
    if pem_body(text, "PRIVATE KEY").is_some() {
        return ed25519_public(&parse_local_key(text.as_bytes(), None)?.secret);
    }
    text_key_bytes(text).and_then(|b| b.try_into().ok())
        .ok_or_else(|| "unrecognized public key (expected base64/hex, PEM, JWK or a keygen file)".into())
}

/// Decode a signature or MAC given as `bbk:v<N>:`, base64, base64url or hex.
pub fn parse_tag(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.starts_with(MANAGED_PREFIX) { return parse_versioned(t).map(|(_, b)| b); }
    if t.len().is_multiple_of(2) && t.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(b) = hex::decode(t) { return Ok(b); }
    }
    B64.decode(t).or_else(|_| B64URL.decode(t.trim_end_matches('=')))
        .map_err(|_| "signature is not hex, base64 or 'bbk:v<N>:' text".into())
}

// ---------------------------------------------------------------------------
// Passwords, key derivation, randomness
// ---------------------------------------------------------------------------

/// Argon2id password hash in the standard PHC string format
/// (`$argon2id$v=19$m=65536,t=3,p=1$…`), verifiable by any Argon2 library.
pub fn password_hash(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(|e| e.to_string())?;
    let params = argon2::Params::new(64 * 1024, 3, 1, None).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Check a password against a PHC string (cost parameters come from the string).
pub fn password_verify(password: &str, phc: &str) -> Result<bool, String> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = PasswordHash::new(phc.trim()).map_err(|e| format!("not a PHC password hash: {e}"))?;
    Ok(argon2::Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfAlg { Argon2id, Scrypt, Pbkdf2 }

impl KdfAlg {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "argon2id" | "argon2" => Ok(Self::Argon2id),
            "scrypt" => Ok(Self::Scrypt),
            "pbkdf2" | "pbkdf2-sha3-512" => Ok(Self::Pbkdf2),
            other => Err(format!("unknown algorithm '{other}' (use argon2id, scrypt or pbkdf2)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self { Self::Argon2id => "argon2id", Self::Scrypt => "scrypt", Self::Pbkdf2 => "pbkdf2-sha3-512" }
    }
}

/// Derive a 256-bit key from a passphrase with the same parameters Blackbook
/// uses internally: Argon2id (64 MiB, t=3, p=1), scrypt (N=2¹², r=16, p=4), or
/// PBKDF2-HMAC-SHA3-512 (200,000 iterations).
pub fn derive_key(alg: KdfAlg, passphrase: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    match alg {
        KdfAlg::Argon2id => credstore::argon2_key(passphrase, salt)
            .map(|(k, _, _, _)| Zeroizing::new(k.to_vec()))
            .map_err(|e| e.to_string()),
        KdfAlg::Scrypt => crate::blackbook_core::scrypt_dek(passphrase.as_bytes(), salt)
            .map(|k| Zeroizing::new(k.to_vec()))
            .map_err(|e| e.to_string()),
        KdfAlg::Pbkdf2 => {
            let mut out = Zeroizing::new(vec![0u8; KEY_LEN]);
            pbkdf2::pbkdf2_hmac::<sha3::Sha3_512>(passphrase.as_bytes(), salt, 200_000, &mut out);
            Ok(out)
        }
    }
}

pub fn random_bytes(n: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    rand::thread_rng().fill_bytes(buf.as_mut_slice());
    buf
}

/// Encode bytes as `hex`, `base64`, or `base64url` (`token` = base64url).
pub fn encode(bytes: &[u8], encoding: &str) -> Result<String, String> {
    match encoding {
        "hex" => Ok(hex::encode(bytes)),
        "base64" => Ok(B64.encode(bytes)),
        "base64url" | "token" => Ok(B64URL.encode(bytes)),
        other => Err(format!("unknown encoding '{other}' (use hex, base64, base64url or token)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        let tag = hmac(HashAlg::Sha256, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(&tag),
                   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert!(hmac_verify(HashAlg::Sha256, b"Jefe", b"what do ya want for nothing?", &tag));
        assert!(!hmac_verify(HashAlg::Sha256, b"Jefe", b"what do ya want for nothing!", &tag));
    }

    #[test]
    fn ed25519_matches_rfc8032_test_1() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let pk = ed25519_public(&seed).unwrap();
        assert_eq!(hex::encode(pk), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = ed25519_sign(&seed, b"").unwrap();
        assert_eq!(hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assert!(ed25519_verify(&pk, b"", &sig));
        assert!(!ed25519_verify(&pk, b"x", &sig));
    }

    #[test]
    fn digests_match_known_vectors() {
        assert_eq!(hex::encode(digest(HashAlg::Sha3_256, b"")),
                   "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(hex::encode(digest(HashAlg::Sha256, b"abc")),
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn versioned_roundtrip_and_rejects_garbage() {
        let s = versioned(3, b"hello");
        assert!(s.starts_with("bbk:v3:"));
        assert_eq!(parse_versioned(&s).unwrap(), (3, b"hello".to_vec()));
        assert!(parse_versioned("bbk:v0:aGk=").is_err());
        assert!(parse_versioned("bbk:vX:aGk=").is_err());
        assert!(parse_versioned("vault:v1:aGk=").is_err());
    }

    #[test]
    fn envelopes_roundtrip_with_aad_and_detect() {
        let key = [7u8; 32];
        let raw = rawkey_seal(b"pt", &key, b"ctx").unwrap();
        assert_eq!(detect(&raw), Some(EnvelopeKind::RawKey));
        assert_eq!(rawkey_open(&raw, &key, b"ctx").unwrap(), b"pt");
        assert!(rawkey_open(&raw, &key, b"other").is_err());

        let cmk = cmk_seal(b"pt", &key, b"").unwrap();
        assert_eq!(detect(&cmk), Some(EnvelopeKind::Cmk));
        assert_eq!(cmk_open(&cmk, &key, b"").unwrap(), b"pt");
        // The CMK envelope uses a subkey, never the CMK itself.
        assert!(rawkey_open(&cmk.replacen(CMK_PREFIX, RAWKEY_PREFIX, 1), &key, b"").is_err());

        let dk = datakey_seal(b"payload", &key, "bbk:v2:d3JhcHBlZA==", b"").unwrap();
        assert_eq!(detect(&dk), Some(EnvelopeKind::DataKey));
        let (wrapped, sealed) = datakey_parse(&dk).unwrap();
        assert_eq!(wrapped, "bbk:v2:d3JhcHBlZA==");
        assert_eq!(datakey_open(&sealed, &key, b"").unwrap(), b"payload");
    }

    #[test]
    fn passphrase_envelope_roundtrips_and_rejects_wrong_passphrase() {
        let env = passphrase_seal(b"top secret", "correct horse", b"").unwrap();
        assert!(env.starts_with(PASSPHRASE_PREFIX));
        assert!(!env.contains("top secret"));
        assert_eq!(passphrase_open(&env, "correct horse", b"").unwrap(), b"top secret");
        assert!(passphrase_open(&env, "wrong", b"").is_err());
        assert!(passphrase_open("bbkx1:not-base64!!", "x", b"").is_err());
        assert!(passphrase_open("no-prefix", "x", b"").is_err());
    }

    fn req(ttl: i64) -> TokenRequest {
        let mut claims = Map::new();
        claims.insert("role".into(), json!("reader"));
        claims.insert("exp".into(), json!(i64::MAX)); // must be overridden
        TokenRequest { claims, subject: Some("svc-a".into()), audience: Some("api".into()), ttl_secs: ttl, ..Default::default() }
    }

    #[test]
    fn eddsa_token_issue_verify_and_reject() {
        let seed = [9u8; 32];
        let pk = ed25519_public(&seed).unwrap();
        let now = 1_700_000_000;
        let claims = token_claims(req(600), now).unwrap();
        assert_eq!(claims["exp"], json!(now + 600));
        let tok = token_issue(&TokenSigner::Ed25519(&seed), Some("k:v1"), &claims).unwrap();
        assert_eq!(token_header(&tok).unwrap()["kid"], json!("k:v1"));

        let v = TokenVerifier::Ed25519(pk);
        let got = token_verify(&tok, &v, now + 10, Some("api")).unwrap();
        assert_eq!(got["sub"], json!("svc-a"));
        assert_eq!(got["role"], json!("reader"));
        assert!(token_verify(&tok, &v, now + 10, Some("other")).unwrap_err().contains("audience"));
        assert!(token_verify(&tok, &v, now + 600 + TOKEN_LEEWAY_SECS + 1, None).unwrap_err().contains("expired"));

        // Tampered payload, wrong key, and an HMAC verifier are all rejected.
        let parts: Vec<&str> = tok.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0],
            B64URL.encode(br#"{"sub":"admin","exp":9999999999}"#), parts[2]);
        assert_eq!(token_verify(&forged, &v, now, None).unwrap_err(), "bad signature");
        let other = TokenVerifier::Ed25519(ed25519_public(&[1u8; 32]).unwrap());
        assert!(token_verify(&tok, &other, now, None).is_err());
        assert!(token_verify(&tok, &TokenVerifier::Hmac(&seed), now, None).unwrap_err().contains("algorithm"));
    }

    #[test]
    fn hs256_token_and_nbf() {
        let key = [3u8; 32];
        let now = 1_700_000_000;
        let mut r = req(60);
        r.not_before_secs = Some(3600);
        let tok = token_issue(&TokenSigner::Hmac(&key), None, &token_claims(r, now).unwrap()).unwrap();
        let v = TokenVerifier::Hmac(&key);
        assert!(token_verify(&tok, &v, now, None).unwrap_err().contains("not valid before"));
        // A token with alg=none is never accepted.
        let none = format!("{}.{}.", B64URL.encode(br#"{"alg":"none"}"#), B64URL.encode(b"{}"));
        assert!(token_verify(&none, &v, now, None).is_err());
        assert!(token_claims(req(0), now).is_err());
    }

    #[test]
    fn key_encodings_roundtrip() {
        let seed = [5u8; 32];
        let pk = ed25519_public(&seed).unwrap();
        assert_eq!(parse_public_key(&ed25519_public_pem(&pk)).unwrap(), pk);
        assert_eq!(parse_public_key(&B64.encode(pk)).unwrap(), pk);
        assert_eq!(parse_public_key(&ed25519_jwk(&pk, "k").to_string()).unwrap(), pk);
        // A private key file yields its public half.
        assert_eq!(parse_public_key(&local_key_json(KeyType::Ed25519, &seed)).unwrap(), pk);
        assert_eq!(parse_public_key(&ed25519_private_pem(&seed)).unwrap(), pk);

        let k = parse_local_key(ed25519_private_pem(&seed).as_bytes(), None).unwrap();
        assert_eq!((k.key_type, k.secret.as_slice()), (KeyType::Ed25519, &seed[..]));
        let k = parse_local_key(local_key_json(KeyType::Hmac, &seed).as_bytes(), None).unwrap();
        assert_eq!(k.key_type, KeyType::Hmac);
        let k = parse_local_key(&seed, Some(KeyType::Hmac)).unwrap();
        assert_eq!(k.key_type, KeyType::Hmac);
        let k = parse_local_key(hex::encode(seed).as_bytes(), None).unwrap();
        assert_eq!((k.key_type, k.secret.as_slice()), (KeyType::Aes256Gcm, &seed[..]));
        assert!(parse_local_key(b"short", None).is_err());
    }

    #[test]
    fn password_hash_is_phc_and_verifies() {
        let h = password_hash("hunter2").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(password_verify("hunter2", &h).unwrap());
        assert!(!password_verify("hunter3", &h).unwrap());
        assert!(password_verify("x", "not-a-hash").is_err());
    }

    #[test]
    fn tags_parse_in_every_encoding() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(parse_tag("deadbeef").unwrap(), raw);
        assert_eq!(parse_tag(&B64.encode(&raw)).unwrap(), raw);
        assert_eq!(parse_tag(&versioned(1, &raw)).unwrap(), raw);
    }
}
