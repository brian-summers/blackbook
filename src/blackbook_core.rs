//! Blackbook Core - Comprehensive cryptographic and database framework
//! 
//! This module provides:
//! - Asymmetric key management (Ed25519, X25519)
//! - Symmetric encryption (AES-GCM)
//! - Key derivation (Scrypt, PBKDF2)
//! - Serialization/Deserialization
//! - Token generation and validation
//! - Database schema and management
//! - Access control lists (ACL)

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_kw::KekAes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Local};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, SignatureError, Verifier};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// Matches the Python prototype's scrypt() helper: n=2^12, r=16, p=4.
// dklen is passed by each call site.
const SCRYPT_LOG_N: u8 = 12;
const SCRYPT_R: u32 = 16;
const SCRYPT_P: u32 = 4;

/// Blackbook version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cryptography error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid key format")]
    InvalidKeyFormat,
}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// Secure identifier with multiple encoding options
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Id {
    raw: Vec<u8>,
    encoding: IdEncoding,
}

impl Default for Id {
    fn default() -> Self {
        Self::new(32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdEncoding {
    Hex,
    Base64,
    Base85,
}

impl Id {
    /// Create a new random ID
    pub fn new(length: usize) -> Self {
        let mut rng = rand::thread_rng();
        let raw = (0..length).map(|_| rng.gen()).collect();
        Self {
            raw,
            encoding: IdEncoding::Hex,
        }
    }

    /// Create ID from bytes
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        Self {
            raw,
            encoding: IdEncoding::Hex,
        }
    }

    /// Create ID from scrypt of a string with domain
    pub fn from_string(value: &str, domain: &str, dklen: usize) -> CryptoResult<Self> {
        let salt = domain.as_bytes();
        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, dklen)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        
        let mut output = vec![0u8; dklen];
        scrypt::scrypt(value.as_bytes(), salt, &params, &mut output)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

        Ok(Self {
            raw: output,
            encoding: IdEncoding::Hex,
        })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Get encoded representation
    pub fn encode(&self) -> String {
        match self.encoding {
            IdEncoding::Hex => hex::encode(&self.raw),
            IdEncoding::Base64 => BASE64.encode(&self.raw),
            IdEncoding::Base85 => base85_encode(&self.raw),
        }
    }

    /// Set encoding method
    pub fn with_encoding(mut self, encoding: IdEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.raw)
    }
}

/// Z85 (ZeroMQ base-85) — compact, printable, terminal-safe ASCII. Encodes
/// each 4-byte group into 5 characters; a trailing partial group is zero-padded
/// (lossless for the 32-byte ids this is used on, which are a multiple of 4).
fn base85_encode(data: &[u8]) -> String {
    const Z85: &[u8; 85] =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    let mut out = String::with_capacity(data.len().div_ceil(4) * 5);
    for chunk in data.chunks(4) {
        let mut n: u32 = 0;
        for i in 0..4 {
            n = n.wrapping_mul(256).wrapping_add(*chunk.get(i).unwrap_or(&0) as u32);
        }
        let mut buf = [0u8; 5];
        let mut v = n;
        for slot in buf.iter_mut().rev() {
            *slot = Z85[(v % 85) as usize];
            v /= 85;
        }
        out.push_str(std::str::from_utf8(&buf).unwrap());
    }
    out
}

/// Asymmetric key pair (Ed25519 for signing)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsymmetricKey {
    pub id: Id,
    signing_key: Vec<u8>,
    verifying_key: Vec<u8>,
    signature: Vec<u8>,
}

impl AsymmetricKey {
    /// Generate new signing key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        for byte in &mut seed {
            *byte = rng.gen();
        }
        
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Self {
            id: Id::new(32),
            signing_key: signing_key.to_bytes().to_vec(),
            verifying_key: verifying_key.to_bytes().to_vec(),
            signature: Vec::new(),
        }
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> CryptoResult<String> {
        if self.signing_key.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat);
        }
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.signing_key);
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(data).to_bytes().to_vec();
        Ok(BASE64.encode(&sig))
    }

    /// Verify signature
    pub fn verify(&self, signature: &str, data: &[u8]) -> CryptoResult<bool> {
        let signature_bytes = BASE64.decode(signature)?;
        
        if self.verifying_key.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat);
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.verifying_key);
        let verifying_key = VerifyingKey::from_bytes(&key)
            .map_err(|_| CryptoError::InvalidKeyFormat)?;

        let sig: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyFormat)?;
        
        match verifying_key.verify(data, &Signature::from_bytes(&sig)) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get public key
    pub fn public_key(&self) -> Vec<u8> {
        self.verifying_key.clone()
    }
}

/// Wipe the Ed25519 private key (and any cached signature) when an
/// `AsymmetricKey` is dropped, so identity key material doesn't linger in
/// freed heap. The public `verifying_key` is not secret and is left as-is.
impl Drop for AsymmetricKey {
    fn drop(&mut self) {
        self.signing_key.zeroize();
        self.signature.zeroize();
    }
}

/// Base symmetric key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaseKey {
    pub id: Id,
    key: Vec<u8>,
}

impl BaseKey {
    /// Create from random bytes
    pub fn new(length: usize) -> Self {
        let mut rng = rand::thread_rng();
        let key: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
        
        Self {
            id: Id::new(32),
            key,
        }
    }

    /// Create from bytes
    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self {
            id: Id::new(32),
            key,
        }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for BaseKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Primary key — a 32-byte secret. **Holds material, does NOT derive.**
///
/// The previous implementation had `PrimaryKey::derive(salt)` so any caller
/// could call `primary.derive(some_bytes)` and get a key, with no compile-time
/// guarantee that two call sites had used different salts. Every actual
/// derivation now flows through [`SecondaryKey`], which carries an immutable
/// `domain` field — so domain separation is enforced by type construction.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrimaryKey {
    base: BaseKey,
}

impl PrimaryKey {
    pub fn new() -> Self {
        Self { base: BaseKey::new(32) }
    }

    /// Crate-internal accessor used by [`SecondaryKey`] to seed its KDF.
    /// **Intentionally not `pub`** — callers should not use these bytes
    /// directly; they should construct a [`SecondaryKey`] with a domain
    /// and let it derive a usable key.
    pub(crate) fn seed(&self) -> &[u8] {
        self.base.as_bytes()
    }
}

impl Default for PrimaryKey {
    fn default() -> Self { Self::new() }
}

/// Which KDF a [`SecondaryKey`] uses to stretch the primary into a usable
/// key. Pinned to the call site at construction so it can't be confused
/// later.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kdf {
    /// scrypt(n=2¹², r=16, p=4) — slow, memory-hard. The default.
    Scrypt,
    /// PBKDF2-HMAC-SHA3-512, 200k iterations. Matches the Python prototype.
    Pbkdf2Sha3_512,
}

/// Secondary key = `(primary, domain, KDF, length)`. The domain is the
/// *only* salt fed into the KDF — there's no `Option<&[u8]>` knob to forget,
/// so two call sites with different domain strings can never accidentally
/// produce the same key bytes.
///
/// For per-message variation (e.g. an iteration counter on AES-KW), use
/// [`Self::handle_with_info`], which feeds `domain || info` to the KDF.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecondaryKey {
    primary: PrimaryKey,
    domain: String,
    kdf: Kdf,
    length: usize,
}

impl SecondaryKey {
    /// scrypt-backed secondary key.
    pub fn scrypt(primary: PrimaryKey, domain: impl Into<String>, length: usize) -> Self {
        Self { primary, domain: domain.into(), kdf: Kdf::Scrypt, length }
    }

    /// PBKDF2-HMAC-SHA3-512-backed secondary key.
    pub fn pbkdf2(primary: PrimaryKey, domain: impl Into<String>, length: usize) -> Self {
        Self { primary, domain: domain.into(), kdf: Kdf::Pbkdf2Sha3_512, length }
    }

    /// Derive bytes with `domain` as the salt.
    pub fn handle(&self) -> CryptoResult<Vec<u8>> {
        self.handle_with_info(&[])
    }

    /// Derive bytes with `domain || info` as the salt. The `info` parameter
    /// is for per-call variation that doesn't warrant a new SecondaryKey
    /// (e.g. round counter in AES-KW iterations).
    pub fn handle_with_info(&self, info: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut salt = Vec::with_capacity(self.domain.len() + info.len());
        salt.extend_from_slice(self.domain.as_bytes());
        salt.extend_from_slice(info);
        let mut output = vec![0u8; self.length];
        match self.kdf {
            Kdf::Scrypt => {
                let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, self.length)
                    .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
                scrypt::scrypt(self.primary.seed(), &salt, &params, &mut output)
                    .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
            }
            Kdf::Pbkdf2Sha3_512 => {
                pbkdf2::pbkdf2_hmac::<sha3::Sha3_512>(
                    self.primary.seed(),
                    &salt,
                    200_000,
                    &mut output,
                );
            }
        }
        Ok(output)
    }

    pub fn domain(&self) -> &str { &self.domain }
    pub fn length(&self) -> usize { self.length }
}

/// Default iteration count for [`WrappedKey`] — matches the Python prototype.
pub const WRAPPED_KEY_ITERATIONS: usize = 30;

/// A 32-byte secret protected by iterative RFC 3394 AES-256 Key Wrap.
///
/// Each iteration uses a fresh KEK derived from the [`SecondaryKey`] with a
/// per-iteration salt: `domain || minimal_big_endian(i)`. This mirrors the
/// Python `WrappedKey.__init__` loop. Each AES-KW step inflates the buffer
/// by 8 bytes (the integrity check word), so wrapping a 32-byte key with 30
/// iterations yields a 272-byte wrapped blob.
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The wrapped (encrypted) form of the inner key. Empty until populated.
    wrapped: Vec<u8>,
    wrapper: SecondaryKey,
    iterations: usize,
}

impl WrappedKey {
    /// Generate a fresh 32-byte secret and wrap it through `iterations` rounds.
    pub fn new(iterations: usize) -> CryptoResult<Self> {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        Self::wrap_bytes(&secret, iterations)
    }

    /// Wrap a caller-supplied 32-byte secret.
    pub fn wrap_bytes(secret: &[u8], iterations: usize) -> CryptoResult<Self> {
        if secret.len() != 32 {
            return Err(CryptoError::Encryption(
                "WrappedKey expects a 32-byte inner secret".to_string(),
            ));
        }
        let wrapper = SecondaryKey::scrypt(PrimaryKey::new(), "key-wrap/v1", 32);
        // `buf` starts as the raw inner secret and holds key material through
        // every round, so it (and each derived KEK) is wiped on drop.
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(secret.to_vec());
        for i in 0..iterations {
            let kek_bytes = Zeroizing::new(wrapper.handle_with_info(&Self::round_info(i))?);
            let kek = KekAes256::from(<[u8; 32]>::try_from(kek_bytes.as_slice())
                .map_err(|_| CryptoError::KeyDerivation("KEK was not 32 bytes".to_string()))?);
            let mut next = Zeroizing::new(vec![0u8; buf.len() + 8]);
            kek.wrap(buf.as_slice(), next.as_mut_slice())
                .map_err(|e| CryptoError::Encryption(format!("aes-kw iter {i}: {e:?}")))?;
            buf = next;
        }
        // The final buffer is the fully-wrapped (encrypted) blob, safe to store.
        Ok(Self { wrapped: buf.to_vec(), wrapper, iterations })
    }

    /// Recover the wrapped secret by reversing every iteration.
    pub fn unwrap(&self) -> CryptoResult<Vec<u8>> {
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(self.wrapped.clone());
        for i in (0..self.iterations).rev() {
            if buf.len() < 8 {
                return Err(CryptoError::Decryption(
                    "wrapped blob is too short to unwrap".to_string(),
                ));
            }
            let kek_bytes = Zeroizing::new(self.wrapper.handle_with_info(&Self::round_info(i))?);
            let kek = KekAes256::from(<[u8; 32]>::try_from(kek_bytes.as_slice())
                .map_err(|_| CryptoError::KeyDerivation("KEK was not 32 bytes".to_string()))?);
            let mut next = Zeroizing::new(vec![0u8; buf.len() - 8]);
            kek.unwrap(buf.as_slice(), next.as_mut_slice())
                .map_err(|e| CryptoError::Decryption(format!("aes-kw iter {i}: {e:?}")))?;
            buf = next;
        }
        // Hand the recovered secret to the caller, which owns its disposal; our
        // intermediate copies are wiped as the Zeroizing buffers drop.
        Ok(buf.to_vec())
    }

    /// Per-iteration `info`: `i` in minimal big-endian form. The wrapper's
    /// domain string is automatically prepended by `handle_with_info`.
    fn round_info(i: usize) -> Vec<u8> {
        if i == 0 { return vec![0]; }
        let bits = usize::BITS - i.leading_zeros();
        let nbytes = (bits / 8 + 1) as usize;
        (0..nbytes).rev().map(|b| ((i >> (b * 8)) & 0xff) as u8).collect()
    }
}

/// Envelope sizes — must match the Python prototype's `encrypt()` output:
///   timestamp(5) || salt(32) || ciphertext-with-tag
const TIMESTAMP_LEN: usize = 5;
const SALT_LEN: usize = 32;
const ENVELOPE_PREFIX: usize = TIMESTAMP_LEN + SALT_LEN;

/// 5-byte unix-seconds timestamp (~10,000 year range), big-endian to match
/// Python's `int(time()).to_bytes(5)` default byte order.
fn timestamp_bytes() -> [u8; TIMESTAMP_LEN] {
    let secs: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let be = secs.to_be_bytes(); // 8 bytes
    let mut out = [0u8; TIMESTAMP_LEN];
    out.copy_from_slice(&be[3..8]); // low 5 bytes, big-endian
    out
}

/// scrypt-derive a 32-byte key. Public so other modules (persistence) can
/// reuse the same KDF parameters when sealing the DEK with a passphrase.
pub fn scrypt_dek(key: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<[u8; 32]>> {
    derive_message_key(key, salt)
}

/// Derive a per-message AES-256 key by running scrypt over the caller's key
/// material with the random salt. Mirrors the Python `encrypt`'s
/// `key = scrypt(key, salt)` step. Returned in a [`Zeroizing`] wrapper so the
/// derived key is wiped from memory when the caller drops it.
fn derive_message_key(key: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(key, salt, &params, out.as_mut_slice())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

/// AES-256-GCM encrypt matching the Python prototype's envelope.
///
/// Per call: generate a random 32-byte salt and a 5-byte timestamp; derive
/// the AES key as scrypt(key, salt); use the salt's first 12 bytes as the
/// GCM nonce; pass the timestamp as AAD. The Python original passes the
/// whole 32-byte salt to `AESGCM.encrypt(nonce=...)`, which the `cryptography`
/// library internally accepts at arbitrary length — Rust's `aes-gcm` requires
/// exactly 12, so we slice. The 32-byte salt remains in the envelope and is
/// still fully used in scrypt for key derivation.
///
/// Output: timestamp(5) || salt(32) || ciphertext-with-tag
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);
    let timestamp = timestamp_bytes();

    let message_key = derive_message_key(key, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(message_key.as_slice()));
    let nonce = Nonce::from_slice(&salt[..12]);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: data, aad: &timestamp })
        .map_err(|_| CryptoError::Encryption("AES-GCM encryption failed".to_string()))?;

    let mut out = Vec::with_capacity(ENVELOPE_PREFIX + ciphertext.len());
    out.extend_from_slice(&timestamp);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Plain AES-256-GCM seal for blobs that already have a unique random DEK
/// (e.g. per-file keys). Skips the scrypt-per-message strengthening that
/// [`encrypt_aes_gcm`] does — that protects against weak key material, which
/// isn't relevant when the key is freshly CSPRNG-random.
///
/// Output: `nonce(12) ‖ ciphertext-with-tag`.
pub fn aead_seal(plaintext: &[u8], dek: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    aead_seal_nonce(plaintext, dek, &nonce)
}

/// AES-256-GCM seal with an explicit 12-byte nonce, returning
/// `nonce(12) ‖ ciphertext-with-tag`. The caller owns nonce uniqueness — used
/// by the tunnel data plane, which derives nonces from a per-direction counter.
pub fn aead_seal_nonce(plaintext: &[u8], dek: &[u8], nonce: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    if dek.len() != 32 {
        return Err(CryptoError::Encryption("DEK must be 32 bytes".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Encryption("AES-GCM seal failed".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`aead_seal_nonce`] but with a *caller-supplied expected nonce*:
/// the frame carries its own nonce prefix, which must equal `expected` (so a
/// relay can't shift the counter). Returns the plaintext.
pub fn aead_open_nonce(frame: &[u8], dek: &[u8], expected: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    if dek.len() != 32 {
        return Err(CryptoError::Decryption("DEK must be 32 bytes".into()));
    }
    if frame.len() < 12 + 16 {
        return Err(CryptoError::Decryption("frame too short".into()));
    }
    if &frame[..12] != expected.as_slice() {
        return Err(CryptoError::Decryption("unexpected nonce (out-of-order or replayed frame)".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    cipher
        .decrypt(Nonce::from_slice(&frame[..12]), &frame[12..])
        .map_err(|_| CryptoError::Decryption("AES-GCM open failed".into()))
}

/// Inverse of [`aead_seal`].
pub fn aead_open(envelope: &[u8], dek: &[u8]) -> CryptoResult<Vec<u8>> {
    if dek.len() != 32 {
        return Err(CryptoError::Decryption("DEK must be 32 bytes".into()));
    }
    if envelope.len() < 12 + 16 {
        return Err(CryptoError::Decryption("envelope too short".into()));
    }
    let nonce = &envelope[..12];
    let body = &envelope[12..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| CryptoError::Decryption("AES-GCM open failed".into()))
}

/// Inverse of [`encrypt_aes_gcm`]. Parses the envelope, re-derives the
/// per-message key via scrypt(key, salt), and verifies the GCM tag with the
/// stored timestamp as AAD. Returns plaintext on success.
pub fn decrypt_aes_gcm(envelope: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if envelope.len() < ENVELOPE_PREFIX + 16 {
        return Err(CryptoError::Decryption(
            "envelope too short (need timestamp+salt+tag at minimum)".to_string(),
        ));
    }
    let timestamp = &envelope[..TIMESTAMP_LEN];
    let salt = &envelope[TIMESTAMP_LEN..ENVELOPE_PREFIX];
    let body = &envelope[ENVELOPE_PREFIX..];

    let message_key = derive_message_key(key, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(message_key.as_slice()));
    let nonce = Nonce::from_slice(&salt[..12]);

    cipher
        .decrypt(nonce, Payload { msg: body, aad: timestamp })
        .map_err(|_| CryptoError::Decryption("AES-GCM decryption failed".to_string()))
}

/// Serialization format
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedData {
    pub data: HashMap<String, Vec<u8>>,
    pub checksum: Vec<u8>,
}

/// Serialize data with a SHA3-256 checksum.
///
/// Note: the Python prototype's `_serialize` uses a custom length-prefixed
/// TLV format with an ephemeral-key-encrypted body and a scrypt-derived
/// checksum prefix. This Rust version keeps the JSON+checksum shape that
/// the original AI port chose, but at least matches the Python prototype's
/// hash family (Keccak / SHA-3) rather than SHA-2.
pub fn serialize(data: &HashMap<String, Vec<u8>>) -> CryptoResult<String> {
    let json = serde_json::to_string(data)?;
    let mut checksum = Sha3_256::new();
    checksum.update(&json);

    let result = SerializedData {
        data: data.clone(),
        checksum: checksum.finalize().to_vec(),
    };

    let serialized = serde_json::to_vec(&result)?;
    Ok(BASE64.encode(&serialized))
}

/// Deserialize and verify data
pub fn deserialize(data: &str) -> CryptoResult<HashMap<String, Vec<u8>>> {
    let decoded = BASE64.decode(data)?;
    let result: SerializedData = serde_json::from_slice(&decoded)?;

    let json = serde_json::to_string(&result.data)?;
    let mut checksum = Sha3_256::new();
    checksum.update(&json);

    if checksum.finalize().to_vec() != result.checksum {
        return Err(CryptoError::Serialization(
            "Checksum verification failed".to_string(),
        ));
    }

    Ok(result.data)
}

/// Token for authentication and authorization
#[derive(Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: Id,
    pub key: AsymmetricKey,
    pub created_at: DateTime<Local>,
    pub expires_at: DateTime<Local>,
    pub signature: Vec<u8>,
}

impl Token {
    /// Generate new token
    pub fn new(ttl_seconds: i64) -> Self {
        let key = AsymmetricKey::generate();
        let created_at = Local::now();
        let expires_at = created_at
            + chrono::Duration::seconds(ttl_seconds);

        Self {
            id: Id::new(32),
            key,
            created_at,
            expires_at,
            signature: Vec::new(),
        }
    }

    /// Sign the token
    pub fn sign(&mut self) -> CryptoResult<String> {
        let token_data = serde_json::to_vec(&serde_json::json!({
            "id": self.id.encode(),
            "created_at": self.created_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        }))?;

        self.signature = self.key.sign(&token_data).map(|s| BASE64.decode(s).unwrap_or_default()).unwrap_or_default();
        Ok(BASE64.encode(&self.signature))
    }

    /// Validate token
    pub fn validate(&self) -> CryptoResult<bool> {
        if Local::now() > self.expires_at {
            return Ok(false);
        }

        let token_data = serde_json::to_vec(&serde_json::json!({
            "id": self.id.encode(),
            "created_at": self.created_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        }))?;

        let sig_str = BASE64.encode(&self.signature);
        self.key.verify(&sig_str, &token_data)
    }

    /// Serialize to string
    pub fn to_string(&self) -> CryptoResult<String> {
        Ok(BASE64.encode(serde_json::to_vec(self)?))
    }

    /// Deserialize from string
    pub fn from_string(data: &str) -> CryptoResult<Self> {
        let decoded = BASE64.decode(data)?;
        Ok(serde_json::from_slice(&decoded)?)
    }
}

/// Access Control List entry
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AclAction {
    Create = 0,
    Read = 1,
    Update = 2,
    Delete = 3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclEntry {
    pub id: Id,
    pub principal: Id,
    pub resource: Id,
    pub actions: Vec<AclAction>,
}

impl AclEntry {
    /// Create new ACL entry
    pub fn new(principal: Id, resource: Id, actions: Vec<AclAction>) -> Self {
        Self {
            id: Id::new(32),
            principal,
            resource,
            actions,
        }
    }

    /// Check if action is allowed
    pub fn has_action(&self, action: AclAction) -> bool {
        self.actions.contains(&action)
    }
}

/// Blackbook database schema structures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page {
    pub id: Id,
    pub content_hash: Id,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Content {
    pub id: Id,
    pub data: Vec<u8>,
    pub signing_key: AsymmetricKey,
    pub encryption_key: BaseKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub id: Uuid,
    pub version: String,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
    pub properties: HashMap<String, String>,
}

impl Metadata {
    /// Create new metadata
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            version: VERSION.to_string(),
            created_at: Local::now(),
            updated_at: Local::now(),
            properties: HashMap::new(),
        }
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Index for fast lookups
#[derive(Clone, Debug, Default)]
pub struct Index {
    pub id: Id,
    pub index_key: String,
    entries: HashMap<String, Id>,
}

impl Index {
    /// Create new index
    pub fn new(index_key: String) -> Self {
        Self {
            id: Id::new(32),
            index_key,
            entries: HashMap::new(),
        }
    }

    /// Get identifier hash
    pub fn get_identifier(&self, identifier: &str) -> CryptoResult<Id> {
        Id::from_string(identifier, &self.index_key, 32)
    }

    /// Add entry to index
    pub fn add(&mut self, key: String, value: Id) {
        self.entries.insert(key, value);
    }

    /// Lookup entry
    pub fn lookup(&self, key: &str) -> Option<&Id> {
        self.entries.get(key)
    }
}

/// Master key bundle held in memory by a running server.
///
/// `root` is the only source of secret material. Every derived key reaches
/// down through one of the named [`SecondaryKey`]s, each of which carries a
/// unique immutable `domain` — so two call sites with different keys can
/// never produce the same bytes by accident.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlackbookKey {
    pub id: Id,
    /// The on-disk encryption key for this BlackbookKey itself.
    pub symmetric: WrappedKey,
    /// Root secret material. `pub` only because serde needs it; do not call
    /// `seed()` from outside this module — derive through a SecondaryKey.
    pub root: PrimaryKey,
    /// Layer-1 of the secrets envelope (the outer of the two AES-GCM rounds).
    pub secret_layer1: SecondaryKey,
    /// Layer-2 of the secrets envelope.
    pub secret_layer2: SecondaryKey,
    /// KEK that wraps the per-file DEK before it's stored in `wrapped_dek`.
    pub file_dek_kek: SecondaryKey,
    /// HMAC key for hashing resource names into opaque DB lookup ids —
    /// keeps the friendly name out of plaintext in the index column.
    pub index: SecondaryKey,
    /// Keyed-MAC key for the tamper-evident audit hash chain (derived once at
    /// server start into `AppState::audit_hmac_key`; see `auth::audit`).
    pub hmac: SecondaryKey,
    /// KEK that wraps per-client TOTP secrets before they're written to
    /// `blackbook_clients.totp_secret_enc`.
    pub mfa_secret_kek: SecondaryKey,
    pub asymmetric: AsymmetricKey,
    pub exchange_key: BaseKey,
}

impl BlackbookKey {
    /// Generate a fresh master key bundle. All SecondaryKeys are constructed
    /// from the same root with distinct domain strings.
    pub fn generate() -> CryptoResult<Self> {
        let id = Id::new(32);
        let symmetric = WrappedKey::new(WRAPPED_KEY_ITERATIONS)?;
        let root = PrimaryKey::new();
        let secret_layer1 = SecondaryKey::scrypt(root.clone(), "secret/layer1/v1", 32);
        let secret_layer2 = SecondaryKey::scrypt(root.clone(), "secret/layer2/v1", 32);
        let file_dek_kek  = SecondaryKey::scrypt(root.clone(), "file/dek-kek/v1", 32);
        let index         = SecondaryKey::pbkdf2(root.clone(), "index/v1", 32);
        let hmac          = SecondaryKey::pbkdf2(root.clone(), "hmac/v1", 32);
        let mfa_secret_kek = SecondaryKey::scrypt(root.clone(), "mfa/secret-kek/v1", 32);
        let asymmetric    = AsymmetricKey::generate();
        let exchange_key  = BaseKey::new(32);
        Ok(Self {
            id, symmetric, root,
            secret_layer1, secret_layer2, file_dek_kek, index, hmac, mfa_secret_kek,
            asymmetric, exchange_key,
        })
    }

    /// Unwrap the symmetric key to its raw 32 bytes.
    pub fn symmetric_bytes(&self) -> CryptoResult<Vec<u8>> {
        self.symmetric.unwrap()
    }

    pub fn serialize(&self) -> CryptoResult<String> {
        // `json` is the entire key hierarchy in the clear; wipe it after sealing.
        let json = Zeroizing::new(serde_json::to_vec(self)?);
        let key_bytes = Zeroizing::new(self.symmetric_bytes()?);
        let encrypted = encrypt_aes_gcm(&json, &key_bytes)?;
        Ok(BASE64.encode(&encrypted))
    }

    pub fn deserialize(data: &str, symmetric_key: &[u8]) -> CryptoResult<Self> {
        let encrypted = BASE64.decode(data)?;
        let decrypted = Zeroizing::new(decrypt_aes_gcm(&encrypted, symmetric_key)?);
        Ok(serde_json::from_slice(&decrypted)?)
    }

    /// Index-domain HMAC of a resource name. Used to store/lookup resources
    /// by an opaque id rather than the friendly name. Same name + same root
    /// → same id; different roots → different ids.
    pub fn index_id(&self, name: &str) -> CryptoResult<String> {
        let bytes = self.index.handle_with_info(name.as_bytes())?;
        Ok(hex::encode(bytes))
    }
}

/// Password hashing utilities
pub mod crypto {
    use super::*;

    /// Hash a password using Scrypt
    pub fn hash_password(password: &str) -> CryptoResult<String> {
        let mut rng = rand::thread_rng();
        let salt: [u8; 32] = rng.gen();
        
        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        
        let mut output = vec![0u8; 32];
        scrypt::scrypt(password.as_bytes(), &salt, &params, &mut output)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        
        // Combine salt and hash
        let mut result = Vec::new();
        result.extend_from_slice(&salt);
        result.extend_from_slice(&output);
        
        Ok(BASE64.encode(&result))
    }

    /// Verify a password against a hash
    pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
        let decoded = BASE64.decode(hash)?;
        
        if decoded.len() != 64 {
            return Err(CryptoError::Encryption("Invalid hash format".to_string()));
        }
        
        let salt = &decoded[..32];
        let stored_hash = &decoded[32..64];
        
        let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        
        let mut output = vec![0u8; 32];
        scrypt::scrypt(password.as_bytes(), salt, &params, &mut output)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        
        Ok(output.as_slice() == stored_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let id = Id::new(32);
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_asymmetric_sign_verify() {
        let key = AsymmetricKey::generate();
        let data = b"test data";
        let signature = key.sign(data).unwrap();
        assert!(key.verify(&signature, data).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let data = b"secret message";
        let encrypted = encrypt_aes_gcm(data, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_token_sign_validate() {
        let mut token = Token::new(3600);
        let _encoded = token.sign().unwrap();
        assert!(token.validate().unwrap());
    }

    #[test]
    fn test_index_operations() {
        let mut index = Index::new("test".to_string());
        let id = Id::new(32);
        index.add("key1".to_string(), id.clone());
        assert_eq!(index.lookup("key1"), Some(&id));
    }

    #[test]
    fn test_blackbook_key_generation() {
        // `symmetric` is a WrappedKey; unwrapping must give a 32-byte secret.
        let key = BlackbookKey::generate().unwrap();
        let raw = key.symmetric_bytes().unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn test_wrapped_key_roundtrip_few_iters() {
        // Use 2 iterations to keep the test fast; correctness is structural.
        let secret = [7u8; 32];
        let wk = WrappedKey::wrap_bytes(&secret, 2).unwrap();
        // Each iteration inflates by 8 bytes (RFC 3394 IV word).
        assert_eq!(wk.wrapped.len(), 32 + 8 * 2);
        let recovered = wk.unwrap().unwrap();
        assert_eq!(&recovered[..], &secret[..]);
    }

    #[test]
    fn test_wrapped_key_full_iters() {
        // Sanity check the documented default count (30). Slow because of
        // 30 scrypt derivations end-to-end, so keep it as one test.
        let wk = WrappedKey::new(WRAPPED_KEY_ITERATIONS).unwrap();
        let recovered = wk.unwrap().unwrap();
        assert_eq!(recovered.len(), 32);
    }

    #[test]
    fn test_encrypt_envelope_shape() {
        let key = [1u8; 32];
        let plaintext = b"hello";
        let env = encrypt_aes_gcm(plaintext, &key).unwrap();
        // timestamp(5) + salt(32) + ciphertext(>=plaintext.len()+tag)
        assert!(env.len() >= 5 + 32 + plaintext.len() + 16);
        // The 32-byte salt should not be all zero (would indicate RNG failure).
        assert!(env[5..37].iter().any(|b| *b != 0));
    }
}
