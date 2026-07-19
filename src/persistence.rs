//! On-disk persistence of the master [`BlackbookKey`], TLS material, and the
//! first-run admin credentials.
//!
//! Layout under `data_dir` (default `/opt/blackbook/data`):
//!
//! ```text
//!   data_dir/
//!     dek.meta        — JSON describing how the DEK is protected. NEVER the
//!                       DEK itself: only a salt (passphrase provider) or the
//!                       DEK *wrapped* under an external keyfile (keyfile
//!                       provider). The plaintext DEK is derived/unwrapped in
//!                       memory at boot and never touches disk.
//!     master.bbkey    — encrypt_aes_gcm(serde_json::to_vec(BlackbookKey), DEK)
//!     ca.crt / ca.key — root CA used to sign server + client certs
//!     server.crt      — server's TLS certificate (signed by the CA)
//!     server.key      — server's TLS private key
//!     admin-token     — first-run admin bearer token (plain; secure or delete)
//!     admin-cert.pem  — admin client certificate (signed by the CA, CN=admin)
//!     admin-key.pem   — admin client private key
//!     admin-bundle.json — the four above bundled for `blackbook login`
//!     contents/       — per-file encrypted blobs (one file per page)
//! ```
//!
//! # Master DEK is never stored in the clear
//!
//! The outermost key (the DEK that wraps `master.bbkey`) is produced at every
//! boot by one of two [`DekProvider`]s and **never persists on disk as raw
//! key material**:
//!
//! - **Passphrase** (`BLACKBOOK_MASTER_PASSPHRASE` / `…_FILE`) — a user-supplied
//!   secret. `DEK = Argon2id(passphrase, salt)`; only the (non-secret) salt is
//!   written. Disk alone is useless without the passphrase.
//! - **Keyfile** (`BLACKBOOK_MASTER_KEYFILE`) — key material stored locally but
//!   *wrapped*. A random DEK is generated once and stored only as
//!   `AES-256-GCM(KEK, DEK)`, where `KEK = SHA3-256(keyfile)`. The keyfile must
//!   live **outside** the data volume (e.g. a Docker secret on a tmpfs mount),
//!   so a thief who copies only the data volume gets ciphertext they can't open.
//!
//! There is intentionally **no "auto" mode** that writes a raw DEK. If neither
//! provider is configured the server refuses to start ([`PersistenceError::NoProvider`]).
//! Legacy volumes that still hold a raw `dek`/`dek.mode` are transparently
//! migrated to the keyfile/passphrase scheme on first boot (see `migrate_legacy_dek`).

use crate::blackbook_core::{
    aead_open, aead_seal, decrypt_aes_gcm, encrypt_aes_gcm, BlackbookKey, CryptoError,
};
use crate::tls::{self, Ca, CertBundle, TlsError};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEK_LEN: usize = 32;
/// Legacy `dek.mode` byte values, recognized only for one-time migration.
const MODE_AUTO: u8 = 0;
const MODE_PASSPHRASE: u8 = 1;
/// Minimum length for a user-supplied master passphrase.
const MIN_PASSPHRASE_LEN: usize = 16;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    #[error("tls: {0}")]
    Tls(#[from] TlsError),

    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),

    #[error("no master-key provider configured. The DEK is never stored in the clear, so the \
             server cannot start without one of:\n  \
             • BLACKBOOK_MASTER_PASSPHRASE (or BLACKBOOK_MASTER_PASSPHRASE_FILE) — a user secret\n  \
             • BLACKBOOK_MASTER_KEYFILE — a path to a keyfile (kept off the data volume) that \
             unwraps a locally-stored wrapped DEK")]
    NoProvider,

    #[error("this data volume was initialized with the '{existing}' key provider, but '{requested}' \
             is configured now — they derive different DEKs and the master key won't decrypt. \
             Restore the original provider, or re-initialize the volume.")]
    ProviderMismatch { existing: String, requested: String },

    #[error("master keyfile {path}: {detail}")]
    Keyfile { path: String, detail: String },

    #[error("BLACKBOOK_MASTER_PASSPHRASE must be at least 16 characters")]
    PassphraseTooShort,

    #[error("could not migrate the legacy on-disk DEK: {0}")]
    Migration(String),

    #[error("corrupt {what}: {detail}")]
    Corrupt { what: &'static str, detail: String },
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

/// Files this module touches under the data dir.
pub struct DataPaths {
    pub dir: PathBuf,
    /// Self-describing DEK metadata (salt or wrapped-DEK) — never the raw DEK.
    pub dek_meta: PathBuf,
    /// Legacy raw-DEK file, read only to migrate away from it.
    pub dek: PathBuf,
    /// Legacy mode byte, read only to migrate away from it.
    pub mode: PathBuf,
    pub master_key: PathBuf,
    pub admin_token: PathBuf,
    pub admin_cert: PathBuf,
    pub admin_key: PathBuf,
    pub admin_bundle: PathBuf,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub contents_dir: PathBuf,
}

impl DataPaths {
    pub fn under(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            dek_meta: dir.join("dek.meta"),
            dek: dir.join("dek"),
            mode: dir.join("dek.mode"),
            master_key: dir.join("master.bbkey"),
            admin_token: dir.join("admin-token"),
            admin_cert: dir.join("admin-cert.pem"),
            admin_key: dir.join("admin-key.pem"),
            admin_bundle: dir.join("admin-bundle.json"),
            ca_cert: dir.join("ca.crt"),
            ca_key: dir.join("ca.key"),
            server_cert: dir.join("server.crt"),
            server_key: dir.join("server.key"),
            contents_dir: dir.join("contents"),
            dir,
        }
    }
}

/// How the master DEK is protected. Neither variant ever causes the plaintext
/// DEK to be written to disk.
pub enum DekProvider {
    /// User-supplied secret. `DEK = Argon2id(passphrase, salt)`; only the salt
    /// persists. The passphrase is held [`Zeroizing`] and wiped after use.
    Passphrase(Zeroizing<String>),
    /// Locally-stored *wrapped* key material: a random DEK sealed under a KEK
    /// derived from the keyfile at the given path. Only the wrapped DEK
    /// persists; the keyfile must live off the data volume.
    Keyfile(PathBuf),
}

impl DekProvider {
    /// Resolve the configured provider from the environment, **failing closed**:
    /// if nothing is configured we return [`PersistenceError::NoProvider`] rather
    /// than inventing a raw on-disk DEK. Precedence: a passphrase (direct env or
    /// a `…_FILE` secret) wins over a keyfile.
    pub fn from_env() -> Result<DekProvider> {
        let passphrase = std::env::var("BLACKBOOK_MASTER_PASSPHRASE").ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("BLACKBOOK_MASTER_PASSPHRASE_FILE").ok()
                .and_then(|p| fs::read_to_string(p).ok())
                // Secret files commonly carry a trailing newline; trim it.
                .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
                .filter(|s| !s.is_empty()));
        if let Some(p) = passphrase {
            if p.len() < MIN_PASSPHRASE_LEN { return Err(PersistenceError::PassphraseTooShort); }
            return Ok(DekProvider::Passphrase(Zeroizing::new(p)));
        }
        if let Ok(kf) = std::env::var("BLACKBOOK_MASTER_KEYFILE") {
            if !kf.is_empty() { return Ok(DekProvider::Keyfile(PathBuf::from(kf))); }
        }
        Err(PersistenceError::NoProvider)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            DekProvider::Passphrase(_) => "passphrase",
            DekProvider::Keyfile(_) => "keyfile",
        }
    }
}

/// On-disk DEK metadata (`dek.meta`). Self-describing and versioned. Holds a
/// salt (passphrase provider) or a wrapped DEK (keyfile provider) — never the
/// raw DEK.
#[derive(Serialize, Deserialize)]
struct DekMeta {
    v: u8,
    provider: String,
    // Passphrase provider:
    #[serde(default, skip_serializing_if = "Option::is_none")] salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] m_cost: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")] t_cost: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")] p_cost: Option<u32>,
    // Keyfile provider:
    #[serde(default, skip_serializing_if = "Option::is_none")] wrapped_dek: Option<String>,
}

/// Derive the 32-byte KEK that wraps the DEK from a keyfile's bytes. The keyfile
/// content can be any length (a random secret, a passphrase, etc.); we hash it
/// with a domain tag so the KEK is always exactly 32 bytes.
fn keyfile_kek(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|e| PersistenceError::Keyfile {
        path: path.display().to_string(),
        detail: format!("cannot read keyfile: {e} (it must exist and be readable, and should \
                         live OUTSIDE the data volume — e.g. a Docker secret)"),
    })?);
    if bytes.is_empty() {
        return Err(PersistenceError::Keyfile {
            path: path.display().to_string(), detail: "keyfile is empty".into(),
        });
    }
    let mut h = Sha3_256::new();
    h.update(b"blackbook-dek-keyfile/v1\0");
    h.update(&bytes);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// Generate a *fresh* DEK for `provider` and the metadata that lets us recover
/// it next boot. Pure — performs no disk writes.
fn init_dek(provider: &DekProvider) -> Result<(Zeroizing<[u8; DEK_LEN]>, DekMeta)> {
    match provider {
        DekProvider::Passphrase(pass) => {
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            // DEK := Argon2id(passphrase, salt) — derived, never random-stored.
            let (dek, m, t, p) = crate::credstore::argon2_key(pass, &salt)
                .map_err(|e| PersistenceError::Migration(format!("argon2: {e}")))?;
            let meta = DekMeta {
                v: 1, provider: "passphrase".into(),
                salt: Some(b64().encode(salt)),
                m_cost: Some(m), t_cost: Some(t), p_cost: Some(p),
                wrapped_dek: None,
            };
            Ok((dek, meta))
        }
        DekProvider::Keyfile(path) => {
            let kek = keyfile_kek(path)?;
            let mut dek = Zeroizing::new([0u8; DEK_LEN]);
            rand::thread_rng().fill_bytes(dek.as_mut_slice());
            let wrapped = aead_seal(dek.as_slice(), kek.as_slice())?;
            let meta = DekMeta {
                v: 1, provider: "keyfile".into(),
                salt: None, m_cost: None, t_cost: None, p_cost: None,
                wrapped_dek: Some(b64().encode(&wrapped)),
            };
            Ok((dek, meta))
        }
    }
}

/// Recover the DEK described by an existing `dek.meta` using `provider`.
fn reconstruct_dek(provider: &DekProvider, meta: &DekMeta) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    if meta.provider != provider.kind() {
        return Err(PersistenceError::ProviderMismatch {
            existing: meta.provider.clone(),
            requested: provider.kind().to_string(),
        });
    }
    match provider {
        DekProvider::Passphrase(pass) => {
            let salt = b64().decode(meta.salt.as_deref().ok_or_else(|| PersistenceError::Corrupt {
                what: "dek.meta", detail: "passphrase provider missing salt".into() })?)
                .map_err(|e| PersistenceError::Corrupt { what: "dek.meta", detail: format!("salt b64: {e}") })?;
            let (m, t, p) = (meta.m_cost.unwrap_or(0), meta.t_cost.unwrap_or(0), meta.p_cost.unwrap_or(0));
            crate::credstore::argon2_key_with(pass, &salt, m, t, p)
                .map_err(|e| PersistenceError::Migration(format!("argon2: {e}")))
        }
        DekProvider::Keyfile(path) => {
            let kek = keyfile_kek(path)?;
            let wrapped = b64().decode(meta.wrapped_dek.as_deref().ok_or_else(|| PersistenceError::Corrupt {
                what: "dek.meta", detail: "keyfile provider missing wrapped_dek".into() })?)
                .map_err(|e| PersistenceError::Corrupt { what: "dek.meta", detail: format!("wrapped_dek b64: {e}") })?;
            let plain = aead_open(&wrapped, kek.as_slice())
                .map_err(|_| PersistenceError::Keyfile {
                    path: path.display().to_string(),
                    detail: "wrong keyfile — wrapped DEK did not unwrap".into() })?;
            if plain.len() != DEK_LEN {
                return Err(PersistenceError::Corrupt { what: "wrapped_dek", detail: "not 32 bytes".into() });
            }
            let mut dek = Zeroizing::new([0u8; DEK_LEN]);
            dek.copy_from_slice(&plain);
            Ok(dek)
        }
    }
}

/// Resolve the DEK for this process. The plaintext DEK is derived/unwrapped in
/// memory and returned [`Zeroizing`]; it is never written to disk.
///
/// Order of operations:
///   1. If a legacy raw `dek`/`dek.mode` exists (and no `dek.meta`), migrate it:
///      re-encrypt the master key under a new provider-backed DEK and securely
///      delete the raw material.
///   2. If `dek.meta` exists, reconstruct the DEK from it (provider must match).
///   3. Otherwise this is a fresh volume: generate the DEK + metadata and write
///      only the metadata.
pub fn resolve_dek(paths: &DataPaths, provider: &DekProvider) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    fs::create_dir_all(&paths.dir)?;
    fs::create_dir_all(&paths.contents_dir)?;

    if !paths.dek_meta.exists() && (paths.dek.exists() || paths.mode.exists()) {
        migrate_legacy_dek(paths, provider)?;
    }

    if paths.dek_meta.exists() {
        let meta: DekMeta = serde_json::from_slice(&fs::read(&paths.dek_meta)?)?;
        return reconstruct_dek(provider, &meta);
    }

    // Fresh volume: mint the DEK and persist only its (non-secret) metadata.
    let (dek, meta) = init_dek(provider)?;
    write_secret(&paths.dek_meta, &serde_json::to_vec_pretty(&meta)?)?;
    log::info!("initialized master DEK with the '{}' provider (no raw key on disk)", provider.kind());
    Ok(dek)
}

/// Rotate the master **DEK** without changing the master key itself: load the
/// key with the current DEK, mint a fresh provider DEK, and re-encrypt the same
/// key under it (atomically). Use after a suspected keyfile/passphrase exposure,
/// or to re-key under a freshly generated keyfile.
///
/// Safe to run while the server is up — it only changes the on-disk *wrapping*;
/// the running server's in-RAM key is unaffected and still matches the rewritten
/// `master.bbkey`. (To pick up a *new* keyfile, generate it, run this, restart.)
pub fn rekey_master_dek(paths: &DataPaths, provider: &DekProvider) -> Result<()> {
    if !paths.master_key.exists() {
        return Err(PersistenceError::Corrupt {
            what: "master.bbkey",
            detail: "no master key to re-key — start the server once first".into(),
        });
    }
    // Reconstruct the current DEK and decrypt the master key with it.
    let old_dek = resolve_dek(paths, provider)?;
    let env = fs::read(&paths.master_key)?;
    let plain = Zeroizing::new(decrypt_aes_gcm(&env, old_dek.as_slice()).map_err(|_|
        PersistenceError::Migration(
            "the current DEK did not decrypt master.bbkey — wrong keyfile/passphrase?".into()))?);
    // Mint a fresh DEK + metadata and re-encrypt the *same* master under it.
    let (new_dek, meta) = init_dek(provider)?;
    let new_env = encrypt_aes_gcm(&plain, new_dek.as_slice())?;
    let tmp = paths.master_key.with_extension("bbkey.rekey");
    write_secret(&tmp, &new_env)?;
    fs::rename(&tmp, &paths.master_key)?;        // atomic swap of the wrapped key
    write_secret(&paths.dek_meta, &serde_json::to_vec_pretty(&meta)?)?;
    Ok(())
}

/// One-time migration from the old raw-DEK / scrypt-passphrase layout to the
/// provider scheme. Reconstructs the *old* DEK exactly as the legacy resolver
/// did, re-encrypts `master.bbkey` under a fresh provider DEK (atomically), then
/// securely deletes the raw `dek`/`dek.mode`. After this the on-disk DEK is gone.
fn migrate_legacy_dek(paths: &DataPaths, provider: &DekProvider) -> Result<()> {
    let mode = fs::read(&paths.mode).ok().and_then(|b| b.first().copied()).unwrap_or(MODE_AUTO);
    let material = Zeroizing::new(fs::read(&paths.dek).map_err(|e|
        PersistenceError::Migration(format!("reading legacy dek: {e}")))?);

    // Recover the legacy DEK.
    let mut old_dek = Zeroizing::new([0u8; DEK_LEN]);
    match mode {
        MODE_AUTO => {
            if material.len() != DEK_LEN {
                return Err(PersistenceError::Migration(format!(
                    "legacy raw dek is {} bytes, expected {DEK_LEN}", material.len())));
            }
            old_dek.copy_from_slice(&material);
        }
        MODE_PASSPHRASE => {
            // The legacy DEK was scrypt(passphrase, salt); we need that same
            // passphrase, which only the passphrase provider carries.
            let DekProvider::Passphrase(pass) = provider else {
                return Err(PersistenceError::Migration(
                    "this volume used a master passphrase; set BLACKBOOK_MASTER_PASSPHRASE \
                     to the SAME passphrase to migrate it".into()));
            };
            let d = crate::blackbook_core::scrypt_dek(pass.as_bytes(), &material)
                .map_err(|e| PersistenceError::Migration(format!("legacy scrypt: {e}")))?;
            old_dek.copy_from_slice(d.as_slice());
        }
        other => return Err(PersistenceError::Migration(format!("unknown legacy mode byte {other}"))),
    }

    // Re-encrypt the master key under a fresh provider-backed DEK.
    let (new_dek, meta) = init_dek(provider)?;
    if paths.master_key.exists() {
        let env = fs::read(&paths.master_key)?;
        let plain = Zeroizing::new(decrypt_aes_gcm(&env, old_dek.as_slice()).map_err(|_|
            PersistenceError::Migration(
                "could not decrypt master.bbkey with the legacy DEK (wrong passphrase, or the \
                 raw dek was already removed)".into()))?);
        let new_env = encrypt_aes_gcm(&plain, new_dek.as_slice())?;
        // Atomic swap so a crash mid-migration can't corrupt the master key.
        let tmp = paths.master_key.with_extension("bbkey.migrating");
        write_secret(&tmp, &new_env)?;
        fs::rename(&tmp, &paths.master_key)?;
    }
    write_secret(&paths.dek_meta, &serde_json::to_vec_pretty(&meta)?)?;
    // Scrub the raw key material from disk.
    let _ = crate::credstore::secure_delete(&paths.dek);
    let _ = crate::credstore::secure_delete(&paths.mode);
    log::warn!("migrated legacy on-disk DEK → '{}' provider; the raw DEK has been securely erased",
               provider.kind());
    Ok(())
}

/// Load the master key if present, otherwise generate one and write it.
/// `dek` is taken as a slice so a [`Zeroizing`] DEK passes straight through.
pub fn load_or_init_master(paths: &DataPaths, dek: &[u8; DEK_LEN]) -> Result<(BlackbookKey, bool)> {
    if paths.master_key.exists() {
        let env = fs::read(&paths.master_key)?;
        // The decrypted bytes are the entire key hierarchy in the clear — wipe
        // them as soon as they've been parsed into the structured key.
        let plain = Zeroizing::new(decrypt_aes_gcm(&env, dek)?);
        let key: BlackbookKey = serde_json::from_slice(&plain)?;
        Ok((key, false))
    } else {
        let key = BlackbookKey::generate()?;
        let plain = Zeroizing::new(serde_json::to_vec(&key)?);
        let env = encrypt_aes_gcm(&plain, dek)?;
        write_secret(&paths.master_key, &env)?;
        Ok((key, true))
    }
}

/// Load the CA if present, otherwise generate a new one and write the cert
/// + key to disk.
pub fn load_or_init_ca(paths: &DataPaths) -> Result<(Ca, bool)> {
    if paths.ca_cert.exists() && paths.ca_key.exists() {
        let cert_pem = fs::read_to_string(&paths.ca_cert)?;
        let key_pem = fs::read_to_string(&paths.ca_key)?;
        let ca = Ca::from_pem(&cert_pem, &key_pem)?;
        Ok((ca, false))
    } else {
        let ca = Ca::generate()?;
        write_secret(&paths.ca_key, ca.key_pem.as_bytes())?;
        // CA cert is public — it's the trust anchor distributed to clients.
        fs::write(&paths.ca_cert, ca.cert_pem.as_bytes())?;
        Ok((ca, true))
    }
}

/// Load the server cert if present, otherwise issue one from the CA.
pub fn load_or_init_server_cert(paths: &DataPaths, ca: &Ca, sans: &[String]) -> Result<bool> {
    if paths.server_cert.exists() && paths.server_key.exists() {
        return Ok(false);
    }
    let bundle = tls::issue_server_cert(ca, sans)?;
    fs::write(&paths.server_cert, bundle.cert_pem.as_bytes())?;
    write_secret(&paths.server_key, bundle.key_pem.as_bytes())?;
    Ok(true)
}

/// Write the admin credential set to the data dir. Emits both the individual
/// files (`admin-token`, `admin-cert.pem`, `admin-key.pem`) for familiarity
/// and a single `admin-bundle.json` in the same shape `client create`
/// produces, so the operator can `blackbook login admin-bundle.json` directly.
///
/// `server_url` is the URL the operator's CLI will connect to — the server
/// can't introspect its own published address, so this is a best-effort
/// default (overridable at login with `-s`).
pub fn write_admin_bundle(
    paths: &DataPaths,
    token: &str,
    bundle: &CertBundle,
    ca_pem: &str,
    server_url: &str,
) -> Result<()> {
    write_secret(&paths.admin_token, token.as_bytes())?;
    fs::write(&paths.admin_cert, bundle.cert_pem.as_bytes())?;
    write_secret(&paths.admin_key, bundle.key_pem.as_bytes())?;

    let json = serde_json::json!({
        "server": server_url,
        "token": token,
        "cert_pem": bundle.cert_pem,
        "key_pem": bundle.key_pem,
        "ca_pem": ca_pem,
        "name": "admin",
        "role": "admin",
    });
    let pretty = serde_json::to_string_pretty(&json)?;
    write_secret(&paths.admin_bundle, pretty.as_bytes())?;
    Ok(())
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("bbk-persist-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn keyfile_in(dir: &Path) -> PathBuf {
        let kf = dir.join("keyfile.bin");
        fs::write(&kf, b"super-random-keyfile-bytes-0123456789abcdef").unwrap();
        kf
    }

    #[test]
    fn keyfile_provider_roundtrips_and_writes_no_raw_dek() {
        let dir = unique_dir("kf");
        let paths = DataPaths::under(&dir);
        let provider = DekProvider::Keyfile(keyfile_in(&dir));

        // First boot: mint DEK + master key.
        let dek1 = resolve_dek(&paths, &provider).unwrap();
        let (_k, new) = load_or_init_master(&paths, &dek1).unwrap();
        assert!(new);
        // The plaintext DEK is never on disk — only wrapped metadata.
        assert!(!paths.dek.exists(), "raw dek file must not be written");
        assert!(paths.dek_meta.exists());
        let meta_bytes = fs::read(&paths.dek_meta).unwrap();
        assert!(!meta_bytes.windows(DEK_LEN).any(|w| w == dek1.as_slice()),
            "plaintext DEK must not appear anywhere in dek.meta");

        // Second boot: same keyfile reconstructs the same DEK and opens master.
        let dek2 = resolve_dek(&paths, &provider).unwrap();
        assert_eq!(dek1.as_slice(), dek2.as_slice());
        let (_k2, new2) = load_or_init_master(&paths, &dek2).unwrap();
        assert!(!new2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_keyfile_cannot_unwrap() {
        let dir = unique_dir("kf-wrong");
        let paths = DataPaths::under(&dir);
        let dek = resolve_dek(&paths, &DekProvider::Keyfile(keyfile_in(&dir))).unwrap();
        let _ = load_or_init_master(&paths, &dek).unwrap();
        let other = dir.join("other.bin");
        fs::write(&other, b"a-totally-different-keyfile").unwrap();
        assert!(matches!(resolve_dek(&paths, &DekProvider::Keyfile(other)),
            Err(PersistenceError::Keyfile { .. })));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provider_mismatch_is_rejected() {
        let dir = unique_dir("mismatch");
        let paths = DataPaths::under(&dir);
        let _ = resolve_dek(&paths, &DekProvider::Keyfile(keyfile_in(&dir))).unwrap();
        // Initialized as keyfile → opening with a passphrase provider must error
        // (checked before any KDF work, so this is fast).
        let p = DekProvider::Passphrase(Zeroizing::new("a-sixteen-char-pp!".to_string()));
        assert!(matches!(resolve_dek(&paths, &p), Err(PersistenceError::ProviderMismatch { .. })));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_raw_dek_is_migrated_and_erased() {
        let dir = unique_dir("legacy");
        let paths = DataPaths::under(&dir);
        fs::create_dir_all(&paths.contents_dir).unwrap();
        // Simulate a legacy auto-mode volume: raw DEK + mode 0 + master sealed under it.
        let mut raw = [0u8; DEK_LEN];
        rand::thread_rng().fill_bytes(&mut raw);
        fs::write(&paths.dek, raw).unwrap();
        fs::write(&paths.mode, [MODE_AUTO]).unwrap();
        let (orig_key, _) = load_or_init_master(&paths, &raw).unwrap();
        let orig_id = orig_key.id.to_hex();

        // Boot with a keyfile provider → migrate.
        let dek = resolve_dek(&paths, &DekProvider::Keyfile(keyfile_in(&dir))).unwrap();
        assert!(!paths.dek.exists(), "raw dek must be removed after migration");
        assert!(!paths.mode.exists());
        assert!(paths.dek_meta.exists());
        // Master key still decrypts under the new DEK and is the SAME key.
        let (key2, new) = load_or_init_master(&paths, &dek).unwrap();
        assert!(!new);
        assert_eq!(key2.id.to_hex(), orig_id, "migration must preserve the master key");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_changes_wrapping_but_preserves_master_key() {
        let dir = unique_dir("rekey");
        let paths = DataPaths::under(&dir);
        let provider = DekProvider::Keyfile(keyfile_in(&dir));

        let dek1 = resolve_dek(&paths, &provider).unwrap();
        let (orig, _) = load_or_init_master(&paths, &dek1).unwrap();
        let orig_id = orig.id.to_hex();
        let wrapped_before = fs::read(&paths.dek_meta).unwrap();
        let master_before = fs::read(&paths.master_key).unwrap();

        rekey_master_dek(&paths, &provider).unwrap();

        // The on-disk wrapping changed (fresh DEK ⇒ new wrapped_dek + new master ct)...
        assert_ne!(wrapped_before, fs::read(&paths.dek_meta).unwrap(), "dek.meta must change");
        assert_ne!(master_before, fs::read(&paths.master_key).unwrap(), "master.bbkey must re-encrypt");
        // ...but the master key itself is intact and still loads under the new DEK.
        let dek2 = resolve_dek(&paths, &provider).unwrap();
        let (after, _) = load_or_init_master(&paths, &dek2).unwrap();
        assert_eq!(after.id.to_hex(), orig_id, "the master key must be unchanged");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passphrase_provider_roundtrips() {
        let dir = unique_dir("pp");
        let paths = DataPaths::under(&dir);
        let pp = || DekProvider::Passphrase(Zeroizing::new("correct-horse-battery-staple".to_string()));
        let dek1 = resolve_dek(&paths, &pp()).unwrap();
        assert!(!paths.dek.exists());
        assert!(paths.dek_meta.exists());
        let dek2 = resolve_dek(&paths, &pp()).unwrap();
        assert_eq!(dek1.as_slice(), dek2.as_slice(), "same passphrase must derive the same DEK");
        let _ = fs::remove_dir_all(&dir);
    }
}
