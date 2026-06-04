//! On-disk persistence of the master [`BlackbookKey`], TLS material, and the
//! first-run admin credentials.
//!
//! Layout under `data_dir` (default `/opt/blackbook/data`):
//!
//! ```text
//!   data_dir/
//!     dek             — 32 bytes of DEK material. Either raw (auto mode)
//!                       or the salt for scrypt-derived DEK (passphrase mode).
//!     dek.mode        — single byte: 0 = auto (raw DEK), 1 = passphrase
//!     master.bbkey    — encrypt_aes_gcm(serde_json::to_vec(BlackbookKey), DEK)
//!     ca.crt / ca.key — root CA used to sign server + client certs
//!     server.crt      — server's TLS certificate (signed by the CA)
//!     server.key      — server's TLS private key
//!     admin-token     — written once on first bootstrap, plain text
//!     admin-cert.pem  — admin client certificate (signed by the CA, CN=admin)
//!     admin-key.pem   — admin client private key
//!     contents/       — per-file encrypted blobs (one file per page)
//! ```

use crate::blackbook_core::{decrypt_aes_gcm, encrypt_aes_gcm, BlackbookKey, CryptoError};
use crate::tls::{self, Ca, CertBundle, TlsError};
use rand::RngCore;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEK_LEN: usize = 32;
const MODE_AUTO: u8 = 0;
const MODE_PASSPHRASE: u8 = 1;

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

    #[error("data dir has DEK file in {existing} mode but env requested {requested} — refuse to overwrite, decide which to keep")]
    ModeMismatch { existing: &'static str, requested: &'static str },

    #[error("BLACKBOOK_MASTER_PASSPHRASE must be at least 16 characters")]
    PassphraseTooShort,

    #[error("corrupt {what}: {detail}")]
    Corrupt { what: &'static str, detail: String },
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

/// Files this module touches under the data dir.
pub struct DataPaths {
    pub dir: PathBuf,
    pub dek: PathBuf,
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

/// Resolve the DEK for this process.
pub fn resolve_dek(paths: &DataPaths, passphrase: Option<&str>) -> Result<[u8; DEK_LEN]> {
    fs::create_dir_all(&paths.dir)?;
    fs::create_dir_all(&paths.contents_dir)?;

    let requested_mode = if passphrase.is_some() { MODE_PASSPHRASE } else { MODE_AUTO };

    if let Some(p) = passphrase {
        if p.len() < 16 { return Err(PersistenceError::PassphraseTooShort); }
    }

    let existing_mode = if paths.mode.exists() {
        let b = fs::read(&paths.mode)?;
        b.first().copied()
    } else { None };

    if let Some(m) = existing_mode {
        if m != requested_mode {
            return Err(PersistenceError::ModeMismatch {
                existing: mode_name(m),
                requested: mode_name(requested_mode),
            });
        }
    }

    let dek_material = if paths.dek.exists() {
        let bytes = fs::read(&paths.dek)?;
        if bytes.len() != DEK_LEN {
            return Err(PersistenceError::Corrupt {
                what: "dek",
                detail: format!("expected {DEK_LEN} bytes, found {}", bytes.len()),
            });
        }
        bytes
    } else {
        let mut bytes = vec![0u8; DEK_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        write_secret(&paths.dek, &bytes)?;
        fs::write(&paths.mode, [requested_mode])?;
        bytes
    };

    let dek = match requested_mode {
        MODE_AUTO => {
            let mut out = [0u8; DEK_LEN];
            out.copy_from_slice(&dek_material);
            out
        }
        MODE_PASSPHRASE => crate::blackbook_core::scrypt_dek(
            passphrase.expect("checked above").as_bytes(),
            &dek_material,
        )?,
        other => unreachable!("requested mode = {other}"),
    };

    Ok(dek)
}

/// Load the master key if present, otherwise generate one and write it.
pub fn load_or_init_master(paths: &DataPaths, dek: &[u8; DEK_LEN]) -> Result<(BlackbookKey, bool)> {
    if paths.master_key.exists() {
        let env = fs::read(&paths.master_key)?;
        let plain = decrypt_aes_gcm(&env, dek)?;
        let key: BlackbookKey = serde_json::from_slice(&plain)?;
        Ok((key, false))
    } else {
        let key = BlackbookKey::generate()?;
        let plain = serde_json::to_vec(&key)?;
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

fn mode_name(b: u8) -> &'static str {
    match b {
        MODE_AUTO => "auto",
        MODE_PASSPHRASE => "passphrase",
        _ => "unknown",
    }
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
