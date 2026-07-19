//! Passphrase-protected credential bundle (Phase 2).
//!
//! A profile on disk used to be a plaintext JSON blob holding the bearer
//! token and the client private key — anyone who could read `~/.bbk` had the
//! full credential. This module wraps that JSON in an Argon2id + AES-256-GCM
//! envelope so the local credentials are themselves protected by a strong
//! passphrase *before* they can be used to authenticate.
//!
//! It also carries a rotation-stable **Client Master Key (CMK)**: 32 random
//! bytes minted at login and sealed inside the same envelope. Phase 3 uses the
//! CMK to encrypt "external" client-side data by default (no separate
//! passphrase needed), and because the CMK is independent of the auth token /
//! cert, rotating those credentials never destroys external data.
//!
//! Unlock UX: a small agent caches the *derived KEK* (never the credentials,
//! never the passphrase) under `~/.bbk/agent/<profile>` with a TTL, so
//! everyday commands don't re-prompt or re-run Argon2id every call. The
//! passphrase can also come from `$BLACKBOOK_PASSPHRASE` for automation.

use argon2::{Argon2, Algorithm, Version, Params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::blackbook_core::{aead_seal, aead_open};

/// Argon2id cost parameters. 64 MiB / t=3 / p=1 — the OWASP-recommended
/// baseline, comfortably stronger than the server's per-message scrypt and
/// appropriate for a human-chosen passphrase guarding local credentials.
const ARGON_M_COST: u32 = 64 * 1024; // KiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

/// Default agent TTL (seconds) when `unlock` doesn't specify one.
pub const DEFAULT_AGENT_TTL_SECS: u64 = 900; // 15 minutes

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    B64(String),
    #[error("kdf: {0}")]
    Kdf(String),
    #[error("decrypt failed — wrong passphrase or corrupt profile")]
    Decrypt,
    #[error("this profile is encrypted; unlock it (`blackbook unlock`) or set $BLACKBOOK_PASSPHRASE")]
    Locked,
    #[error("profile passphrase required (set $BLACKBOOK_PASSPHRASE, or run interactively to be prompted)")]
    NoPassphrase,
}

pub type Result<T> = std::result::Result<T, CredError>;

/// On-disk encrypted profile envelope (format `v2`).
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedProfile {
    /// Format version. 2 = Argon2id + AES-256-GCM.
    pub v: u8,
    /// Algorithm tag, for forward compatibility / diagnostics.
    pub enc: String,
    /// Argon2 salt (base64).
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// `aead_seal(inner_plaintext_json, kek)` (base64).
    pub ct: String,
}

/// Argon2id-derive a 32-byte key from a passphrase + salt using the default
/// cost parameters. Public so the "external" client-side storage path can use
/// the same strong KDF when a user supplies an explicit passphrase. Returns
/// the derived key plus the cost parameters actually used, so callers can
/// record them in a versioned envelope.
pub fn argon2_key(passphrase: &str, salt: &[u8]) -> Result<(Zeroizing<[u8; 32]>, u32, u32, u32)> {
    let k = derive_kek(passphrase, salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
    Ok((k, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST))
}

/// Argon2id-derive with explicit cost parameters (for opening an envelope that
/// recorded its own costs).
pub fn argon2_key_with(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    derive_kek(passphrase, salt, m, t, p)
}

/// Derive the 32-byte KEK from a passphrase + salt with Argon2id. The derived
/// key is returned in a [`Zeroizing`] wrapper so it is wiped from memory once
/// the caller is done sealing/opening with it.
fn derive_kek(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32))
        .map_err(|e| CredError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase.as_bytes(), salt, out.as_mut_slice())
        .map_err(|e| CredError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Encrypt `inner_json` (the serialized Session+CMK) under `passphrase`,
/// producing the on-disk envelope.
pub fn seal_profile(passphrase: &str, inner_json: &[u8]) -> Result<EncryptedProfile> {
    use base64::Engine as _;
    use rand::RngCore;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
    let ct = aead_seal(inner_json, kek.as_slice()).map_err(|e| CredError::Kdf(e.to_string()))?;
    Ok(EncryptedProfile {
        v: 2,
        enc: "argon2id-aes256gcm".into(),
        salt: b64.encode(salt),
        m_cost: ARGON_M_COST,
        t_cost: ARGON_T_COST,
        p_cost: ARGON_P_COST,
        ct: b64.encode(ct),
    })
}

impl EncryptedProfile {
    /// Re-derive the KEK for this envelope from a passphrase (using the
    /// envelope's own recorded cost parameters, so old files keep opening
    /// even if the defaults change). Returned [`Zeroizing`] for safe disposal.
    pub fn derive_kek(&self, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
        use base64::Engine as _;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&self.salt).map_err(|e| CredError::B64(e.to_string()))?;
        derive_kek(passphrase, &salt, self.m_cost, self.t_cost, self.p_cost)
    }

    /// Decrypt the inner JSON given an already-derived KEK (the agent path).
    /// The plaintext is the credential bundle (token + private key + CMK), so
    /// it is returned [`Zeroizing`] and wiped once the caller has parsed it.
    pub fn open_with_kek(&self, kek: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use base64::Engine as _;
        let ct = base64::engine::general_purpose::STANDARD
            .decode(&self.ct).map_err(|e| CredError::B64(e.to_string()))?;
        aead_open(&ct, kek).map(Zeroizing::new).map_err(|_| CredError::Decrypt)
    }

    /// Decrypt the inner JSON directly from a passphrase.
    pub fn open_with_passphrase(&self, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
        let kek = self.derive_kek(passphrase)?;
        self.open_with_kek(kek.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Passphrase sourcing
// ---------------------------------------------------------------------------

/// True when interactive passphrase prompts are forbidden. Set by non-tty
/// front-ends (the web console) so a child process can't grab the controlling
/// terminal and hang — instead the passphrase sites return a clear error.
/// `rpassword` on Windows reads the console device directly (not stdin), so
/// closing the child's stdin is not enough; this flag is the reliable guard.
pub fn prompts_suppressed() -> bool {
    std::env::var("BLACKBOOK_NO_PROMPT").map(|v| !v.is_empty()).unwrap_or(false)
}

/// Resolve a passphrase for sealing/opening: explicit arg → $BLACKBOOK_PASSPHRASE
/// → interactive no-echo prompt (only if attached to a TTY). `confirm` asks
/// twice when prompting (used at login/seal time).
pub fn resolve_passphrase(explicit: Option<&str>, prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(p) = explicit {
        if !p.is_empty() { return Ok(Zeroizing::new(p.to_string())); }
    }
    if let Ok(p) = std::env::var("BLACKBOOK_PASSPHRASE") {
        if !p.is_empty() { return Ok(Zeroizing::new(p)); }
    }
    if prompts_suppressed() { return Err(CredError::NoPassphrase); }
    // Fall back to an interactive prompt. rpassword errors if there's no TTY,
    // which we surface as NoPassphrase so automation gets a clear message.
    let p1 = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|_| CredError::NoPassphrase)?);
    if p1.is_empty() { return Err(CredError::NoPassphrase); }
    if confirm {
        let p2 = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|_| CredError::NoPassphrase)?);
        if *p1 != *p2 {
            return Err(CredError::Kdf("passphrases did not match".into()));
        }
    }
    Ok(p1)
}

// ---------------------------------------------------------------------------
// Unlock agent — caches the derived KEK (not credentials) with a TTL
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct AgentEntry {
    /// Derived KEK (base64). This unlocks the profile but is not itself a
    /// credential — it's useless without the encrypted profile file.
    kek: String,
    /// Unix epoch seconds after which this entry is ignored.
    expires_at: u64,
}

fn agent_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| CredError::Io(
        std::io::Error::new(std::io::ErrorKind::NotFound, "no home directory")))?;
    Ok(home.join(".bbk").join("agent"))
}

fn agent_path(profile: &str) -> Result<PathBuf> {
    Ok(agent_dir()?.join(profile))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Cache a derived KEK for `profile` for `ttl_secs`, `0600`.
pub fn agent_store(profile: &str, kek: &[u8], ttl_secs: u64) -> Result<()> {
    use base64::Engine as _;
    let dir = agent_dir()?;
    std::fs::create_dir_all(&dir)?;
    let entry = AgentEntry {
        kek: base64::engine::general_purpose::STANDARD.encode(kek),
        expires_at: now_secs() + ttl_secs,
    };
    let path = agent_path(profile)?;
    std::fs::write(&path, serde_json::to_vec(&entry)?)?;
    harden_perms(&path);
    Ok(())
}

/// Fetch a still-valid cached KEK for `profile`, if any. Expired entries are
/// securely removed and treated as absent. The KEK is returned [`Zeroizing`]
/// so the caller's copy is wiped after it opens the profile.
pub fn agent_get(profile: &str) -> Option<Zeroizing<[u8; 32]>> {
    use base64::Engine as _;
    let path = agent_path(profile).ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let entry: AgentEntry = serde_json::from_slice(&bytes).ok()?;
    if entry.expires_at <= now_secs() {
        let _ = secure_delete(&path);
        return None;
    }
    let raw = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(&entry.kek).ok()?);
    if raw.len() != 32 { return None; }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Some(out)
}

/// Remove any cached KEK for `profile`, overwriting it first. Returns whether
/// something was removed.
pub fn agent_clear(profile: &str) -> bool {
    match agent_path(profile) {
        Ok(p) if p.exists() => secure_delete(&p).is_ok(),
        _ => false,
    }
}

/// Best-effort secure file deletion: overwrite the file's bytes with random
/// data, flush to disk, then unlink. This lowers the chance that a secret
/// (a cached KEK, a resident stash, a shredded plaintext) survives in freed
/// blocks after a plain unlink. It is *best-effort*: copy-on-write, log-
/// structured, and wear-levelled (SSD) filesystems may still retain the old
/// blocks, so it complements — does not replace — full-disk encryption.
pub fn secure_delete(path: &Path) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    use rand::RngCore;
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len();
        if len > 0 {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let mut remaining = len;
                let mut buf = [0u8; 4096];
                let _ = f.seek(SeekFrom::Start(0));
                while remaining > 0 {
                    rand::thread_rng().fill_bytes(&mut buf);
                    let n = remaining.min(buf.len() as u64) as usize;
                    if f.write_all(&buf[..n]).is_err() { break; }
                    remaining -= n as u64;
                }
                let _ = f.flush();
                let _ = f.sync_all();
            }
        }
    }
    std::fs::remove_file(path)
}

fn harden_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_via_passphrase_and_kek() {
        // The credential bundle round-trips through the (now Zeroizing) seal/
        // open paths — both the passphrase path and the cached-KEK agent path.
        let secret = br#"{"token":"bbk_abc","key_pem":"-----KEY-----","cmk":"zz"}"#;
        let env = seal_profile("correct horse battery", secret).unwrap();

        let opened = env.open_with_passphrase("correct horse battery").unwrap();
        assert_eq!(opened.as_slice(), secret.as_slice());

        let kek = env.derive_kek("correct horse battery").unwrap();
        let opened2 = env.open_with_kek(kek.as_slice()).unwrap();
        assert_eq!(opened2.as_slice(), secret.as_slice());
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let env = seal_profile("right", b"payload").unwrap();
        assert!(matches!(env.open_with_passphrase("wrong"), Err(CredError::Decrypt)));
    }

    #[test]
    fn secure_delete_removes_the_file() {
        let path = std::env::temp_dir().join(format!("bbk-sd-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::write(&path, b"sensitive-bytes-that-should-be-scrubbed").unwrap();
        assert!(path.exists());
        secure_delete(&path).unwrap();
        assert!(!path.exists(), "secure_delete must remove the file");
    }
}
