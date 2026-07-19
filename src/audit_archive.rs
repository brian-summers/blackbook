//! Audit-log archival: export a contiguous prefix of the tamper-evident audit
//! chain to a **compressed, encrypted, independently-verifiable** file, so the
//! live `blackbook_audit` table stays bounded without losing the integrity
//! guarantee.
//!
//! An archive is `AES-256-GCM( gzip( JSON(AuditArchive) ) )`:
//! - **gzip** — the log is highly compressible (a small action/status vocabulary
//!   plus encrypted blobs).
//! - **AES-256-GCM** under a key derived from the master (`audit-archive-enc/v1`)
//!   — the archive carries plaintext resource/message (the hash chain binds
//!   plaintext), so it must be encrypted at rest, and the GCM tag authenticates
//!   the whole file (tamper of the container is detected on open).
//! - the JSON itself carries each row's `prev_hash`/`row_hash` plus the chain
//!   anchors, so [`verify_archive`] can recompute the keyed-SHA3 chain end to
//!   end with the master MAC key — proving no archived row was altered,
//!   dropped, or reordered, independent of the database.

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::auth::compute_audit_hash;
use crate::blackbook_core::{aead_open, aead_seal};

/// One archived audit row, in the canonical (decrypted) form the hash chain is
/// computed over. `prev_hash`/`row_hash` are lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchivedRow {
    pub id: i64,
    pub ts_micros: i64,
    pub client_id: Option<String>,
    pub action: String,
    pub status: String,
    pub resource: Option<String>,
    pub message: Option<String>,
    pub prev_hash: String,
    pub row_hash: String,
}

/// The decoded archive payload (before gzip+AEAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditArchive {
    pub v: u8,
    pub created_at: String,
    pub count: usize,
    pub first_id: i64,
    pub last_id: i64,
    /// `prev_hash` of the first archived row — the chain value this archive
    /// continues from (`00..00` if it starts at genesis).
    pub genesis_prev: String,
    /// `row_hash` of the last archived row — the chain value the live log
    /// continues from after these rows are pruned (the post-prune anchor).
    pub final_row_hash: String,
    pub rows: Vec<ArchivedRow>,
}

pub const ARCHIVE_VERSION: u8 = 1;
/// Magic prefix so an archive file is self-identifying even before decryption.
pub const ARCHIVE_MAGIC: &[u8] = b"BBKA1\0";

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("not a Blackbook audit archive (bad magic)")]
    BadMagic,
    #[error("decrypt/authenticate failed — wrong key or the archive was tampered")]
    Crypto,
    #[error("gzip: {0}")]
    Gzip(String),
    #[error("json: {0}")]
    Json(String),
}

/// Build an archive blob from rows already verified to be a contiguous chain.
/// Output: `MAGIC ‖ AES-256-GCM(enc_key, gzip(json))`.
pub fn build_archive(enc_key: &[u8], archive: &AuditArchive) -> Result<Vec<u8>, ArchiveError> {
    let json = serde_json::to_vec(archive).map_err(|e| ArchiveError::Json(e.to_string()))?;
    let mut gz = GzEncoder::new(Vec::new(), Compression::best());
    gz.write_all(&json).map_err(|e| ArchiveError::Gzip(e.to_string()))?;
    let compressed = gz.finish().map_err(|e| ArchiveError::Gzip(e.to_string()))?;
    let sealed = aead_seal(&compressed, enc_key).map_err(|_| ArchiveError::Crypto)?;
    let mut out = Vec::with_capacity(ARCHIVE_MAGIC.len() + sealed.len());
    out.extend_from_slice(ARCHIVE_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decrypt + decompress an archive blob back to its payload (does NOT verify the
/// hash chain — call [`verify_archive`] for that).
pub fn open_archive(enc_key: &[u8], blob: &[u8]) -> Result<AuditArchive, ArchiveError> {
    let body = blob.strip_prefix(ARCHIVE_MAGIC).ok_or(ArchiveError::BadMagic)?;
    let compressed = aead_open(body, enc_key).map_err(|_| ArchiveError::Crypto)?;
    let mut gz = GzDecoder::new(&compressed[..]);
    let mut json = Vec::new();
    gz.read_to_end(&mut json).map_err(|e| ArchiveError::Gzip(e.to_string()))?;
    serde_json::from_slice(&json).map_err(|e| ArchiveError::Json(e.to_string()))
}

/// Outcome of verifying an archive's internal hash chain.
#[derive(Debug, Serialize)]
pub struct ArchiveVerification {
    pub ok: bool,
    pub count: usize,
    pub verified: usize,
    pub first_id: i64,
    pub last_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_bad_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Recompute the keyed-SHA3 hash chain across every archived row, starting from
/// the archive's `genesis_prev`, and confirm it lands exactly on `final_row_hash`.
/// Catches any altered, dropped, or reordered row. `mac_key` is the master audit
/// HMAC key (same one the live chain uses).
pub fn verify_archive(mac_key: &[u8], archive: &AuditArchive) -> ArchiveVerification {
    let bail = |verified: usize, id: i64, why: &str| ArchiveVerification {
        ok: false, count: archive.count, verified,
        first_id: archive.first_id, last_id: archive.last_id,
        first_bad_id: Some(id), reason: Some(why.to_string()),
    };
    let mut prev = match hex32(&archive.genesis_prev) {
        Some(p) => p,
        None => return bail(0, archive.first_id, "genesis_prev is not 32-byte hex"),
    };
    for (i, r) in archive.rows.iter().enumerate() {
        if r.prev_hash != hex::encode(prev) {
            return bail(i, r.id, "prev_hash does not chain to the preceding row (drop/reorder?)");
        }
        let computed = compute_audit_hash(
            mac_key, &prev, r.ts_micros,
            r.client_id.as_deref(), &r.action, r.resource.as_deref(), &r.status, r.message.as_deref(),
        );
        if hex::encode(computed) != r.row_hash {
            return bail(i, r.id, "row_hash mismatch (row contents were altered?)");
        }
        prev = computed;
    }
    if hex::encode(prev) != archive.final_row_hash {
        return bail(archive.rows.len(), archive.last_id, "final chain value does not match final_row_hash");
    }
    ArchiveVerification {
        ok: true, count: archive.count, verified: archive.rows.len(),
        first_id: archive.first_id, last_id: archive.last_id,
        first_bad_id: None, reason: None,
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok().map(|_| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a valid 3-row chain the way the live writer does, archive it, and
    // assert the roundtrip + chain verification, then assert tamper detection.
    fn make_chain(mac: &[u8]) -> AuditArchive {
        let mut rows = Vec::new();
        let mut prev = [0u8; 32];
        let specs = [
            (1i64, 100i64, Some("c1"), "store", "ok", Some("api-key"), None),
            (2, 200, Some("c1"), "read", "ok", Some("api-key"), Some("served")),
            (3, 300, None, "audit.verify", "ok", None, Some("verified 2 rows")),
        ];
        for (id, ts, cid, action, status, res, msg) in specs {
            let h = compute_audit_hash(mac, &prev, ts, cid, action, res, status, msg);
            rows.push(ArchivedRow {
                id, ts_micros: ts, client_id: cid.map(String::from), action: action.into(),
                status: status.into(), resource: res.map(String::from), message: msg.map(String::from),
                prev_hash: hex::encode(prev), row_hash: hex::encode(h),
            });
            prev = h;
        }
        AuditArchive {
            v: ARCHIVE_VERSION, created_at: "now".into(), count: rows.len(),
            first_id: 1, last_id: 3, genesis_prev: hex::encode([0u8; 32]),
            final_row_hash: hex::encode(prev), rows,
        }
    }

    #[test]
    fn roundtrip_and_verify_ok() {
        let mac = &[7u8; 32];
        let enc = &[9u8; 32];
        let archive = make_chain(mac);
        let blob = build_archive(enc, &archive).unwrap();
        // Encrypted + compressed; the plaintext resource name must not leak.
        assert!(!blob.windows(7).any(|w| w == b"api-key"), "archive must not contain plaintext");
        let reopened = open_archive(enc, &blob).unwrap();
        let v = verify_archive(mac, &reopened);
        assert!(v.ok, "valid archive must verify: {v:?}");
        assert_eq!(v.verified, 3);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let enc = &[9u8; 32];
        let blob = build_archive(enc, &make_chain(&[1u8; 32])).unwrap();
        assert!(matches!(open_archive(&[3u8; 32], &blob), Err(ArchiveError::Crypto)));
    }

    #[test]
    fn tampered_row_is_caught() {
        let mac = &[7u8; 32];
        let mut archive = make_chain(mac);
        archive.rows[1].resource = Some("rotated-the-content".into()); // alter a row
        let v = verify_archive(mac, &archive);
        assert!(!v.ok && v.first_bad_id == Some(2), "altered row must be flagged: {v:?}");
    }

    #[test]
    fn dropped_row_breaks_chain() {
        let mac = &[7u8; 32];
        let mut archive = make_chain(mac);
        archive.rows.remove(1); // drop the middle row
        let v = verify_archive(mac, &archive);
        assert!(!v.ok, "a dropped row must break the chain");
    }
}
