//! TLS material: CA, server cert, per-client certs.
//!
//! Blackbook auto-provisions its own internal CA on first boot and signs a
//! server cert from it. When a client is provisioned (`client create`), the
//! server issues that client a leaf certificate whose CN is the client name;
//! the CN is later read out of the TLS handshake to identify the caller.
//!
//! We use rcgen (which uses ring) so we don't need OpenSSL just to mint a
//! cert — that keeps the build self-contained. The certs are still consumed
//! by the openssl-backed actix-tls acceptor at serve time.
//!
//! All keys/certs are ECDSA P-256 / SHA-256 — well-supported, ~2x faster
//! than RSA, smaller than RSA, mature in every TLS 1.3 stack.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SanType,
};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use time::OffsetDateTime;

const CA_LIFETIME_DAYS: i64 = 365 * 10;
const SERVER_LIFETIME_DAYS: i64 = 365;
/// Default TTL for a client certificate when the caller doesn't specify one.
pub const DEFAULT_CLIENT_TTL_DAYS: i64 = 30;
/// Default TTL for admin certificates — long-lived to avoid lockout.
pub const ADMIN_CLIENT_TTL_DAYS: i64 = 365;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::RcgenError),
    #[error("invalid PEM: {0}")]
    Pem(String),
}

pub type Result<T> = std::result::Result<T, TlsError>;

/// A CA usable for issuing new leaf certs.
pub struct Ca {
    /// The CA's signing Certificate object — used as the "signer" argument to
    /// rcgen's `serialize_pem_with_signer`.
    pub cert: Certificate,
    /// PEM that goes to clients so they can verify the server's cert chain.
    pub cert_pem: String,
    /// PEM of the CA's private key. Stays on the server.
    pub key_pem: String,
}

impl Ca {
    /// Generate a brand-new self-signed CA.
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::new(vec!["Blackbook Root CA".to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Blackbook Root CA");
        dn.push(DnType::OrganizationName, "Blackbook");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let (nb, na) = lifetime(CA_LIFETIME_DAYS);
        params.not_before = nb;
        params.not_after = na;

        let cert = Certificate::from_params(params)?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();
        Ok(Self { cert, cert_pem, key_pem })
    }

    /// Reconstruct an in-memory CA from saved PEMs so we can keep issuing
    /// child certs after a restart.
    ///
    /// rcgen 0.12 doesn't have a `from_ca_cert_pem` constructor, so we
    /// rebuild `CertificateParams` with the same DN we always use and load
    /// the saved key pair. The resulting `Certificate` is only used as a
    /// signer (`serialize_pem_with_signer`); we never serialize the CA's
    /// own PEM again — that stays as the bytes from disk so clients keep
    /// validating against the same trust anchor.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem)?;
        let mut params = CertificateParams::new(vec!["Blackbook Root CA".to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Blackbook Root CA");
        dn.push(DnType::OrganizationName, "Blackbook");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let (nb, na) = lifetime(CA_LIFETIME_DAYS);
        params.not_before = nb;
        params.not_after = na;
        params.key_pair = Some(key_pair);

        let cert = Certificate::from_params(params)?;
        Ok(Self {
            cert,
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
        })
    }
}

/// PEM-encoded cert + key, returned to callers (server cert, client cert).
#[derive(Debug, Clone)]
pub struct CertBundle {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA3-256 hex of the DER-encoded certificate. Used as a tamper-evident
    /// fingerprint in the database.
    pub fingerprint: String,
}

/// Issue a server certificate signed by the CA, with the given SANs (host
/// names / IPs that clients will try to connect to).
pub fn issue_server_cert(ca: &Ca, sans: &[String]) -> Result<CertBundle> {
    let san_entries: Vec<SanType> = sans
        .iter()
        .map(|s| {
            if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                SanType::IpAddress(ip)
            } else {
                SanType::DnsName(s.clone())
            }
        })
        .collect();
    let mut params = CertificateParams::new(sans.to_vec());
    params.subject_alt_names = san_entries;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, sans.first().cloned().unwrap_or_else(|| "blackbook-server".into()));
    dn.push(DnType::OrganizationName, "Blackbook");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let (nb, na) = lifetime(SERVER_LIFETIME_DAYS);
    params.not_before = nb;
    params.not_after = na;

    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem_with_signer(&ca.cert)?;
    let key_pem = cert.serialize_private_key_pem();
    let fingerprint = fingerprint_pem(&cert_pem)?;
    Ok(CertBundle { cert_pem, key_pem, fingerprint })
}

/// Issue a client certificate. CN encodes the client name; later the server's
/// mTLS handshake reads that CN out of the peer cert and uses it as identity.
pub fn issue_client_cert(ca: &Ca, client_name: &str, ttl_days: i64) -> Result<CertBundle> {
    let mut params = CertificateParams::new(vec![]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, client_name);
    dn.push(DnType::OrganizationName, "Blackbook");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let (nb, na) = lifetime(ttl_days);
    params.not_before = nb;
    params.not_after = na;

    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem_with_signer(&ca.cert)?;
    let key_pem = cert.serialize_private_key_pem();
    let fingerprint = fingerprint_pem(&cert_pem)?;
    Ok(CertBundle { cert_pem, key_pem, fingerprint })
}

/// Wraps the CA so it can be stored in `AppState` (Arc-shared, immutable
/// after startup; nobody re-keys mid-flight).
pub type SharedCa = Arc<Ca>;

/// SHA3-256 hex of the DER form of a PEM certificate.
fn fingerprint_pem(pem: &str) -> Result<String> {
    let der = pem_to_der(pem)?;
    let mut h = Sha3_256::new();
    h.update(&der);
    Ok(hex::encode(h.finalize()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    // Minimal PEM parser — peel `-----BEGIN…-----` headers, base64-decode body.
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") { in_block = true; continue; }
        if line.starts_with("-----END") { break; }
        if in_block { b64.push_str(line); }
    }
    if b64.is_empty() { return Err(TlsError::Pem("no PEM block found".into())); }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| TlsError::Pem(format!("base64: {e}")))
}

/// Pull the Common Name out of a PEM certificate. Works on both server and
/// client certs we issue (we always put CN in the subject).
pub fn extract_cn(pem: &str) -> Result<Option<String>> {
    let der = pem_to_der(pem)?;
    // Walk the DER looking for the CN OID (2.5.4.3 = `0x55 0x04 0x03`).
    // CN appears as: OID(2.5.4.3) followed by a string-type tag (0x0C UTF8,
    // 0x13 PrintableString, etc.), followed by length, followed by bytes.
    //
    // In X.509 DER the Issuer field precedes the Subject field, so the first
    // CN match is the issuer's CN and the last match is the subject's CN.
    // We keep scanning and return the final valid hit.
    const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
    let mut found: Option<String> = None;
    let mut i = 0;
    while i + CN_OID.len() + 2 < der.len() {
        if &der[i..i + CN_OID.len()] == CN_OID {
            let after = i + CN_OID.len();
            let tag = der[after];
            // Accept UTF8String(0x0C), PrintableString(0x13), IA5String(0x16),
            // T61String(0x14), BMPString(0x1E), UniversalString(0x1C).
            if matches!(tag, 0x0C | 0x13 | 0x16 | 0x14 | 0x1E | 0x1C) {
                let len = der[after + 1] as usize;
                let start = after + 2;
                let end = start + len;
                if end <= der.len() {
                    if let Ok(s) = std::str::from_utf8(&der[start..end]) {
                        found = Some(s.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    Ok(found)
}

fn lifetime(days: i64) -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    // Backdate by a minute to dodge clock skew between server and client.
    let nb = now - time::Duration::minutes(1);
    let na = now + time::Duration::days(days);
    (nb, na)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_round_trip_can_sign() {
        let ca = Ca::generate().unwrap();
        let reloaded = Ca::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
        let server = issue_server_cert(&reloaded, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(server.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn client_cert_cn_round_trip() {
        let ca = Ca::generate().unwrap();
        let cb = issue_client_cert(&ca, "alice", 7).unwrap();
        let cn = extract_cn(&cb.cert_pem).unwrap();
        assert_eq!(cn.as_deref(), Some("alice"));
    }
}
