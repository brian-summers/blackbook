//! Tunnel crypto core — authenticated, end-to-end-encrypted channel between two
//! blackbook clients, relayed (but never readable) by the server.
//!
//! # Threat model & guarantees
//!
//! The two clients have no direct network path to each other; the blackbook
//! server relays opaque frames between them. The server already authenticated
//! both ends over mTLS, so it acts as a *trusted introducer*: it tells each
//! peer the other's client name and the SHA3-256 fingerprint of their
//! certificate. But the server must not be able to read or tamper with the
//! tunnel. This module delivers that:
//!
//! - **End-to-end confidentiality / integrity.** A fresh ephemeral X25519 key
//!   pair per side; the shared secret runs through HKDF-SHA256 into two
//!   *directional* AES-256-GCM keys. The server never sees an ephemeral private
//!   key, so it cannot derive the session key; the GCM tag makes tampering
//!   detectable. (Ephemeral keys also give forward secrecy.)
//!
//! - **Mutual, credential-bound identification.** Each side signs the handshake
//!   transcript with the *private key of its existing client certificate*
//!   (ECDSA P-256 — the real blackbook credential, which the server does not
//!   hold). The peer verifies that signature against the certificate whose
//!   fingerprint the server vouched. Because the server cannot forge that
//!   signature, identity is cryptographic, not merely "the server says so" — a
//!   malicious server can relay or drop, but cannot impersonate either party or
//!   sit in the middle reading plaintext.
//!
//! The transcript binds the protocol label, tunnel id, both client names, both
//! cert fingerprints, and *both* ephemeral public keys, so a captured signature
//! cannot be replayed into a different tunnel, peer, or session.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::blackbook_core::{aead_seal_nonce, aead_open_nonce, CryptoError, CryptoResult};

/// Protocol/version label mixed into every transcript. Bump on any wire change.
pub const TUNNEL_PROTO: &[u8] = b"blackbook/tunnel/v1";

/// The handshake message each side sends. Carries the ephemeral public key and
/// a signature, by the sender's client-cert private key, over the transcript.
/// The cert PEM is included so the peer can verify the signature *and* confirm
/// the cert's fingerprint matches what the server vouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Sender's blackbook client name (as the server knows it).
    pub from: String,
    /// Sender's ephemeral X25519 public key (32 bytes, base64).
    pub eph_pub: String,
    /// Sender's client certificate (PEM) — peer pins it to the vouched fingerprint.
    pub cert_pem: String,
    /// ECDSA P-256 signature (base64, DER) over the canonical transcript.
    pub signature: String,
}

/// Role determines which directional key encrypts vs decrypts, so the two sides
/// never share a key+nonce space (which would be catastrophic for GCM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role { Initiator, Responder }

/// An established session: directional AES-256-GCM keys + monotonic per-direction
/// nonce counters. `send`/`recv` are relative to *this* side.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
    /// The verified peer identity (name + cert fingerprint).
    pub peer_name: String,
    pub peer_fingerprint: String,
}

/// The session-binding base: protocol, tunnel id, and *both* ephemeral public
/// keys in role order (initiator first). Both sides compute this identically.
/// Each side's signature is over `base ‖ signer_name ‖ signer_fp`, so a
/// signature authenticates the signer's identity *bound to this exact session's
/// ephemeral keys* — it can't be replayed into another tunnel or session, and
/// can't be lifted onto a different identity. Length-prefixed to avoid ambiguity.
fn session_base(tunnel_id: &str, init_eph: &[u8], resp_eph: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    let field = |h: &mut Sha3_256, b: &[u8]| {
        h.update((b.len() as u32).to_be_bytes());
        h.update(b);
    };
    field(&mut h, TUNNEL_PROTO);
    field(&mut h, tunnel_id.as_bytes());
    field(&mut h, init_eph);
    field(&mut h, resp_eph);
    h.finalize().into()
}

/// What a party with the given identity signs: the session base hash plus their
/// own name and cert fingerprint, length-prefixed.
fn signing_payload(base: &[u8; 32], signer_name: &str, signer_fp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 64 + signer_name.len());
    let push = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    };
    push(&mut out, base);
    push(&mut out, signer_name.as_bytes());
    push(&mut out, signer_fp.as_bytes());
    out
}

/// SHA3-256 hex of a certificate PEM's DER — identical to `tls::fingerprint_pem`
/// so server-vouched fingerprints and locally-computed ones agree.
pub fn cert_fingerprint(cert_pem: &str) -> CryptoResult<String> {
    let der = pem_to_der(cert_pem)?;
    let mut h = Sha3_256::new();
    h.update(&der);
    Ok(hex::encode(h.finalize()))
}

fn pem_to_der(pem: &str) -> CryptoResult<Vec<u8>> {
    use base64::Engine as _;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") { in_block = true; continue; }
        if line.starts_with("-----END") { break; }
        if in_block { b64.push_str(line); }
    }
    if b64.is_empty() { return Err(CryptoError::InvalidKeyFormat); }
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| CryptoError::InvalidKeyFormat)
}

// --- ECDSA P-256 sign/verify over the client cert keypair (via openssl) ------

/// Sign `msg` with the client's certificate private key (PEM, ECDSA P-256).
fn ecdsa_sign(key_pem: &str, msg: &[u8]) -> CryptoResult<Vec<u8>> {
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use openssl::hash::MessageDigest;
    let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| CryptoError::Encryption(format!("load client key: {e}")))?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| CryptoError::Encryption(format!("signer: {e}")))?;
    signer.update(msg).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    signer.sign_to_vec().map_err(|e| CryptoError::Encryption(e.to_string()))
}

/// Verify an ECDSA P-256 signature against the public key inside `cert_pem`.
fn ecdsa_verify(cert_pem: &str, msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    use openssl::x509::X509;
    use openssl::sign::Verifier;
    use openssl::hash::MessageDigest;
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| CryptoError::Decryption(format!("parse peer cert: {e}")))?;
    let pkey = cert.public_key()
        .map_err(|e| CryptoError::Decryption(format!("peer cert pubkey: {e}")))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;
    verifier.update(msg).map_err(|e| CryptoError::Decryption(e.to_string()))?;
    Ok(verifier.verify(sig).unwrap_or(false))
}

// --- Handshake construction & completion -------------------------------------

/// Build *this* side's handshake message and hold the ephemeral secret needed
/// to finish. The transcript (and thus the signature) requires the peer's
/// ephemeral public key, so signing happens in [`complete`], not here — here we
/// only publish our ephemeral public key + identity.
pub struct Pending {
    role: Role,
    tunnel_id: String,
    my_name: String,
    my_cert_pem: String,
    my_key_pem: String,
    eph_secret: EphemeralSecret,
    eph_pub: [u8; 32],
}

/// Start a handshake: generate the ephemeral key and return the bundle plus the
/// ephemeral public key to advertise. (The full signed `Handshake` is produced
/// by [`complete`] once the peer's ephemeral public key is known.)
pub fn begin(role: Role, tunnel_id: &str, my_name: &str, my_cert_pem: &str, my_key_pem: &str) -> Pending {
    use rand::rngs::OsRng;
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret).to_bytes();
    Pending {
        role,
        tunnel_id: tunnel_id.to_string(),
        my_name: my_name.to_string(),
        my_cert_pem: my_cert_pem.to_string(),
        my_key_pem: my_key_pem.to_string(),
        eph_secret,
        eph_pub,
    }
}

impl Pending {
    /// Our ephemeral public key (32 bytes) — send this to the peer first.
    pub fn eph_pub(&self) -> [u8; 32] { self.eph_pub }

    /// Produce our signed handshake message, given the peer's ephemeral pubkey.
    /// We sign the session base (both ephemeral keys, role-ordered) bound to our
    /// own name + fingerprint — proving we hold our cert's key for *this* session.
    pub fn sign(&self, peer_eph_pub: &[u8; 32]) -> CryptoResult<Handshake> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let my_fp = cert_fingerprint(&self.my_cert_pem)?;
        let (init_eph, resp_eph) = match self.role {
            Role::Initiator => (self.eph_pub, *peer_eph_pub),
            Role::Responder => (*peer_eph_pub, self.eph_pub),
        };
        let base = session_base(&self.tunnel_id, &init_eph, &resp_eph);
        let payload = signing_payload(&base, &self.my_name, &my_fp);
        let sig = ecdsa_sign(&self.my_key_pem, &payload)?;
        Ok(Handshake {
            from: self.my_name.clone(),
            eph_pub: b64.encode(self.eph_pub),
            cert_pem: self.my_cert_pem.clone(),
            signature: b64.encode(sig),
        })
    }

    /// Verify the peer's handshake and derive the session. `expected_peer_name`
    /// and `expected_peer_fp` are what the *server vouched*; we require the
    /// peer's presented cert to match the fingerprint, and the signature to
    /// verify over the transcript — proving the peer holds that cert's key.
    pub fn complete(
        self,
        peer: &Handshake,
        expected_peer_name: &str,
        expected_peer_fp: &str,
    ) -> CryptoResult<Session> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;

        // 1. The peer's cert must match the fingerprint the server vouched.
        let peer_fp = cert_fingerprint(&peer.cert_pem)?;
        if peer_fp != expected_peer_fp {
            return Err(CryptoError::Decryption(
                "peer certificate fingerprint does not match the server-vouched value".into()));
        }
        if peer.from != expected_peer_name {
            return Err(CryptoError::Decryption(
                "peer name does not match the server-vouched value".into()));
        }

        let peer_eph_vec = b64.decode(peer.eph_pub.as_bytes())
            .map_err(|_| CryptoError::Decryption("peer eph_pub not base64".into()))?;
        if peer_eph_vec.len() != 32 {
            return Err(CryptoError::Decryption("peer eph_pub wrong length".into()));
        }
        let mut peer_eph = [0u8; 32];
        peer_eph.copy_from_slice(&peer_eph_vec);

        // 2. Verify the peer's signature. Both sides compute the same session
        //    base (initiator eph first); the peer signed `base ‖ peer_name ‖
        //    peer_fp`, which we reconstruct from the now-verified peer identity.
        let (init_eph, resp_eph) = match self.role {
            Role::Initiator => (self.eph_pub, peer_eph),   // peer is responder
            Role::Responder => (peer_eph, self.eph_pub),   // peer is initiator
        };
        let base = session_base(&self.tunnel_id, &init_eph, &resp_eph);
        let peer_payload = signing_payload(&base, &peer.from, &peer_fp);
        let sig = b64.decode(peer.signature.as_bytes())
            .map_err(|_| CryptoError::Decryption("peer signature not base64".into()))?;
        if !ecdsa_verify(&peer.cert_pem, &peer_payload, &sig)? {
            return Err(CryptoError::Decryption(
                "peer handshake signature failed — identity not authenticated".into()));
        }

        // 3. X25519 ECDH → HKDF-SHA256 → two directional keys, salted by the
        //    session base so the keys are bound to this exact session.
        let shared = self.eph_secret.diffie_hellman(&PublicKey::from(peer_eph));
        let (k_i2r, k_r2i) = derive_keys(shared.as_bytes(), &base)?;

        // Directional assignment by role.
        let (send_key, recv_key) = match self.role {
            Role::Initiator => (k_i2r, k_r2i),
            Role::Responder => (k_r2i, k_i2r),
        };
        Ok(Session {
            send_key, recv_key, send_ctr: 0, recv_ctr: 0,
            peer_name: expected_peer_name.to_string(),
            peer_fingerprint: expected_peer_fp.to_string(),
        })
    }
}

/// HKDF-SHA256 the X25519 shared secret into two 32-byte directional keys,
/// using the transcript hash as salt and a fixed info label per direction.
fn derive_keys(shared: &[u8], transcript: &[u8; 32]) -> CryptoResult<([u8; 32], [u8; 32])> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    hk.expand(b"blackbook/tunnel/v1 i2r", &mut k_i2r)
        .map_err(|_| CryptoError::KeyDerivation("hkdf i2r".into()))?;
    hk.expand(b"blackbook/tunnel/v1 r2i", &mut k_r2i)
        .map_err(|_| CryptoError::KeyDerivation("hkdf r2i".into()))?;
    Ok((k_i2r, k_r2i))
}

impl Session {
    /// Seal one frame for the peer. Nonce = 96-bit big-endian send counter, so
    /// it never repeats under a given directional key. Returns ciphertext+tag.
    pub fn seal(&mut self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = ctr_nonce(self.send_ctr);
        self.send_ctr = self.send_ctr.checked_add(1)
            .ok_or_else(|| CryptoError::Encryption("tunnel nonce space exhausted".into()))?;
        aead_seal_nonce(plaintext, &self.send_key, &nonce)
    }

    /// Open one frame from the peer, enforcing strictly increasing counters so a
    /// relay can't replay or reorder frames undetected.
    pub fn open(&mut self, frame: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = ctr_nonce(self.recv_ctr);
        let pt = aead_open_nonce(frame, &self.recv_key, &nonce)?;
        self.recv_ctr = self.recv_ctr.checked_add(1)
            .ok_or_else(|| CryptoError::Decryption("tunnel nonce space exhausted".into()))?;
        Ok(pt)
    }
}

/// 96-bit nonce from a 64-bit counter (4 zero bytes ‖ counter big-endian).
fn ctr_nonce(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls;

    /// Issue two real client certs from a throwaway CA, run the full handshake,
    /// and assert: both sides derive matching directional keys, data round-trips,
    /// tampering is caught, replay is caught, and a forged/mismatched identity
    /// is rejected.
    fn two_clients() -> (tls::CertBundle, tls::CertBundle, tls::Ca) {
        let ca = tls::Ca::generate().unwrap();
        let alice = tls::issue_client_cert(&ca, "alice", 7).unwrap();
        let bob = tls::issue_client_cert(&ca, "bob", 7).unwrap();
        (alice, bob, ca)
    }

    fn run_handshake(alice: &tls::CertBundle, bob: &tls::CertBundle)
        -> CryptoResult<(Session, Session)> {
        let tid = "tunnel-123";
        let a = begin(Role::Initiator, tid, "alice", &alice.cert_pem, &alice.key_pem);
        let b = begin(Role::Responder, tid, "bob", &bob.cert_pem, &bob.key_pem);
        let a_pub = a.eph_pub();
        let b_pub = b.eph_pub();
        let a_hs = a.sign(&b_pub)?;
        let b_hs = b.sign(&a_pub)?;
        let a_sess = a.complete(&b_hs, "bob", &bob.fingerprint)?;
        let b_sess = b.complete(&a_hs, "alice", &alice.fingerprint)?;
        Ok((a_sess, b_sess))
    }

    #[test]
    fn handshake_and_roundtrip() {
        let (alice, bob, _ca) = two_clients();
        let (mut a, mut b) = run_handshake(&alice, &bob).unwrap();
        // alice → bob
        let frame = a.seal(b"hello bob").unwrap();
        assert_eq!(b.open(&frame).unwrap(), b"hello bob");
        // bob → alice
        let frame = b.seal(b"hi alice").unwrap();
        assert_eq!(a.open(&frame).unwrap(), b"hi alice");
        // verified peer identity surfaced
        assert_eq!(a.peer_name, "bob");
        assert_eq!(a.peer_fingerprint, bob.fingerprint);
        assert_eq!(b.peer_name, "alice");
    }

    #[test]
    fn tamper_is_detected() {
        let (alice, bob, _ca) = two_clients();
        let (mut a, mut b) = run_handshake(&alice, &bob).unwrap();
        let mut frame = a.seal(b"sensitive").unwrap();
        let n = frame.len() - 1;
        frame[n] ^= 0x01; // flip a tag bit
        assert!(b.open(&frame).is_err());
    }

    #[test]
    fn replay_is_detected() {
        let (alice, bob, _ca) = two_clients();
        let (mut a, mut b) = run_handshake(&alice, &bob).unwrap();
        let f1 = a.seal(b"one").unwrap();
        let f2 = a.seal(b"two").unwrap();
        assert_eq!(b.open(&f1).unwrap(), b"one");
        assert_eq!(b.open(&f2).unwrap(), b"two");
        // replaying f1 now fails: recv counter has advanced.
        assert!(b.open(&f1).is_err());
    }

    #[test]
    fn forged_fingerprint_rejected() {
        // A server (or MITM) lies about bob's fingerprint → alice must reject.
        let (alice, bob, _ca) = two_clients();
        let tid = "t";
        let a = begin(Role::Initiator, tid, "alice", &alice.cert_pem, &alice.key_pem);
        let b = begin(Role::Responder, tid, "bob", &bob.cert_pem, &bob.key_pem);
        let a_pub = a.eph_pub(); let b_pub = b.eph_pub();
        let b_hs = b.sign(&a_pub).unwrap();
        let _a_hs = a.sign(&b_pub).unwrap();
        let bad_fp = "0".repeat(64);
        assert!(a.complete(&b_hs, "bob", &bad_fp).is_err());
    }

    #[test]
    fn impostor_with_wrong_key_rejected() {
        // mallory presents bob's *name+fingerprint claim* but signs with her own
        // key (she can't have bob's private key). Verification must fail because
        // the presented cert's fingerprint won't match bob's, OR if she presents
        // bob's cert, her signature won't verify under it.
        let (alice, bob, ca) = two_clients();
        let mallory = tls::issue_client_cert(&ca, "bob", 7).unwrap(); // same CN, different key
        let tid = "t";
        let a = begin(Role::Initiator, tid, "alice", &alice.cert_pem, &alice.key_pem);
        let m = begin(Role::Responder, tid, "bob", &mallory.cert_pem, &mallory.key_pem);
        let a_pub = a.eph_pub(); let m_pub = m.eph_pub();
        let m_hs = m.sign(&a_pub).unwrap();
        let _ = a.sign(&m_pub).unwrap();
        // alice expects the REAL bob's fingerprint → mallory's cert won't match.
        assert!(a.complete(&m_hs, "bob", &bob.fingerprint).is_err());
    }
}
