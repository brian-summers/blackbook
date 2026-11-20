//! Key shares: handing an external item's data key from the client that sealed
//! it to another client, without the server being able to read it.
//!
//! An external item is sealed on the client. A random data key (DEK) encrypts
//! the value, and the DEK is wrapped under the sealer's client master key
//! (CMK), which never leaves the sealer's profile. So neither the server nor a
//! grantee can open it. To let a grantee read it, the sealer encrypts the DEK
//! to the grantee's *share identity*, a long-term public key bundle, and
//! deposits the result (a key share) with the server. The grantee collects it
//! once, checks it, and keeps the DEK in its own local key store, sealed under
//! its own CMK. The server deletes the share once the grantee confirms.
//!
//! # Guarantees
//!
//! - **Confidentiality.** A share is encrypted to the recipient with a hybrid
//!   KEM: X25519 and ML-KEM-768, combined so that the key stays secret while
//!   either one holds. A share recorded today can't be opened later by a
//!   quantum computer (ML-KEM covers that), nor by a flaw found in ML-KEM alone
//!   (X25519 covers that).
//! - **Authenticity.** The sealer signs every share with the Ed25519 key in its
//!   own share identity. Without this, the server could give a grantee a DEK
//!   of its own choosing together with a matching envelope, and so substitute
//!   the value the grantee reads.
//! - **Binding.** The domain, the item's kind and name, the key id, and both
//!   clients' names and identity fingerprints are associated data of the
//!   share's AEAD and covered by the signature. A share can't be moved onto
//!   another item, another version of the item, or another recipient.
//! - **Key commitment.** The key id is a hash of the DEK, and [`open`] checks
//!   it, so a share can only ever yield the key it names.
//!
//! # Trusting identities
//!
//! A client publishes its identity signed with its certificate key, and the
//! server vouches for the certificate's fingerprint, as it does for tunnels
//! ([`verify_identity`]). The first identity seen for a client name is pinned
//! in the local store, trust on first use like SSH host keys, and a different
//! one later is refused until the user confirms its fingerprint
//! (`bbk share trust`). A malicious server could therefore substitute an
//! identity only for a client this one has never exchanged a share with.

use aws_lc_rs::kem::{AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::blackbook_core::{aead_open_aad, aead_seal_aad};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Domain-separation labels. Bump the version on any change to what they cover.
const IDENTITY_LABEL: &[u8] = b"blackbook/share-identity/v1";
const BINDING_LABEL: &[u8] = b"blackbook/share-identity-cert/v1";
const SHARE_LABEL: &[u8] = b"blackbook/key-share/v1";
const COMBINER_LABEL: &[u8] = b"blackbook/hybrid-kem/x25519-mlkem768/v1";
const KEY_ID_LABEL: &[u8] = b"blackbook/key-id/v1";

/// Wire version of a key share.
const SHARE_VERSION: u8 = 1;

/// Upper bound on an encoded share. A real one is about 1.3 KiB: X25519 (32)
/// and ML-KEM-768 (1088) ciphertexts, the sealed 32-byte key (60), and the
/// signature (64), each length-prefixed.
pub const MAX_SHARE_LEN: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShareError {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("the key share's signature doesn't verify against the sender's identity")]
    BadSignature,
    #[error(
        "the key share can't be opened with this client's identity \
         (it's addressed to another identity, or it's corrupted)"
    )]
    Decrypt,
    #[error("the key share holds a different key than the one it names")]
    KeyMismatch,
    #[error("the identity isn't signed by the certificate the server vouched for")]
    BadBinding,
    #[error("crypto: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ShareError>;

fn internal(e: impl std::fmt::Display) -> ShareError {
    ShareError::Internal(e.to_string())
}

/// Appends `b` with a 4-byte big-endian length prefix, so that no two
/// different field sequences encode to the same bytes.
fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Reads fields written by [`put`].
struct Fields<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Fields<'a> {
    fn take(&mut self) -> Result<&'a [u8]> {
        if self.buf.len() < 4 {
            return Err(ShareError::Malformed(self.what));
        }
        let (len, rest) = self.buf.split_at(4);
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        if rest.len() < len {
            return Err(ShareError::Malformed(self.what));
        }
        let (field, rest) = rest.split_at(len);
        self.buf = rest;
        Ok(field)
    }
    fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(ShareError::Malformed(self.what))
        }
    }
}

fn b64_exact<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    let raw = B64.decode(s).map_err(|_| ShareError::Malformed(what))?;
    raw.try_into().map_err(|_| ShareError::Malformed(what))
}

/// The key id of a data key: SHA3-256 over a label and the key, hex. Public:
/// the server stores it, and both sides use it to name which version of an
/// item a share is for. A hash of a uniformly random 256-bit key reveals
/// nothing usable about it.
pub fn key_id(dek: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(KEY_ID_LABEL);
    h.update(dek);
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// A client's public share identity. This is what the client publishes, and
/// what senders encrypt to and pin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareIdentity {
    /// Ed25519 verifying key: checks the shares this client sends (base64).
    pub sign: String,
    /// X25519 public key (base64).
    pub x25519: String,
    /// ML-KEM-768 encapsulation key (base64).
    pub mlkem768: String,
}

/// An identity's keys, decoded and checked.
struct PublicKeys {
    sign: VerifyingKey,
    x25519: [u8; 32],
    mlkem768: Vec<u8>,
}

impl ShareIdentity {
    fn decode(&self) -> Result<PublicKeys> {
        let sign = VerifyingKey::from_bytes(&b64_exact::<32>(&self.sign, "identity")?)
            .map_err(|_| ShareError::Malformed("identity"))?;
        let x25519 = b64_exact::<32>(&self.x25519, "identity")?;
        let mlkem768 = B64
            .decode(&self.mlkem768)
            .map_err(|_| ShareError::Malformed("identity"))?;
        // Rejects a key of the wrong size before anyone encapsulates to it.
        EncapsulationKey::new(&ML_KEM_768, &mlkem768)
            .map_err(|_| ShareError::Malformed("identity"))?;
        Ok(PublicKeys {
            sign,
            x25519,
            mlkem768,
        })
    }

    /// The canonical encoding: a label and the three raw keys, length-prefixed.
    /// Fingerprints and signatures cover this, never the base64 text.
    fn canonical(&self) -> Result<Vec<u8>> {
        let k = self.decode()?;
        let mut out = Vec::with_capacity(IDENTITY_LABEL.len() + 1260);
        out.extend_from_slice(IDENTITY_LABEL);
        put(&mut out, k.sign.as_bytes());
        put(&mut out, &k.x25519);
        put(&mut out, &k.mlkem768);
        Ok(out)
    }

    /// SHA3-256 of the canonical encoding, hex. This is what gets pinned and
    /// what users compare out of band.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode(Sha3_256::digest(self.canonical()?)))
    }
}

/// A fingerprint in groups of four hex digits, for reading aloud or comparing
/// by eye.
pub fn display_fingerprint(fp: &str) -> String {
    fp.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalizes a fingerprint typed by a user (spaces, colons, either case) to
/// the 64-hex-digit form. `None` if it isn't one.
pub fn parse_fingerprint(s: &str) -> Option<String> {
    let fp: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    (fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit())).then_some(fp)
}

/// A client's private share keys, with the identity they belong to.
pub struct ShareSecret {
    sign: SigningKey,
    x25519: StaticSecret,
    mlkem768: DecapsulationKey<AlgorithmId>,
    identity: ShareIdentity,
}

/// The private keys in storable form. Only ever written inside the local key
/// store, which is sealed under the profile's CMK.
#[derive(Serialize, Deserialize)]
pub struct StoredShareSecret {
    pub identity: ShareIdentity,
    sign: String,
    x25519: String,
    mlkem768: String,
}

impl Drop for StoredShareSecret {
    fn drop(&mut self) {
        self.sign.zeroize();
        self.x25519.zeroize();
        self.mlkem768.zeroize();
    }
}

impl ShareSecret {
    /// A fresh identity from the OS random number generator.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut_slice());
        let sign = SigningKey::from_bytes(&seed);
        let x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let mlkem768 = DecapsulationKey::generate(&ML_KEM_768).map_err(internal)?;
        let ek = mlkem768
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(internal)?;
        let identity = ShareIdentity {
            sign: B64.encode(sign.verifying_key().as_bytes()),
            x25519: B64.encode(PublicKey::from(&x25519).as_bytes()),
            mlkem768: B64.encode(ek.as_ref()),
        };
        Ok(Self {
            sign,
            x25519,
            mlkem768,
            identity,
        })
    }

    pub fn identity(&self) -> &ShareIdentity {
        &self.identity
    }

    pub fn to_stored(&self) -> Result<StoredShareSecret> {
        let dk = self.mlkem768.key_bytes().map_err(internal)?;
        Ok(StoredShareSecret {
            identity: self.identity.clone(),
            sign: B64.encode(self.sign.to_bytes()),
            x25519: B64.encode(self.x25519.to_bytes()),
            mlkem768: B64.encode(dk.as_ref()),
        })
    }

    /// Rebuilds the keys and checks that they belong to the stored identity:
    /// the Ed25519 and X25519 public keys are recomputed, and an ML-KEM
    /// round trip proves the decapsulation key matches the published one.
    pub fn from_stored(s: &StoredShareSecret) -> Result<Self> {
        let bad = || ShareError::Malformed("stored share identity");
        let sign = SigningKey::from_bytes(&Zeroizing::new(b64_exact::<32>(
            &s.sign,
            "stored share identity",
        )?));
        let x25519 = StaticSecret::from(*Zeroizing::new(b64_exact::<32>(
            &s.x25519,
            "stored share identity",
        )?));
        let dk = Zeroizing::new(B64.decode(&s.mlkem768).map_err(|_| bad())?);
        let mlkem768 = DecapsulationKey::new(&ML_KEM_768, &dk).map_err(|_| bad())?;

        let public = s.identity.decode()?;
        if sign.verifying_key() != public.sign
            || PublicKey::from(&x25519).as_bytes() != &public.x25519
        {
            return Err(bad());
        }
        let ek = EncapsulationKey::new(&ML_KEM_768, &public.mlkem768).map_err(|_| bad())?;
        let (ct, ss) = ek.encapsulate().map_err(internal)?;
        let ss2 = mlkem768
            .decapsulate(Ciphertext::from(ct.as_ref()))
            .map_err(|_| bad())?;
        if ss.as_ref() != ss2.as_ref() {
            return Err(bad());
        }
        Ok(Self {
            sign,
            x25519,
            mlkem768,
            identity: s.identity.clone(),
        })
    }
}

/// What a client signs with its certificate key when it publishes its
/// identity: the client name, the certificate fingerprint, and the identity
/// fingerprint.
fn binding_message(name: &str, cert_fp: &str, identity_fp: &str) -> Vec<u8> {
    let mut out = BINDING_LABEL.to_vec();
    put(&mut out, name.as_bytes());
    put(&mut out, cert_fp.as_bytes());
    put(&mut out, identity_fp.as_bytes());
    out
}

/// Signs `identity` with the client's certificate key, binding it to `name`
/// and to that certificate.
pub fn sign_identity(
    key_pem: &str,
    cert_pem: &str,
    name: &str,
    identity: &ShareIdentity,
) -> Result<Vec<u8>> {
    let cert_fp = crate::tunnel_crypto::cert_fingerprint(cert_pem).map_err(internal)?;
    let msg = binding_message(name, &cert_fp, &identity.fingerprint()?);
    crate::tunnel_crypto::ecdsa_sign(key_pem, &msg).map_err(internal)
}

/// Checks that `identity` was published by the holder of the certificate the
/// server vouches for: the certificate's fingerprint must be `vouched_fp`, and
/// its key must have signed the binding. Returns the identity's fingerprint.
pub fn verify_identity(
    name: &str,
    cert_pem: &str,
    vouched_fp: &str,
    identity: &ShareIdentity,
    sig: &[u8],
) -> Result<String> {
    let cert_fp =
        crate::tunnel_crypto::cert_fingerprint(cert_pem).map_err(|_| ShareError::BadBinding)?;
    if !cert_fp.eq_ignore_ascii_case(vouched_fp) {
        return Err(ShareError::BadBinding);
    }
    let fp = identity.fingerprint()?;
    let msg = binding_message(name, &cert_fp, &fp);
    match crate::tunnel_crypto::ecdsa_verify(cert_pem, &msg, sig) {
        Ok(true) => Ok(fp),
        _ => Err(ShareError::BadBinding),
    }
}

// ---------------------------------------------------------------------------
// Shares
// ---------------------------------------------------------------------------

/// The item and the two clients a share is for. Every field is bound into the
/// share.
pub struct ShareContext<'a> {
    /// Domain name, as the server reports it.
    pub domain: &'a str,
    /// `secret` or `file`.
    pub kind: &'a str,
    pub name: &'a str,
    /// [`key_id`] of the data key being shared.
    pub key_id: &'a str,
    /// Sender and recipient client names.
    pub sender: &'a str,
    pub recipient: &'a str,
}

/// The share's associated data, which the signature also covers.
fn associated_data(
    ctx: &ShareContext,
    sender_fp: &str,
    recipient_fp: &str,
    ct_x: &[u8],
    ct_m: &[u8],
) -> Vec<u8> {
    let mut out = SHARE_LABEL.to_vec();
    out.push(SHARE_VERSION);
    for f in [
        ctx.domain,
        ctx.kind,
        ctx.name,
        ctx.key_id,
        ctx.sender,
        sender_fp,
        ctx.recipient,
        recipient_fp,
    ] {
        put(&mut out, f.as_bytes());
    }
    put(&mut out, ct_x);
    put(&mut out, ct_m);
    out
}

/// Combines the two shared secrets into the share's AES-256-GCM key. It hashes
/// both secrets with both ciphertexts and the recipient's X25519 key and
/// identity fingerprint, so the result is secret as long as either KEM is,
/// and is tied to this encapsulation and this recipient. (This includes more
/// than the X-Wing combiner needs, which costs nothing and doesn't lean on
/// ML-KEM's ciphertext binding.)
fn combine(
    ss_m: &[u8],
    ss_x: &[u8],
    ct_x: &[u8],
    pk_x: &[u8],
    ct_m: &[u8],
    recipient_fp: &str,
) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(COMBINER_LABEL.to_vec());
    for f in [ss_m, ss_x, ct_x, pk_x, ct_m, recipient_fp.as_bytes()] {
        put(&mut input, f);
    }
    Zeroizing::new(Sha3_256::digest(input.as_slice()).into())
}

/// Encrypts `dek` to `recipient` and signs it with `sender`'s key.
pub fn seal(
    sender: &ShareSecret,
    recipient: &ShareIdentity,
    ctx: &ShareContext,
    dek: &[u8; 32],
) -> Result<Vec<u8>> {
    if key_id(dek) != ctx.key_id {
        return Err(ShareError::KeyMismatch);
    }
    let r = recipient.decode()?;
    let sender_fp = sender.identity.fingerprint()?;
    let recipient_fp = recipient.fingerprint()?;

    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ct_x = PublicKey::from(&eph).to_bytes();
    let ss_x = eph.diffie_hellman(&PublicKey::from(r.x25519));
    // A low-order recipient key would make the shared secret a constant.
    if !ss_x.was_contributory() {
        return Err(ShareError::Malformed("identity"));
    }
    let ek = EncapsulationKey::new(&ML_KEM_768, &r.mlkem768).map_err(internal)?;
    let (ct_m, ss_m) = ek.encapsulate().map_err(internal)?;
    let ct_m = ct_m.as_ref().to_vec();

    let key = combine(
        ss_m.as_ref(),
        ss_x.as_bytes(),
        &ct_x,
        &r.x25519,
        &ct_m,
        &recipient_fp,
    );
    let aad = associated_data(ctx, &sender_fp, &recipient_fp, &ct_x, &ct_m);
    let body = aead_seal_aad(dek, key.as_slice(), &aad).map_err(internal)?;
    let mut signed = aad;
    put(&mut signed, &body);
    let sig = sender.sign.sign(&signed);

    let mut out = vec![SHARE_VERSION];
    put(&mut out, &ct_x);
    put(&mut out, &ct_m);
    put(&mut out, &body);
    put(&mut out, &sig.to_bytes());
    Ok(out)
}

/// Checks a share's signature against `sender`, opens it with `recipient`,
/// and returns the data key, which is guaranteed to have id `ctx.key_id`.
pub fn open(
    recipient: &ShareSecret,
    sender: &ShareIdentity,
    ctx: &ShareContext,
    blob: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    if blob.len() > MAX_SHARE_LEN || blob.first() != Some(&SHARE_VERSION) {
        return Err(ShareError::Malformed("key share"));
    }
    let mut f = Fields {
        buf: &blob[1..],
        what: "key share",
    };
    let ct_x = f.take()?;
    let ct_m = f.take()?;
    let body = f.take()?;
    let sig = f.take()?;
    f.finish()?;
    let ct_x: [u8; 32] = ct_x
        .try_into()
        .map_err(|_| ShareError::Malformed("key share"))?;
    let sig = Signature::from_slice(sig).map_err(|_| ShareError::Malformed("key share"))?;

    // Signature first: nothing from an unauthenticated share is decrypted.
    let s = sender.decode()?;
    let sender_fp = sender.fingerprint()?;
    let recipient_fp = recipient.identity.fingerprint()?;
    let aad = associated_data(ctx, &sender_fp, &recipient_fp, &ct_x, ct_m);
    let mut signed = aad.clone();
    put(&mut signed, body);
    s.sign
        .verify_strict(&signed, &sig)
        .map_err(|_| ShareError::BadSignature)?;

    let ss_x = recipient.x25519.diffie_hellman(&PublicKey::from(ct_x));
    if !ss_x.was_contributory() {
        return Err(ShareError::Decrypt);
    }
    let ss_m = recipient
        .mlkem768
        .decapsulate(Ciphertext::from(ct_m))
        .map_err(|_| ShareError::Decrypt)?;
    let pk_x = PublicKey::from(&recipient.x25519).to_bytes();
    let key = combine(
        ss_m.as_ref(),
        ss_x.as_bytes(),
        &ct_x,
        &pk_x,
        ct_m,
        &recipient_fp,
    );
    let dek =
        Zeroizing::new(aead_open_aad(body, key.as_slice(), &aad).map_err(|_| ShareError::Decrypt)?);
    let dek: [u8; 32] = dek
        .as_slice()
        .try_into()
        .map_err(|_| ShareError::KeyMismatch)?;
    let dek = Zeroizing::new(dek);
    if key_id(dek.as_slice()) != ctx.key_id {
        return Err(ShareError::KeyMismatch);
    }
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls;

    const DEK: [u8; 32] = [7u8; 32];

    fn ctx<'a>(key_id: &'a str) -> ShareContext<'a> {
        ShareContext {
            domain: "e2e",
            kind: "secret",
            name: "app-db-password",
            key_id,
            sender: "alice",
            recipient: "bob",
        }
    }

    #[test]
    fn share_round_trip() {
        let (alice, bob) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&DEK);
        let blob = seal(&alice, bob.identity(), &ctx(&kid), &DEK).unwrap();
        assert!(blob.len() < MAX_SHARE_LEN);
        let dek = open(&bob, alice.identity(), &ctx(&kid), &blob).unwrap();
        assert_eq!(*dek, DEK);
    }

    #[test]
    fn another_identity_cant_open_it() {
        let (alice, bob, carol) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&DEK);
        let blob = seal(&alice, bob.identity(), &ctx(&kid), &DEK).unwrap();
        // Carol's fingerprint differs, so the associated data, and with it the
        // signature, no longer match: refused before any decryption.
        assert_eq!(
            open(&carol, alice.identity(), &ctx(&kid), &blob),
            Err(ShareError::BadSignature)
        );
    }

    #[test]
    fn a_forged_sender_is_refused() {
        let (alice, bob, mallory) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&DEK);
        // Mallory (or the server) encrypts a key of its choosing to bob and
        // presents it as alice's.
        let forged = seal(&mallory, bob.identity(), &ctx(&kid), &DEK).unwrap();
        assert_eq!(
            open(&bob, alice.identity(), &ctx(&kid), &forged),
            Err(ShareError::BadSignature)
        );
    }

    #[test]
    fn a_share_cant_be_moved_to_another_item_or_key() {
        let (alice, bob) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&DEK);
        let blob = seal(&alice, bob.identity(), &ctx(&kid), &DEK).unwrap();
        let other_name = ShareContext {
            name: "app-api-key",
            ..ctx(&kid)
        };
        let other_domain = ShareContext {
            domain: "default",
            ..ctx(&kid)
        };
        let other_kind = ShareContext {
            kind: "file",
            ..ctx(&kid)
        };
        let other_key = key_id(&[8u8; 32]);
        for c in [other_name, other_domain, other_kind, ctx(&other_key)] {
            assert_eq!(
                open(&bob, alice.identity(), &c, &blob),
                Err(ShareError::BadSignature)
            );
        }
    }

    #[test]
    fn tampering_is_detected() {
        let (alice, bob) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&DEK);
        let blob = seal(&alice, bob.identity(), &ctx(&kid), &DEK).unwrap();
        for i in [1, 10, 100, 1000, blob.len() - 1] {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert!(
                open(&bob, alice.identity(), &ctx(&kid), &t).is_err(),
                "byte {i}"
            );
        }
        assert!(open(&bob, alice.identity(), &ctx(&kid), &blob[..blob.len() - 1]).is_err());
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(
            open(&bob, alice.identity(), &ctx(&kid), &longer),
            Err(ShareError::Malformed("key share"))
        );
    }

    #[test]
    fn seal_refuses_a_key_that_doesnt_match_its_id() {
        let (alice, bob) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let kid = key_id(&[8u8; 32]);
        assert_eq!(
            seal(&alice, bob.identity(), &ctx(&kid), &DEK),
            Err(ShareError::KeyMismatch)
        );
    }

    #[test]
    fn stored_identity_round_trips_and_is_checked() {
        let a = ShareSecret::generate().unwrap();
        let stored = a.to_stored().unwrap();
        let json = serde_json::to_string(&stored).unwrap();
        let back = ShareSecret::from_stored(&serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(back.identity(), a.identity());
        assert_eq!(
            back.identity().fingerprint().unwrap(),
            a.identity().fingerprint().unwrap()
        );

        // Private keys paired with someone else's public identity are refused.
        let b = ShareSecret::generate().unwrap();
        let mut mixed = a.to_stored().unwrap();
        mixed.identity = b.identity().clone();
        assert!(ShareSecret::from_stored(&mixed).is_err());
        let mut mixed_kem = a.to_stored().unwrap();
        mixed_kem.identity.mlkem768 = b.identity().mlkem768.clone();
        assert!(ShareSecret::from_stored(&mixed_kem).is_err());
    }

    #[test]
    fn identity_binding_checks_the_vouched_certificate() {
        let ca = tls::Ca::generate().unwrap();
        let alice = tls::issue_client_cert(&ca, "alice", 7).unwrap();
        let bob = tls::issue_client_cert(&ca, "bob", 7).unwrap();
        let id = ShareSecret::generate().unwrap();
        let sig = sign_identity(&alice.key_pem, &alice.cert_pem, "alice", id.identity()).unwrap();
        let fp = verify_identity(
            "alice",
            &alice.cert_pem,
            &alice.fingerprint,
            id.identity(),
            &sig,
        )
        .unwrap();
        assert_eq!(fp, id.identity().fingerprint().unwrap());

        // Wrong name, a certificate the server doesn't vouch for, someone
        // else's certificate, or a different identity: all refused.
        let other = ShareSecret::generate().unwrap();
        let refused = [
            verify_identity(
                "bob",
                &alice.cert_pem,
                &alice.fingerprint,
                id.identity(),
                &sig,
            ),
            verify_identity(
                "alice",
                &alice.cert_pem,
                &bob.fingerprint,
                id.identity(),
                &sig,
            ),
            verify_identity(
                "alice",
                &bob.cert_pem,
                &bob.fingerprint,
                id.identity(),
                &sig,
            ),
            verify_identity(
                "alice",
                &alice.cert_pem,
                &alice.fingerprint,
                other.identity(),
                &sig,
            ),
        ];
        for r in refused {
            assert_eq!(r, Err(ShareError::BadBinding));
        }
    }

    #[test]
    fn fingerprints_parse_and_display() {
        let fp = "0123456789abcdef".repeat(4);
        let shown = display_fingerprint(&fp);
        assert_eq!(shown.split(' ').count(), 16);
        assert_eq!(parse_fingerprint(&shown).as_deref(), Some(fp.as_str()));
        assert_eq!(
            parse_fingerprint(&shown.to_uppercase()).as_deref(),
            Some(fp.as_str())
        );
        assert_eq!(parse_fingerprint("0123"), None);
        assert_eq!(parse_fingerprint(&"z".repeat(64)), None);
    }

    #[test]
    fn key_ids_are_stable_and_distinct() {
        assert_eq!(key_id(&DEK), key_id(&DEK));
        assert_ne!(key_id(&DEK), key_id(&[8u8; 32]));
        assert_eq!(key_id(&DEK).len(), 64);
    }
}
