//! Key sharing, client side: the local key store, the flows that send an
//! external item's key to another client or receive one, and `bbk share`.
//! The cryptography is in [`crate::share_crypto`], the server's part in
//! [`crate::share_api`].
//!
//! The local key store, `~/.bbk/share/<profile>.json`, holds:
//! - this profile's share identity, private keys included;
//! - the identity fingerprints pinned for other clients (trust on first use);
//! - the data keys this client has received from other clients' items.
//!
//! The whole file is sealed with AES-256-GCM under a purpose-bound subkey of
//! the profile's client master key, so it's protected exactly as well as the
//! external items themselves: opening it takes the profile passphrase, or the
//! unlock agent's cached key.

use base64::Engine as _;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use crate::blackbook_core::{aead_open, aead_open_aad, aead_seal_aad};
use crate::client::{self, BlackbookClient, ClientError, Session};
use crate::share_api::{ItemKind, PickupResponse, PublishedIdentity, RequestView};
use crate::share_crypto::{self, ShareContext, ShareIdentity, ShareSecret, StoredShareSecret};
use crate::{AppError, Result};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const STORE_LABEL: &[u8] = b"blackbook/share-store/v1";

fn crypto_err(e: share_crypto::ShareError) -> AppError {
    AppError::Crypto(e.to_string())
}

#[derive(Default, Serialize, Deserialize)]
struct StoreData {
    #[serde(default)]
    identity: Option<StoredShareSecret>,
    /// What was last published (identity fingerprint, certificate
    /// fingerprint, server), so publishing is skipped until one changes.
    #[serde(default)]
    published: Option<String>,
    /// Client name → pinned identity fingerprint.
    #[serde(default)]
    pins: BTreeMap<String, String>,
    /// [`item_slot`] → the key received for that item.
    #[serde(default)]
    keys: BTreeMap<String, ReceivedKey>,
}

#[derive(Serialize, Deserialize)]
struct ReceivedKey {
    key_id: String,
    /// base64 of the data key.
    dek: String,
    from: String,
}

impl Drop for ReceivedKey {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

/// The file on disk: the sealed [`StoreData`].
#[derive(Serialize, Deserialize)]
struct SealedStore {
    v: u8,
    ct: String,
}

fn item_slot(kind: ItemKind, domain: &str, name: &str) -> String {
    format!("{}\n{domain}\n{name}", kind.as_str())
}

/// This profile's local key store (see the module docs).
pub struct KeyStore {
    path: PathBuf,
    cmk: Zeroizing<[u8; 32]>,
    /// Associated data: the label and the profile name, so a store copied
    /// into another profile's place doesn't open.
    aad: Vec<u8>,
    data: StoreData,
}

impl KeyStore {
    /// The store of the active profile.
    pub fn open(session: &Session) -> Result<Self> {
        Self::open_named(session, &client::active_profile())
    }

    /// The store of the named profile, whose session `session` is.
    pub fn open_named(session: &Session, profile: &str) -> Result<Self> {
        let cmk = Zeroizing::new(session.cmk_bytes().ok_or_else(|| {
            AppError::Config(
                "this profile has no client master key, which key sharing needs; run `bbk login` again"
                    .into(),
            )
        })?);
        let path = Session::bbk_dir()?
            .join("share")
            .join(format!("{profile}.json"));
        let aad = [STORE_LABEL, profile.as_bytes()].concat();
        let key = crate::crypto_ops::cmk_subkey(cmk.as_slice(), "share-store");
        let data = match std::fs::read(&path) {
            Ok(bytes) => {
                let opened = serde_json::from_slice::<SealedStore>(&bytes)
                    .ok()
                    .and_then(|s| B64.decode(s.ct).ok())
                    .and_then(|ct| aead_open_aad(&ct, key.as_slice(), &aad).ok())
                    .map(Zeroizing::new);
                match opened {
                    Some(pt) => serde_json::from_slice(&pt)?,
                    None => {
                        // Sealed under another CMK (the profile was set up
                        // again) or damaged. Keep it, out of the way.
                        let secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let aside = path.with_extension(format!("json.unreadable-{secs}"));
                        std::fs::rename(&path, &aside)?;
                        eprintln!(
                            "warning: the key store {} doesn't open with this profile's client master \
                             key (was the profile set up again?). Moved it to {} and starting a new one: \
                             keys shared with you before will be asked for again.",
                            path.display(),
                            aside.display()
                        );
                        StoreData::default()
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreData::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            cmk,
            aad,
            data,
        })
    }

    fn save(&self) -> Result<()> {
        let pt = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let key = crate::crypto_ops::cmk_subkey(self.cmk.as_slice(), "share-store");
        let ct = aead_seal_aad(&pt, key.as_slice(), &self.aad)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        let out = serde_json::to_vec(&SealedStore {
            v: 1,
            ct: B64.encode(ct),
        })?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Write then rename, so an interrupted write can't leave half a store.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, out)?;
        Session::harden(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// This profile's share identity, created on first use.
    fn identity(&mut self) -> Result<ShareSecret> {
        if let Some(s) = &self.data.identity {
            return ShareSecret::from_stored(s).map_err(crypto_err);
        }
        let s = ShareSecret::generate().map_err(crypto_err)?;
        self.data.identity = Some(s.to_stored().map_err(crypto_err)?);
        self.data.published = None;
        self.save()?;
        Ok(s)
    }

    /// The id of the key held for the item, or `"none"`: the value of the
    /// held-key header on a read.
    pub fn held_key_id(&self, kind: ItemKind, domain: &str, name: &str) -> String {
        self.data
            .keys
            .get(&item_slot(kind, domain, name))
            .map(|k| k.key_id.clone())
            .unwrap_or_else(|| "none".into())
    }

    /// The key held for the item, if it's the one with `key_id`.
    pub fn key_for(
        &self,
        kind: ItemKind,
        domain: &str,
        name: &str,
        key_id: &str,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let k = self.data.keys.get(&item_slot(kind, domain, name))?;
        if k.key_id != key_id {
            return None;
        }
        let raw = Zeroizing::new(B64.decode(&k.dek).ok()?);
        let dek: [u8; 32] = raw.as_slice().try_into().ok()?;
        Some(Zeroizing::new(dek))
    }

    /// Checks a peer's identity against the certificate the server vouches
    /// for and against this store's pin for the name, pinning it on first
    /// use. Refuses an identity that differs from the pinned one.
    fn trust(&mut self, peer: &PublishedIdentity) -> Result<ShareIdentity> {
        let name = &peer.client;
        let sig = B64.decode(&peer.cert_sig).map_err(|_| {
            AppError::Crypto(format!("{name}'s share identity has a malformed signature"))
        })?;
        let fp = share_crypto::verify_identity(
            name,
            &peer.cert_pem,
            &peer.cert_fingerprint,
            &peer.identity,
            &sig,
        )
        .map_err(|e| AppError::Crypto(format!("{name}'s share identity: {e}")))?;
        match self.data.pins.get(name) {
            Some(pinned) if *pinned == fp => {}
            Some(pinned) => {
                return Err(AppError::Crypto(format!(
                "{name}'s share identity has changed: you pinned {}, and the server now has {}. \
                     If {name} set up their profile again, check the new fingerprint with them \
                     (they run `bbk share whoami`), then run `bbk share trust {name} {fp}`.",
                share_crypto::display_fingerprint(pinned),
                share_crypto::display_fingerprint(&fp),
            )))
            }
            None => {
                eprintln!(
                    "pinned {name}'s share identity {} (first use)",
                    share_crypto::display_fingerprint(&fp)
                );
                self.data.pins.insert(name.clone(), fp);
                self.save()?;
            }
        }
        Ok(peer.identity.clone())
    }
}

/// This client's identity, published unless the server already has this
/// identity with this certificate. Returns it with this client's name.
async fn ensure_published(
    bb: &BlackbookClient,
    session: &Session,
    store: &mut KeyStore,
    force: bool,
) -> Result<(ShareSecret, String)> {
    let me = store.identity()?;
    let name = bb.whoami().await?.name;
    let (Some(cert_pem), Some(key_pem)) = (session.cert_pem.as_deref(), session.key_pem.as_deref())
    else {
        return Err(AppError::Config(
            "this profile has no client certificate to sign a share identity with".into(),
        ));
    };
    let cert_fp = crate::tunnel_crypto::cert_fingerprint(cert_pem)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    let marker = format!(
        "{}:{cert_fp}:{}",
        me.identity().fingerprint().map_err(crypto_err)?,
        bb.server_url()
    );
    if force || store.data.published.as_deref() != Some(marker.as_str()) {
        let sig = share_crypto::sign_identity(key_pem, cert_pem, &name, me.identity())
            .map_err(crypto_err)?;
        bb.share_publish_identity(me.identity(), cert_pem, &B64.encode(sig))
            .await?;
        store.data.published = Some(marker);
        store.save()?;
    }
    Ok((me, name))
}

/// Publishes this profile's share identity, best effort: called after login so
/// that others can share keys with this client before it first asks.
pub async fn publish_after_login(bb: &BlackbookClient, session: &Session, profile: &str) {
    let result = async {
        let mut store = KeyStore::open_named(session, profile)?;
        ensure_published(bb, session, &mut store, true).await
    }
    .await;
    if let Err(e) = result {
        eprintln!("note: couldn't publish a share identity yet ({e}); it will be published when first needed");
    }
}

// ---------------------------------------------------------------------------
// Reading an item sealed by someone else
// ---------------------------------------------------------------------------

/// The held-key header value for reading the item, or `None` when this
/// profile can't take part in sharing (no CMK), in which case reads behave
/// as before key sharing.
pub fn held_key(session: &Session, kind: ItemKind, domain: &str, name: &str) -> Option<String> {
    session.cmk_bytes()?;
    KeyStore::open(session)
        .ok()
        .map(|s| s.held_key_id(kind, domain, name))
}

/// The received key for the item, if this client holds the one with `key_id`.
pub fn received_key(
    session: &Session,
    kind: ItemKind,
    domain: &str,
    name: &str,
    key_id: Option<&str>,
) -> Option<Zeroizing<[u8; 32]>> {
    KeyStore::open(session)
        .ok()?
        .key_for(kind, domain, name, key_id?)
}

/// What happened after the server said the key was needed.
pub enum KeyOutcome {
    /// The waiting share was collected: read again.
    Received,
    /// No share was waiting; the sealer has been asked for one.
    Requested { sealer: String },
}

/// Handles a `KeyNeeded` answer: collects the waiting share if there is one,
/// otherwise asks the sealer for one.
pub async fn on_key_needed(
    bb: &BlackbookClient,
    session: &Session,
    kind: ItemKind,
    name: &str,
    share_ready: bool,
) -> Result<KeyOutcome> {
    let mut store = KeyStore::open(session)?;
    let (me, my_name) = ensure_published(bb, session, &mut store, false).await?;
    if share_ready {
        if let Some(p) = bb.share_pickup(kind.as_str(), name).await? {
            // The signature covers the item the share is for, so a share for
            // another item couldn't pass as this one; still, refuse it rather
            // than file it away.
            if p.kind != kind || p.name != name || p.domain != bb.domain() {
                return Err(AppError::Crypto(format!(
                    "the server returned a key share for {} '{}' in '{}' when asked for '{name}'",
                    p.kind.as_str(),
                    p.name,
                    p.domain
                )));
            }
            receive(&mut store, &me, &my_name, &p)?;
            bb.share_ack(&p.share_id).await?;
            return Ok(KeyOutcome::Received);
        }
    }
    let sealer = match bb.share_request(kind.as_str(), name).await {
        Ok(s) => s,
        // The server lost the identity (a database restore, say): publish
        // it again and retry once.
        Err(ClientError::Api {
            status: 409,
            message,
        }) if message.ends_with("[no_identity]") => {
            ensure_published(bb, session, &mut store, true).await?;
            bb.share_request(kind.as_str(), name).await?
        }
        Err(e) => return Err(e.into()),
    };
    Ok(KeyOutcome::Requested { sealer })
}

/// Opens a collected share and keeps its key.
fn receive(
    store: &mut KeyStore,
    me: &ShareSecret,
    my_name: &str,
    p: &PickupResponse,
) -> Result<()> {
    let sender = store.trust(&p.sender)?;
    let ctx = ShareContext {
        domain: &p.domain,
        kind: p.kind.as_str(),
        name: &p.name,
        key_id: &p.key_id,
        sender: &p.sender.client,
        recipient: my_name,
    };
    let blob = B64
        .decode(&p.share)
        .map_err(|_| AppError::Crypto("the key share isn't valid base64".into()))?;
    let dek = share_crypto::open(me, &sender, &ctx, &blob).map_err(crypto_err)?;
    store.data.keys.insert(
        item_slot(p.kind, &p.domain, &p.name),
        ReceivedKey {
            key_id: p.key_id.clone(),
            dek: B64.encode(dek.as_slice()),
            from: p.sender.client.clone(),
        },
    );
    store.save()?;
    eprintln!("received the key to '{}' from {}", p.name, p.sender.client);
    Ok(())
}

// ---------------------------------------------------------------------------
// Sending keys for items this client sealed
// ---------------------------------------------------------------------------

/// Unwraps an item's data key from its envelope header with this profile's
/// CMK (envelope mode 0: the CMK wraps the key directly; see main.rs).
fn unwrap_with_cmk(header: &[u8], cmk: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let bad = || AppError::Crypto("malformed envelope header".into());
    match crate::share_api::envelope_seal(header) {
        Some((crate::share_api::Seal::Cmk, end)) => {
            let salt_len = header[14] as usize;
            let wrapped = header.get(15 + salt_len + 4..end).ok_or_else(bad)?;
            let dek = Zeroizing::new(aead_open(wrapped, cmk).map_err(|_| {
                AppError::Crypto(
                    "this profile's client master key doesn't open the item's key (was it sealed from another profile?)"
                        .into(),
                )
            })?);
            let dek: [u8; 32] = dek.as_slice().try_into().map_err(|_| bad())?;
            Ok(Zeroizing::new(dek))
        }
        _ => Err(bad()),
    }
}

#[derive(Default)]
struct DeliverReport {
    sent: Vec<String>,
    skipped: Vec<String>,
}

/// Delivers the given requests: unwraps each item's key, encrypts it to the
/// recipient's pinned identity, and hands it to the server.
async fn deliver(
    bb: &BlackbookClient,
    session: &Session,
    store: &mut KeyStore,
    requests: &[RequestView],
) -> Result<DeliverReport> {
    let (me, my_name) = ensure_published(bb, session, store, false).await?;
    let mut report = DeliverReport::default();
    for r in requests {
        let what = format!("'{}' to {}", r.name, r.recipient);
        let result: Result<()> = async {
            if let Some(why) = &r.blocked {
                return Err(AppError::Client(why.clone()));
            }
            let peer = r.recipient_identity.as_ref().ok_or_else(|| {
                AppError::Client(format!(
                    "{} hasn't published a share identity yet; it's published when they log in or read the item",
                    r.recipient
                ))
            })?;
            let recipient = store.trust(peer)?;
            let header = B64
                .decode(r.header.as_deref().unwrap_or_default())
                .map_err(|_| AppError::Crypto("malformed envelope header".into()))?;
            let dek = unwrap_with_cmk(&header, store.cmk.as_slice())?;
            if share_crypto::key_id(dek.as_slice()) != r.key_id {
                return Err(AppError::Crypto(
                    "the item's key doesn't match its recorded key id".into(),
                ));
            }
            let ctx = ShareContext {
                domain: &r.domain,
                kind: r.kind.as_str(),
                name: &r.name,
                key_id: &r.key_id,
                sender: &my_name,
                recipient: &r.recipient,
            };
            let blob = share_crypto::seal(&me, &recipient, &ctx, &dek).map_err(crypto_err)?;
            bb.share_deliver(&r.id, &r.key_id, &B64.encode(blob)).await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => report.sent.push(what),
            Err(e) => report.skipped.push(format!("{what}: {e}")),
        }
    }
    Ok(report)
}

fn print_report(report: &DeliverReport) {
    for s in &report.sent {
        eprintln!("shared the key to {s}");
    }
    for s in &report.skipped {
        eprintln!("not shared yet: {s}");
    }
}

/// After a store or a grant: delivers the requests the server says this
/// client should fulfil now. Failures are reported, not returned: the store
/// or grant itself succeeded, and `bbk share sync` can finish the job.
pub async fn deliver_now(bb: &BlackbookClient, session: &Session, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let result = async {
        let mut store = KeyStore::open(session)?;
        let pending: Vec<RequestView> = bb
            .share_requests()
            .await?
            .into_iter()
            .filter(|r| ids.contains(&r.id))
            .collect();
        deliver(bb, session, &mut store, &pending).await
    }
    .await;
    match result {
        Ok(report) => print_report(&report),
        Err(e) => eprintln!("couldn't share the key yet ({e}); run `bbk share sync` to retry"),
    }
}

/// Prints what granting a read rule found among external items, and
/// delivers the keys the granting client sealed itself.
pub async fn after_grant(bb: &BlackbookClient, session: &Session, sharing: &serde_json::Value) {
    let Ok(s) = serde_json::from_value::<crate::share_api::GrantSharing>(sharing.clone()) else {
        return;
    };
    let n = |count: usize, one: &str, many: &str| {
        if count == 1 {
            one.to_string()
        } else {
            format!("{count} {many}")
        }
    };
    if s.already > 0 {
        eprintln!(
            "external items: {} already held",
            n(s.already, "one key is", "keys are")
        );
    }
    for w in &s.waiting {
        eprintln!(
            "external items: {} waiting on {}, who runs `bbk share sync` to send {}",
            n(w.requests, "one key request is", "key requests are"),
            w.sealer,
            if w.requests == 1 { "it" } else { "them" }
        );
    }
    if s.passphrase_sealed > 0 {
        eprintln!(
            "external items: {} sealed with a passphrase; readers need that passphrase from its owner",
            n(s.passphrase_sealed, "one is", "are")
        );
    }
    if s.resident > 0 {
        eprintln!(
            "external items: {} resident {}, whose ciphertext is only on the owner's disk; they can't be shared through the server",
            n(s.resident, "one is a", "are"),
            if s.resident == 1 { "file" } else { "files" }
        );
    }
    if s.legacy > 0 {
        eprintln!(
            "external items: {} sealed before key sharing; whoever stored {} runs `bbk rekey NAME` (or `bbk file rekey NAME`) to make {} shareable",
            n(s.legacy, "one was", "were"),
            if s.legacy == 1 { "it" } else { "them" },
            if s.legacy == 1 { "it" } else { "them" }
        );
    }
    deliver_now(bb, session, &s.yours).await;
}

// ---------------------------------------------------------------------------
// `bbk share`
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum ShareCmd {
    /// Show this client's share identity fingerprint, for others to check
    /// against what they pinned. Also publishes it.
    Whoami,
    /// List the key requests waiting on you: others who may read items you
    /// sealed and need their keys.
    Ls,
    /// Send the keys others asked for, for items you sealed. Asks before
    /// sending unless --yes.
    Sync {
        /// Only requests from this client.
        #[arg(long)]
        to: Option<String>,
        /// Don't ask for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Only show what would be sent.
        #[arg(long)]
        dry_run: bool,
    },
    /// Decline a key request (its id is in `bbk share ls`).
    Reject { id: String },
    /// Accept a new share identity for CLIENT, after checking FINGERPRINT with
    /// them out of band. Needed when a client set up its profile again.
    Trust { client: String, fingerprint: String },
}

fn print_requests(requests: &[RequestView]) {
    if requests.is_empty() {
        println!("(no key requests waiting on you)");
        return;
    }
    for r in requests {
        let note = match (&r.blocked, &r.recipient_identity) {
            (Some(why), _) => format!("  [blocked: {why}]"),
            (None, None) => "  [waiting for them to publish a share identity]".to_string(),
            (None, Some(_)) => String::new(),
        };
        println!(
            "{}  {} {}/{} → {}  ({}){note}",
            r.id,
            r.kind.as_str(),
            r.domain,
            r.name,
            r.recipient,
            &r.created_at[..r.created_at.len().min(19)]
        );
    }
}

fn confirm(question: &str) -> Result<bool> {
    use std::io::IsTerminal;
    if crate::credstore::prompts_suppressed() || !std::io::stdin().is_terminal() {
        return Err(AppError::Config(
            "not sending keys without confirmation: pass --yes".into(),
        ));
    }
    eprint!("{question} [y/N] ");
    let answer = crate::read_stdin_line();
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

pub async fn cmd_share(cmd: ShareCmd) -> Result<()> {
    let session = Session::load()?;
    let bb = crate::build_client(&session, None, None)?;
    match cmd {
        ShareCmd::Whoami => {
            let mut store = KeyStore::open(&session)?;
            let (me, name) = ensure_published(&bb, &session, &mut store, true).await?;
            let fp = me.identity().fingerprint().map_err(crypto_err)?;
            println!("{name}: {}", share_crypto::display_fingerprint(&fp));
        }
        ShareCmd::Ls => print_requests(&bb.share_requests().await?),
        ShareCmd::Sync { to, yes, dry_run } => {
            let requests: Vec<RequestView> = bb
                .share_requests()
                .await?
                .into_iter()
                .filter(|r| to.as_deref().map_or(true, |t| r.recipient == t))
                .collect();
            print_requests(&requests);
            if requests.is_empty() || dry_run {
                return Ok(());
            }
            let recipients: std::collections::BTreeSet<&str> =
                requests.iter().map(|r| r.recipient.as_str()).collect();
            if !yes
                && !confirm(&format!(
                    "Send {} {} to {}?",
                    requests.len(),
                    if requests.len() == 1 { "key" } else { "keys" },
                    recipients.into_iter().collect::<Vec<_>>().join(", ")
                ))?
            {
                println!("nothing sent");
                return Ok(());
            }
            let mut store = KeyStore::open(&session)?;
            let report = deliver(&bb, &session, &mut store, &requests).await?;
            print_report(&report);
            if !report.skipped.is_empty() && report.sent.is_empty() {
                return Err(AppError::Client("no keys were sent".into()));
            }
        }
        ShareCmd::Reject { id } => {
            bb.share_reject(&id).await?;
            println!("rejected request {id}");
        }
        ShareCmd::Trust {
            client: name,
            fingerprint,
        } => {
            let fp = share_crypto::parse_fingerprint(&fingerprint).ok_or_else(|| {
                AppError::Config("a fingerprint is 64 hex digits (spaces allowed)".into())
            })?;
            let mut store = KeyStore::open(&session)?;
            let old = store.data.pins.insert(name.clone(), fp.clone());
            store.save()?;
            match old {
                Some(o) if o != fp => println!(
                    "{name}: now trusting {} (was {})",
                    share_crypto::display_fingerprint(&fp),
                    share_crypto::display_fingerprint(&o)
                ),
                _ => println!(
                    "{name}: trusting {}",
                    share_crypto::display_fingerprint(&fp)
                ),
            }
        }
    }
    Ok(())
}
