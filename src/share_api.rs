//! Key sharing for external items: the server side.
//!
//! The cryptography, and what it guarantees, is in [`crate::share_crypto`].
//! The server never holds a data key, and every share is encrypted to its
//! recipient, so all it does here is keep records and route them:
//!
//! - **Identities.** It stores each client's published share identity after
//!   checking that the client's registered certificate signed it.
//! - **Requests.** A client that may read an external item, but doesn't hold
//!   its current key, asks for it. The request goes to whoever sealed the
//!   item (its `sealed_by`), who fulfils it with `bbk share sync`. Granting a
//!   read rule creates requests for every external item the rule covers.
//! - **Shares.** The sealer delivers the key encrypted to the recipient. The
//!   server holds it, sealed again under its metadata key at rest, until the
//!   recipient confirms it has stored the key, then deletes it.
//! - **Holders.** It remembers who received which key, so that when the
//!   sealer stores a new value those clients are asked again automatically.
//! - **Rotations.** Every change to who may read an item calls for a new key:
//!   - a client that gains access gets a key made after it did;
//!   - a client that loses access keeps only a key that no longer opens
//!     anything the server holds.
//!
//!   The server can't make a new key itself, so it records the rotation as
//!   due and refuses to deliver the old key. The sealer's client rotates the
//!   item with `bbk share sync`, re-encrypting it under a new key that is
//!   then delivered to everyone who still reads it. A passphrase-sealed item
//!   is rotated by hand: its owner changes the passphrase, and the record
//!   reminds them until the item is stored again.
//!
//! It also enforces who may take part. Only the item's sealer can deliver,
//! and only while it can still read the item. A recipient must be a member of
//! the domain with a read rule for the item, both when a share is delivered
//! and when it's collected. Requests and uncollected shares expire after
//! [`SHARE_TTL_DAYS`].
//!
//! Collecting a share needs only a read rule that allows the caller now, not
//! the item's other gates (MFA, K-of-N approval, read limits): a share is the
//! data key alone, which is useless without the ciphertext, and the
//! ciphertext is only ever served by a read that passes every gate.

use actix_web::http::StatusCode;
use actix_web::{web, HttpResponse, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::auth::{self, acl_check, audit, AuditStatus, AuthenticatedClient};
use crate::blackbook_core::{AclAction, Id};
use crate::server::{
    dec_field, dec_str, enc_field, err, name_id_hex, resolve_and_gate_domain, AppState, DomainQuery,
};
use crate::share_crypto::{self, ShareIdentity};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How long a request, or a share nobody has collected, is kept.
pub const SHARE_TTL_DAYS: i32 = 30;

/// The request header in which a reader names the key id it holds for the
/// item. See [`key_needed`].
pub const HELD_KEY_HEADER: &str = "X-Blackbook-Held-Key";

/// The request header in which a sealer names the key it is rotating, on the
/// read that fetches the item to re-encrypt it. See [`rotation_read`].
pub const ROTATE_HEADER: &str = "X-Blackbook-Rotate";

fn internal(e: impl std::fmt::Display) -> actix_web::Error {
    actix_web::error::ErrorInternalServerError(e.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Secret,
    File,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Secret => "secret",
            ItemKind::File => "file",
        }
    }
}

/// How an external item's data key is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seal {
    /// Wrapped under the sealer's client master key: shareable.
    Cmk,
    /// Wrapped under a passphrase. A reader needs the passphrase, which isn't
    /// something to share through the server.
    Passphrase,
    /// A resident file, whose ciphertext lives on the sealer's disk.
    Resident,
}

/// Envelope layout (main.rs `ext_encode_v2`): version, mode, three 4-byte
/// Argon2 costs, salt length and salt, wrapped-key length and wrapped key,
/// then the ciphertext. Returns how the key is sealed and where the
/// ciphertext starts. Version 1 envelopes are always passphrase-sealed.
pub fn envelope_seal(buf: &[u8]) -> Option<(Seal, usize)> {
    match buf.first()? {
        1 => Some((Seal::Passphrase, 0)),
        2 => {
            let mode = *buf.get(1)?;
            let salt_len = *buf.get(14)? as usize;
            let p = 15 + salt_len;
            let wrapped_len = u32::from_be_bytes(buf.get(p..p + 4)?.try_into().ok()?) as usize;
            let end = p + 4 + wrapped_len;
            if buf.len() < end {
                return None;
            }
            let seal = if mode == 0 {
                Seal::Cmk
            } else {
                Seal::Passphrase
            };
            Some((seal, end))
        }
        _ => None,
    }
}

/// The key id to record for a stored item: the client's, when the envelope is
/// sealed under its CMK. Anything else has no key to share, so gets none.
pub(crate) fn stored_key_id(
    envelope: Option<&[u8]>,
    key_id: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    let Some(k) = key_id else {
        return Ok(None);
    };
    if k.len() != 64 || !k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("key_id must be 64 lowercase hex digits".into());
    }
    Ok(match envelope.and_then(envelope_seal) {
        Some((Seal::Cmk, _)) => Some(k.to_string()),
        _ => None,
    })
}

/// What sharing needs to know about an external item.
pub(crate) struct Item {
    pub kind: ItemKind,
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub sealed_by: Option<String>,
    pub key_id: Option<String>,
    pub seal: Seal,
    /// The envelope up to its ciphertext: what the sealer needs to unwrap the
    /// data key, and nothing of the value. CMK-sealed items only.
    pub header: Option<Vec<u8>>,
    /// `no_overwrite`: the item can't be stored again, so its key can't be
    /// rotated.
    pub immutable: bool,
}

impl Item {
    fn item_key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.id)
    }
    fn secret_id(&self) -> Option<&str> {
        (self.kind == ItemKind::Secret).then_some(self.id.as_str())
    }
    fn page_id(&self) -> Option<&str> {
        (self.kind == ItemKind::File).then_some(self.id.as_str())
    }
    /// Sealed under a CMK by a known client, with a recorded key id. Items
    /// sealed before key sharing have neither until they're stored again.
    fn shareable(&self) -> bool {
        self.seal == Seal::Cmk && self.sealed_by.is_some() && self.key_id.is_some()
    }
    /// Whether a change in who may read the item calls for a rotation: a new
    /// key from the sealer's client, or a new passphrase from its owner.
    fn rotatable(&self) -> bool {
        !self.immutable
            && match self.seal {
                Seal::Cmk => self.shareable(),
                Seal::Passphrase => self.sealed_by.is_some(),
                Seal::Resident => false,
            }
    }
}

type SecretRow = (
    String,
    String,
    Vec<u8>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    bool,
);
type PageRow = (
    String,
    String,
    Vec<u8>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    i16,
    bool,
);

const SECRET_COLS: &str =
    "resource_id, domain_id, resource_name_enc, sealed_by, key_id, external_envelope,
     COALESCE((flags->>'no_overwrite')::boolean, false)
     FROM blackbook_secrets WHERE is_external AND exhausted_at IS NULL";
// Files: kind 1 is external-key, kind 2 resident (stored with is_external
// false, since the server holds no ciphertext for it).
const PAGE_COLS: &str = "id, domain_id, name_enc, sealed_by, key_id, external_meta, external_kind,
     COALESCE((flags->>'no_overwrite')::boolean, false)
     FROM blackbook_pages WHERE external_kind IN (1, 2) AND exhausted_at IS NULL";

fn secret_item(state: &AppState, r: SecretRow) -> Option<Item> {
    let (id, domain_id, name_enc, sealed_by, key_id, at_rest, immutable) = r;
    let name = dec_str(&state.metadata_enc_key, &name_enc).ok()?;
    let envelope = dec_field(&state.metadata_enc_key, &at_rest?).ok()?;
    let (seal, header_end) = envelope_seal(&envelope)?;
    let header = (seal == Seal::Cmk).then(|| envelope[..header_end].to_vec());
    Some(Item {
        kind: ItemKind::Secret,
        id,
        domain_id,
        name,
        sealed_by,
        key_id,
        seal,
        header,
        immutable,
    })
}

fn page_item(state: &AppState, r: PageRow) -> Option<Item> {
    let (id, domain_id, name_enc, sealed_by, key_id, meta, kind, immutable) = r;
    let name = dec_str(&state.metadata_enc_key, &name_enc).ok()?;
    let (seal, header) = if kind == 2 {
        (Seal::Resident, None)
    } else {
        // A file's meta is the envelope header alone: its ciphertext is the blob.
        let meta = meta?;
        let (seal, _) = envelope_seal(&meta)?;
        (seal, (seal == Seal::Cmk).then_some(meta))
    };
    Some(Item {
        kind: ItemKind::File,
        id,
        domain_id,
        name,
        sealed_by,
        key_id,
        seal,
        header,
        immutable,
    })
}

/// The external item `name` of `kind` in `domain_id`. `None` if there's no
/// such item, or it isn't external, or its data has been scrubbed.
pub(crate) async fn find_item(
    state: &AppState,
    domain_id: &str,
    kind: ItemKind,
    name: &str,
) -> sqlx::Result<Option<Item>> {
    let name_id = name_id_hex(&state.name_index_key, domain_id, name);
    Ok(match kind {
        ItemKind::Secret => sqlx::query_as::<_, SecretRow>(&format!(
            "SELECT {SECRET_COLS} AND domain_id = $1 AND name_id = $2"
        ))
        .bind(domain_id)
        .bind(&name_id)
        .fetch_optional(&state.db)
        .await?
        .and_then(|r| secret_item(state, r)),
        ItemKind::File => sqlx::query_as::<_, PageRow>(&format!(
            "SELECT {PAGE_COLS} AND domain_id = $1 AND name_id = $2"
        ))
        .bind(domain_id)
        .bind(&name_id)
        .fetch_optional(&state.db)
        .await?
        .and_then(|r| page_item(state, r)),
    })
}

/// The external item a request, share or holder row refers to.
async fn item_by_ref(
    state: &AppState,
    secret_id: Option<&str>,
    page_id: Option<&str>,
) -> sqlx::Result<Option<Item>> {
    if let Some(id) = secret_id {
        let r =
            sqlx::query_as::<_, SecretRow>(&format!("SELECT {SECRET_COLS} AND resource_id = $1"))
                .bind(id)
                .fetch_optional(&state.db)
                .await?;
        return Ok(r.and_then(|r| secret_item(state, r)));
    }
    if let Some(id) = page_id {
        let r = sqlx::query_as::<_, PageRow>(&format!("SELECT {PAGE_COLS} AND id = $1"))
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
        return Ok(r.and_then(|r| page_item(state, r)));
    }
    Ok(None)
}

/// Every external item in a domain.
async fn items_in_domain(state: &AppState, domain_id: &str) -> sqlx::Result<Vec<Item>> {
    let secrets =
        sqlx::query_as::<_, SecretRow>(&format!("SELECT {SECRET_COLS} AND domain_id = $1"))
            .bind(domain_id)
            .fetch_all(&state.db)
            .await?;
    let pages = sqlx::query_as::<_, PageRow>(&format!("SELECT {PAGE_COLS} AND domain_id = $1"))
        .bind(domain_id)
        .fetch_all(&state.db)
        .await?;
    Ok(secrets
        .into_iter()
        .filter_map(|r| secret_item(state, r))
        .chain(pages.into_iter().filter_map(|r| page_item(state, r)))
        .collect())
}

/// An active client by id, as the ACL functions want it.
async fn client_by_id(state: &AppState, id: &str) -> sqlx::Result<Option<AuthenticatedClient>> {
    let row: Option<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT name_enc, role FROM blackbook_clients WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.and_then(|(name_enc, role)| {
        Some(AuthenticatedClient {
            id: id.to_string(),
            name: dec_str(&state.metadata_enc_key, &name_enc).ok()?,
            role,
            auth_method: auth::AuthMethod::MutualTlsAndToken,
        })
    }))
}

async fn client_name(state: &AppState, id: &str) -> String {
    match client_by_id(state, id).await {
        Ok(Some(c)) => c.name,
        _ => "(unknown client)".to_string(),
    }
}

async fn domain_name(state: &AppState, id: &str) -> sqlx::Result<String> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT name_enc FROM blackbook_domains WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row
        .and_then(|(n,)| dec_str(&state.metadata_enc_key, &n).ok())
        .unwrap_or_default())
}

/// Whether `client` can read the item now: a member of the domain (or an
/// admin) whom the ACL allows to read it. Doesn't count a use.
async fn can_read_now(
    state: &AppState,
    client: &AuthenticatedClient,
    item: &Item,
) -> sqlx::Result<bool> {
    if !auth::domain_member(&state.db, client, &item.domain_id).await? {
        return Ok(false);
    }
    let d = acl_check(
        &state.db,
        &state.metadata_enc_key,
        client,
        &item.domain_id,
        &item.name,
        AclAction::Read,
    )
    .await?;
    Ok(d.is_allowed())
}

/// Whether the sealer may hand `recipient_id` the item's key: an active
/// client, a member of the domain (or an admin), with a read rule for the item
/// that hasn't expired or been used up. Unlike `acl_check`, it ignores the
/// rule's start time, schedule and rate limit. Those decide when the
/// recipient may read, which the collection and the read itself enforce, not
/// whether the sealer may deliver now.
async fn may_receive(state: &AppState, recipient_id: &str, item: &Item) -> sqlx::Result<bool> {
    let names = [item.name.as_str()];
    Ok(receivable(state, recipient_id, &item.domain_id, &names).await?[0])
}

/// [`may_receive`] for several items of one domain at once: one answer per
/// name, in order.
async fn receivable(
    state: &AppState,
    recipient_id: &str,
    domain_id: &str,
    names: &[&str],
) -> sqlx::Result<Vec<bool>> {
    let all = |v: bool| Ok(vec![v; names.len()]);
    let Some(r) = client_by_id(state, recipient_id).await? else {
        return all(false);
    };
    if r.is_admin() || auth::domain_admin(&state.db, &r, domain_id).await? {
        return all(true);
    }
    if !auth::domain_member(&state.db, &r, domain_id).await? {
        return all(false);
    }
    let patterns: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT a.pattern_enc FROM blackbook_acl a
         WHERE a.domain_id = $1
           AND (a.client_id = $2
             OR a.group_domain_id IN
                (SELECT domain_id FROM blackbook_domain_members WHERE client_id = $2))
           AND (a.actions & $3) <> 0
           AND (a.expires_at IS NULL OR a.expires_at > CURRENT_TIMESTAMP)
           AND (a.max_uses IS NULL OR a.use_count < a.max_uses)",
    )
    .bind(domain_id)
    .bind(recipient_id)
    .bind(auth::action_bit(AclAction::Read))
    .fetch_all(&state.db)
    .await?;
    let patterns: Vec<String> = patterns
        .iter()
        .filter_map(|(p,)| dec_str(&state.metadata_enc_key, p).ok())
        .collect();
    Ok(names
        .iter()
        .map(|n| patterns.iter().any(|p| auth::sql_like_match(p, n)))
        .collect())
}

/// A client's name whether or not it has been revoked, for reports about who
/// lost access.
async fn any_client_name(state: &AppState, id: &str) -> String {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT name_enc FROM blackbook_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    row.and_then(|(n,)| dec_str(&state.metadata_enc_key, &n).ok())
        .unwrap_or_else(|| "(unknown client)".to_string())
}

/// Records (or refreshes) `recipient_id`'s request for the item's key and
/// returns its id.
async fn upsert_request(state: &AppState, item: &Item, recipient_id: &str) -> sqlx::Result<String> {
    Ok(upsert_request_new(state, item, recipient_id).await?.0)
}

/// [`upsert_request`], also saying whether the request is new rather than a
/// refreshed one (`xmax` is 0 for a row the INSERT created).
async fn upsert_request_new(
    state: &AppState,
    item: &Item,
    recipient_id: &str,
) -> sqlx::Result<(String, bool)> {
    sqlx::query_as(
        "INSERT INTO blackbook_share_requests
             (id, secret_id, page_id, item_key, recipient_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP + make_interval(days => $6))
         ON CONFLICT (recipient_id, item_key)
         DO UPDATE SET expires_at = EXCLUDED.expires_at
         RETURNING id, (xmax = 0)",
    )
    .bind(Id::new(12).encode())
    .bind(item.secret_id())
    .bind(item.page_id())
    .bind(item.item_key())
    .bind(recipient_id)
    .bind(SHARE_TTL_DAYS)
    .fetch_one(&state.db)
    .await
}

/// A request for the item's key from a client that doesn't hold it: the
/// client has gained access, so the key it gets must be a new one.
async fn request_new_reader(
    state: &AppState,
    item: &Item,
    recipient_id: &str,
) -> sqlx::Result<String> {
    let (id, new) = upsert_request_new(state, item, recipient_id).await?;
    if new && !holds_current_key(state, item, recipient_id).await? {
        mark_rotation(state, item, &[recipient_id.to_string()], &[]).await?;
    }
    Ok(id)
}

/// Whether `recipient_id` has already received the item's current key.
async fn holds_current_key(
    state: &AppState,
    item: &Item,
    recipient_id: &str,
) -> sqlx::Result<bool> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM blackbook_share_holders
         WHERE recipient_id = $1 AND item_key = $2 AND key_id = $3",
    )
    .bind(recipient_id)
    .bind(item.item_key())
    .bind(&item.key_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

/// A client's published identity, with what a peer needs to check it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedIdentity {
    pub client: String,
    pub identity: ShareIdentity,
    /// The certificate that signed the identity, and its signature (base64).
    pub cert_pem: String,
    pub cert_sig: String,
    /// The certificate fingerprint the server has on record for the client
    /// now. The identity is valid only if `cert_pem` has this fingerprint.
    pub cert_fingerprint: String,
}

async fn load_identity(
    state: &AppState,
    client_id: &str,
) -> sqlx::Result<Option<PublishedIdentity>> {
    let row: Option<(
        sqlx::types::Json<ShareIdentity>,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT i.identity, i.cert_pem, i.cert_sig, c.name_enc, c.cert_fingerprint
             FROM blackbook_share_identities i JOIN blackbook_clients c ON c.id = i.client_id
             WHERE i.client_id = $1 AND c.revoked_at IS NULL",
    )
    .bind(client_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(
        row.and_then(|(identity, cert_pem, cert_sig, name_enc, fp)| {
            Some(PublishedIdentity {
                client: dec_str(&state.metadata_enc_key, &name_enc).ok()?,
                identity: identity.0,
                cert_pem,
                cert_sig: B64.encode(cert_sig),
                cert_fingerprint: fp?,
            })
        }),
    )
}

async fn audit_share(
    state: &AppState,
    client: &AuthenticatedClient,
    action: &str,
    resource: Option<&str>,
    status: AuditStatus,
    message: Option<&str>,
) {
    audit(
        &state.db,
        &state.audit_hmac_key,
        &state.metadata_enc_key,
        Some(&client.id),
        action,
        resource,
        status,
        message,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Rotations
// ---------------------------------------------------------------------------

/// Records that the item needs rotating because the clients in `granted`
/// gained, or those in `revoked` lost, access to it. That means a new key for
/// a CMK-sealed item, or a new passphrase for a passphrase-sealed one. The
/// record is kept until the item is stored again (see [`after_store`]). It
/// holds client ids, not names, so it keeps no plaintext identifiers.
async fn mark_rotation(
    state: &AppState,
    item: &Item,
    granted: &[String],
    revoked: &[String],
) -> sqlx::Result<()> {
    if !item.rotatable() || (granted.is_empty() && revoked.is_empty()) {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO blackbook_key_rotations (item_key, secret_id, page_id, key_id, granted, revoked)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (item_key) DO UPDATE SET
           key_id = EXCLUDED.key_id,
           granted = ARRAY(SELECT DISTINCT unnest(blackbook_key_rotations.granted || EXCLUDED.granted)),
           revoked = ARRAY(SELECT DISTINCT unnest(blackbook_key_rotations.revoked || EXCLUDED.revoked))",
    )
    .bind(item.item_key())
    .bind(item.secret_id())
    .bind(item.page_id())
    .bind(&item.key_id)
    .bind(granted)
    .bind(revoked)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Whether the item's current key must be rotated before it's shared.
async fn rotation_due(state: &AppState, item: &Item) -> sqlx::Result<bool> {
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM blackbook_key_rotations WHERE item_key = $1 AND key_id = $2")
            .bind(item.item_key())
            .bind(&item.key_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.is_some())
}

/// Catches access that was lost without an event the server hooks, such as a
/// rule that expired or ran out of uses. A client that holds the item's
/// current key, and may no longer receive it, makes a rotation due.
async fn sweep(state: &AppState, item: &Item) -> sqlx::Result<()> {
    if !item.shareable() || !item.rotatable() {
        return Ok(());
    }
    let holders: Vec<(String,)> = sqlx::query_as(
        "SELECT recipient_id FROM blackbook_share_holders
         WHERE item_key = $1 AND key_id = $2 AND recipient_id <> $3",
    )
    .bind(item.item_key())
    .bind(&item.key_id)
    .bind(item.sealed_by.as_deref().unwrap_or_default())
    .fetch_all(&state.db)
    .await?;
    let mut lost = Vec::new();
    for (h,) in holders {
        if !may_receive(state, &h, item).await? {
            lost.push(h);
        }
    }
    mark_rotation(state, item, &[], &lost).await
}

/// Whether a read that carries the [`ROTATE_HEADER`] is the sealer fetching
/// the item to rotate its key. It is when the caller sealed the item,
/// `rotating` is its current key, and a rotation of that key is due.
///
/// Such a read passes every gate any read does, but isn't counted against the
/// item's read limits: counting it would let a rotation use up a
/// `delete_on_read` item. Any other read with the header is refused
/// ([`not_rotating`]) rather than counted as a read the client didn't mean to
/// make.
pub(crate) async fn rotation_read(
    state: &AppState,
    kind: ItemKind,
    item_id: &str,
    caller: &AuthenticatedClient,
    sealed_by: Option<&str>,
    key_id: Option<&str>,
    rotating: &str,
) -> sqlx::Result<bool> {
    if sealed_by != Some(caller.id.as_str()) || key_id != Some(rotating) {
        return Ok(false);
    }
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM blackbook_key_rotations WHERE item_key = $1 AND key_id = $2")
            .bind(format!("{}:{item_id}", kind.as_str()))
            .bind(rotating)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.is_some())
}

/// The answer to a read with the [`ROTATE_HEADER`] that isn't a rotation.
pub(crate) fn not_rotating(name: &str) -> HttpResponse {
    err(
        StatusCode::CONFLICT,
        "no_rotation_due",
        format!("no rotation of '{name}' is due on you, for that key"),
    )
}

/// The checks a store that rotates an item's key (`rotates`, the key it
/// replaces) must pass beyond a normal overwrite. The item must be external,
/// sealed by the caller, and still have that key, so a rotation can't
/// overwrite a value someone else stored meanwhile. The new envelope must be
/// sealed under the caller's CMK, with a key id.
pub(crate) fn check_rotation_store(
    name: &str,
    caller: &AuthenticatedClient,
    current: Option<(bool, Option<String>, Option<String>)>,
    rotates: &str,
    new_key_id: Option<&str>,
) -> Option<HttpResponse> {
    rotation_store_refusal(name, &caller.id, current, rotates, new_key_id)
        .map(|(code, msg)| err(StatusCode::CONFLICT, code, msg))
}

/// [`check_rotation_store`]'s decision: the error code and message, if refused.
fn rotation_store_refusal(
    name: &str,
    caller_id: &str,
    current: Option<(bool, Option<String>, Option<String>)>,
    rotates: &str,
    new_key_id: Option<&str>,
) -> Option<(&'static str, String)> {
    let Some((is_external, sealed_by, key_id)) = current else {
        return Some(("not_found", format!("there's no '{name}' to rotate")));
    };
    if !is_external || sealed_by.as_deref() != Some(caller_id) {
        return Some((
            "not_sealer",
            format!("'{name}' isn't an external item you sealed"),
        ));
    }
    if key_id.as_deref() != Some(rotates) {
        return Some((
            "key_changed",
            format!("'{name}' was stored again since its rotation was listed; run `bbk share sync` again"),
        ));
    }
    if new_key_id.is_none() {
        return Some((
            "not_shareable",
            format!("a rotation of '{name}' must seal it under your client master key"),
        ));
    }
    None
}

/// The clients and domains a change to who may read items can affect.
pub(crate) struct Scope {
    clients: Vec<String>,
    domains: Vec<String>,
}

/// Who may receive which external item within a [`Scope`], compared before
/// and after an access change. Pairs are (client id, item key).
pub(crate) struct Access {
    items: HashMap<String, Item>,
    pairs: HashSet<(String, String)>,
}

async fn group_members(state: &AppState, group_domain_id: &str) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT m.client_id FROM blackbook_domain_members m
         JOIN blackbook_clients c ON c.id = m.client_id
         WHERE m.domain_id = $1 AND c.revoked_at IS NULL",
    )
    .bind(group_domain_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

impl Scope {
    /// A rule in `domain_id` for one client, or for the members of a group.
    pub(crate) async fn rule(
        state: &AppState,
        domain_id: &str,
        client_id: Option<&str>,
        group_domain_id: Option<&str>,
    ) -> sqlx::Result<Self> {
        let clients = match (client_id, group_domain_id) {
            (Some(c), _) => vec![c.to_string()],
            (None, Some(g)) => group_members(state, g).await?,
            (None, None) => Vec::new(),
        };
        Ok(Self {
            clients,
            domains: vec![domain_id.to_string()],
        })
    }

    /// A client's membership of a domain. It decides access to the domain's
    /// own items, and through rules naming the domain as a group, to items
    /// in other domains.
    pub(crate) async fn membership(
        state: &AppState,
        domain_id: &str,
        client_id: &str,
    ) -> sqlx::Result<Self> {
        let mut domains = vec![domain_id.to_string()];
        let via_group: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT domain_id FROM blackbook_acl WHERE group_domain_id = $1",
        )
        .bind(domain_id)
        .fetch_all(&state.db)
        .await?;
        domains.extend(
            via_group
                .into_iter()
                .map(|(d,)| d)
                .filter(|d| d != domain_id),
        );
        Ok(Self {
            clients: vec![client_id.to_string()],
            domains,
        })
    }

    /// Everything a client might read: for its revocation.
    pub(crate) async fn client(state: &AppState, client_id: &str) -> sqlx::Result<Self> {
        let domains: Vec<(String,)> = sqlx::query_as("SELECT id FROM blackbook_domains")
            .fetch_all(&state.db)
            .await?;
        Ok(Self {
            clients: vec![client_id.to_string()],
            domains: domains.into_iter().map(|(d,)| d).collect(),
        })
    }

    /// Which of the scope's clients may receive which of its domains' items
    /// now. Only items with a known sealer count, and never the sealer itself.
    pub(crate) async fn access(&self, state: &AppState) -> sqlx::Result<Access> {
        let mut out = Access {
            items: HashMap::new(),
            pairs: HashSet::new(),
        };
        for d in &self.domains {
            let items: Vec<Item> = items_in_domain(state, d)
                .await?
                .into_iter()
                .filter(|i| i.sealed_by.is_some() && i.seal != Seal::Resident)
                .collect();
            if items.is_empty() {
                continue;
            }
            let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
            for c in &self.clients {
                let can = receivable(state, c, d, &names).await?;
                for (item, yes) in items.iter().zip(can) {
                    if yes && item.sealed_by.as_deref() != Some(c.as_str()) {
                        out.pairs.insert((c.clone(), item.item_key()));
                    }
                }
            }
            for item in items {
                out.items.insert(item.item_key(), item);
            }
        }
        Ok(out)
    }
}

/// An item named in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemName {
    pub domain: String,
    pub kind: ItemKind,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealerCount {
    pub sealer: String,
    pub count: usize,
}

/// What a change to who may read external items calls for.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccessChange {
    /// Items the caller sealed whose keys must be rotated. Its client rotates
    /// them right away: making the change was the decision.
    #[serde(default)]
    pub yours: Vec<ItemName>,
    /// Keys other sealers must rotate, with `bbk share sync`.
    #[serde(default)]
    pub waiting: Vec<SealerCount>,
    /// Passphrase-sealed items, by owner, whose passphrase must be changed by
    /// hand.
    #[serde(default)]
    pub by_hand: Vec<SealerCount>,
    /// Immutable items, which can't be stored again, so keep their keys.
    #[serde(default)]
    pub immutable: usize,
}

async fn names_of(state: &AppState, ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        out.push(any_client_name(state, id).await);
    }
    out
}

async fn by_sealer(state: &AppState, counts: BTreeMap<String, usize>) -> Vec<SealerCount> {
    let mut out = Vec::new();
    for (id, count) in counts {
        out.push(SealerCount {
            sealer: any_client_name(state, &id).await,
            count,
        });
    }
    out
}

/// After a change to who may read external items, with `before` taken by
/// [`Scope::access`] just before it: records the rotations the change calls
/// for, and reports them.
/// - A client that lost access while holding an item's current key makes a
///   rotation of that key due. Any request it had waiting, and any share it
///   hadn't collected, are dropped.
/// - A client that gained or lost access to a passphrase-sealed item makes a
///   passphrase change due.
///
/// A client that gains access to a CMK-sealed item makes its rotation due
/// when it asks for the key ([`request_new_reader`]), so an item nobody new
/// reads isn't rotated for nothing.
pub(crate) async fn after_access_change(
    state: &AppState,
    actor: &AuthenticatedClient,
    scope: &Scope,
    before: Access,
) -> sqlx::Result<AccessChange> {
    let after = scope.access(state).await?;
    let mut lost: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut gained: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (c, k) in before.pairs.difference(&after.pairs) {
        lost.entry(k.as_str()).or_default().push(c.clone());
    }
    for (c, k) in after.pairs.difference(&before.pairs) {
        gained.entry(k.as_str()).or_default().push(c.clone());
    }
    let changed: BTreeSet<&str> = lost.keys().chain(gained.keys()).copied().collect();
    let mut out = AccessChange::default();
    let mut waiting: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_hand: BTreeMap<String, usize> = BTreeMap::new();
    let none = Vec::new();
    for k in changed {
        let Some(item) = after.items.get(k).or_else(|| before.items.get(k)) else {
            continue;
        };
        let lost_here = lost.get(k).unwrap_or(&none);
        let gained_here = gained.get(k).unwrap_or(&none);
        let sealer = item.sealed_by.clone().unwrap_or_default();
        match item.seal {
            Seal::Cmk if item.shareable() => {
                let mut held = Vec::new();
                for c in lost_here {
                    if holds_current_key(state, item, c).await? {
                        held.push(c.clone());
                    }
                    for table in ["blackbook_share_requests", "blackbook_key_shares"] {
                        sqlx::query(&format!(
                            "DELETE FROM {table} WHERE recipient_id = $1 AND item_key = $2"
                        ))
                        .bind(c)
                        .bind(k)
                        .execute(&state.db)
                        .await?;
                    }
                }
                if held.is_empty() {
                    continue;
                }
                if item.immutable {
                    out.immutable += 1;
                    continue;
                }
                mark_rotation(state, item, &[], &held).await?;
                if sealer == actor.id {
                    out.yours.push(ItemName {
                        domain: domain_name(state, &item.domain_id).await?,
                        kind: item.kind,
                        name: item.name.clone(),
                    });
                } else {
                    *waiting.entry(sealer).or_default() += 1;
                }
            }
            Seal::Passphrase => {
                if item.immutable {
                    out.immutable += 1;
                    continue;
                }
                mark_rotation(state, item, gained_here, lost_here).await?;
                *by_hand.entry(sealer).or_default() += 1;
            }
            _ => {}
        }
    }
    out.waiting = by_sealer(state, waiting).await;
    out.by_hand = by_sealer(state, by_hand).await;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Hooks called from server.rs
// ---------------------------------------------------------------------------

/// After an external item is stored (sealed_by and key_id are already
/// written): drops shares of any earlier key, and asks for the new one
/// everyone who received an earlier key or had one delivered. Returns those
/// requests' ids. The sealer's client delivers them right away, since these
/// clients already held the item's key. The new key is a rotation, so any
/// rotation that was due is done.
///
/// An item that's no longer shareable (now passphrase-sealed, or not
/// external) loses its requests, holders and rotations. For a passphrase
/// item, being stored again is how its owner changes the passphrase.
pub(crate) async fn after_store(
    state: &AppState,
    kind: ItemKind,
    item_id: &str,
    sealer_id: &str,
) -> sqlx::Result<Vec<String>> {
    let (secret_id, page_id) = match kind {
        ItemKind::Secret => (Some(item_id), None),
        ItemKind::File => (None, Some(item_id)),
    };
    let item_key = format!("{}:{item_id}", kind.as_str());
    let item = item_by_ref(state, secret_id, page_id).await?;
    let Some(item) = item.filter(Item::shareable) else {
        for table in [
            "blackbook_key_shares",
            "blackbook_share_requests",
            "blackbook_share_holders",
            "blackbook_key_rotations",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE item_key = $1"))
                .bind(&item_key)
                .execute(&state.db)
                .await?;
        }
        return Ok(Vec::new());
    };
    // IS DISTINCT FROM: a passphrase reminder from before the item was
    // sealed under a CMK has no key id, and goes too.
    sqlx::query(
        "DELETE FROM blackbook_key_rotations WHERE item_key = $1 AND key_id IS DISTINCT FROM $2",
    )
    .bind(&item_key)
    .bind(&item.key_id)
    .execute(&state.db)
    .await?;
    // A share of an earlier key that its recipient never collected: the
    // sealer gave it that key, so like a holder it's asked for the new one.
    let uncollected: Vec<(String,)> = sqlx::query_as(
        "DELETE FROM blackbook_key_shares WHERE item_key = $1 AND key_id <> $2
         RETURNING recipient_id",
    )
    .bind(&item_key)
    .bind(&item.key_id)
    .fetch_all(&state.db)
    .await?;
    let holders: Vec<(String,)> = sqlx::query_as(
        "SELECT recipient_id FROM blackbook_share_holders
         WHERE item_key = $1 AND key_id <> $2",
    )
    .bind(&item_key)
    .bind(&item.key_id)
    .fetch_all(&state.db)
    .await?;
    let recipients: BTreeSet<String> = holders
        .into_iter()
        .chain(uncollected)
        .map(|(r,)| r)
        .filter(|r| r != sealer_id)
        .collect();
    let mut ids = Vec::new();
    for recipient in recipients {
        if may_receive(state, &recipient, &item).await? {
            ids.push(upsert_request(state, &item, &recipient).await?);
        }
    }
    Ok(ids)
}

/// The 409 a reader gets instead of the item when it's external, sealed by
/// someone else, and the key the reader says it holds (the
/// [`HELD_KEY_HEADER`]) isn't the current one. It's sent before any gate runs
/// or any read is counted, so a reader without the key can't burn a
/// `delete_on_read` or `max_reads` item. If a share is waiting, the client
/// collects it and reads again; otherwise it asks the sealer for one.
pub(crate) async fn key_needed(
    state: &AppState,
    kind: ItemKind,
    item_id: &str,
    name: &str,
    reader: &AuthenticatedClient,
    sealed_by: &str,
    key_id: &str,
) -> Result<HttpResponse> {
    let item_key = format!("{}:{item_id}", kind.as_str());
    let ready: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM blackbook_key_shares
         WHERE recipient_id = $1 AND item_key = $2 AND key_id = $3
           AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(&reader.id)
    .bind(&item_key)
    .bind(key_id)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let sealer = client_name(state, sealed_by).await;
    Ok(HttpResponse::Conflict().json(serde_json::json!({
        "error": "key_needed",
        "message": format!(
            "'{name}' is encrypted client-side by {sealer}, and this client doesn't hold its current key"
        ),
        "request_id": uuid::Uuid::new_v4().to_string(),
        "key_id": key_id,
        "sealer": sealer,
        "share_ready": ready.is_some(),
    })))
}

/// What granting a read rule found among the external items it covers.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GrantSharing {
    /// Requests for items the granting client sealed. Its client delivers
    /// them right away: granting the rule was the decision to share.
    pub yours: Vec<String>,
    /// Requests waiting on other sealers, who run `bbk share sync`.
    pub waiting: Vec<SealerRequests>,
    /// Recipient and item pairs where the recipient already holds the key.
    pub already: usize,
    /// Items sealed with a passphrase. Their readers get it from the owner,
    /// out of band: there is no key for the server to pass on.
    pub out_of_band: usize,
    /// Resident files, whose ciphertext is only on the sealer's disk.
    pub resident: usize,
    /// Items sealed before key sharing existed. Their sealer stores them again
    /// (`put --overwrite`, `rekey`) to make them shareable.
    pub legacy: usize,
    /// Immutable items: they can't be stored again, so their keys are shared
    /// without being rotated first.
    #[serde(default)]
    pub immutable: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealerRequests {
    pub sealer: String,
    pub requests: usize,
}

/// After a rule granting read on `pattern` in `domain_id` is created: asks the
/// sealer of every external item it covers to share the key with each client
/// the rule covers (the client, or every member of the group domain) who may
/// receive it. Each of those clients is a new reader, so the key it gets is a
/// new one: the sealer rotates the item before sending it. `before` is the
/// scope's [`Scope::access`] from just before the rule was created, from which
/// the passphrase items whose readers changed are found.
pub(crate) async fn after_grant(
    state: &AppState,
    granter: &AuthenticatedClient,
    domain_id: &str,
    pattern: &str,
    scope: &Scope,
    before: Access,
) -> sqlx::Result<GrantSharing> {
    after_access_change(state, granter, scope, before).await?;
    let recipients = &scope.clients;
    let mut out = GrantSharing::default();
    let mut waiting: BTreeMap<String, usize> = Default::default();
    for item in items_in_domain(state, domain_id).await? {
        if !auth::sql_like_match(pattern, &item.name) {
            continue;
        }
        match item.seal {
            Seal::Passphrase => {
                out.out_of_band += 1;
                continue;
            }
            Seal::Resident => {
                out.resident += 1;
                continue;
            }
            Seal::Cmk if !item.shareable() => {
                out.legacy += 1;
                continue;
            }
            Seal::Cmk => {}
        }
        let sealer = item.sealed_by.clone().unwrap_or_default();
        let mut requested = false;
        for r in recipients {
            if *r == sealer || !may_receive(state, r, &item).await? {
                continue;
            }
            if holds_current_key(state, &item, r).await? {
                out.already += 1;
                continue;
            }
            requested = true;
            let id = request_new_reader(state, &item, r).await?;
            if sealer == granter.id {
                out.yours.push(id);
            } else {
                *waiting.entry(sealer.clone()).or_default() += 1;
            }
        }
        if requested && item.immutable {
            out.immutable += 1;
        }
    }
    for (sealer_id, requests) in waiting {
        out.waiting.push(SealerRequests {
            sealer: client_name(state, &sealer_id).await,
            requests,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub identity: ShareIdentity,
    pub cert_pem: String,
    /// base64 of the certificate key's signature over the identity binding.
    pub cert_sig: String,
}

/// `PUT /api/v1/share/identity`: publishes the caller's share identity. It
/// must be signed by the certificate the caller is registered with. Publishing
/// the same identity again changes nothing (and isn't audited), so clients
/// publish whenever they're about to use sharing. A new identity, from a
/// profile created again, replaces the old one, and any share waiting for the
/// old identity, which it can no longer open, becomes a request again.
pub async fn publish_identity(
    state: web::Data<AppState>,
    req: web::Json<PublishRequest>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let registered: Option<(Option<String>,)> =
        sqlx::query_as("SELECT cert_fingerprint FROM blackbook_clients WHERE id = $1")
            .bind(&client.id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    let Some(cert_fp) = registered.and_then(|(fp,)| fp) else {
        return Ok(err(
            StatusCode::CONFLICT,
            "no_certificate",
            "this client has no registered certificate to sign its share identity with",
        ));
    };
    let sig = match B64.decode(&req.cert_sig) {
        Ok(s) => s,
        Err(_) => {
            return Ok(err(
                StatusCode::BAD_REQUEST,
                "validation_error",
                "cert_sig is not valid base64",
            ))
        }
    };
    let fingerprint = match share_crypto::verify_identity(
        &client.name,
        &req.cert_pem,
        &cert_fp,
        &req.identity,
        &sig,
    ) {
        Ok(fp) => fp,
        Err(e) => {
            audit_share(
                &state,
                &client,
                "share.identity",
                None,
                AuditStatus::Denied,
                Some(&e.to_string()),
            )
            .await;
            return Ok(err(StatusCode::BAD_REQUEST, "bad_identity", e.to_string()));
        }
    };

    let previous: Option<(String,)> =
        sqlx::query_as("SELECT fingerprint FROM blackbook_share_identities WHERE client_id = $1")
            .bind(&client.id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
    let changed = previous
        .as_ref()
        .map(|(fp,)| *fp != fingerprint)
        .unwrap_or(true);
    sqlx::query(
        "INSERT INTO blackbook_share_identities (client_id, identity, cert_pem, cert_sig, fingerprint)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (client_id) DO UPDATE SET
           identity = EXCLUDED.identity, cert_pem = EXCLUDED.cert_pem,
           cert_sig = EXCLUDED.cert_sig, fingerprint = EXCLUDED.fingerprint,
           updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&client.id)
    .bind(sqlx::types::Json(&req.identity))
    .bind(&req.cert_pem)
    .bind(&sig)
    .bind(&fingerprint)
    .execute(&state.db)
    .await
    .map_err(internal)?;

    if changed {
        if previous.is_some() {
            // Shares encrypted to the old identity can't be opened any more:
            // ask their sealers again.
            let stale: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                "DELETE FROM blackbook_key_shares WHERE recipient_id = $1
                 RETURNING id, secret_id, page_id",
            )
            .bind(&client.id)
            .fetch_all(&state.db)
            .await
            .map_err(internal)?;
            for (_, secret_id, page_id) in stale {
                if let Some(item) = item_by_ref(&state, secret_id.as_deref(), page_id.as_deref())
                    .await
                    .map_err(internal)?
                {
                    upsert_request(&state, &item, &client.id)
                        .await
                        .map_err(internal)?;
                }
            }
        }
        audit_share(
            &state,
            &client,
            "share.identity",
            None,
            AuditStatus::Ok,
            Some(&format!("fingerprint={fingerprint}")),
        )
        .await;
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "fingerprint": fingerprint,
        "changed": changed,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ItemRef {
    pub kind: ItemKind,
    pub name: String,
}

/// Gate shared by the recipient-side endpoints: the domain, the item, and the
/// caller's read permission (not counted as a use).
async fn recipient_gate(
    state: &AppState,
    client: &AuthenticatedClient,
    q: &DomainQuery,
    item: &ItemRef,
    action: &str,
) -> std::result::Result<(Item, String), HttpResponse> {
    let (domain_id, domain_name) = resolve_and_gate_domain(state, client, q).await?;
    let found = find_item(state, &domain_id, item.kind, &item.name)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;
    let Some(found) = found else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("no external {} named '{}'", item.kind.as_str(), item.name),
        ));
    };
    let readable = can_read_now(state, client, &found)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;
    if !readable {
        audit_share(
            state,
            client,
            action,
            Some(&item.name),
            AuditStatus::Denied,
            None,
        )
        .await;
        return Err(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            format!("not permitted to read '{}'", item.name),
        ));
    }
    Ok((found, domain_name))
}

/// `POST /api/v1/share/request?domain=D` `{kind, name}`: the caller, who may
/// read the item, asks its sealer for the current key.
pub async fn request_key(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    req: web::Json<ItemRef>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (item, _) = match recipient_gate(&state, &client, &q, &req, "share.request").await {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let name = &item.name;
    match item.seal {
        Seal::Passphrase => {
            return Ok(err(
                StatusCode::CONFLICT,
                "passphrase_sealed",
                format!("'{name}' is sealed with a passphrase; its owner has to give you the passphrase"),
            ))
        }
        Seal::Resident => {
            return Ok(err(
                StatusCode::CONFLICT,
                "resident",
                format!("'{name}' is a resident file: its ciphertext is only on its owner's disk, and can't be shared through the server"),
            ))
        }
        Seal::Cmk if !item.shareable() => {
            return Ok(err(
                StatusCode::CONFLICT,
                "sealed_before_sharing",
                format!("'{name}' was sealed before key sharing existed; whoever stored it has to store it again (`bbk rekey`, or `put --overwrite`) before its key can be shared"),
            ))
        }
        Seal::Cmk => {}
    }
    let sealer_id = item.sealed_by.clone().unwrap_or_default();
    if sealer_id == client.id {
        return Ok(err(
            StatusCode::CONFLICT,
            "own_item",
            format!("you sealed '{name}'; your own client master key opens it"),
        ));
    }
    if load_identity(&state, &client.id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Ok(err(
            StatusCode::CONFLICT,
            "no_identity",
            "publish a share identity first (PUT /api/v1/share/identity)",
        ));
    }
    let id = request_new_reader(&state, &item, &client.id)
        .await
        .map_err(internal)?;
    let sealer = client_name(&state, &sealer_id).await;
    audit_share(
        &state,
        &client,
        "share.request",
        Some(name),
        AuditStatus::Ok,
        Some(&format!("sealer={sealer}")),
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"request_id": id, "sealer": sealer})))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PickupResponse {
    pub share_id: String,
    pub domain: String,
    pub kind: ItemKind,
    pub name: String,
    pub key_id: String,
    pub sender: PublishedIdentity,
    /// base64 of the share.
    pub share: String,
}

/// `GET /api/v1/share/pickup?domain=D&kind=K&name=N`: the share waiting for
/// the caller for the item's current key.
pub async fn pickup(
    state: web::Data<AppState>,
    q: web::Query<DomainQuery>,
    item_ref: web::Query<ItemRef>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let (item, domain) = match recipient_gate(&state, &client, &q, &item_ref, "share.pickup").await
    {
        Ok(x) => x,
        Err(resp) => return Ok(resp),
    };
    let none = || {
        err(
            StatusCode::NOT_FOUND,
            "no_share",
            format!("no key share is waiting for you for '{}'", item.name),
        )
    };
    let Some(key_id) = item.key_id.clone().filter(|_| item.shareable()) else {
        return Ok(none());
    };
    let row: Option<(String, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, key_id, sender_id, share_enc FROM blackbook_key_shares
         WHERE recipient_id = $1 AND item_key = $2 AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(&client.id)
    .bind(item.item_key())
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let Some((share_id, share_key_id, sender_id, share_enc)) = row else {
        return Ok(none());
    };
    // A share for an earlier key, or from a client that's no longer the
    // sealer or no longer exists, is of no use: drop it.
    let sender = load_identity(&state, &sender_id).await.map_err(internal)?;
    let sender =
        sender.filter(|_| share_key_id == key_id && item.sealed_by.as_deref() == Some(&sender_id));
    let Some(sender) = sender else {
        sqlx::query("DELETE FROM blackbook_key_shares WHERE id = $1")
            .bind(&share_id)
            .execute(&state.db)
            .await
            .map_err(internal)?;
        return Ok(none());
    };
    let share = dec_field(&state.metadata_enc_key, &share_enc).map_err(internal)?;
    // The key is in the caller's hands from here, whether or not it confirms
    // storing it, so it counts as a holder now: if it loses access, the key
    // is rotated.
    record_holder(
        &state,
        item.secret_id(),
        item.page_id(),
        &item.item_key(),
        &client.id,
        &key_id,
    )
    .await
    .map_err(internal)?;
    audit_share(
        &state,
        &client,
        "share.pickup",
        Some(&item.name),
        AuditStatus::Ok,
        Some(&format!("from={}", sender.client)),
    )
    .await;
    Ok(HttpResponse::Ok().json(PickupResponse {
        share_id,
        domain,
        kind: item.kind,
        name: item.name.clone(),
        key_id,
        sender,
        share: B64.encode(share),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ShareIdRequest {
    pub share_id: String,
}

async fn record_holder(
    state: &AppState,
    secret_id: Option<&str>,
    page_id: Option<&str>,
    item_key: &str,
    recipient_id: &str,
    key_id: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO blackbook_share_holders (secret_id, page_id, item_key, recipient_id, key_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (recipient_id, item_key)
         DO UPDATE SET key_id = EXCLUDED.key_id, received_at = CURRENT_TIMESTAMP",
    )
    .bind(secret_id)
    .bind(page_id)
    .bind(item_key)
    .bind(recipient_id)
    .bind(key_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// `POST /api/v1/share/ack` `{share_id}`: the recipient has stored the key.
/// The share is deleted and the recipient recorded as holding that key.
pub async fn ack(
    state: web::Data<AppState>,
    req: web::Json<ShareIdRequest>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let row: Option<(Option<String>, Option<String>, String, String)> = sqlx::query_as(
        "DELETE FROM blackbook_key_shares WHERE id = $1 AND recipient_id = $2
         RETURNING secret_id, page_id, item_key, key_id",
    )
    .bind(&req.share_id)
    .bind(&client.id)
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?;
    let Some((secret_id, page_id, item_key, key_id)) = row else {
        return Ok(err(
            StatusCode::NOT_FOUND,
            "no_share",
            "no such key share for you",
        ));
    };
    record_holder(
        &state,
        secret_id.as_deref(),
        page_id.as_deref(),
        &item_key,
        &client.id,
        &key_id,
    )
    .await
    .map_err(internal)?;
    sqlx::query("DELETE FROM blackbook_share_requests WHERE recipient_id = $1 AND item_key = $2")
        .bind(&client.id)
        .bind(&item_key)
        .execute(&state.db)
        .await
        .map_err(internal)?;
    let name = item_by_ref(&state, secret_id.as_deref(), page_id.as_deref())
        .await
        .map_err(internal)?
        .map(|i| i.name);
    audit_share(
        &state,
        &client,
        "share.ack",
        name.as_deref(),
        AuditStatus::Ok,
        None,
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"ok": true})))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestView {
    pub id: String,
    pub domain: String,
    pub kind: ItemKind,
    pub name: String,
    pub recipient: String,
    pub created_at: String,
    pub key_id: String,
    /// base64 of the envelope header, from which the sealer unwraps the key.
    /// Absent when `blocked` is set.
    pub header: Option<String>,
    /// The recipient's identity; absent until the recipient has published one.
    pub recipient_identity: Option<PublishedIdentity>,
    /// Why the caller can't fulfil the request now, if it can't.
    pub blocked: Option<String>,
}

/// `GET /api/v1/share/requests`: the requests waiting on the caller, i.e. for
/// items the caller sealed. A request whose item is gone or no longer
/// shareable is deleted rather than listed.
pub async fn list_requests(
    state: web::Data<AppState>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let rows: Vec<(String, Option<String>, Option<String>, String, String)> = sqlx::query_as(
        "SELECT r.id, r.secret_id, r.page_id, r.recipient_id, r.created_at::text
         FROM blackbook_share_requests r
         LEFT JOIN blackbook_secrets s ON s.resource_id = r.secret_id
         LEFT JOIN blackbook_pages p ON p.id = r.page_id
         WHERE COALESCE(s.sealed_by, p.sealed_by) = $1 AND r.expires_at > CURRENT_TIMESTAMP
         ORDER BY r.created_at",
    )
    .bind(&client.id)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    let mut domains: std::collections::HashMap<String, String> = Default::default();
    let mut out = Vec::new();
    for (id, secret_id, page_id, recipient_id, created_at) in rows {
        let item = item_by_ref(&state, secret_id.as_deref(), page_id.as_deref())
            .await
            .map_err(internal)?
            .filter(|i| i.shareable() && i.sealed_by.as_deref() == Some(&client.id));
        let Some(item) = item else {
            sqlx::query("DELETE FROM blackbook_share_requests WHERE id = $1")
                .bind(&id)
                .execute(&state.db)
                .await
                .map_err(internal)?;
            continue;
        };
        let domain = match domains.get(&item.domain_id) {
            Some(d) => d.clone(),
            None => {
                let d = domain_name(&state, &item.domain_id)
                    .await
                    .map_err(internal)?;
                domains.insert(item.domain_id.clone(), d.clone());
                d
            }
        };
        let blocked = if !can_read_now(&state, &client, &item)
            .await
            .map_err(internal)?
        {
            Some("you can no longer read this item, so you can't share it".to_string())
        } else if !may_receive(&state, &recipient_id, &item)
            .await
            .map_err(internal)?
        {
            Some("the recipient no longer has a read rule for this item".to_string())
        } else {
            None
        };
        out.push(RequestView {
            id,
            domain,
            kind: item.kind,
            name: item.name.clone(),
            recipient: client_name(&state, &recipient_id).await,
            created_at,
            key_id: item.key_id.clone().unwrap_or_default(),
            header: if blocked.is_none() {
                item.header.as_ref().map(|h| B64.encode(h))
            } else {
                None
            },
            recipient_identity: load_identity(&state, &recipient_id)
                .await
                .map_err(internal)?,
            blocked,
        });
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({ "requests": out })))
}

#[derive(Debug, Deserialize)]
pub struct DeliverRequest {
    pub request_id: String,
    /// The key id the share is for; must still be the item's current one.
    pub key_id: String,
    /// base64 of the share.
    pub share: String,
}

/// The request with this id, if it's for an item the caller sealed. Anything
/// else is reported as not found, so a client can't probe others' requests.
async fn own_request(
    state: &AppState,
    client: &AuthenticatedClient,
    request_id: &str,
) -> sqlx::Result<Option<(Item, String)>> {
    let row: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT secret_id, page_id, recipient_id FROM blackbook_share_requests
         WHERE id = $1 AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(request_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((secret_id, page_id, recipient_id)) = row else {
        return Ok(None);
    };
    let item = item_by_ref(state, secret_id.as_deref(), page_id.as_deref()).await?;
    Ok(item
        .filter(|i| i.sealed_by.as_deref() == Some(&client.id))
        .map(|i| (i, recipient_id)))
}

/// `POST /api/v1/share/deliver` `{request_id, key_id, share}`: the sealer
/// fulfils a request.
pub async fn deliver(
    state: web::Data<AppState>,
    req: web::Json<DeliverRequest>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let Some((item, recipient_id)) = own_request(&state, &client, &req.request_id)
        .await
        .map_err(internal)?
    else {
        return Ok(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such request for an item you sealed",
        ));
    };
    let name = item.name.clone();
    if !item.shareable() {
        return Ok(err(
            StatusCode::CONFLICT,
            "not_shareable",
            format!("'{name}' is no longer sealed under your client master key"),
        ));
    }
    if item.key_id.as_deref() != Some(req.key_id.as_str()) {
        return Ok(err(
            StatusCode::CONFLICT,
            "key_changed",
            format!(
                "'{name}' has a new key since this request was listed; run `bbk share sync` again"
            ),
        ));
    }
    if !can_read_now(&state, &client, &item)
        .await
        .map_err(internal)?
    {
        audit_share(
            &state,
            &client,
            "share.deliver",
            Some(&name),
            AuditStatus::Denied,
            Some("sealer can't read the item"),
        )
        .await;
        return Ok(err(
            StatusCode::FORBIDDEN,
            "forbidden",
            format!("you can no longer read '{name}', so you can't share it"),
        ));
    }
    if !may_receive(&state, &recipient_id, &item)
        .await
        .map_err(internal)?
    {
        sqlx::query("DELETE FROM blackbook_share_requests WHERE id = $1")
            .bind(&req.request_id)
            .execute(&state.db)
            .await
            .map_err(internal)?;
        audit_share(
            &state,
            &client,
            "share.deliver",
            Some(&name),
            AuditStatus::Denied,
            Some("recipient has no read rule"),
        )
        .await;
        return Ok(err(
            StatusCode::FORBIDDEN,
            "recipient_not_authorized",
            format!(
                "the recipient no longer has a read rule for '{name}'; the request was dropped"
            ),
        ));
    }
    if load_identity(&state, &recipient_id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Ok(err(
            StatusCode::CONFLICT,
            "no_identity",
            "the recipient hasn't published a share identity yet",
        ));
    }
    // Someone gained or lost access since this key was made: it goes no
    // further until the sealer rotates it.
    sweep(&state, &item).await.map_err(internal)?;
    if rotation_due(&state, &item).await.map_err(internal)? {
        return Ok(err(
            StatusCode::CONFLICT,
            "rotation_due",
            format!(
                "'{name}' needs a new key first: who may read it has changed. Run `bbk share sync`, which rotates its key, then sends it"
            ),
        ));
    }
    let share = match B64.decode(&req.share) {
        Ok(s) if !s.is_empty() && s.len() <= share_crypto::MAX_SHARE_LEN => s,
        _ => {
            return Ok(err(
                StatusCode::BAD_REQUEST,
                "validation_error",
                "share must be base64, at most 4 KiB",
            ))
        }
    };
    let share_enc = enc_field(&state.metadata_enc_key, &share).map_err(internal)?;
    let (share_id,): (String,) = sqlx::query_as(
        "INSERT INTO blackbook_key_shares
             (id, secret_id, page_id, item_key, key_id, sender_id, recipient_id, share_enc, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP + make_interval(days => $9))
         ON CONFLICT (recipient_id, item_key) DO UPDATE SET
           id = EXCLUDED.id, key_id = EXCLUDED.key_id, sender_id = EXCLUDED.sender_id,
           share_enc = EXCLUDED.share_enc, created_at = CURRENT_TIMESTAMP,
           expires_at = EXCLUDED.expires_at
         RETURNING id",
    )
    .bind(Id::new(12).encode())
    .bind(item.secret_id())
    .bind(item.page_id())
    .bind(item.item_key())
    .bind(&req.key_id)
    .bind(&client.id)
    .bind(&recipient_id)
    .bind(&share_enc)
    .bind(SHARE_TTL_DAYS)
    .fetch_one(&state.db)
    .await
    .map_err(internal)?;
    sqlx::query("DELETE FROM blackbook_share_requests WHERE id = $1")
        .bind(&req.request_id)
        .execute(&state.db)
        .await
        .map_err(internal)?;
    let recipient = client_name(&state, &recipient_id).await;
    audit_share(
        &state,
        &client,
        "share.deliver",
        Some(&name),
        AuditStatus::Ok,
        Some(&format!("to={recipient}")),
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"share_id": share_id})))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationView {
    pub domain: String,
    pub kind: ItemKind,
    pub name: String,
    /// The key to retire. `None` for a passphrase-sealed item, whose owner
    /// changes the passphrase by hand.
    pub key_id: Option<String>,
    /// Who gained access, and who lost it, since the key was made.
    pub granted: Vec<String>,
    pub revoked: Vec<String>,
    pub created_at: String,
    /// Why the caller can't rotate it now, if it can't.
    pub blocked: Option<String>,
}

/// `GET /api/v1/share/rotations`: the rotations due on items the caller
/// sealed. First catches access lost since it was last checked (see
/// [`sweep`]). A record whose item is gone, or has been stored again since, is
/// deleted rather than listed.
pub async fn list_rotations(
    state: web::Data<AppState>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let held: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT h.secret_id, h.page_id FROM blackbook_share_holders h
         LEFT JOIN blackbook_secrets s ON s.resource_id = h.secret_id
         LEFT JOIN blackbook_pages p ON p.id = h.page_id
         WHERE COALESCE(s.sealed_by, p.sealed_by) = $1
           AND h.key_id = COALESCE(s.key_id, p.key_id)
           AND h.recipient_id <> $1",
    )
    .bind(&client.id)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    for (secret_id, page_id) in held {
        if let Some(item) = item_by_ref(&state, secret_id.as_deref(), page_id.as_deref())
            .await
            .map_err(internal)?
        {
            sweep(&state, &item).await.map_err(internal)?;
        }
    }
    type Row = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Vec<String>,
        Vec<String>,
        String,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r.item_key, r.secret_id, r.page_id, r.key_id, r.granted, r.revoked,
                r.created_at::text
         FROM blackbook_key_rotations r
         LEFT JOIN blackbook_secrets s ON s.resource_id = r.secret_id
         LEFT JOIN blackbook_pages p ON p.id = r.page_id
         WHERE COALESCE(s.sealed_by, p.sealed_by) = $1
         ORDER BY r.created_at",
    )
    .bind(&client.id)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;
    let mut out = Vec::new();
    for (item_key, secret_id, page_id, key_id, granted, revoked, created_at) in rows {
        let item = item_by_ref(&state, secret_id.as_deref(), page_id.as_deref())
            .await
            .map_err(internal)?
            .filter(|i| {
                i.rotatable()
                    && i.sealed_by.as_deref() == Some(&client.id)
                    && (i.seal != Seal::Cmk || i.key_id == key_id)
            });
        let Some(item) = item else {
            sqlx::query("DELETE FROM blackbook_key_rotations WHERE item_key = $1")
                .bind(&item_key)
                .execute(&state.db)
                .await
                .map_err(internal)?;
            continue;
        };
        let blocked = if !can_read_now(&state, &client, &item)
            .await
            .map_err(internal)?
        {
            Some("you can no longer read it, so you can't rotate it".to_string())
        } else if !acl_check(
            &state.db,
            &state.metadata_enc_key,
            &client,
            &item.domain_id,
            &item.name,
            AclAction::Update,
        )
        .await
        .map_err(internal)?
        .is_allowed()
        {
            Some("you may not update it, so you can't store it again".to_string())
        } else {
            None
        };
        out.push(RotationView {
            domain: domain_name(&state, &item.domain_id)
                .await
                .map_err(internal)?,
            kind: item.kind,
            name: item.name.clone(),
            key_id,
            granted: names_of(&state, &granted).await,
            revoked: names_of(&state, &revoked).await,
            created_at,
            blocked,
        });
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({ "rotations": out })))
}

#[derive(Debug, Deserialize)]
pub struct RequestIdRequest {
    pub request_id: String,
}

/// `POST /api/v1/share/reject` `{request_id}`: the sealer declines a request.
pub async fn reject(
    state: web::Data<AppState>,
    req: web::Json<RequestIdRequest>,
    client: AuthenticatedClient,
) -> Result<HttpResponse> {
    let Some((item, recipient_id)) = own_request(&state, &client, &req.request_id)
        .await
        .map_err(internal)?
    else {
        return Ok(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such request for an item you sealed",
        ));
    };
    sqlx::query("DELETE FROM blackbook_share_requests WHERE id = $1")
        .bind(&req.request_id)
        .execute(&state.db)
        .await
        .map_err(internal)?;
    let recipient = client_name(&state, &recipient_id).await;
    audit_share(
        &state,
        &client,
        "share.reject",
        Some(&item.name),
        AuditStatus::Ok,
        Some(&format!("to={recipient}")),
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(seal: Seal, sealed: bool, has_key: bool, immutable: bool) -> Item {
        Item {
            kind: ItemKind::Secret,
            id: "s1".into(),
            domain_id: "d1".into(),
            name: "db-password".into(),
            sealed_by: sealed.then(|| "alice".to_string()),
            key_id: has_key.then(|| "a".repeat(64)),
            seal,
            header: None,
            immutable,
        }
    }

    #[test]
    fn which_items_a_change_of_access_rotates() {
        assert!(item(Seal::Cmk, true, true, false).rotatable());
        // Sealed before key sharing: no sealer, or no key id, to rotate.
        assert!(!item(Seal::Cmk, false, false, false).rotatable());
        assert!(!item(Seal::Cmk, true, false, false).rotatable());
        // A passphrase item is rotated by hand: a reminder to its sealer.
        assert!(item(Seal::Passphrase, true, false, false).rotatable());
        assert!(!item(Seal::Passphrase, false, false, false).rotatable());
        assert!(!item(Seal::Resident, true, false, false).rotatable());
        // Immutable items can't be stored again.
        assert!(!item(Seal::Cmk, true, true, true).rotatable());
        assert!(!item(Seal::Passphrase, true, false, true).rotatable());
    }

    #[test]
    fn a_rotation_replaces_only_the_key_it_names() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let current = |external: bool, sealer: &str, key: &str| {
            Some((external, Some(sealer.to_string()), Some(key.to_string())))
        };
        let refusal = |current, new_key: Option<&str>| {
            rotation_store_refusal("x", "alice", current, &old, new_key).map(|(code, _)| code)
        };
        assert_eq!(refusal(current(true, "alice", &old), Some(&new)), None);
        assert_eq!(refusal(None, Some(&new)), Some("not_found"));
        assert_eq!(
            refusal(current(false, "alice", &old), Some(&new)),
            Some("not_sealer")
        );
        assert_eq!(
            refusal(current(true, "bob", &old), Some(&new)),
            Some("not_sealer")
        );
        // Stored again since: the rotation would overwrite that value.
        assert_eq!(
            refusal(current(true, "alice", &new), Some(&new)),
            Some("key_changed")
        );
        // A rotation to a passphrase envelope has no key id to share.
        assert_eq!(
            refusal(current(true, "alice", &old), None),
            Some("not_shareable")
        );
    }

    // `field` fills the length-prefixed slot where a passphrase envelope keeps
    // its KDF salt; these tests only exercise the layout.
    fn v2(mode: u8, field: &[u8], wrapped: &[u8], ct: &[u8]) -> Vec<u8> {
        let mut out = vec![2, mode];
        out.extend_from_slice(&[0u8; 12]);
        out.push(field.len() as u8);
        out.extend_from_slice(field);
        out.extend_from_slice(&(wrapped.len() as u32).to_be_bytes());
        out.extend_from_slice(wrapped);
        out.extend_from_slice(ct);
        out
    }

    #[test]
    fn envelope_header_stops_at_the_ciphertext() {
        let env = v2(0, b"", &[9u8; 60], b"the ciphertext");
        let (seal, end) = envelope_seal(&env).unwrap();
        assert_eq!(seal, Seal::Cmk);
        assert_eq!(&env[end..], b"the ciphertext");
        // A file's meta is the header alone.
        let meta = v2(0, b"", &[9u8; 60], b"");
        assert_eq!(envelope_seal(&meta), Some((Seal::Cmk, meta.len())));
    }

    #[test]
    fn envelope_modes() {
        assert_eq!(
            envelope_seal(&v2(1, &[1u8; 16], &[9u8; 60], b"x")).map(|s| s.0),
            Some(Seal::Passphrase)
        );
        assert_eq!(
            envelope_seal(&[1, 16, 0]).map(|s| s.0),
            Some(Seal::Passphrase)
        );
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let env = v2(0, b"", &[9u8; 60], b"");
        assert_eq!(envelope_seal(&env[..env.len() - 1]), None);
        assert_eq!(envelope_seal(&env[..10]), None);
        assert_eq!(envelope_seal(&[]), None);
        assert_eq!(envelope_seal(&[3, 0]), None);
    }
}
