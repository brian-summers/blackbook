//! Tunnel relay (server side).
//!
//! Two blackbook clients have no direct path to each other, so the server pairs
//! them and relays **opaque** frames between their WebSockets. The server's only
//! cryptographic role is as a *trusted introducer*: when both sides are
//! connected it tells each the other's client name and the SHA3-256 fingerprint
//! of their certificate (looked up from the DB by the authenticated identity).
//! Each client then runs the authenticated handshake from [`crate::tunnel_crypto`]
//! and verifies the peer's signature against that vouched fingerprint. The
//! server never sees an ephemeral private key, so it cannot read or forge the
//! E2E channel — it can only relay, drop, or refuse.
//!
//! Lifecycle:
//!   1. Offerer `POST /api/v1/tunnels {target}` → server mints a tunnel id,
//!      records {offerer identity, target name}, returns the id.
//!   2. Offerer opens `GET /api/v1/tunnels/{id}/ws` (WebSocket upgrade).
//!   3. Answerer (must be the named target) opens the same WS URL.
//!   4. Server vouches each peer to the other (control frame), then pipes
//!      binary frames straight through until either side closes.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use serde::{Deserialize, Serialize};

use crate::blackbook_core::Id;

/// One pending/active tunnel. Created by the offerer's POST, completed when both
/// WebSockets attach. The `tx` channels let each side's WS task forward frames
/// to the other.
pub struct Tunnel {
    /// Offerer (initiator) — authenticated client name + cert fingerprint.
    pub offerer_name: String,
    pub offerer_fp: String,
    /// The client name the offerer wants to reach (the only one allowed to join).
    pub target_name: String,
    /// Answerer identity, set when they attach.
    pub answerer_name: Option<String>,
    pub answerer_fp: Option<String>,
    /// Sender into each side's outbound queue (frames destined *to* that side).
    /// Set when that side's WS attaches.
    pub to_offerer: Option<mpsc::UnboundedSender<RelayMsg>>,
    pub to_answerer: Option<mpsc::UnboundedSender<RelayMsg>>,
    /// Wall-clock creation, for TTL sweeping of abandoned offers.
    pub created: std::time::Instant,
}

/// What the relay pushes to a connected side. `Vouch` is the one-time control
/// frame identifying the peer; `Frame` is opaque E2E ciphertext; `PeerGone`
/// signals teardown.
#[derive(Debug, Clone)]
pub enum RelayMsg {
    Vouch(Vouch),
    Frame(Vec<u8>),
    PeerGone,
}

/// The server's introduction of the peer to one side. The client trusts this
/// only as far as the fingerprint: it will still cryptographically verify the
/// peer's handshake signature against `peer_fingerprint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vouch {
    /// Is the receiving side the tunnel initiator (offerer)? Determines the
    /// handshake role so the two derive matching directional keys.
    pub you_are_initiator: bool,
    pub tunnel_id: String,
    pub peer_name: String,
    pub peer_fingerprint: String,
}

/// In-memory tunnel registry shared on AppState. Tunnels are ephemeral — no DB
/// row; if the server restarts, in-flight tunnels simply drop (clients reconnect).
#[derive(Clone, Default)]
pub struct TunnelHub {
    inner: Arc<Mutex<HashMap<String, Tunnel>>>,
}

/// How long an unattached offer lives before it's swept.
const OFFER_TTL: std::time::Duration = std::time::Duration::from_secs(120);

impl TunnelHub {
    pub fn new() -> Self { Self::default() }

    /// Register an offer; returns the new tunnel id.
    pub async fn offer(&self, offerer_name: &str, offerer_fp: &str, target_name: &str) -> String {
        let id = Id::new(16).to_hex();
        let mut map = self.inner.lock().await;
        // Opportunistic sweep of stale, never-completed offers.
        map.retain(|_, t| t.answerer_name.is_some() || t.created.elapsed() < OFFER_TTL);
        map.insert(id.clone(), Tunnel {
            offerer_name: offerer_name.to_string(),
            offerer_fp: offerer_fp.to_string(),
            target_name: target_name.to_string(),
            answerer_name: None,
            answerer_fp: None,
            to_offerer: None,
            to_answerer: None,
            created: std::time::Instant::now(),
        });
        id
    }

    /// List tunnels visible to `client_name` (those they offered or are the
    /// target of), for `tunnel ls`.
    pub async fn list_for(&self, client_name: &str) -> Vec<TunnelInfo> {
        let map = self.inner.lock().await;
        map.iter()
            .filter(|(_, t)| t.offerer_name == client_name || t.target_name == client_name)
            .map(|(id, t)| TunnelInfo {
                id: id.clone(),
                offerer: t.offerer_name.clone(),
                target: t.target_name.clone(),
                state: if t.to_offerer.is_some() && t.to_answerer.is_some() { "connected" }
                       else if t.answerer_name.is_some() { "joining" }
                       else { "offered" }.to_string(),
            })
            .collect()
    }

    /// Attach a side's outbound channel. `as_offerer` picks which slot.
    /// Returns the peer's outbound sender if the peer is already attached, so
    /// the caller can wire both directions; plus the Vouch to send this side
    /// once the peer is known.
    pub async fn attach_offerer(&self, id: &str, tx: mpsc::UnboundedSender<RelayMsg>) {
        let mut map = self.inner.lock().await;
        if let Some(t) = map.get_mut(id) { t.to_offerer = Some(tx); }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelInfo {
    pub id: String,
    pub offerer: String,
    pub target: String,
    pub state: String,
}

/// Access to the shared map for the WS handler (which needs fine-grained,
/// multi-step locking the helper methods above don't cover).
impl TunnelHub {
    pub async fn with_lock<R>(&self, f: impl FnOnce(&mut HashMap<String, Tunnel>) -> R) -> R {
        let mut map = self.inner.lock().await;
        f(&mut map)
    }
}
