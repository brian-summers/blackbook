//! Tunnel client engine + port forwarding (client side).
//!
//! Connects to the server relay over the existing mTLS WebSocket, runs the
//! authenticated handshake from [`crate::tunnel_crypto`] against the peer the
//! server vouched, then multiplexes local TCP/UDP port-forwards over the single
//! end-to-end-encrypted channel.
//!
//! Wire layering (outermost first):
//!   WebSocket binary message  =  AEAD frame (nonce ‖ ct+tag)   [E2E, server-opaque]
//!     AEAD plaintext          =  inner frame = kind(1) ‖ stream_id(4) ‖ payload
//!
//! Inner frame kinds (the tunnel's own mux protocol, invisible to the server):
//!   OPEN_TCP / OPEN_UDP : listener asks the peer to dial `payload` ("host:port")
//!                         for the new `stream_id`.
//!   DATA                : stream bytes (TCP) or one datagram (UDP).
//!   CLOSE               : stream finished/aborted.
//!
//! The session-start `Vouch` is the one WebSocket *text* message; the ephemeral
//! pubkey exchange and handshakes are binary; everything after is binary AEAD.

use std::collections::HashMap;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::Message;

use crate::client::TunnelWs;
use crate::tunnel_crypto::{self, Role, Session};

/// Server's peer introduction (mirrors `tunnel_relay::Vouch` on the wire).
#[derive(Debug, Clone, Deserialize)]
pub struct Vouch {
    pub you_are_initiator: bool,
    pub tunnel_id: String,
    pub peer_name: String,
    pub peer_fingerprint: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("ws: {0}")]
    Ws(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("relay closed before the peer joined")]
    PeerNeverJoined,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
type Result<T> = std::result::Result<T, TunnelError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Proto { Tcp, Udp }

// --- inner mux frame kinds ---------------------------------------------------
const KIND_OPEN_TCP: u8 = 1;
const KIND_OPEN_UDP: u8 = 2;
const KIND_DATA: u8 = 3;
const KIND_CLOSE: u8 = 4;

fn inner_encode(kind: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.push(kind);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}
fn inner_decode(buf: &[u8]) -> Option<(u8, u32, &[u8])> {
    if buf.len() < 5 { return None; }
    Some((buf[0], u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]), &buf[5..]))
}

// --- handshake ---------------------------------------------------------------

/// Run the authenticated handshake over an established relay WebSocket. Returns
/// the AEAD session and the verified peer identity. Consumes nothing — leaves
/// `ws` ready for the data plane.
pub async fn handshake(
    ws: &mut TunnelWs,
    my_name: &str, my_cert_pem: &str, my_key_pem: &str,
) -> Result<(Session, Vouch)> {
    // 1. First relay message is the text Vouch describing our peer.
    let vouch: Vouch = match next_msg(ws).await? {
        Some(Message::Text(t)) => serde_json::from_str(&t)
            .map_err(|e| TunnelError::Ws(format!("bad vouch: {e}")))?,
        Some(_) => return Err(TunnelError::Ws("expected vouch text first".into())),
        None => return Err(TunnelError::PeerNeverJoined),
    };
    let role = if vouch.you_are_initiator { Role::Initiator } else { Role::Responder };
    let pending = tunnel_crypto::begin(role, &vouch.tunnel_id, my_name, my_cert_pem, my_key_pem);

    // 2a. Exchange ephemeral pubkeys (raw 32 bytes).
    ws.send(Message::Binary(pending.eph_pub().to_vec())).await
        .map_err(|e| TunnelError::Ws(e.to_string()))?;
    let peer_eph = match next_msg(ws).await? {
        Some(Message::Binary(b)) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
        _ => return Err(TunnelError::Ws("expected peer ephemeral pubkey (32 bytes)".into())),
    };

    // 2b. Sign over the session and exchange full handshakes.
    let my_hs = pending.sign(&peer_eph).map_err(|e| TunnelError::Crypto(e.to_string()))?;
    let my_hs_json = serde_json::to_vec(&my_hs).map_err(|e| TunnelError::Ws(e.to_string()))?;
    ws.send(Message::Binary(my_hs_json)).await.map_err(|e| TunnelError::Ws(e.to_string()))?;
    let peer_hs: tunnel_crypto::Handshake = match next_msg(ws).await? {
        Some(Message::Binary(b)) => serde_json::from_slice(&b)
            .map_err(|e| TunnelError::Ws(format!("bad peer handshake: {e}")))?,
        _ => return Err(TunnelError::Ws("expected peer handshake".into())),
    };

    // 3. Verify peer signature against the server-vouched fingerprint.
    let session = pending.complete(&peer_hs, &vouch.peer_name, &vouch.peer_fingerprint)
        .map_err(|e| TunnelError::Crypto(e.to_string()))?;
    Ok((session, vouch))
}

/// Read the next non-control WebSocket message (skips ping/pong).
async fn next_msg(ws: &mut TunnelWs) -> Result<Option<Message>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(m @ Message::Text(_))) | Some(Ok(m @ Message::Binary(_))) => return Ok(Some(m)),
            Some(Ok(Message::Close { .. })) | None => return Ok(None),
            Some(Err(e)) => return Err(TunnelError::Ws(e.to_string())),
        }
    }
}

// --- engine ------------------------------------------------------------------
//
// One central task owns the `Session` and both WebSocket halves. It selects on:
//   * inbound WS frames → AEAD-open → inner-decode → dispatch to a stream
//   * an outbound mpsc of inner frames (from forwarders/listeners) → AEAD-seal → WS
// Forwarder tasks never touch the Session; they exchange plaintext inner frames
// with the engine over channels.

/// Per-stream inbound sink (engine → that stream's socket pump).
type StreamInbound = mpsc::UnboundedSender<StreamMsg>;
enum StreamMsg { Data(Vec<u8>), Close }

/// Command from a forwarder/listener to the engine.
enum EngineCmd {
    /// Send an inner frame to the peer.
    Send(Vec<u8>),
    /// Register a stream's inbound sink so the engine can route DATA/CLOSE to it.
    Register(u32, StreamInbound),
}

/// Run as the **listener** side: bind locally and, per connection, ask the peer
/// to dial `remote`. Blocks until the tunnel closes.
pub async fn run_listener(ws: TunnelWs, session: Session, proto: Proto, listen: String, remote: String) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<EngineCmd>();
    let streams: SharedStreams = Default::default();
    // Spawn the local acceptor that creates streams on demand.
    let acceptor = tokio::spawn(listen_loop(proto, listen, remote, cmd_tx.clone(), streams.clone()));
    let res = engine_loop(ws, session, cmd_rx, cmd_tx, streams, /*is_target=*/false).await;
    acceptor.abort();
    res
}

/// Run as the **target** side: accept OPEN frames and dial locally. Blocks.
pub async fn run_target(ws: TunnelWs, session: Session) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<EngineCmd>();
    let streams: SharedStreams = Default::default();
    engine_loop(ws, session, cmd_rx, cmd_tx, streams, /*is_target=*/true).await
}

type SharedStreams = std::sync::Arc<std::sync::Mutex<HashMap<u32, StreamInbound>>>;

/// The central multiplexer.
async fn engine_loop(
    ws: TunnelWs,
    mut session: Session,
    mut cmd_rx: mpsc::UnboundedReceiver<EngineCmd>,
    cmd_tx: mpsc::UnboundedSender<EngineCmd>,
    streams: SharedStreams,
    is_target: bool,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    loop {
        tokio::select! {
            // Outbound: a forwarder wants to send / register.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(EngineCmd::Send(inner)) => {
                        let frame = session.seal(&inner).map_err(|e| TunnelError::Crypto(e.to_string()))?;
                        if sink.send(Message::Binary(frame)).await.is_err() { break; }
                    }
                    Some(EngineCmd::Register(sid, tx)) => { streams.lock().unwrap().insert(sid, tx); }
                    None => break,
                }
            }
            // Inbound: a frame from the peer (via the relay).
            msg = stream.next() => {
                let msg = match msg {
                    Some(Ok(Message::Binary(b))) => b,
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) => continue,
                    Some(Ok(Message::Close { .. })) | None => break,
                    Some(Err(e)) => return Err(TunnelError::Ws(e.to_string())),
                };
                let inner = session.open(&msg).map_err(|e| TunnelError::Crypto(e.to_string()))?;
                let Some((kind, sid, payload)) = inner_decode(&inner) else { continue };
                match kind {
                    KIND_OPEN_TCP | KIND_OPEN_UDP if is_target => {
                        let addr = String::from_utf8_lossy(payload).to_string();
                        let proto = if kind == KIND_OPEN_TCP { Proto::Tcp } else { Proto::Udp };
                        spawn_target_stream(proto, sid, addr, cmd_tx.clone(), streams.clone());
                    }
                    KIND_DATA => {
                        if let Some(tx) = streams.lock().unwrap().get(&sid) {
                            let _ = tx.send(StreamMsg::Data(payload.to_vec()));
                        }
                    }
                    KIND_CLOSE => {
                        if let Some(tx) = streams.lock().unwrap().remove(&sid) {
                            let _ = tx.send(StreamMsg::Close);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// --- listener (initiator side) ----------------------------------------------

static NEXT_STREAM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
fn next_sid() -> u32 { NEXT_STREAM_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) }

async fn listen_loop(
    proto: Proto, listen: String, remote: String,
    cmd_tx: mpsc::UnboundedSender<EngineCmd>, streams: SharedStreams,
) -> Result<()> {
    match proto {
        Proto::Tcp => {
            let l = tokio::net::TcpListener::bind(&listen).await?;
            log::info!("tunnel: forwarding local tcp {listen} → peer:{remote}");
            loop {
                let (sock, _peer) = l.accept().await?;
                let sid = next_sid();
                let open = inner_encode(KIND_OPEN_TCP, sid, remote.as_bytes());
                if cmd_tx.send(EngineCmd::Send(open)).is_err() { break; }
                let (in_tx, in_rx) = mpsc::unbounded_channel::<StreamMsg>();
                let _ = cmd_tx.send(EngineCmd::Register(sid, in_tx));
                tokio::spawn(pump_tcp(sock, sid, cmd_tx.clone(), in_rx, streams.clone()));
            }
            Ok(())
        }
        Proto::Udp => {
            let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind(&listen).await?);
            log::info!("tunnel: forwarding local udp {listen} → peer:{remote}");
            // One stream per source addr so replies route back correctly.
            let mut by_src: HashMap<std::net::SocketAddr, u32> = HashMap::new();
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, src) = sock.recv_from(&mut buf).await?;
                let sid = *by_src.entry(src).or_insert_with(|| {
                    let sid = next_sid();
                    let open = inner_encode(KIND_OPEN_UDP, sid, remote.as_bytes());
                    let _ = cmd_tx.send(EngineCmd::Send(open));
                    let (in_tx, in_rx) = mpsc::unbounded_channel::<StreamMsg>();
                    let _ = cmd_tx.send(EngineCmd::Register(sid, in_tx));
                    tokio::spawn(udp_reply_pump(sock.clone(), src, in_rx));
                    sid
                });
                let data = inner_encode(KIND_DATA, sid, &buf[..n]);
                if cmd_tx.send(EngineCmd::Send(data)).is_err() { break; }
            }
            Ok(())
        }
    }
}

/// Listener-side UDP: deliver peer replies for one source back to it.
async fn udp_reply_pump(sock: std::sync::Arc<tokio::net::UdpSocket>, src: std::net::SocketAddr, mut in_rx: mpsc::UnboundedReceiver<StreamMsg>) {
    while let Some(msg) = in_rx.recv().await {
        match msg {
            StreamMsg::Data(d) => { let _ = sock.send_to(&d, src).await; }
            StreamMsg::Close => break,
        }
    }
}

// --- target side -------------------------------------------------------------

fn spawn_target_stream(proto: Proto, sid: u32, addr: String, cmd_tx: mpsc::UnboundedSender<EngineCmd>, streams: SharedStreams) {
    let (in_tx, in_rx) = mpsc::unbounded_channel::<StreamMsg>();
    streams.lock().unwrap().insert(sid, in_tx);
    match proto {
        Proto::Tcp => { tokio::spawn(async move {
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(sock) => { let _ = pump_tcp(sock, sid, cmd_tx, in_rx, streams).await; }
                Err(e) => {
                    log::warn!("tunnel target: dial {addr} failed: {e}");
                    let _ = cmd_tx.send(EngineCmd::Send(inner_encode(KIND_CLOSE, sid, &[])));
                    streams.lock().unwrap().remove(&sid);
                }
            }
        }); }
        Proto::Udp => { tokio::spawn(target_udp(sid, addr, cmd_tx, in_rx, streams)); }
    }
}

/// Target-side UDP: one local socket per stream; send peer datagrams out, return replies.
async fn target_udp(sid: u32, addr: String, cmd_tx: mpsc::UnboundedSender<EngineCmd>, mut in_rx: mpsc::UnboundedReceiver<StreamMsg>, streams: SharedStreams) {
    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s, Err(e) => { log::warn!("tunnel target udp bind: {e}"); return; }
    };
    if let Err(e) = sock.connect(&addr).await { log::warn!("tunnel target udp connect {addr}: {e}"); return; }
    let sock = std::sync::Arc::new(sock);
    let recv_sock = sock.clone();
    let recv_tx = cmd_tx.clone();
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match recv_sock.recv(&mut buf).await {
                Ok(n) => { if recv_tx.send(EngineCmd::Send(inner_encode(KIND_DATA, sid, &buf[..n]))).is_err() { break; } }
                Err(_) => break,
            }
        }
    });
    while let Some(msg) = in_rx.recv().await {
        match msg {
            StreamMsg::Data(d) => { let _ = sock.send(&d).await; }
            StreamMsg::Close => break,
        }
    }
    recv.abort();
    streams.lock().unwrap().remove(&sid);
}

// --- shared TCP pump (both sides) -------------------------------------------

/// Pipe a TCP socket ↔ the tunnel for one stream: socket reads → DATA frames to
/// the engine; inbound StreamMsg → socket writes. Sends CLOSE when the socket ends.
async fn pump_tcp(
    sock: tokio::net::TcpStream, sid: u32,
    cmd_tx: mpsc::UnboundedSender<EngineCmd>, mut in_rx: mpsc::UnboundedReceiver<StreamMsg>,
    streams: SharedStreams,
) -> Result<()> {
    let (mut rd, mut wr) = sock.into_split();
    // socket → tunnel
    let up_tx = cmd_tx.clone();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => { let _ = up_tx.send(EngineCmd::Send(inner_encode(KIND_CLOSE, sid, &[]))); break; }
                Ok(n) => { if up_tx.send(EngineCmd::Send(inner_encode(KIND_DATA, sid, &buf[..n]))).is_err() { break; } }
            }
        }
    });
    // tunnel → socket
    while let Some(msg) = in_rx.recv().await {
        match msg {
            StreamMsg::Data(d) => { if wr.write_all(&d).await.is_err() { break; } }
            StreamMsg::Close => break,
        }
    }
    up.abort();
    streams.lock().unwrap().remove(&sid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inner_frame_roundtrips() {
        let f = inner_encode(KIND_DATA, 0x01020304, b"hello");
        let (k, sid, p) = inner_decode(&f).unwrap();
        assert_eq!(k, KIND_DATA);
        assert_eq!(sid, 0x01020304);
        assert_eq!(p, b"hello");
        assert!(inner_decode(b"abc").is_none());
    }
}
