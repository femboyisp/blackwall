//! Thin async BGP session FSM — TCP socket, timers, reconnect loop.
//!
//! All framing and encoding is delegated to the codec in the rest of the
//! crate; this file is intentionally thin I/O glue and is excluded from
//! coverage measurement (see `scripts/coverage.sh`).
//!
//! # Overview
//!
//! [`spawn`] creates an [`mpsc`] channel and [`tokio::spawn`]s [`run`],
//! returning a [`BgpHandle`] for injecting routes and a
//! [`JoinHandle`] for shutdown signalling.
//!
//! [`run`] loops forever (reconnecting on any error):
//! 1. TCP-connect `cfg.peer_addr`.
//! 2. Send an OPEN.
//! 3. Read frames until the peer's OPEN; negotiate hold time.
//! 4. Send KEEPALIVE → Established.
//! 5. Re-announce the full `active` set.
//! 6. `tokio::select!` over keepalive interval / hold timeout / socket
//!    readable / command channel.
//! 7. On any error: drain pending commands, log, sleep 5 s, restart.

use crate::{
    build_announce, build_withdraw, decode_message, encode_keepalive, encode_notification,
    encode_open, BgpMessage, NotificationMsg, OpenMsg, Route,
};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

// ── Public types ─────────────────────────────────────────────────────────────

/// Configuration for a single BGP peer session.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Local Autonomous System number (4-octet).
    pub local_asn: u32,
    /// Remote Autonomous System number (used for logging; iBGP = same as local).
    pub peer_asn: u32,
    /// TCP address of the remote BGP peer (usually port 179).
    pub peer_addr: SocketAddr,
    /// BGP router-ID to advertise in the OPEN message.
    pub router_id: Ipv4Addr,
    /// Proposed hold time in seconds (0 = no hold timer; otherwise ≥ 3).
    pub hold_time: u16,
}

/// A command sent from the application to the BGP session.
pub enum SessionCommand {
    /// Announce a route; replaces any existing entry for the same prefix.
    Announce(Route),
    /// Withdraw a previously-announced prefix.
    Withdraw(IpNet),
}

/// A handle to a running BGP session for injecting routes.
///
/// Cheaply cloneable; all clones share the same channel.
#[derive(Clone)]
pub struct BgpHandle {
    tx: mpsc::Sender<SessionCommand>,
}

impl BgpHandle {
    /// Announce a route to the BGP peer.
    ///
    /// The route is stored in the session's active set and re-announced on
    /// reconnect.  Silently drops the command if the session has exited.
    pub async fn announce(&self, route: Route) {
        let _ = self.tx.send(SessionCommand::Announce(route)).await;
    }

    /// Withdraw a previously-announced prefix.
    ///
    /// Silently drops the command if the session has exited.
    pub async fn withdraw(&self, prefix: IpNet) {
        let _ = self.tx.send(SessionCommand::Withdraw(prefix)).await;
    }
}

// ── spawn ─────────────────────────────────────────────────────────────────────

/// Spawn a BGP session task and return a handle for controlling it.
///
/// The task runs until the process exits (or the [`JoinHandle`] is aborted).
/// It reconnects automatically on any I/O error or hold-timer expiry.
pub fn spawn(cfg: PeerConfig) -> (BgpHandle, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(256);
    let handle = BgpHandle { tx };
    let join = tokio::spawn(run(cfg, rx));
    (handle, join)
}

// ── FSM ───────────────────────────────────────────────────────────────────────

/// The BGP session FSM loop.
///
/// Never returns under normal operation — reconnects indefinitely on error.
/// Maintains `active: HashMap<IpNet, Route>` and re-advertises after each
/// successful session establishment.
pub async fn run(cfg: PeerConfig, mut commands: mpsc::Receiver<SessionCommand>) {
    let mut active: HashMap<IpNet, Route> = HashMap::new();

    loop {
        let outcome = session_once(&cfg, &mut commands, &mut active).await;
        match outcome {
            SessionOutcome::Reconnect(msg) => {
                info!(peer = %cfg.peer_addr, "{msg}; reconnecting in 5 s");
            }
            SessionOutcome::CommandsExhausted => {
                info!(
                    peer = %cfg.peer_addr,
                    "command channel closed; exiting BGP session loop"
                );
                return;
            }
        }
        // Drain any queued commands before sleeping (keeps active in sync).
        drain_commands(&mut commands, &mut active);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Why the current session attempt ended.
enum SessionOutcome {
    /// Ended due to an error or protocol condition — caller should reconnect.
    Reconnect(String),
    /// The command channel was closed — caller should exit permanently.
    CommandsExhausted,
}

/// Apply pending commands to `active` without writing anything on the wire.
///
/// Called while no session is up, so we just update the local state.
fn drain_commands(
    commands: &mut mpsc::Receiver<SessionCommand>,
    active: &mut HashMap<IpNet, Route>,
) {
    loop {
        match commands.try_recv() {
            Ok(SessionCommand::Announce(route)) => {
                let prefix = route.prefix;
                active.insert(prefix, route);
            }
            Ok(SessionCommand::Withdraw(prefix)) => {
                active.remove(&prefix);
            }
            Err(_) => break,
        }
    }
}

/// Run a single connect → open-handshake → established → select loop.
///
/// Mutates `active` in response to commands so that the outer `run` loop sees
/// the up-to-date set on reconnect.
async fn session_once(
    cfg: &PeerConfig,
    commands: &mut mpsc::Receiver<SessionCommand>,
    active: &mut HashMap<IpNet, Route>,
) -> SessionOutcome {
    // ── 1. TCP connect ──────────────────────────────────────────────────────
    let mut stream = match TcpStream::connect(cfg.peer_addr).await {
        Ok(s) => {
            info!(peer = %cfg.peer_addr, "TCP connected");
            s
        }
        Err(e) => return SessionOutcome::Reconnect(format!("connect failed: {e}")),
    };

    // ── 2. Send our OPEN ────────────────────────────────────────────────────
    let local_open = OpenMsg {
        asn: cfg.local_asn,
        hold_time: cfg.hold_time,
        router_id: u32::from(cfg.router_id),
        ipv4_unicast: true,
        ipv6_unicast: true,
    };
    let open_bytes = encode_open(&local_open);
    if let Err(e) = stream.write_all(&open_bytes).await {
        return SessionOutcome::Reconnect(format!("send OPEN failed: {e}"));
    }
    debug!(peer = %cfg.peer_addr, "OPEN sent");

    // ── 3. Read peer's OPEN (with partial-frame buffering) ─────────────────
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let peer_open = loop {
        let mut tmp = [0u8; 4096];
        let n = match stream.read(&mut tmp).await {
            Ok(0) => {
                return SessionOutcome::Reconnect(
                    "peer closed connection during handshake".to_owned(),
                )
            }
            Ok(n) => n,
            Err(e) => {
                return SessionOutcome::Reconnect(format!("read error during handshake: {e}"))
            }
        };
        buf.extend_from_slice(&tmp[..n]);

        match decode_message(&buf) {
            Ok((BgpMessage::Open(o), consumed)) => {
                buf.drain(..consumed);
                break o;
            }
            Ok((BgpMessage::Notification(n), _)) => {
                warn!(
                    peer = %cfg.peer_addr,
                    code = n.code,
                    subcode = n.subcode,
                    "NOTIFICATION during handshake"
                );
                return SessionOutcome::Reconnect(format!(
                    "NOTIFICATION during handshake code={} subcode={}",
                    n.code, n.subcode
                ));
            }
            Ok(_) => {
                // Unexpected Keepalive/Update before OPEN — ignore, keep waiting.
                warn!(peer = %cfg.peer_addr, "unexpected non-OPEN message during handshake");
            }
            Err(e) if is_partial(&e) => {
                // Partial frame — keep reading.
            }
            Err(e) => {
                return SessionOutcome::Reconnect(format!("decode error during handshake: {e}"));
            }
        }
    };

    // ── 4. Negotiate hold time, send KEEPALIVE → Established ───────────────
    let hold_secs = cfg.hold_time.min(peer_open.hold_time);
    info!(
        peer = %cfg.peer_addr,
        peer_asn = peer_open.asn,
        hold = hold_secs,
        "OPEN received; negotiated hold time"
    );

    if let Err(e) = stream.write_all(&encode_keepalive()).await {
        return SessionOutcome::Reconnect(format!("send post-open KEEPALIVE failed: {e}"));
    }
    info!(peer = %cfg.peer_addr, "Established");

    // ── 5. Re-announce the full active set ──────────────────────────────────
    for route in active.values() {
        let pkt = build_announce(route);
        if let Err(e) = stream.write_all(&pkt).await {
            return SessionOutcome::Reconnect(format!("re-announce write failed: {e}"));
        }
    }
    if !active.is_empty() {
        debug!(peer = %cfg.peer_addr, count = active.len(), "re-announced active routes");
    }

    // ── 6. Established event loop ───────────────────────────────────────────
    established_loop(cfg, commands, active, &mut stream, &mut buf, hold_secs).await
}

/// Return `true` when a decode error means the buffer is simply incomplete.
fn is_partial(e: &crate::BgpError) -> bool {
    let s = e.to_string();
    s.contains("buffer too short") || s.contains("short header")
}

/// The established-state event loop.
///
/// Drives keepalive/hold timers and processes both inbound frames and outbound
/// commands.  Returns when the session needs to reconnect or the command
/// channel closes.
async fn established_loop(
    cfg: &PeerConfig,
    commands: &mut mpsc::Receiver<SessionCommand>,
    active: &mut HashMap<IpNet, Route>,
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    hold_secs: u16,
) -> SessionOutcome {
    // Keepalive interval = hold/3, minimum 1 s.  RFC 4271 §6.7.
    // If hold_secs == 0, no hold timer; use a 30 s keepalive to stay alive.
    let ka_interval = if hold_secs == 0 {
        Duration::from_secs(30)
    } else {
        Duration::from_secs((u64::from(hold_secs) / 3).max(1))
    };
    let hold_dur = if hold_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(u64::from(hold_secs)))
    };

    let mut ka_deadline = Instant::now() + ka_interval;
    let mut hold_deadline = hold_dur.map(|d| Instant::now() + d);

    loop {
        // Drain all completely buffered frames before sleeping.
        loop {
            match decode_message(buf) {
                Ok((msg, consumed)) => {
                    buf.drain(..consumed);
                    match msg {
                        BgpMessage::Keepalive | BgpMessage::Update => {
                            debug!(peer = %cfg.peer_addr, "inbound KEEPALIVE/UPDATE — reset hold timer");
                            hold_deadline = hold_dur.map(|d| Instant::now() + d);
                        }
                        BgpMessage::Notification(n) => {
                            warn!(
                                peer = %cfg.peer_addr,
                                code = n.code,
                                subcode = n.subcode,
                                "received NOTIFICATION — reconnecting"
                            );
                            return SessionOutcome::Reconnect(format!(
                                "peer sent NOTIFICATION code={} subcode={}",
                                n.code, n.subcode
                            ));
                        }
                        BgpMessage::Open(_) => {
                            warn!(
                                peer = %cfg.peer_addr,
                                "unexpected OPEN in Established state — ignoring"
                            );
                        }
                    }
                }
                Err(e) if is_partial(&e) => break,
                Err(e) => {
                    error!(peer = %cfg.peer_addr, "frame decode error: {e}");
                    return SessionOutcome::Reconnect(format!("frame decode error: {e}"));
                }
            }
        }

        // Compute remaining time until each deadline.
        let now = Instant::now();
        let ka_wait = ka_deadline.saturating_duration_since(now);

        // Compute hold timer wait; if hold_secs == 0, hold_deadline is None.
        let hold_remaining = hold_deadline.map(|d| d.saturating_duration_since(now));

        tokio::select! {
            biased;

            // Keepalive timer: send KEEPALIVE.
            () = tokio::time::sleep(ka_wait) => {
                if let Err(e) = stream.write_all(&encode_keepalive()).await {
                    return SessionOutcome::Reconnect(format!("keepalive write failed: {e}"));
                }
                debug!(peer = %cfg.peer_addr, "KEEPALIVE sent");
                ka_deadline = Instant::now() + ka_interval;
            }

            // Hold timer: send NOTIFICATION code 4 sub 0 and reconnect.
            () = async {
                match hold_remaining {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            } => {
                warn!(peer = %cfg.peer_addr, "hold timer expired — sending NOTIFICATION");
                let notif = encode_notification(&NotificationMsg {
                    code: 4,
                    subcode: 0,
                    data: vec![],
                });
                let _ = stream.write_all(&notif).await;
                return SessionOutcome::Reconnect("hold timer expired".to_owned());
            }

            // Socket readable: read into buffer.
            result = stream.read_buf(buf) => {
                match result {
                    Ok(0) => {
                        return SessionOutcome::Reconnect("peer closed connection".to_owned());
                    }
                    Ok(_) => {
                        // Data appended; next iteration decodes.
                    }
                    Err(e) => {
                        return SessionOutcome::Reconnect(format!("socket read error: {e}"));
                    }
                }
            }

            // Application command.
            cmd = commands.recv() => {
                match cmd {
                    None => {
                        return SessionOutcome::CommandsExhausted;
                    }
                    Some(SessionCommand::Announce(route)) => {
                        let prefix = route.prefix;
                        let pkt = build_announce(&route);
                        active.insert(prefix, route);
                        if let Err(e) = stream.write_all(&pkt).await {
                            return SessionOutcome::Reconnect(
                                format!("announce write failed: {e}")
                            );
                        }
                        debug!(peer = %cfg.peer_addr, %prefix, "announced");
                    }
                    Some(SessionCommand::Withdraw(prefix)) => {
                        active.remove(&prefix);
                        let pkt = build_withdraw(&prefix);
                        if let Err(e) = stream.write_all(&pkt).await {
                            return SessionOutcome::Reconnect(
                                format!("withdraw write failed: {e}")
                            );
                        }
                        debug!(peer = %cfg.peer_addr, %prefix, "withdrawn");
                    }
                }
            }
        }
    }
}
