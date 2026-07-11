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
//! [`tokio::task::JoinHandle`] for shutdown signalling.
//!
//! [`run`] loops forever (reconnecting on any error):
//! 1. TCP-connect `cfg.peer_addr`.
//! 2. Send an OPEN.
//! 3. Read frames until the peer's OPEN; negotiate hold time.
//! 4. Send KEEPALIVE → Established.
//! 5. Re-announce the full `active` set.
//! 6. `tokio::select!` over keepalive interval / hold timeout / socket
//!    readable / command channel.
//! 7. On any error: drain pending commands, log, back off (exponential),
//!    restart.

use crate::{
    build_announce, build_flowspec_announce, build_flowspec_withdraw, build_withdraw,
    decode_message, encode_keepalive, encode_notification, encode_open, parse_header, BgpMessage,
    FlowSpecRule, NotificationMsg, OpenMsg, Route, HEADER_LEN,
};
use ipnet::IpNet;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    future, io,
    net::{Ipv4Addr, SocketAddr},
    os::unix::io::AsRawFd,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, watch},
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
    /// Optional TCP-MD5 (RFC 2385) shared secret. When `Some`, the session
    /// installs the key via `setsockopt(TCP_MD5SIG)` before connecting, so the
    /// TCP connection itself is authenticated. `None` connects in the clear.
    pub md5: Option<String>,
    /// Optional GTSM (RFC 5082) TTL-security hop count. When `Some(n)`, the
    /// session sends with IP TTL 255 and rejects received packets whose TTL is
    /// below `256 - n` (so `1` = a directly-connected peer must arrive with TTL
    /// 255). Cheaply defeats off-link spoofed BGP packets. `None` disables it.
    pub gtsm_hops: Option<u8>,
    /// Optional BGP source address. When `Some`, the session binds it as the TCP
    /// source before connecting, so a pinned-`neighbor` peer (e.g. BIRD) accepts
    /// the session. `None` = OS-chosen source.
    pub local_addr: Option<std::net::IpAddr>,
}

/// A `PeerConfig` that cannot form a valid iBGP session.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerConfigError {
    /// This speaker is iBGP-injection-only; local and peer ASN must match.
    #[error("not iBGP: local_asn {local} != peer_asn {peer}")]
    NotIbgp {
        /// The configured local ASN.
        local: u32,
        /// The configured peer ASN.
        peer: u32,
    },
    /// RFC 4271: a non-zero hold time below 3 seconds is unacceptable.
    #[error("hold time {0} is invalid (must be 0 or >= 3)")]
    BadHoldTime(u16),
    /// GTSM (RFC 5082) requires a hop count of at least 1.
    #[error("gtsm hops must be >= 1")]
    BadGtsmHops,
}

/// A route command could not be delivered to the session task.
#[derive(Debug, thiserror::Error)]
#[error("BGP session task is not running; command dropped")]
pub struct BgpSendError;

impl PeerConfig {
    /// Validate the configuration for an iBGP-injection session.
    ///
    /// # Errors
    ///
    /// Returns [`PeerConfigError`] if `local_asn != peer_asn` (eBGP is
    /// unsupported) or if the hold time is 1 or 2 (RFC 4271 requires 0 or ≥ 3).
    pub fn validate(&self) -> Result<(), PeerConfigError> {
        if self.local_asn != self.peer_asn {
            return Err(PeerConfigError::NotIbgp {
                local: self.local_asn,
                peer: self.peer_asn,
            });
        }
        if self.hold_time == 1 || self.hold_time == 2 {
            return Err(PeerConfigError::BadHoldTime(self.hold_time));
        }
        if self.gtsm_hops == Some(0) {
            return Err(PeerConfigError::BadGtsmHops);
        }
        Ok(())
    }
}

/// A command sent from the application to the BGP session.
pub enum SessionCommand {
    /// Announce a route; replaces any existing entry for the same prefix.
    Announce(Route),
    /// Withdraw a previously-announced prefix.
    Withdraw(IpNet),
    /// Announce a FlowSpec rule; replaces any existing entry with the same
    /// encoded NLRI.
    AnnounceFlowSpec(FlowSpecRule),
    /// Withdraw a previously-announced FlowSpec rule.
    WithdrawFlowSpec(FlowSpecRule),
}

/// The observable state of a BGP session.
///
/// Published on a [`tokio::sync::watch`] channel (see [`BgpHandle::state_watch`])
/// so a supervisor can react when the session leaves [`SessionState::Established`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session is running — the command channel closed and the task exited.
    Idle,
    /// (Re)connecting: TCP connect plus the OPEN handshake, including the
    /// exponential backoff between reconnect attempts.
    Connecting,
    /// Established: the OPEN handshake completed and routes are being exchanged.
    Established,
}

/// A handle to a running BGP session for injecting routes.
///
/// Cheaply cloneable; all clones share the same channel and observe the same
/// session state.
#[derive(Clone)]
pub struct BgpHandle {
    tx: mpsc::Sender<SessionCommand>,
    state: watch::Receiver<SessionState>,
    reconnects: Arc<AtomicU64>,
}

impl BgpHandle {
    /// The latest observed [`SessionState`].
    #[must_use]
    pub fn state(&self) -> SessionState {
        *self.state.borrow()
    }

    /// A [`watch::Receiver`] for awaiting session-state transitions — e.g. a
    /// supervisor that warns when the session leaves [`SessionState::Established`].
    #[must_use]
    pub fn state_watch(&self) -> watch::Receiver<SessionState> {
        self.state.clone()
    }

    /// Total reconnect attempts since [`spawn`] (excludes the initial connect).
    #[must_use]
    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// Announce a route to the BGP peer.
    ///
    /// The route is stored in the session's active set and re-announced on
    /// reconnect.
    ///
    /// # Errors
    ///
    /// Returns [`BgpSendError`] if the session task has exited (the route is
    /// not queued). The caller should treat this as a failed announce.
    pub async fn announce(&self, route: Route) -> Result<(), BgpSendError> {
        self.tx
            .send(SessionCommand::Announce(route))
            .await
            .map_err(|_| {
                warn!("BGP announce dropped: session task not running");
                BgpSendError
            })
    }

    /// Withdraw a previously-announced prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BgpSendError`] if the session task has exited.
    pub async fn withdraw(&self, prefix: IpNet) -> Result<(), BgpSendError> {
        self.tx
            .send(SessionCommand::Withdraw(prefix))
            .await
            .map_err(|_| {
                warn!("BGP withdraw dropped: session task not running");
                BgpSendError
            })
    }

    /// Announce a FlowSpec rule to the BGP peer.
    ///
    /// The rule is stored in the session's active FlowSpec set and
    /// re-announced on reconnect.
    ///
    /// # Errors
    ///
    /// Returns [`BgpSendError`] if the session task has exited (the rule is
    /// not queued). The caller should treat this as a failed announce.
    pub async fn announce_flowspec(&self, rule: FlowSpecRule) -> Result<(), BgpSendError> {
        self.tx
            .send(SessionCommand::AnnounceFlowSpec(rule))
            .await
            .map_err(|_| {
                warn!("BGP FlowSpec announce dropped: session task not running");
                BgpSendError
            })
    }

    /// Withdraw a previously-announced FlowSpec rule.
    ///
    /// # Errors
    ///
    /// Returns [`BgpSendError`] if the session task has exited.
    pub async fn withdraw_flowspec(&self, rule: FlowSpecRule) -> Result<(), BgpSendError> {
        self.tx
            .send(SessionCommand::WithdrawFlowSpec(rule))
            .await
            .map_err(|_| {
                warn!("BGP FlowSpec withdraw dropped: session task not running");
                BgpSendError
            })
    }
}

// ── spawn ─────────────────────────────────────────────────────────────────────

/// Spawn a BGP session task and return a handle for controlling it.
///
/// The task runs until the process exits (or the [`tokio::task::JoinHandle`] is aborted).
/// It reconnects automatically on any I/O error or hold-timer expiry.
///
/// # Errors
///
/// Returns [`PeerConfigError`] if `cfg` is not a valid iBGP configuration.
pub fn spawn(cfg: PeerConfig) -> Result<(BgpHandle, tokio::task::JoinHandle<()>), PeerConfigError> {
    cfg.validate()?;
    if cfg.hold_time == 0 {
        warn!(peer = %cfg.peer_addr, "hold_time is 0: dead-peer detection disabled");
    }
    let (tx, rx) = mpsc::channel(256);
    let (state_tx, state_rx) = watch::channel(SessionState::Idle);
    let reconnects = Arc::new(AtomicU64::new(0));
    let handle = BgpHandle {
        tx,
        state: state_rx,
        reconnects: Arc::clone(&reconnects),
    };
    let join = tokio::spawn(run(cfg, rx, state_tx, reconnects));
    Ok((handle, join))
}

// ── FSM ───────────────────────────────────────────────────────────────────────

/// The BGP session FSM loop.
///
/// Never returns under normal operation — reconnects indefinitely on error.
/// Maintains `active: HashMap<IpNet, Route>` and re-advertises after each
/// successful session establishment.
pub async fn run(
    cfg: PeerConfig,
    mut commands: mpsc::Receiver<SessionCommand>,
    state: watch::Sender<SessionState>,
    reconnects: Arc<AtomicU64>,
) {
    let mut active: HashMap<IpNet, Route> = HashMap::new();
    let mut active_flowspec: HashMap<Vec<u8>, FlowSpecRule> = HashMap::new();
    let mut consecutive_failures: u32 = 0;

    // Announce the initial connect attempt before the first `session_once`.
    let _ = state.send(SessionState::Connecting);

    loop {
        let outcome = session_once(
            &cfg,
            &mut commands,
            &mut active,
            &mut active_flowspec,
            &state,
            &mut consecutive_failures,
        )
        .await;
        match outcome {
            SessionOutcome::Reconnect(msg) => {
                // The session dropped (or never came up): leave Established
                // immediately so a supervisor sees the outage, then back off.
                let _ = state.send(SessionState::Connecting);
                reconnects.fetch_add(1, Ordering::Relaxed);
                consecutive_failures = consecutive_failures.saturating_add(1);
                let delay = backoff_delay(consecutive_failures);
                info!(peer = %cfg.peer_addr, ?delay, "{msg}; reconnecting");
                // Drain any queued commands before sleeping (keeps active in sync).
                drain_commands(&mut commands, &mut active, &mut active_flowspec);
                tokio::time::sleep(delay).await;
            }
            SessionOutcome::CommandsExhausted => {
                let _ = state.send(SessionState::Idle);
                info!(
                    peer = %cfg.peer_addr,
                    "command channel closed; exiting BGP session loop"
                );
                return;
            }
        }
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

/// Read buffer ceiling: 64 KiB.  A single BGP message is ≤ 4096 bytes, so if
/// the buffer grows past this the peer is dribbling bytes without completing
/// frames — treat it as corruption and reconnect.
const READ_BUF_LIMIT: usize = 65536;

/// Apply pending commands to `active` without writing anything on the wire.
///
/// Called while no session is up, so we just update the local state.
fn drain_commands(
    commands: &mut mpsc::Receiver<SessionCommand>,
    active: &mut HashMap<IpNet, Route>,
    active_flowspec: &mut HashMap<Vec<u8>, FlowSpecRule>,
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
            Ok(SessionCommand::AnnounceFlowSpec(rule)) => {
                let key = crate::flowspec::encode_flowspec_nlri(&rule);
                active_flowspec.insert(key, rule);
            }
            Ok(SessionCommand::WithdrawFlowSpec(rule)) => {
                let key = crate::flowspec::encode_flowspec_nlri(&rule);
                active_flowspec.remove(&key);
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
    active_flowspec: &mut HashMap<Vec<u8>, FlowSpecRule>,
    state: &watch::Sender<SessionState>,
    consecutive_failures: &mut u32,
) -> SessionOutcome {
    // ── 1. TCP connect ──────────────────────────────────────────────────────
    let mut stream = match connect_peer(
        cfg.peer_addr,
        cfg.md5.as_deref(),
        cfg.gtsm_hops,
        cfg.local_addr,
    )
    .await
    {
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
        flowspec_v4: true,
        flowspec_v6: true,
    };
    let open_bytes = encode_open(&local_open);
    if let Err(e) = stream.write_all(&open_bytes).await {
        return SessionOutcome::Reconnect(format!("send OPEN failed: {e}"));
    }
    debug!(peer = %cfg.peer_addr, "OPEN sent");

    // ── 3. Read peer's OPEN (length-based framing) ─────────────────────────
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let peer_open = 'handshake: loop {
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

        // Fix 2: reject runaway buffers.
        if buf.len() > READ_BUF_LIMIT {
            error!(peer = %cfg.peer_addr, "read buffer overflow during handshake");
            return SessionOutcome::Reconnect("read buffer overflow".to_owned());
        }

        // Fix 1: length-based framing — try to consume all complete frames.
        loop {
            if buf.len() < HEADER_LEN {
                // Not enough bytes for a header yet; read more.
                break;
            }
            let (ty, total_len) = match parse_header(&buf) {
                Ok(v) => v,
                Err(e) => {
                    error!(peer = %cfg.peer_addr, "bad BGP header during handshake: {e}");
                    return SessionOutcome::Reconnect(format!(
                        "decode error during handshake: {e}"
                    ));
                }
            };
            if buf.len() < total_len {
                // Frame is incomplete; read more bytes.
                break;
            }
            // We have a complete frame — decode it.
            match decode_message(&buf[..total_len]) {
                Ok((BgpMessage::Open(o), _)) => {
                    buf.drain(..total_len);
                    break 'handshake o;
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
                    // Unexpected Keepalive/Update before OPEN — skip and keep waiting.
                    warn!(
                        peer = %cfg.peer_addr,
                        msg_type = ty,
                        "unexpected non-OPEN message during handshake"
                    );
                    buf.drain(..total_len);
                }
                Err(e) => {
                    return SessionOutcome::Reconnect(format!(
                        "decode error during handshake: {e}"
                    ));
                }
            }
        }
    };

    // Validate the peer's OPEN. iBGP: the peer's ASN must equal the configured
    // peer ASN. RFC 4271 §6.2: OPEN error (code 2), bad-peer-AS (subcode 2).
    if peer_open.asn != cfg.peer_asn {
        let notif = encode_notification(&NotificationMsg {
            code: 2,
            subcode: 2,
            data: vec![],
        });
        let _ = stream.write_all(&notif).await;
        return SessionOutcome::Reconnect(format!(
            "peer ASN {} != configured {}",
            peer_open.asn, cfg.peer_asn
        ));
    }
    // RFC 4271 §6.2: unacceptable hold time (subcode 6) for a non-zero value < 3.
    if peer_open.hold_time == 1 || peer_open.hold_time == 2 {
        let notif = encode_notification(&NotificationMsg {
            code: 2,
            subcode: 6,
            data: vec![],
        });
        let _ = stream.write_all(&notif).await;
        return SessionOutcome::Reconnect(format!(
            "peer proposed unacceptable hold time {}",
            peer_open.hold_time
        ));
    }

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
    // RFC 4271: not Established until the peer confirms our OPEN with a KEEPALIVE
    // (or UPDATE). Wait for one before advertising, so a strict peer's OpenConfirm
    // state can't reject our early UPDATEs with an FSM error and flap us.
    //
    // Bound that wait with the OpenConfirm HoldTimer (RFC 4271 §8): a peer that
    // accepts our OPEN and then goes silent must force a reconnect, not hang the
    // session task forever. Use the negotiated hold time, or a fixed ceiling when
    // hold timers are disabled (hold == 0).
    let confirm_timeout = if hold_secs == 0 {
        Duration::from_secs(240)
    } else {
        Duration::from_secs(u64::from(hold_secs))
    };
    match tokio::time::timeout(
        confirm_timeout,
        await_peer_confirmation(cfg, &mut stream, &mut buf),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(outcome)) => return outcome,
        Err(_elapsed) => {
            return SessionOutcome::Reconnect(
                "timed out waiting for peer OPEN confirmation".to_owned(),
            )
        }
    }
    info!(peer = %cfg.peer_addr, "Established");
    *consecutive_failures = 0;
    let _ = state.send(SessionState::Established);

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

    for rule in active_flowspec.values() {
        let pkt = build_flowspec_announce(rule);
        if let Err(e) = stream.write_all(&pkt).await {
            return SessionOutcome::Reconnect(format!("FlowSpec re-announce write failed: {e}"));
        }
    }
    if !active_flowspec.is_empty() {
        debug!(
            peer = %cfg.peer_addr,
            count = active_flowspec.len(),
            "re-announced active FlowSpec rules"
        );
    }

    // ── 6. Established event loop ───────────────────────────────────────────
    established_loop(
        cfg,
        commands,
        active,
        active_flowspec,
        &mut stream,
        &mut buf,
        hold_secs,
    )
    .await
}

/// Wait for the peer to confirm our OPEN with a KEEPALIVE (or UPDATE), per
/// RFC 4271's OpenConfirm state.
///
/// Uses the same length-based framing as the handshake loop in
/// [`session_once`], honoring [`READ_BUF_LIMIT`]. Any leftover buffered bytes
/// (e.g. a piggy-backed UPDATE after the confirming frame) remain in `buf`
/// for `established_loop` to consume. A stray OPEN is ignored and discarded;
/// a NOTIFICATION, decode error, EOF, or buffer overflow ends the session.
async fn await_peer_confirmation(
    cfg: &PeerConfig,
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<(), SessionOutcome> {
    loop {
        // Drain any already-buffered complete frames first.
        loop {
            if buf.len() < HEADER_LEN {
                break;
            }
            let (_, total_len) = match parse_header(buf) {
                Ok(v) => v,
                Err(e) => {
                    return Err(SessionOutcome::Reconnect(format!(
                        "decode error awaiting OpenConfirm: {e}"
                    )))
                }
            };
            if buf.len() < total_len {
                break;
            }
            match decode_message(&buf[..total_len]) {
                Ok((BgpMessage::Keepalive | BgpMessage::Update, _)) => {
                    buf.drain(..total_len);
                    return Ok(());
                }
                Ok((BgpMessage::Notification(n), _)) => {
                    warn!(
                        peer = %cfg.peer_addr,
                        code = n.code,
                        subcode = n.subcode,
                        "NOTIFICATION awaiting OpenConfirm"
                    );
                    return Err(SessionOutcome::Reconnect(format!(
                        "NOTIFICATION awaiting OpenConfirm code={} subcode={}",
                        n.code, n.subcode
                    )));
                }
                Ok((BgpMessage::Open(_), _)) => {
                    // Stray retransmitted OPEN — discard and keep waiting.
                    warn!(peer = %cfg.peer_addr, "unexpected OPEN awaiting OpenConfirm — ignoring");
                    buf.drain(..total_len);
                }
                Err(e) => {
                    return Err(SessionOutcome::Reconnect(format!(
                        "decode error awaiting OpenConfirm: {e}"
                    )));
                }
            }
        }

        let mut tmp = [0u8; 4096];
        let n = match stream.read(&mut tmp).await {
            Ok(0) => {
                return Err(SessionOutcome::Reconnect(
                    "peer closed connection awaiting OpenConfirm".to_owned(),
                ))
            }
            Ok(n) => n,
            Err(e) => {
                return Err(SessionOutcome::Reconnect(format!(
                    "read error awaiting OpenConfirm: {e}"
                )))
            }
        };
        buf.extend_from_slice(&tmp[..n]);

        if buf.len() > READ_BUF_LIMIT {
            error!(peer = %cfg.peer_addr, "read buffer overflow awaiting OpenConfirm");
            return Err(SessionOutcome::Reconnect(
                "read buffer overflow awaiting OpenConfirm".to_owned(),
            ));
        }
    }
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
    active_flowspec: &mut HashMap<Vec<u8>, FlowSpecRule>,
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    hold_secs: u16,
) -> SessionOutcome {
    // Fix 3: when hold_secs == 0 (RFC 4271: no keepalive/hold timers), park the
    // keepalive arm on `pending()` so we never send unsolicited KEEPALIVEs.
    // When hold_secs > 0, keepalive every hold/3 (min 1 s).  RFC 4271 §6.7.
    let ka_interval = if hold_secs == 0 {
        None
    } else {
        Some(Duration::from_secs((u64::from(hold_secs) / 3).max(1)))
    };
    let hold_dur = if hold_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(u64::from(hold_secs)))
    };

    let mut ka_deadline = ka_interval.map(|d| Instant::now() + d);
    let mut hold_deadline = hold_dur.map(|d| Instant::now() + d);

    loop {
        // Fix 1: length-based framing — drain all complete buffered frames.
        loop {
            if buf.len() < HEADER_LEN {
                break;
            }
            let (_, total_len) = match parse_header(buf) {
                Ok(v) => v,
                Err(e) => {
                    error!(peer = %cfg.peer_addr, "bad BGP header: {e}");
                    return SessionOutcome::Reconnect(format!("frame decode error: {e}"));
                }
            };
            if buf.len() < total_len {
                // Incomplete frame — wait for more bytes.
                break;
            }
            match decode_message(&buf[..total_len]) {
                Ok((msg, _)) => {
                    buf.drain(..total_len);
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
                Err(e) => {
                    error!(peer = %cfg.peer_addr, "frame decode error: {e}");
                    return SessionOutcome::Reconnect(format!("frame decode error: {e}"));
                }
            }
        }

        // Compute remaining time until each deadline.
        let now = Instant::now();

        // Keepalive wait: None → park on pending() (hold == 0 case).
        let ka_remaining = ka_deadline.map(|d| d.saturating_duration_since(now));

        // Hold timer wait; if hold_secs == 0, hold_deadline is None → pending().
        let hold_remaining = hold_deadline.map(|d| d.saturating_duration_since(now));

        tokio::select! {
            biased;

            // Keepalive timer: send KEEPALIVE, or park forever when hold == 0.
            () = async {
                match ka_remaining {
                    Some(d) => tokio::time::sleep(d).await,
                    None => future::pending().await,
                }
            } => {
                if let Err(e) = stream.write_all(&encode_keepalive()).await {
                    return SessionOutcome::Reconnect(format!("keepalive write failed: {e}"));
                }
                debug!(peer = %cfg.peer_addr, "KEEPALIVE sent");
                ka_deadline = ka_interval.map(|d| Instant::now() + d);
            }

            // Hold timer: send NOTIFICATION code 4 sub 0 and reconnect.
            () = async {
                match hold_remaining {
                    Some(d) => tokio::time::sleep(d).await,
                    None => future::pending().await,
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
                        // Fix 2: reject runaway buffers.
                        if buf.len() > READ_BUF_LIMIT {
                            error!(peer = %cfg.peer_addr, "read buffer overflow");
                            return SessionOutcome::Reconnect("read buffer overflow".to_owned());
                        }
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
                    Some(SessionCommand::AnnounceFlowSpec(rule)) => {
                        let key = crate::flowspec::encode_flowspec_nlri(&rule);
                        let pkt = build_flowspec_announce(&rule);
                        active_flowspec.insert(key, rule);
                        if let Err(e) = stream.write_all(&pkt).await {
                            return SessionOutcome::Reconnect(
                                format!("FlowSpec announce write failed: {e}")
                            );
                        }
                        debug!(peer = %cfg.peer_addr, "FlowSpec rule announced");
                    }
                    Some(SessionCommand::WithdrawFlowSpec(rule)) => {
                        let key = crate::flowspec::encode_flowspec_nlri(&rule);
                        active_flowspec.remove(&key);
                        let pkt = build_flowspec_withdraw(&rule);
                        if let Err(e) = stream.write_all(&pkt).await {
                            return SessionOutcome::Reconnect(
                                format!("FlowSpec withdraw write failed: {e}")
                            );
                        }
                        debug!(peer = %cfg.peer_addr, "FlowSpec rule withdrawn");
                    }
                }
            }
        }
    }
}

// ── Reconnect backoff + TCP connect (optional TCP-MD5, RFC 2385) ───────────────

/// Reconnect backoff: 1s, 2, 4, 8, 16, then capped at 30s. Reset to `0` after a
/// session reaches Established. No jitter — a single local peer, no herd.
fn backoff_delay(consecutive_failures: u32) -> Duration {
    let secs = 1u64
        .checked_shl(consecutive_failures)
        .unwrap_or(u64::MAX)
        .min(30);
    Duration::from_secs(secs)
}

/// The Linux `struct tcp_md5sig` (RFC 2385), mirrored from
/// `include/uapi/linux/tcp.h`.
///
/// `libc` 0.2.186 exposes the `TCP_MD5SIG*` constants but not this struct, so we
/// reproduce its `#[repr(C)]` layout: a `sockaddr_storage`, the extension header
/// (`flags`, `prefixlen`, `keylen`, `ifindex`), then the fixed-length key. We
/// only use the base `TCP_MD5SIG` option, so `flags`/`prefixlen`/`ifindex`
/// remain zero.
#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: libc::c_int,
    tcpm_key: [u8; libc::TCP_MD5SIG_MAXKEYLEN],
}

/// Connect to `addr`, optionally installing a TCP-MD5 (RFC 2385) signature for
/// the peer and/or binding a specific source address. With `md5 == None`,
/// `gtsm_hops == None`, and `local_addr == None` this is exactly
/// [`TcpStream::connect`].
///
/// # Errors
///
/// Returns any TCP connect error, an error from installing the MD5 key (e.g.
/// a key longer than [`libc::TCP_MD5SIG_MAXKEYLEN`] bytes), or an error from
/// binding `local_addr`.
async fn connect_peer(
    addr: SocketAddr,
    md5: Option<&str>,
    gtsm_hops: Option<u8>,
    local_addr: Option<std::net::IpAddr>,
) -> io::Result<TcpStream> {
    // The plain path is only valid with none of the socket options set;
    // otherwise build the socket ourselves so we can apply them before connect.
    if md5.is_none() && gtsm_hops.is_none() && local_addr.is_none() {
        return TcpStream::connect(addr).await;
    }
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if let Some(key) = md5 {
        set_tcp_md5sig(&sock, addr, key)?;
    }
    if let Some(hops) = gtsm_hops {
        set_gtsm(&sock, addr, hops)?;
    }
    if let Some(src) = local_addr {
        sock.bind(&socket2::SockAddr::from(std::net::SocketAddr::new(src, 0)))?;
    }
    sock.set_nonblocking(true)?;
    // A nonblocking connect returns EINPROGRESS; hand the fd to tokio, which
    // drives the connect to completion.
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?; // completes the async connect
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}

/// Install `TCP_MD5SIG` on `sock` for peer `addr` with `key` (Linux, RFC 2385).
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidInput`] if `key` exceeds
/// [`libc::TCP_MD5SIG_MAXKEYLEN`] bytes (the key is never truncated), or the
/// last OS error if `setsockopt` fails.
fn set_tcp_md5sig(sock: &Socket, addr: SocketAddr, key: &str) -> io::Result<()> {
    let key_bytes = key.as_bytes();
    if key_bytes.len() > libc::TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-MD5 key exceeds maximum length",
        ));
    }

    // SAFETY: `TcpMd5Sig` is a `#[repr(C)]` plain-old-data struct (integers and
    // byte arrays); an all-zero bit pattern is a valid, well-defined value.
    let mut sig: TcpMd5Sig = unsafe { std::mem::zeroed() };

    let ss: socket2::SockAddr = addr.into();
    let copy_len = usize::try_from(ss.len())
        .unwrap_or(0)
        .min(std::mem::size_of::<libc::sockaddr_storage>());
    // SAFETY: `sig.tcpm_addr` is a `sockaddr_storage` sized to hold any address
    // family; we copy exactly `copy_len` bytes (bounded by the size of
    // `sockaddr_storage`) from socket2's validated, non-overlapping `SockAddr`.
    unsafe {
        std::ptr::copy_nonoverlapping(
            ss.as_ptr().cast::<u8>(),
            std::ptr::addr_of_mut!(sig.tcpm_addr).cast::<u8>(),
            copy_len,
        );
    }

    sig.tcpm_keylen = u16::try_from(key_bytes.len()).unwrap_or(0);
    sig.tcpm_key[..key_bytes.len()].copy_from_slice(key_bytes);

    let optlen = u32::try_from(std::mem::size_of::<TcpMd5Sig>()).unwrap_or(0);
    // SAFETY: `setsockopt` reads `optlen` bytes from `&sig`, which points to a
    // live, fully-initialised `TcpMd5Sig` of exactly that size; `sock` owns a
    // valid file descriptor for the duration of the call. A non-zero return is
    // mapped to the last OS error.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig).cast(),
            optlen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install GTSM (RFC 5082) TTL-security on `sock` for a peer `hops` away.
///
/// Sends with the maximum IP TTL (255) and refuses received packets whose TTL
/// dropped below `256 - hops` — so a directly-connected peer (`hops == 1`) must
/// arrive with TTL 255, which an off-link attacker cannot forge. Sets the IPv4
/// (`IP_TTL`/`IP_MINTTL`) or IPv6 (`IPV6_UNICAST_HOPS`/`IPV6_MINHOPCOUNT`)
/// options according to the peer's address family.
///
/// # Errors
///
/// Returns the last OS error if any `setsockopt` fails. `hops` must be ≥ 1
/// (validated by [`PeerConfig::validate`]); the minimum TTL is clamped to 1.
fn set_gtsm(sock: &Socket, addr: SocketAddr, hops: u8) -> io::Result<()> {
    // Directly-connected peer (hops == 1) → min TTL 255; each extra hop lowers
    // the floor by one. Clamp to 1 so a pathological hop count stays valid.
    let min_ttl: libc::c_int = (256 - i32::from(hops)).max(1);
    let max_ttl: libc::c_int = 255;

    let (level, ttl_opt, min_opt) = if addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_TTL, libc::IP_MINTTL)
    } else {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            libc::IPV6_MINHOPCOUNT,
        )
    };
    set_sockopt_int(sock, level, ttl_opt, max_ttl)?;
    set_sockopt_int(sock, level, min_opt, min_ttl)?;
    Ok(())
}

/// `setsockopt` for a single `c_int`-valued option.
///
/// # Errors
///
/// Returns the last OS error if `setsockopt` fails.
fn set_sockopt_int(
    sock: &Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let optlen = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(0);
    // SAFETY: `setsockopt` reads `optlen` bytes from `&value`, which points to a
    // live `c_int` of exactly that size; `sock` owns a valid fd for the call.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            optlen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(local: u32, peer: u32, hold: u16) -> PeerConfig {
        PeerConfig {
            local_asn: local,
            peer_asn: peer,
            peer_addr: "10.0.0.2:179".parse().unwrap(),
            router_id: "10.0.0.1".parse().unwrap(),
            hold_time: hold,
            md5: None,
            gtsm_hops: None,
            local_addr: None,
        }
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(backoff_delay(1), Duration::from_secs(2));
        assert_eq!(backoff_delay(4), Duration::from_secs(16));
        assert_eq!(backoff_delay(5), Duration::from_secs(30)); // 32 capped to 30
        assert_eq!(backoff_delay(99), Duration::from_secs(30));
    }

    #[test]
    fn validate_accepts_ibgp_and_valid_hold() {
        assert!(cfg(65001, 65001, 90).validate().is_ok());
        assert!(cfg(65001, 65001, 0).validate().is_ok()); // 0 = no hold timer
    }

    #[test]
    fn validate_rejects_ebgp() {
        assert!(matches!(
            cfg(65001, 65002, 90).validate(),
            Err(PeerConfigError::NotIbgp { .. })
        ));
    }

    #[test]
    fn validate_rejects_hold_time_1_or_2() {
        assert!(matches!(
            cfg(65001, 65001, 1).validate(),
            Err(PeerConfigError::BadHoldTime(1))
        ));
        assert!(matches!(
            cfg(65001, 65001, 2).validate(),
            Err(PeerConfigError::BadHoldTime(2))
        ));
    }

    #[test]
    fn validate_rejects_zero_gtsm_hops() {
        let mut c = cfg(65001, 65001, 90);
        c.gtsm_hops = Some(0);
        assert!(matches!(c.validate(), Err(PeerConfigError::BadGtsmHops)));
    }

    #[test]
    fn validate_accepts_gtsm_hops() {
        let mut c = cfg(65001, 65001, 90);
        c.gtsm_hops = Some(1);
        assert!(c.validate().is_ok());
    }

    /// Read back a `c_int` socket option to confirm `set_gtsm` actually applied.
    fn getsockopt_int(sock: &Socket, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut val: libc::c_int = 0;
        let mut len = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
        // SAFETY: `getsockopt` writes up to `len` bytes into `&val`, a live
        // `c_int`; `sock` owns a valid fd for the call.
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                level,
                name,
                std::ptr::addr_of_mut!(val).cast(),
                std::ptr::addr_of_mut!(len),
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        val
    }

    #[test]
    fn set_gtsm_sets_ipv4_ttl_and_minttl() {
        let addr: SocketAddr = "10.0.0.2:179".parse().unwrap();
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
            .expect("socket");
        set_gtsm(&sock, addr, 1).expect("set_gtsm v4");
        assert_eq!(getsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_TTL), 255);
        assert_eq!(
            getsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_MINTTL),
            255
        );
    }

    #[test]
    fn set_gtsm_multihop_lowers_min_ttl() {
        let addr: SocketAddr = "10.0.0.2:179".parse().unwrap();
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
            .expect("socket");
        // 3 hops → min accepted TTL 256 - 3 = 253.
        set_gtsm(&sock, addr, 3).expect("set_gtsm v4");
        assert_eq!(
            getsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_MINTTL),
            253
        );
    }

    #[test]
    fn set_gtsm_sets_ipv6_hops_and_minhops() {
        let addr: SocketAddr = "[2001:db8::2]:179".parse().unwrap();
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
            .expect("socket");
        set_gtsm(&sock, addr, 1).expect("set_gtsm v6");
        assert_eq!(
            getsockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            255
        );
        assert_eq!(
            getsockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
            255
        );
    }

    #[test]
    fn bind_source_sets_local_addr() {
        let peer: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let sock =
            Socket::new(Domain::for_address(peer), Type::STREAM, Some(Protocol::TCP)).unwrap();
        sock.bind(&socket2::SockAddr::from(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            0,
        )))
        .unwrap();
        let local = sock.local_addr().unwrap().as_socket().unwrap();
        assert_eq!(
            local.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }
}
