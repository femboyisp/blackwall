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
    encode_open, parse_header, BgpMessage, NotificationMsg, OpenMsg, Route, HEADER_LEN,
};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    future,
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
        Ok(())
    }
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
}

// ── spawn ─────────────────────────────────────────────────────────────────────

/// Spawn a BGP session task and return a handle for controlling it.
///
/// The task runs until the process exits (or the [`JoinHandle`] is aborted).
/// It reconnects automatically on any I/O error or hold-timer expiry.
///
/// # Errors
///
/// Returns [`PeerConfigError`] if `cfg` is not a valid iBGP configuration.
pub fn spawn(
    cfg: PeerConfig,
) -> Result<(BgpHandle, tokio::task::JoinHandle<()>), PeerConfigError> {
    cfg.validate()?;
    if cfg.hold_time == 0 {
        warn!(peer = %cfg.peer_addr, "hold_time is 0: dead-peer detection disabled");
    }
    let (tx, rx) = mpsc::channel(256);
    let handle = BgpHandle { tx };
    let join = tokio::spawn(run(cfg, rx));
    Ok((handle, join))
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
        let notif = encode_notification(&NotificationMsg { code: 2, subcode: 2, data: vec![] });
        let _ = stream.write_all(&notif).await;
        return SessionOutcome::Reconnect(format!(
            "peer ASN {} != configured {}", peer_open.asn, cfg.peer_asn
        ));
    }
    // RFC 4271 §6.2: unacceptable hold time (subcode 6) for a non-zero value < 3.
    if peer_open.hold_time == 1 || peer_open.hold_time == 2 {
        let notif = encode_notification(&NotificationMsg { code: 2, subcode: 6, data: vec![] });
        let _ = stream.write_all(&notif).await;
        return SessionOutcome::Reconnect(format!(
            "peer proposed unacceptable hold time {}", peer_open.hold_time
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
                }
            }
        }
    }
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
        }
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
}
