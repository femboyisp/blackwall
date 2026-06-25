//! A transparent (TPROXY) TCP listener: accepts connections addressed to *any*
//! destination diverted to us by nftables, preserving the original dst.

use crate::conn::{AsyncStream, DeceptionConn, DeceptionMeta};
use crate::emulator::{EmulatorOutcome, EmulatorRegistry};
use crate::error::DeceptionError;
use blackwall_core::L4Proto;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// A TPROXY-enabled TCP listener that preserves the original destination address
/// of each diverted connection.
pub struct TproxyListener {
    inner: TcpListener,
}

impl TproxyListener {
    /// Bind a transparent listener at `addr` (typically a single local port that
    /// nftables `tproxy to`-redirects all deception TCP to). Requires
    /// `CAP_NET_ADMIN`.
    pub fn bind(addr: SocketAddr) -> Result<TproxyListener, DeceptionError> {
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_nonblocking(true)?;
        sock.set_reuse_address(true)?;
        // IP_TRANSPARENT lets us accept connections destined to non-local addrs.
        sock.set_ip_transparent(true)?;
        sock.bind(&addr.into())?;
        sock.listen(1024)?;
        let std_listener: std::net::TcpListener = sock.into();
        let inner = TcpListener::from_std(std_listener)?;
        Ok(TproxyListener { inner })
    }

    /// Accept one diverted connection. `meta.local` is the original destination
    /// the client tried to reach (preserved by TPROXY). `meta.peer` is the
    /// client address.
    pub async fn accept(&self) -> Result<(TcpStream, DeceptionMeta), DeceptionError> {
        let (stream, peer) = self.inner.accept().await?;
        let local = stream.local_addr()?;
        Ok((
            stream,
            DeceptionMeta {
                local,
                peer,
                proto: L4Proto::Tcp,
            },
        ))
    }
}

/// One completed deception session, for audit/metrics.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Connection metadata (original destination, peer, protocol).
    pub meta: DeceptionMeta,
    /// Short name of the emulator that handled the connection.
    pub emulator: String,
    /// What the emulator reported.
    pub outcome: EmulatorOutcome,
}

/// Accept diverted connections forever, dispatching each to its emulator and
/// reporting completed sessions on `sessions`.
///
/// The loop runs until the [`TproxyListener`] is dropped or the process exits.
/// Transient accept errors are logged and retried after a short back-off.
/// Emulator errors are logged but do not crash the loop.
pub async fn serve(
    listener: TproxyListener,
    registry: Arc<EmulatorRegistry>,
    sessions: mpsc::Sender<SessionRecord>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, meta)) => {
                let registry = registry.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let emulator = registry.for_port(meta.local.port());
                    let name = emulator.name().to_owned();
                    let conn = DeceptionConn {
                        stream: Box::new(stream) as Box<dyn AsyncStream>,
                        meta,
                    };
                    match emulator.handle(conn).await {
                        Ok(outcome) => {
                            let _ = sessions
                                .send(SessionRecord {
                                    meta,
                                    emulator: name,
                                    outcome,
                                })
                                .await;
                        }
                        Err(err) => {
                            tracing::debug!(
                                %err,
                                port = meta.local.port(),
                                "emulator error",
                            );
                        }
                    }
                });
            }
            Err(err) => {
                tracing::warn!(%err, "tproxy accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}
