//! Thin async TCP connection flood: hold `concurrency` concurrent connections
//! cycling connect -> read the banner -> close, classifying each as served
//! (banner), dropped (accepted then closed with no banner = the engine's
//! drop-at-cap), or failed (connect errored). Coverage-excluded; validated by
//! the deception-resilience lab gate.

use crate::report::ConnectReport;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

/// Per-connection `connect` cap. The engine's drop-at-cap defense stops
/// `accept()`ing once it is saturated; further SYNs then sit unanswered in a
/// full listen backlog, so an un-bounded `TcpStream::connect` would block
/// indefinitely (the root cause of the #136 hang). Bounding it means a stalled
/// connect is classified as `failed` (backlog) instead of wedging the worker.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-connection banner-read cap: a connection the engine accepted but never
/// sent a banner on (drop-at-cap) is counted `dropped` once the read stalls.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Run a connection flood to `dst:port` with `concurrency` workers for `duration`.
///
/// Every worker races each connect+read attempt against the shared `deadline`
/// (`Instant::now() + duration`), so the flood **always** returns within
/// `duration` plus a small grace, even if every target connection is accepted
/// then held open or silently black-holed. A connection cut off at the deadline
/// counts as `dropped` (attempted, no banner) so the report stays meaningful.
pub async fn run_connect_flood(
    dst: Ipv4Addr,
    port: u16,
    concurrency: usize,
    duration: Duration,
) -> ConnectReport {
    let attempted = Arc::new(AtomicU64::new(0));
    let served = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let addr = SocketAddr::new(IpAddr::V4(dst), port);
    let deadline = tokio::time::Instant::now() + duration;

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let (a, s, d, f) = (
            attempted.clone(),
            served.clone(),
            dropped.clone(),
            failed.clone(),
        );
        handles.push(tokio::spawn(async move {
            while tokio::time::Instant::now() < deadline {
                a.fetch_add(1, Ordering::Relaxed);
                // One connect + banner-read attempt, each independently bounded.
                let attempt = async {
                    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                        Ok(Ok(mut stream)) => {
                            let mut buf = [0u8; 64];
                            match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
                                Ok(Ok(n)) if n > 0 => s.fetch_add(1, Ordering::Relaxed),
                                // EOF (0 bytes), read error, or read timeout: no banner = dropped at cap.
                                _ => d.fetch_add(1, Ordering::Relaxed),
                            };
                            // `stream` drops here -> connection closed, freeing a slot.
                        }
                        // connect errored (refused/reset) or timed out (full backlog): bounded.
                        _ => {
                            f.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                };
                // Race the attempt against the global deadline: a connection the
                // engine accepts-then-stalls (or black-holes) can never outlive
                // `duration`. If the deadline wins, the in-flight attempt is
                // cancelled (its socket dropped) and counted as `dropped`.
                tokio::select! {
                    () = attempt => {}
                    () = tokio::time::sleep_until(deadline) => {
                        d.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    ConnectReport {
        attempted: attempted.load(Ordering::Relaxed),
        served: served.load(Ordering::Relaxed),
        dropped: dropped.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    /// Regression for #136: a target that accepts connections then holds them
    /// open without ever sending a banner must NOT wedge the flood. Before the
    /// deadline race, an un-bounded connect/read against a saturating engine
    /// blocked a worker past the deadline and `run_connect_flood` never
    /// returned. The invariant: the flood returns within `duration` + grace even
    /// when every connection is accepted-then-held, classifying them `dropped`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_flood_returns_when_target_accepts_and_holds() {
        // Bind a listener and hold it: the kernel completes each handshake into
        // the accept backlog, so every connect succeeds but no banner is ever
        // written -> each worker's read stalls until its per-read timeout.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let duration = Duration::from_secs(1);
        let grace = Duration::from_secs(3);
        let report = tokio::time::timeout(
            duration + grace,
            run_connect_flood(Ipv4Addr::LOCALHOST, port, 8, duration),
        )
        .await
        .expect("connect flood must return within duration + grace, not hang");

        // Meaningful classification: attempts were made and the held (banner-less)
        // connections counted as dropped, keeping `served>0 AND dropped+failed>0`
        // achievable for a real engine that also serves some.
        assert!(report.attempted > 0, "no attempts recorded: {report:?}");
        assert!(
            report.dropped + report.failed > 0,
            "held connections were not counted as dropped/failed: {report:?}"
        );

        drop(listener);
    }

    /// Regression for #136: a black-holed target (SYNs silently dropped, connect
    /// never completes) must still honor the deadline. `203.0.113.0/24` is
    /// TEST-NET-3 (RFC 5737), guaranteed not to host a responder. Whether the
    /// local stack stalls the connect (the pre-fix hang) or errors it quickly,
    /// the flood must return within `duration` + grace.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_flood_honors_deadline_against_blackhole() {
        let duration = Duration::from_secs(1);
        let grace = Duration::from_secs(3);
        let blackhole = Ipv4Addr::new(203, 0, 113, 1);
        let report = tokio::time::timeout(
            duration + grace,
            run_connect_flood(blackhole, 22, 16, duration),
        )
        .await
        .expect("connect flood to a black hole must return within duration + grace, not hang");

        assert!(
            report.served == 0,
            "black hole cannot serve a banner: {report:?}"
        );
        assert!(report.attempted > 0, "no attempts recorded: {report:?}");
    }
}
