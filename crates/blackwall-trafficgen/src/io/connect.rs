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

/// Run a connection flood to `dst:port` with `concurrency` workers for `duration`.
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
                match TcpStream::connect(addr).await {
                    Ok(mut stream) => {
                        let mut buf = [0u8; 64];
                        match tokio::time::timeout(
                            Duration::from_millis(500),
                            stream.read(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => s.fetch_add(1, Ordering::Relaxed),
                            // EOF (0 bytes), read error, or read timeout: no banner = dropped at cap.
                            _ => d.fetch_add(1, Ordering::Relaxed),
                        };
                        // `stream` drops here -> connection closed, freeing a slot.
                    }
                    Err(_) => {
                        f.fetch_add(1, Ordering::Relaxed);
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
