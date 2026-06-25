//! Ookla (speedtest.net) network provider — thin adapter; coverage-excluded.
//!
//! All parsing lives in [`super::ookla_parse`]; all math in [`crate::throughput::mbps_from`].

use async_trait::async_trait;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::throughput::{keep_downloading, mbps_from};

use super::ookla_parse::{download_command, parse_hello, parse_servers};

/// Maximum bytes to request in a single Ookla download (25 MiB).
const MAX_OOKLA_BYTES: u64 = 25 * 1024 * 1024;

/// Server list URL for Ookla/speedtest.net.
const SERVER_LIST_URL: &str = "https://www.speedtest.net/api/js/servers?engine=js&limit=5";

/// Speedtest provider backed by the Ookla/speedtest.net TCP protocol.
pub struct OoklaProvider {
    client: reqwest::Client,
}

impl OoklaProvider {
    /// Create a new [`OoklaProvider`] with a default [`reqwest::Client`].
    pub fn new() -> Self {
        OoklaProvider {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for OoklaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpeedtestProvider for OoklaProvider {
    fn name(&self) -> &str {
        "ookla"
    }

    /// Measure download throughput via the Ookla TCP text protocol.
    ///
    /// Fetches the server list, connects to the first server, performs the
    /// `HI`/`DOWNLOAD` handshake, and times the transfer. Download is capped
    /// at `min(cfg.max_bytes, 25 MiB)`.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
        // Fetch and parse the server list.
        let json = self
            .client
            .get(SERVER_LIST_URL)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?
            .text()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let servers = parse_servers(&json)?;
        let server = servers.into_iter().next().ok_or(SpeedtestError::NoResult)?;

        // Connect via raw TCP.
        let mut stream = TcpStream::connect(&server.host)
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        // Send HI greeting.
        stream
            .write_all(b"HI\n")
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        // Read the HELLO response line.
        let hello_line = read_line(&mut stream).await?;
        let _version = parse_hello(&hello_line);

        // Request the download.
        let bytes = cfg.max_bytes.min(MAX_OOKLA_BYTES);
        let cmd = download_command(bytes);
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        // Time the download.
        let start = Instant::now();
        let mut buf = vec![0u8; 65536];
        let mut received: u64 = 0;
        loop {
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| SpeedtestError::Http(e.to_string()))?;
            if n == 0 {
                break;
            }
            received = received.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if !keep_downloading(received, bytes, start.elapsed(), cfg.measure_window) {
                break;
            }
        }
        let elapsed = start.elapsed();

        if received == 0 {
            return Err(SpeedtestError::NoResult);
        }

        let download_mbps = mbps_from(received, elapsed);
        let latency_ms = elapsed.as_secs_f64() * 1000.0;

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps: None,
            latency_ms,
        })
    }
}

/// Read bytes from `stream` until a `\n` is encountered, returning the line
/// (without the newline).
async fn read_line(stream: &mut TcpStream) -> Result<String, SpeedtestError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).map_err(|e| SpeedtestError::Parse(e.to_string()))
}
