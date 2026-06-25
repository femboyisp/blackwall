//! Ookla (speedtest.net) network provider — thin adapter; coverage-excluded.
//!
//! All parsing lives in [`super::ookla_parse`]; all math in [`crate::throughput::mbps_from`].

use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::source::SpeedtestSource;
use crate::throughput::{keep_downloading, mbps_from};

use super::ookla_parse::{download_command, parse_hello, parse_servers, upload_command};

/// Maximum bytes to request in a single Ookla download (25 MiB).
const MAX_OOKLA_BYTES: u64 = 25 * 1024 * 1024;

/// Server list URL for Ookla/speedtest.net.
const SERVER_LIST_URL: &str = "https://www.speedtest.net/api/js/servers?engine=js&limit=5";

/// Speedtest provider backed by the Ookla/speedtest.net TCP protocol.
pub struct OoklaProvider {
    client: reqwest::Client,
    source: SpeedtestSource,
}

impl OoklaProvider {
    /// Create an [`OoklaProvider`] using the host's default route.
    pub fn new() -> Self {
        Self::with_source(SpeedtestSource::Default)
    }

    /// Create an [`OoklaProvider`] whose connections bind to `source`.
    ///
    /// The HTTP client used to fetch the server list is also bound to `source`.
    /// The raw TCP measurement connection is bound via [`connect_bound`].
    pub fn with_source(source: SpeedtestSource) -> Self {
        OoklaProvider {
            client: super::build_client(&source),
            source,
        }
    }
}

impl Default for OoklaProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve `host` (e.g. `"host:port"`) to a single [`SocketAddr`].
async fn resolve_one(host: &str) -> Result<SocketAddr, SpeedtestError> {
    tokio::net::lookup_host(host)
        .await
        .map_err(|e| SpeedtestError::Http(e.to_string()))?
        .next()
        .ok_or(SpeedtestError::NoResult)
}

/// Connect to `host` and bind the local side according to `source`.
async fn connect_bound(host: &str, source: &SpeedtestSource) -> Result<TcpStream, SpeedtestError> {
    match source {
        SpeedtestSource::Default => TcpStream::connect(host)
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string())),
        SpeedtestSource::Ip(ip) => {
            let addr = resolve_one(host).await?;
            let sock = if ip.is_ipv4() {
                tokio::net::TcpSocket::new_v4()
            } else {
                tokio::net::TcpSocket::new_v6()
            }
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;
            sock.bind(SocketAddr::new(*ip, 0))
                .map_err(|e| SpeedtestError::Http(e.to_string()))?;
            sock.connect(addr)
                .await
                .map_err(|e| SpeedtestError::Http(e.to_string()))
        }
        SpeedtestSource::Iface(name) => connect_bound_device(host, name).await,
    }
}

/// Connect to `host` binding the socket to network interface `iface_name`
/// via `SO_BINDTODEVICE` (Linux; requires `CAP_NET_RAW`).
///
/// Uses a blocking `socket2` connect then converts to a tokio `TcpStream`.
async fn connect_bound_device(host: &str, iface_name: &str) -> Result<TcpStream, SpeedtestError> {
    let addr = resolve_one(host).await?;
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)
        .map_err(|e| SpeedtestError::Http(e.to_string()))?;
    sock.bind_device(Some(iface_name.as_bytes()))
        .map_err(|e| SpeedtestError::Http(e.to_string()))?;
    // Blocking connect; acceptable for a one-shot measurement.
    sock.connect(&addr.into())
        .map_err(|e| SpeedtestError::Http(e.to_string()))?;
    sock.set_nonblocking(true)
        .map_err(|e| SpeedtestError::Http(e.to_string()))?;
    let std_stream: std::net::TcpStream = sock.into();
    TcpStream::from_std(std_stream).map_err(|e| SpeedtestError::Http(e.to_string()))
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
    /// at `min(cfg.max_bytes, 25 MiB)`. The TCP connection is bound to
    /// the provider's configured [`SpeedtestSource`].
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

        // Connect via raw TCP, bound to the configured source.
        let mut stream = connect_bound(&server.host, &self.source).await?;

        // Send HI greeting and time the HELLO response as latency.
        let hi_start = Instant::now();
        stream
            .write_all(b"HI\n")
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        // Read the HELLO response line.
        let hello_line = read_line(&mut stream).await?;
        let latency_ms = hi_start.elapsed().as_secs_f64() * 1000.0;
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

        // Open a fresh connection for the upload measurement; the post-download
        // socket state is unreliable for reuse.
        let upload_mbps = 'upload: {
            let mut up_stream = match connect_bound(&server.host, &self.source).await {
                Ok(s) => s,
                Err(_) => break 'upload None,
            };
            // Perform HI/HELLO handshake on the new connection.
            if up_stream.write_all(b"HI\n").await.is_err() {
                break 'upload None;
            }
            if read_line(&mut up_stream).await.is_err() {
                break 'upload None;
            }
            // Send the UPLOAD command.
            let up_cmd = upload_command(bytes);
            if up_stream.write_all(up_cmd.as_bytes()).await.is_err() {
                break 'upload None;
            }
            // Write data until the time/byte window expires.
            let up_start = Instant::now();
            let buf = vec![0u8; 65536];
            let mut sent: u64 = 0;
            loop {
                if let Err(err) = up_stream.write_all(&buf).await {
                    tracing::debug!(%err, "ookla upload write failed");
                    break 'upload None;
                }
                sent = sent.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
                if !keep_downloading(sent, bytes, up_start.elapsed(), cfg.measure_window) {
                    break;
                }
            }
            if sent == 0 {
                break 'upload None;
            }
            Some(mbps_from(sent, up_start.elapsed()))
        };

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps,
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
