//! The Incus client: an abstract trait plus a unix-socket HTTP adapter.

use crate::error::DiscoveryError;
use crate::incus_event::LifecycleEvent;
use crate::incus_model::Instance;
use async_trait::async_trait;

/// Source of Incus instance state and lifecycle events.
#[async_trait]
pub trait IncusClient: Send + Sync {
    /// List all instances with their addresses and opted-in ports.
    async fn list_instances(&self) -> Result<Vec<Instance>, DiscoveryError>;
    /// Await the next lifecycle event, or `None` when the stream ends.
    async fn next_event(&mut self) -> Result<Option<LifecycleEvent>, DiscoveryError>;
}

/// Maximum chunk size accepted from the server (4 MiB).
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Decode a single HTTP/1.1 chunked body into a `Vec<u8>`.
///
/// Reads `<hex-size>\r\n<data>\r\n` pairs until the terminal `0\r\n\r\n`.
async fn read_chunked_body<R>(reader: &mut R) -> Result<Vec<u8>, DiscoveryError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;

    let mut body = Vec::new();
    loop {
        // Read the chunk-size line.
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        let hex = size_line
            .trim_end_matches("\r\n")
            .trim_end_matches('\n')
            .trim();
        // Strip optional chunk extensions (after ';').
        let hex = hex.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| DiscoveryError::Parse(format!("invalid chunk size: {:?}", hex)))?;
        if size > MAX_CHUNK_SIZE {
            return Err(DiscoveryError::Parse(format!(
                "chunk size {} exceeds limit",
                size
            )));
        }
        if size == 0 {
            // Consume the trailing CRLF.
            let mut tail = String::new();
            reader.read_line(&mut tail).await?;
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        // Consume the CRLF after the chunk data.
        let mut crlf = String::new();
        reader.read_line(&mut crlf).await?;
    }
    Ok(body)
}

/// Read the next decoded chunk from a streaming chunked response.
///
/// Returns `None` on the terminal zero-size chunk or EOF.
async fn read_next_chunk<R>(reader: &mut R) -> Result<Option<Vec<u8>>, DiscoveryError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;

    let mut size_line = String::new();
    let n = reader.read_line(&mut size_line).await?;
    if n == 0 {
        return Ok(None); // EOF
    }
    let hex = size_line
        .trim_end_matches("\r\n")
        .trim_end_matches('\n')
        .trim();
    let hex = hex.split(';').next().unwrap_or("").trim();
    if hex.is_empty() {
        return Ok(None);
    }
    let size = usize::from_str_radix(hex, 16)
        .map_err(|_| DiscoveryError::Parse(format!("invalid chunk size: {:?}", hex)))?;
    if size > MAX_CHUNK_SIZE {
        return Err(DiscoveryError::Parse(format!(
            "chunk size {} exceeds limit",
            size
        )));
    }
    if size == 0 {
        // Terminal chunk — consume trailing CRLF.
        let mut tail = String::new();
        reader.read_line(&mut tail).await?;
        return Ok(None);
    }
    let mut chunk = vec![0u8; size];
    reader.read_exact(&mut chunk).await?;
    // Consume the CRLF after chunk data.
    let mut crlf = String::new();
    reader.read_line(&mut crlf).await?;
    Ok(Some(chunk))
}

/// Scan headers (already-read lines) for `Transfer-Encoding: chunked`.
fn is_chunked(headers: &[String]) -> bool {
    headers.iter().any(|h| {
        let lower = h.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    })
}

/// A thin HTTP/1.1-over-unix-socket adapter to the Incus daemon.
///
/// Talks to the Incus unix socket at a configurable path.  `list_instances`
/// performs a one-shot `GET /1.0/instances?recursion=2` and parses the
/// response body; `next_event` reads one newline-delimited JSON line from a
/// persistent `GET /1.0/events?type=lifecycle` stream.
pub struct UnixIncusClient {
    socket_path: std::path::PathBuf,
    /// Underlying reader for the persistent event stream.
    event_reader: Option<tokio::io::BufReader<tokio::net::UnixStream>>,
    /// Whether the event stream uses chunked transfer encoding.
    event_chunked: bool,
    /// Decoded bytes not yet consumed by `next_event`.
    event_buf: Vec<u8>,
}

impl UnixIncusClient {
    /// Open a connection to the Incus unix socket at `socket_path`.
    ///
    /// The connection is lazy; actual I/O occurs on the first method call.
    ///
    /// # Errors
    /// Currently infallible; returns `Ok` unconditionally.
    pub fn connect(socket_path: &std::path::Path) -> Result<Self, DiscoveryError> {
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            event_reader: None,
            event_chunked: false,
            event_buf: Vec::new(),
        })
    }

    /// Send a minimal HTTP/1.1 GET request over a new unix-socket connection
    /// and return the response body as a `String`.
    async fn http_get_body(
        socket_path: &std::path::Path,
        path: &str,
    ) -> Result<String, DiscoveryError> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(socket_path).await?;
        let mut stream = BufReader::new(stream);

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        stream.get_mut().write_all(request.as_bytes()).await?;

        // Read response headers, collecting them to detect chunked encoding.
        let mut headers: Vec<String> = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            stream.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            headers.push(line.clone());
        }

        let bytes = if is_chunked(&headers) {
            read_chunked_body(&mut stream).await?
        } else {
            // Fall back: read to EOF.
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            buf
        };

        String::from_utf8(bytes)
            .map_err(|e| DiscoveryError::Parse(format!("response is not valid UTF-8: {}", e)))
    }
}

#[async_trait]
impl IncusClient for UnixIncusClient {
    async fn list_instances(&self) -> Result<Vec<Instance>, DiscoveryError> {
        let body = Self::http_get_body(&self.socket_path, "/1.0/instances?recursion=2").await?;

        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| DiscoveryError::Parse(e.to_string()))?;

        let items = v["metadata"].as_array().ok_or_else(|| {
            DiscoveryError::Parse("instances response missing metadata array".to_owned())
        })?;

        items
            .iter()
            .map(|item| {
                let s = item.to_string();
                crate::incus_model::parse_instance(&s)
            })
            .collect()
    }

    async fn next_event(&mut self) -> Result<Option<LifecycleEvent>, DiscoveryError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        if self.event_reader.is_none() {
            let stream = UnixStream::connect(&self.socket_path).await?;
            let mut reader = BufReader::new(stream);
            let request =
                "GET /1.0/events?type=lifecycle HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
            reader.get_mut().write_all(request.as_bytes()).await?;

            // Read and collect response headers.
            let mut headers: Vec<String> = Vec::new();
            let mut line = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).await?;
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push(line.clone());
            }
            self.event_chunked = is_chunked(&headers);
            self.event_reader = Some(reader);
        }

        // `event_reader` is guaranteed Some here.
        let reader = self
            .event_reader
            .as_mut()
            .ok_or_else(|| DiscoveryError::Parse("event reader missing".to_owned()))?;

        loop {
            // Try to extract a complete newline-terminated line from the buffer.
            if let Some(pos) = self.event_buf.iter().position(|&b| b == b'\n') {
                let line_bytes = self.event_buf.drain(..=pos).collect::<Vec<_>>();
                let line = String::from_utf8(line_bytes)
                    .map_err(|e| DiscoveryError::Parse(format!("event not valid UTF-8: {}", e)))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                return crate::incus_event::parse_event(trimmed);
            }

            // Need more data.
            if self.event_chunked {
                match read_next_chunk(reader).await? {
                    Some(chunk) => self.event_buf.extend_from_slice(&chunk),
                    None => return Ok(None),
                }
            } else {
                // Non-chunked: read a line directly.
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Ok(None);
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                return crate::incus_event::parse_event(trimmed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incus_event::InstanceChange;
    use blackwall_core::L4Proto;

    struct MockIncusClient {
        instances: Vec<Instance>,
        events: Vec<LifecycleEvent>,
    }

    #[async_trait]
    impl IncusClient for MockIncusClient {
        async fn list_instances(&self) -> Result<Vec<Instance>, DiscoveryError> {
            Ok(self.instances.clone())
        }
        async fn next_event(&mut self) -> Result<Option<LifecycleEvent>, DiscoveryError> {
            Ok(self.events.pop())
        }
    }

    #[tokio::test]
    async fn mock_client_lists_and_streams() {
        let mut client = MockIncusClient {
            instances: vec![Instance {
                name: "web01".to_owned(),
                addresses: vec!["203.0.113.5".parse().unwrap()],
                ports: vec![(L4Proto::Tcp, 443)],
            }],
            events: vec![LifecycleEvent {
                instance: "web01".to_owned(),
                change: InstanceChange::Started,
            }],
        };
        assert_eq!(client.list_instances().await.unwrap().len(), 1);
        assert_eq!(
            client.next_event().await.unwrap().unwrap().instance,
            "web01"
        );
        assert_eq!(client.next_event().await.unwrap(), None);
    }
}
