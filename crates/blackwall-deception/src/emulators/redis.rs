//! A low-interaction Redis responder speaking enough RESP to answer common
//! probes (PING/INFO) convincingly.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_BYTES: usize = 16 * 1024;

/// Answers Redis probes over RESP.
pub struct RedisEmulator {
    version: String,
}

impl RedisEmulator {
    /// Create an emulator advertising server `version` (e.g. `"7.2.4"`).
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }

    /// RESP reply for a single (already-parsed) command verb.
    pub fn reply_for(&self, command: &str) -> Vec<u8> {
        match command.to_ascii_uppercase().as_str() {
            "PING" => b"+PONG\r\n".to_vec(),
            "INFO" => {
                let body = format!("# Server\r\nredis_version:{}\r\n", self.version);
                let len = body.len();
                format!("${len}\r\n{body}\r\n").into_bytes()
            }
            "COMMAND" | "CLIENT" | "AUTH" | "SELECT" | "HELLO" => b"+OK\r\n".to_vec(),
            "QUIT" => b"+OK\r\n".to_vec(),
            _ => b"-ERR unknown command\r\n".to_vec(),
        }
    }
}

/// Outcome of parsing one command from the front of an accumulated buffer.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// A complete command: its verb, and how many bytes it consumed from the
    /// front of the buffer (so the caller can drain them and parse the next).
    Command(String, usize),
    /// Not enough bytes for a complete command yet — wait for more.
    Incomplete,
    /// A malformed frame the parser cannot make progress on — close.
    Invalid,
}

/// Find the next CRLF at or after `start`, returning the line (excluding CRLF)
/// and the offset just past the CRLF.
fn read_crlf_line(buf: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let rest = buf.get(start..)?;
    let idx = rest.windows(2).position(|w| w == b"\r\n")?;
    Some((&rest[..idx], start + idx + 2))
}

/// Parse exactly one command (RESP array or inline) from the front of `buf`.
///
/// Reports the number of bytes consumed so the caller can drain a completed
/// command and parse the next, which makes the emulator robust to commands
/// fragmented across TCP segments and to pipelined commands in one segment.
fn parse_one(buf: &[u8]) -> Parsed {
    match buf.first() {
        None => Parsed::Incomplete,
        Some(b'*') => parse_resp_array(buf),
        Some(_) => parse_inline(buf),
    }
}

/// Parse a RESP array command (`*<argc>\r\n` then `argc` bulk strings).
fn parse_resp_array(buf: &[u8]) -> Parsed {
    let Some((argc_line, mut cur)) = read_crlf_line(buf, 0) else {
        return Parsed::Incomplete;
    };
    // `argc_line` is `*<n>`; the leading `*` was checked by the caller.
    let Some(argc) = std::str::from_utf8(&argc_line[1..])
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return Parsed::Invalid;
    };
    if argc == 0 {
        return Parsed::Invalid; // a command has at least one element
    }
    let mut verb: Option<String> = None;
    for i in 0..argc {
        let Some((len_line, after_len)) = read_crlf_line(buf, cur) else {
            return Parsed::Incomplete;
        };
        if len_line.first() != Some(&b'$') {
            return Parsed::Invalid;
        }
        let Some(blen) = std::str::from_utf8(&len_line[1..])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            return Parsed::Invalid;
        };
        let data_end = after_len + blen;
        // Need `blen` data bytes plus the trailing CRLF.
        if buf.len() < data_end + 2 {
            return Parsed::Incomplete;
        }
        if &buf[data_end..data_end + 2] != b"\r\n" {
            return Parsed::Invalid;
        }
        if i == 0 {
            verb = Some(String::from_utf8_lossy(&buf[after_len..data_end]).into_owned());
        }
        cur = data_end + 2;
    }
    match verb {
        Some(v) if !v.is_empty() => Parsed::Command(v, cur),
        _ => Parsed::Invalid,
    }
}

/// Parse an inline command: the first whitespace-delimited word of the line.
fn parse_inline(buf: &[u8]) -> Parsed {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        return Parsed::Incomplete;
    };
    let line = &buf[..nl]; // excludes '\n'; a trailing '\r' is treated as whitespace
    match String::from_utf8_lossy(line).split_whitespace().next() {
        Some(word) => Parsed::Command(word.to_owned(), nl + 1),
        None => Parsed::Invalid, // blank line
    }
}

#[async_trait]
impl ServiceEmulator for RedisEmulator {
    fn name(&self) -> &str {
        "redis"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let mut bytes_in: u64 = 0;
        let mut bytes_out: u64 = 0;
        let mut chunk = [0u8; 1024];
        let mut total = Vec::new();
        let mut first_cmd: Option<String> = None;

        'read: loop {
            let n = conn.stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes_in += u64::try_from(n).unwrap_or(0);
            total.extend_from_slice(&chunk[..n]);

            // Drain every complete command now buffered (handles pipelining);
            // stop at the first incomplete one and wait for the next read.
            loop {
                match parse_one(&total) {
                    Parsed::Command(verb, consumed) => {
                        total.drain(..consumed);
                        if first_cmd.is_none() {
                            first_cmd = Some(verb.clone());
                        }
                        let reply = self.reply_for(&verb);
                        conn.stream.write_all(&reply).await?;
                        conn.stream.flush().await?;
                        bytes_out += u64::try_from(reply.len()).unwrap_or(0);
                        if verb.eq_ignore_ascii_case("QUIT") {
                            break 'read;
                        }
                    }
                    Parsed::Incomplete => break,
                    // Malformed frame: close rather than spin on unconsumable bytes.
                    Parsed::Invalid => break 'read,
                }
            }
            // Cap a client that dribbles an ever-growing incomplete command.
            if total.len() > MAX_BYTES {
                break;
            }
        }
        Ok(EmulatorOutcome {
            bytes_in,
            bytes_out,
            note: first_cmd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{DeceptionConn, DeceptionMeta};
    use blackwall_core::L4Proto;

    #[test]
    fn ping_and_info_and_unknown() {
        let e = RedisEmulator::new("7.2.4");
        assert_eq!(e.reply_for("PING"), b"+PONG\r\n");
        let info = e.reply_for("INFO");
        let body = "# Server\r\nredis_version:7.2.4\r\n";
        let expected = format!("${}\r\n{}\r\n", body.len(), body);
        assert_eq!(info, expected.as_bytes());
        assert!(e.reply_for("FLOOByARG").starts_with(b"-ERR"));
    }

    #[test]
    fn parses_resp_array_and_inline() {
        assert_eq!(
            parse_one(b"*1\r\n$4\r\nPING\r\n"),
            Parsed::Command("PING".to_owned(), 14)
        );
        assert_eq!(
            parse_one(b"PING\r\n"),
            Parsed::Command("PING".to_owned(), 6)
        );
        assert_eq!(parse_one(b""), Parsed::Incomplete);
        assert_eq!(parse_one(b"*1\r\n"), Parsed::Incomplete); // truncated RESP array
        assert_eq!(parse_one(b"*1\r\nXXXX\r\nPING\r\n"), Parsed::Invalid); // bad length-prefix line
    }

    #[test]
    fn resp_command_fragmented_across_segments_is_incomplete_then_complete() {
        // First TCP segment carries only the header; the old per-read parser
        // dropped this command entirely.
        assert_eq!(parse_one(b"*1\r\n$4\r\n"), Parsed::Incomplete);
        // Once the rest arrives, the full command parses.
        assert_eq!(
            parse_one(b"*1\r\n$4\r\nPING\r\n"),
            Parsed::Command("PING".to_owned(), 14)
        );
    }

    #[test]
    fn pipelined_commands_are_drained_one_at_a_time() {
        let buf = b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nINFO\r\n".to_vec();
        let Parsed::Command(v1, consumed) = parse_one(&buf) else {
            panic!("first command must parse");
        };
        assert_eq!(v1, "PING");
        // The second command follows immediately after the consumed prefix.
        assert_eq!(
            parse_one(&buf[consumed..]),
            Parsed::Command("INFO".to_owned(), 14)
        );
    }

    #[test]
    fn inline_command_consumes_through_newline() {
        assert_eq!(
            parse_one(b"PING\r\nEXTRA"),
            Parsed::Command("PING".to_owned(), 6)
        );
        assert_eq!(parse_one(b"PING"), Parsed::Incomplete); // no newline yet
    }

    #[tokio::test]
    async fn answers_ping() {
        let emu = RedisEmulator::new("7.2.4");
        let (client, server) = tokio::io::duplex(1024);
        let meta = DeceptionMeta {
            local: "203.0.113.5:6379".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
            let mut resp = [0u8; 16];
            let n = client.read(&mut resp).await.unwrap();
            resp[..n].to_vec()
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let resp = driver.await.unwrap();
        assert_eq!(resp, b"+PONG\r\n");
        assert_eq!(outcome.note.as_deref(), Some("PING"));
    }

    #[tokio::test]
    async fn answers_ping_fragmented_across_two_writes() {
        let emu = RedisEmulator::new("7.2.4");
        let (client, server) = tokio::io::duplex(1024);
        let meta = DeceptionMeta {
            local: "203.0.113.5:6379".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Split one command across two segments — the previous per-read
            // parser answered neither half.
            client.write_all(b"*1\r\n$4\r\n").await.unwrap();
            client.flush().await.unwrap();
            client.write_all(b"PING\r\n").await.unwrap();
            client.flush().await.unwrap();
            let mut resp = [0u8; 16];
            let n = client.read(&mut resp).await.unwrap();
            resp[..n].to_vec()
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let resp = driver.await.unwrap();
        assert_eq!(resp, b"+PONG\r\n");
        assert_eq!(outcome.note.as_deref(), Some("PING"));
    }
}
