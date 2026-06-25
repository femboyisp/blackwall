//! A low-interaction MySQL responder: send a believable protocol-10 handshake,
//! then reject the login. No authentication is performed.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Wrap a MySQL payload in a packet header (3-byte LE length + sequence id).
fn framed(payload: &[u8], seq: u8) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(0);
    let b = len.to_le_bytes();
    let mut out = vec![b[0], b[1], b[2], seq];
    out.extend_from_slice(payload);
    out
}

/// Answers MySQL with a handshake then an auth-failure error.
pub struct MysqlEmulator {
    version: String,
}

impl MysqlEmulator {
    /// Create an emulator advertising server `version` (e.g. `"8.0.36"`).
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }

    /// The protocol-10 initial handshake packet (sequence 0).
    pub fn handshake_packet(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(10u8); // protocol version
        p.extend_from_slice(self.version.as_bytes());
        p.push(0u8); // NUL-terminated server version
        p.extend_from_slice(&1u32.to_le_bytes()); // connection id
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // auth-plugin-data part 1
        p.push(0u8); // filler
        p.extend_from_slice(&0x0000u16.to_le_bytes()); // capability flags (lower)
        p.push(0x21u8); // charset (utf8)
        p.extend_from_slice(&0x0002u16.to_le_bytes()); // status flags
        p.extend_from_slice(&0x0000u16.to_le_bytes()); // capability flags (upper)
        p.push(21u8); // length of auth-plugin-data
        p.extend_from_slice(&[0u8; 10]); // reserved
        p.extend_from_slice(b"123456789012\0"); // auth-plugin-data part 2 (>=13)
        p.extend_from_slice(b"mysql_native_password\0");
        framed(&p, 0)
    }

    /// An ERR packet rejecting the login (sequence 2).
    pub fn auth_error_packet() -> Vec<u8> {
        let mut p = Vec::new();
        p.push(0xffu8); // ERR header
        p.extend_from_slice(&1045u16.to_le_bytes()); // error code: access denied
        p.extend_from_slice(b"#28000"); // SQL state marker + state
        p.extend_from_slice(b"Access denied for user");
        framed(&p, 2)
    }
}

#[async_trait]
impl ServiceEmulator for MysqlEmulator {
    fn name(&self) -> &str {
        "mysql"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let handshake = self.handshake_packet();
        conn.stream.write_all(&handshake).await?;
        conn.stream.flush().await?;

        let mut chunk = [0u8; 1024];
        let n = conn.stream.read(&mut chunk).await?;
        let bytes_in = u64::try_from(n).unwrap_or(0);

        let err = Self::auth_error_packet();
        conn.stream.write_all(&err).await?;
        conn.stream.flush().await?;

        let note = (n > 0).then(|| format!("login request: {n} bytes"));
        let bytes_out = u64::try_from(handshake.len() + err.len()).unwrap_or(u64::MAX);
        Ok(EmulatorOutcome {
            bytes_in,
            bytes_out,
            note,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{DeceptionConn, DeceptionMeta};
    use blackwall_core::L4Proto;

    #[test]
    fn handshake_header_length_matches_payload() {
        let pkt = MysqlEmulator::new("8.0.36").handshake_packet();
        let len = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], 0]);
        assert_eq!(usize::try_from(len).unwrap(), pkt.len() - 4);
        assert_eq!(pkt[3], 0u8); // sequence id 0
        assert_eq!(pkt[4], 10u8); // protocol version
    }

    #[test]
    fn err_packet_has_ff_header_and_seq_2() {
        let pkt = MysqlEmulator::auth_error_packet();
        assert_eq!(pkt[3], 2u8); // sequence id 2
        assert_eq!(pkt[4], 0xffu8); // ERR
    }

    #[tokio::test]
    async fn sends_handshake_then_error() {
        let emu = MysqlEmulator::new("8.0.36");
        let (client, server) = tokio::io::duplex(4096);
        let meta = DeceptionMeta {
            local: "203.0.113.5:3306".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut hs = [0u8; 128];
            let n = client.read(&mut hs).await.unwrap();
            client
                .write_all(b"\x20\x00\x00\x01login-bytes")
                .await
                .unwrap();
            let mut err = Vec::new();
            client.read_to_end(&mut err).await.unwrap();
            (hs[..n].to_vec(), err)
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let (hs, err) = driver.await.unwrap();
        assert_eq!(hs[4], 10u8);
        assert_eq!(err[4], 0xffu8);
        assert!(outcome.note.is_some());
    }
}
