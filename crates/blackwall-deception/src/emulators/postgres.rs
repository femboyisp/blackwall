//! A low-interaction PostgreSQL responder: read the client's StartupMessage,
//! then reply with an ErrorResponse and close. No authentication is performed.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers PostgreSQL with an immediate ErrorResponse after the startup packet.
#[derive(Default)]
pub struct PostgresEmulator;

impl PostgresEmulator {
    /// Create the emulator.
    pub fn new() -> Self {
        PostgresEmulator
    }

    /// A PostgreSQL `ErrorResponse` (severity FATAL, code 28P01, a message),
    /// framed as `'E'` + int32 length + fields + final NUL.
    pub fn error_response() -> Vec<u8> {
        let mut fields = Vec::new();
        fields.push(b'S');
        fields.extend_from_slice(b"FATAL\0");
        fields.push(b'C');
        fields.extend_from_slice(b"28P01\0");
        fields.push(b'M');
        fields.extend_from_slice(b"password authentication failed\0");
        fields.push(0u8); // terminator

        let length = u32::try_from(4 + fields.len()).unwrap_or(0);
        let mut out = vec![b'E'];
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&fields);
        out
    }
}

#[async_trait]
impl ServiceEmulator for PostgresEmulator {
    fn name(&self) -> &str {
        "postgres"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let mut chunk = [0u8; 1024];
        let n = conn.stream.read(&mut chunk).await?;
        let bytes_in = u64::try_from(n).unwrap_or(0);

        let err = Self::error_response();
        conn.stream.write_all(&err).await?;
        conn.stream.flush().await?;

        let note = (n > 0).then(|| format!("startup: {n} bytes"));
        let bytes_out = u64::try_from(err.len()).unwrap_or(u64::MAX);
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
    fn error_response_is_framed() {
        let pkt = PostgresEmulator::error_response();
        assert_eq!(pkt[0], b'E');
        let len = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
        assert_eq!(usize::try_from(len).unwrap(), pkt.len() - 1); // length excludes the type byte
    }

    #[tokio::test]
    async fn reads_startup_then_errors() {
        let emu = PostgresEmulator::new();
        let (client, server) = tokio::io::duplex(4096);
        let meta = DeceptionMeta {
            local: "203.0.113.5:5432".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // A minimal fake StartupMessage.
            client
                .write_all(b"\x00\x00\x00\x08\x00\x03\x00\x00")
                .await
                .unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).await.unwrap();
            resp
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let resp = driver.await.unwrap();
        assert_eq!(resp[0], b'E');
        assert!(outcome.note.is_some());
    }
}
