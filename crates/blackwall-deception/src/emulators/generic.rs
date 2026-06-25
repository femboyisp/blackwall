//! An emulator that sends a port-appropriate banner and optionally tarpits.

use crate::banner::BannerStore;
use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Sends the banner registered for the connection's port, then (optionally)
/// holds the connection open for `tarpit` to waste an attacker's time.
pub struct GenericBannerEmulator {
    store: Arc<BannerStore>,
    tarpit: Option<Duration>,
}

impl GenericBannerEmulator {
    /// Create an emulator backed by `store`, with an optional tarpit delay.
    pub fn new(store: Arc<BannerStore>, tarpit: Option<Duration>) -> Self {
        Self { store, tarpit }
    }
}

#[async_trait]
impl ServiceEmulator for GenericBannerEmulator {
    fn name(&self) -> &str {
        "generic"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let banner = self.store.banner_for(conn.meta.local.port()).to_vec();
        conn.stream.write_all(&banner).await?;
        conn.stream.flush().await?;
        if let Some(delay) = self.tarpit {
            tokio::time::sleep(delay).await;
        }
        let bytes_out = u64::try_from(banner.len()).unwrap_or(u64::MAX);
        Ok(EmulatorOutcome {
            bytes_in: 0,
            bytes_out,
            note: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::DeceptionMeta;
    use blackwall_core::L4Proto;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn writes_port_banner_to_client() {
        let store = Arc::new(BannerStore::from_text("80 = HELLO\\r\\n\n* = X\\r\\n").unwrap());
        let emu = GenericBannerEmulator::new(store, None);

        let (client, server) = tokio::io::duplex(64);
        let meta = DeceptionMeta {
            local: "203.0.113.5:80".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");

        let mut buf = Vec::new();
        let mut client = client;
        // The server half is dropped after handle() returns, so read to EOF.
        client.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"HELLO\r\n");
        assert_eq!(outcome.bytes_out, 7);
    }
}
