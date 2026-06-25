//! The [`ServiceEmulator`] abstraction and a port-keyed registry.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::error::DeceptionError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Summary of what an emulator session did, for audit/metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmulatorOutcome {
    /// Bytes received from the client.
    pub bytes_in: u64,
    /// Bytes sent to the client.
    pub bytes_out: u64,
    /// Optional captured detail (e.g. request line, attempted creds).
    pub note: Option<String>,
}

/// A fake service that holds a conversation on a deception connection.
#[async_trait]
pub trait ServiceEmulator: Send + Sync {
    /// Stable short name (for logs/metrics), e.g. `"http"`.
    fn name(&self) -> &str;

    /// Handle one terminated connection to completion.
    async fn handle(
        &self,
        conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError>;
}

/// Chooses an emulator for a connection by its destination port.
pub struct EmulatorRegistry {
    by_port: HashMap<u16, Arc<dyn ServiceEmulator>>,
    default: Arc<dyn ServiceEmulator>,
}

impl EmulatorRegistry {
    /// Create a registry whose `default` answers any port without a specific
    /// emulator registered.
    pub fn new(default: Arc<dyn ServiceEmulator>) -> Self {
        Self {
            by_port: HashMap::new(),
            default,
        }
    }

    /// Register `emulator` for `port`.
    pub fn register(&mut self, port: u16, emulator: Arc<dyn ServiceEmulator>) {
        self.by_port.insert(port, emulator);
    }

    /// Return the emulator for `port`, or the default.
    pub fn for_port(&self, port: u16) -> Arc<dyn ServiceEmulator> {
        self.by_port
            .get(&port)
            .cloned()
            .unwrap_or_else(|| self.default.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::DeceptionConn;

    struct Stub(&'static str);
    #[async_trait]
    impl ServiceEmulator for Stub {
        fn name(&self) -> &str {
            self.0
        }
        async fn handle(
            &self,
            _conn: DeceptionConn<Box<dyn AsyncStream>>,
        ) -> Result<EmulatorOutcome, DeceptionError> {
            Ok(EmulatorOutcome::default())
        }
    }

    #[test]
    fn for_port_prefers_registered_then_default() {
        let mut reg = EmulatorRegistry::new(Arc::new(Stub("default")));
        reg.register(80, Arc::new(Stub("http")));
        assert_eq!(reg.for_port(80).name(), "http");
        assert_eq!(reg.for_port(12345).name(), "default");
    }

    #[test]
    fn emulator_outcome_default_is_zero() {
        let o = EmulatorOutcome::default();
        assert_eq!(o.bytes_in, 0);
        assert_eq!(o.bytes_out, 0);
        assert_eq!(o.note, None);
    }

    #[test]
    fn emulator_outcome_equality() {
        let a = EmulatorOutcome {
            bytes_in: 10,
            bytes_out: 20,
            note: Some("test".to_owned()),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = EmulatorOutcome::default();
        assert_ne!(a, c);
    }
}
