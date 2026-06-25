//! Resource limits for the deception engine's accept loop.

use std::time::Duration;

/// Bounds on concurrent deception sessions and how long any one may run.
#[derive(Debug, Clone, Copy)]
pub struct EngineLimits {
    /// Maximum number of deception sessions handled concurrently. Connections
    /// arriving while at the cap are dropped rather than queued, so a flood
    /// cannot exhaust tasks or file descriptors.
    pub max_concurrent: usize,
    /// Hard ceiling on a single session's duration. Caps slow-loris clients
    /// and runaway emulators. Should exceed the largest configured tarpit.
    pub session_timeout: Duration,
}

impl Default for EngineLimits {
    fn default() -> Self {
        EngineLimits {
            max_concurrent: 1024,
            session_timeout: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = EngineLimits::default();
        assert_eq!(l.max_concurrent, 1024);
        assert_eq!(l.session_timeout, Duration::from_secs(60));
    }
}
