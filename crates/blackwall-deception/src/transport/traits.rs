//! The [`DeceptionTransport`] abstraction unifying the deception engine's
//! transports.

use async_trait::async_trait;

/// A way deception traffic reaches the engine, run until shutdown.
///
/// The deception engine currently has two tiers, each its own transport:
///
/// - **Interactive** (`tproxy-interactive`): nft TPROXY hands the kernel's
///   fully-stateful TCP connection to a [`crate::emulator::ServiceEmulator`]
///   for a real, multi-turn conversation. Higher cost per connection.
/// - **Stateless** (`nfqueue-stateless`): nft NFQUEUEs packets to userspace,
///   which synthesises SYN-cookie/ICMP/UDP replies with no per-connection
///   state, so a spoofed-source flood cannot exhaust engine or kernel
///   resources.
///
/// This trait exists solely so `blackwalld run` can hold both tiers in one
/// list and supervise them uniformly (spawn each, join on whichever exits
/// first) without knowing which concrete transport it is. It is deliberately
/// minimal: a name for logs/metrics and a run-until-shutdown method are the
/// only things the daemon's supervision loop needs. A future on-box XDP
/// transport (sub-project B2) is expected to implement this same trait
/// alongside the two above, rather than requiring new supervision code.
#[async_trait]
pub trait DeceptionTransport: Send {
    /// Stable short name for logs/metrics, e.g. `"nfqueue-stateless"` or
    /// `"tproxy-interactive"`.
    fn name(&self) -> &str;

    /// Run the transport until it exits.
    ///
    /// Mirrors how `blackwalld run` already supervises these tasks: each
    /// transport is spawned onto the daemon's `JoinSet` and runs
    /// indefinitely, returning only on error or process shutdown. Blocking
    /// work (the NFQUEUE loop) is offloaded onto a blocking thread by the
    /// implementation itself, so this method never blocks the async runtime.
    async fn run(self: Box<Self>);
}
