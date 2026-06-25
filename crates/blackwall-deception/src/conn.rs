//! The connection/metadata an emulator receives.

use blackwall_core::L4Proto;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// A bytestream that an emulator reads from and writes to.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Where a deception connection came from and was headed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeceptionMeta {
    /// The original destination the client tried to reach.
    pub local: SocketAddr,
    /// The client address.
    pub peer: SocketAddr,
    /// Transport protocol.
    pub proto: L4Proto,
}

/// A terminated deception connection handed to an emulator.
pub struct DeceptionConn<S> {
    /// The bytestream.
    pub stream: S,
    /// Connection metadata.
    pub meta: DeceptionMeta,
}
