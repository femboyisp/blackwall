//! Operations control API wiring: the address it listens on and where its
//! admin bearer token is read from.

use serde::{Deserialize, Serialize};

/// Configuration for the operations control API (`api` directive); `None` on
/// [`crate::Policy`] disables the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Address the API binds to (bind to localhost / a management interface;
    /// TLS is terminated by a reverse proxy).
    pub listen: std::net::SocketAddr,
    /// Path to a file whose first line is the admin bearer token.
    pub token_file: std::path::PathBuf,
}
