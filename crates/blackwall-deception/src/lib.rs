//! Blackwall's deception engine: terminates deception traffic and answers it
//! with realistic, interactive protocol emulators.

mod banner;
mod banner_reload;
mod conn;
mod emulator;
mod error;
mod limits;

pub mod emulators;
pub mod transport;

pub use banner::BannerStore;
pub use banner_reload::SharedBanners;
pub use conn::{AsyncStream, DeceptionConn, DeceptionMeta};
pub use emulator::{EmulatorOutcome, EmulatorRegistry, ServiceEmulator};
pub use emulators::{GenericBannerEmulator, HttpEmulator};
pub use error::DeceptionError;
pub use limits::EngineLimits;

use std::sync::Arc;

/// Build the default emulator registry used by `blackwalld run`.
///
/// Registers an [`HttpEmulator`] on ports 80 and 8080 and uses a
/// [`GenericBannerEmulator`] (no tarpit delay) as the fallback for every other
/// port.
pub fn default_registry(banners: Arc<BannerStore>) -> EmulatorRegistry {
    let http = Arc::new(HttpEmulator::new("nginx/1.24.0"));
    let generic = Arc::new(GenericBannerEmulator::new(banners, None));
    let mut reg = EmulatorRegistry::new(generic);
    reg.register(80, http.clone());
    reg.register(8080, http);
    reg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_maps_http_and_generic() {
        let store = Arc::new(BannerStore::from_text("* = X\\r\\n").unwrap());
        let reg = default_registry(store);
        assert_eq!(reg.for_port(80).name(), "http");
        assert_eq!(reg.for_port(8080).name(), "http");
        assert_eq!(reg.for_port(9999).name(), "generic");
    }
}
