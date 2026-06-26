//! Blackwall's deception engine: terminates deception traffic and answers it
//! with realistic, interactive protocol emulators.

mod banner;
mod banner_reload;
mod banner_source;
mod conn;
mod emulator;
mod error;
mod flux;
mod limits;

pub mod emulators;
pub mod transport;

pub use banner::BannerStore;
pub use banner_reload::SharedBanners;
pub use banner_source::BannerSource;
pub use conn::{AsyncStream, DeceptionConn, DeceptionMeta};
pub use emulator::{EmulatorOutcome, EmulatorRegistry, ServiceEmulator};
pub use emulators::{
    GenericBannerEmulator, HttpEmulator, MysqlEmulator, PostgresEmulator, RedisEmulator,
    SmtpEmulator, SshEmulator,
};
pub use error::DeceptionError;
pub use flux::{flux_index, next_boundary_delay, BannerFlux, BannerPool};
pub use limits::EngineLimits;

/// Build the default emulator registry used by `blackwalld run`.
///
/// Registers protocol-specific emulators on their standard ports:
/// - [`SshEmulator`] on port 22
/// - [`SmtpEmulator`] on ports 25 and 587
/// - [`HttpEmulator`] on ports 80 and 8080
/// - [`MysqlEmulator`] on port 3306
/// - [`PostgresEmulator`] on port 5432
/// - [`RedisEmulator`] on port 6379
///
/// Uses a [`GenericBannerEmulator`] (no tarpit delay) as the fallback for
/// every other port.
pub fn default_registry(banners: impl Into<BannerSource>) -> EmulatorRegistry {
    let generic = std::sync::Arc::new(GenericBannerEmulator::new(banners, None));
    let mut reg = EmulatorRegistry::new(generic);
    reg.register(
        22,
        std::sync::Arc::new(SshEmulator::new("SSH-2.0-OpenSSH_9.6")),
    );
    reg.register(
        25,
        std::sync::Arc::new(SmtpEmulator::new("mail.example.com")),
    );
    reg.register(
        587,
        std::sync::Arc::new(SmtpEmulator::new("mail.example.com")),
    );
    let http = std::sync::Arc::new(HttpEmulator::new("nginx/1.24.0"));
    reg.register(80, http.clone());
    reg.register(8080, http);
    reg.register(3306, std::sync::Arc::new(MysqlEmulator::new("8.0.36")));
    reg.register(5432, std::sync::Arc::new(PostgresEmulator::new()));
    reg.register(6379, std::sync::Arc::new(RedisEmulator::new("7.2.4")));
    reg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn default_registry_maps_known_ports() {
        let store = Arc::new(BannerStore::from_text("* = X\\r\\n").unwrap());
        let reg = default_registry(store);
        assert_eq!(reg.for_port(22).name(), "ssh");
        assert_eq!(reg.for_port(25).name(), "smtp");
        assert_eq!(reg.for_port(80).name(), "http");
        assert_eq!(reg.for_port(3306).name(), "mysql");
        assert_eq!(reg.for_port(5432).name(), "postgres");
        assert_eq!(reg.for_port(587).name(), "smtp");
        assert_eq!(reg.for_port(8080).name(), "http");
        assert_eq!(reg.for_port(6379).name(), "redis");
        assert_eq!(reg.for_port(9999).name(), "generic");
    }
}
