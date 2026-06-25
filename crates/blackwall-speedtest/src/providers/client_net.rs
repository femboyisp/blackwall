//! Builds a `reqwest::Client` bound to a chosen source. Thin (no logic worth
//! unit-testing the binding of); coverage-excluded as a `*_net.rs` file.

use crate::source::SpeedtestSource;

/// Build a [`reqwest::Client`] bound to `source`.
///
/// Falls back to a default client if the builder fails (e.g. an interface that
/// cannot be bound without privileges) so a measurement is still attempted.
#[expect(dead_code, reason = "called by providers added in subsequent tasks")]
pub fn build_client(source: &SpeedtestSource) -> reqwest::Client {
    let builder = match source {
        SpeedtestSource::Default => reqwest::Client::builder(),
        SpeedtestSource::Ip(ip) => reqwest::Client::builder().local_address(*ip),
        SpeedtestSource::Iface(name) => reqwest::Client::builder().interface(name),
    };
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}
