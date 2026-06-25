//! Multi-source speedtest aggregator for Blackwall.

mod aggregate;
mod error;
mod provider;
mod reading;
mod throughput;

pub use aggregate::aggregate;
pub use error::SpeedtestError;
pub use provider::{SpeedtestConfig, SpeedtestProvider};
pub use reading::{Aggregate, ProviderReading};
pub use throughput::{mbps_from, trimmed_mean};
