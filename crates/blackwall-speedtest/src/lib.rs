//! Multi-source speedtest aggregator for Blackwall.

mod aggregate;
mod error;
mod provider;
pub mod providers;
mod reading;
mod runner;
mod throughput;

pub use aggregate::aggregate;
pub use error::SpeedtestError;
pub use provider::{SpeedtestConfig, SpeedtestProvider};
pub use reading::{Aggregate, ProviderReading};
pub use runner::Speedtest;
pub use throughput::{mbps_from, trimmed_mean};
