//! Multi-source speedtest aggregator for Blackwall.

mod error;
mod provider;
mod reading;

pub use error::SpeedtestError;
pub use provider::{SpeedtestConfig, SpeedtestProvider};
pub use reading::{Aggregate, ProviderReading};
