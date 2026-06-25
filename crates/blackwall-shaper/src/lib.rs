//! CAKE traffic shaping for Blackwall.

mod bandwidth;
mod error;
mod plan;

pub use bandwidth::parse_bandwidth;
pub use error::ShaperError;
pub use plan::{plan_for, ShapePlan};
