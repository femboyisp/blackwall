//! Banner fast-flux configuration parsed from the policy DSL.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for rotating the deception banner "persona" over time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BannerFluxConfig {
    /// Directory of banner files; each file is one persona variant.
    pub dir: PathBuf,
    /// How long each persona stays active before the next is selected.
    pub period: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_flux_config_round_trips_through_json() {
        let c = BannerFluxConfig {
            dir: PathBuf::from("/etc/blackwall/banners.d"),
            period: Duration::from_secs(6 * 3600),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(c, serde_json::from_str(&json).unwrap());
    }
}
