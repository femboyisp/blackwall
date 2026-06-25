//! Resolve a [`ShapeRule`] (plus an optional measurement) into a concrete plan.

use crate::error::ShaperError;
use blackwall_core::{ShapeBandwidth, ShapeRule};
use blackwall_speedtest::Aggregate;

/// A fully-resolved shaping plan for one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapePlan {
    /// Interface to shape.
    pub iface: String,
    /// Egress (upload) CAKE bandwidth in megabits/sec.
    pub egress_mbit: u32,
    /// Ingress (download) CAKE bandwidth in megabits/sec.
    pub ingress_mbit: u32,
    /// Optional CAKE rtt hint (ms).
    pub rtt_ms: Option<u32>,
}

fn resolve(which: ShapeBandwidth, measured: Option<f64>, dir: &str) -> Result<u32, ShaperError> {
    match which {
        ShapeBandwidth::Fixed(n) => Ok(n),
        ShapeBandwidth::Auto => {
            let mbps = measured
                .ok_or_else(|| ShaperError::Resolve(format!("auto {dir}: no measurement")))?;
            let rounded = mbps.round();
            if !rounded.is_finite() || rounded < 1.0 {
                return Err(ShaperError::Resolve(format!(
                    "auto {dir}: bad measurement {mbps}"
                )));
            }
            // rounded is finite and >= 1.0; range-checked above.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "rounded is finite and >= 1.0; range-checked"
            )]
            u32::try_from(rounded as i64)
                .map_err(|_| ShaperError::Resolve(format!("auto {dir}: out of range")))
        }
    }
}

/// Build a [`ShapePlan`] from `rule`, using `measured` for any `Auto` direction.
pub fn plan_for(rule: &ShapeRule, measured: Option<&Aggregate>) -> Result<ShapePlan, ShaperError> {
    let ingress_mbit = resolve(rule.download, measured.map(|a| a.download_mbps), "download")?;
    let egress_mbit = resolve(rule.upload, measured.and_then(|a| a.upload_mbps), "upload")?;
    Ok(ShapePlan {
        iface: rule.iface.clone(),
        egress_mbit,
        ingress_mbit,
        rtt_ms: rule.rtt_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_speedtest::ProviderReading;

    fn agg(down: f64, up: Option<f64>) -> Aggregate {
        Aggregate {
            download_mbps: down,
            upload_mbps: up,
            latency_ms: 10.0,
            samples: 1,
            readings: vec![ProviderReading {
                provider: "x".to_owned(),
                download_mbps: down,
                upload_mbps: up,
                latency_ms: 10.0,
            }],
        }
    }

    #[test]
    fn fixed_directions_need_no_measurement() {
        let rule = ShapeRule {
            iface: "eth0".to_owned(),
            download: ShapeBandwidth::Fixed(900),
            upload: ShapeBandwidth::Fixed(100),
            rtt_ms: Some(50),
        };
        let plan = plan_for(&rule, None).unwrap();
        assert_eq!(plan.ingress_mbit, 900);
        assert_eq!(plan.egress_mbit, 100);
        assert_eq!(plan.rtt_ms, Some(50));
    }

    #[test]
    fn auto_uses_measurement_both_ways() {
        let rule = ShapeRule {
            iface: "eth0".to_owned(),
            download: ShapeBandwidth::Auto,
            upload: ShapeBandwidth::Auto,
            rtt_ms: None,
        };
        let plan = plan_for(&rule, Some(&agg(940.4, Some(880.6)))).unwrap();
        assert_eq!(plan.ingress_mbit, 940);
        assert_eq!(plan.egress_mbit, 881);
    }

    #[test]
    fn auto_without_measurement_errors() {
        let rule = ShapeRule {
            iface: "eth0".to_owned(),
            download: ShapeBandwidth::Auto,
            upload: ShapeBandwidth::Fixed(100),
            rtt_ms: None,
        };
        assert!(plan_for(&rule, None).is_err());
    }

    #[test]
    fn auto_upload_without_upload_measurement_errors() {
        let rule = ShapeRule {
            iface: "eth0".to_owned(),
            download: ShapeBandwidth::Auto,
            upload: ShapeBandwidth::Auto,
            rtt_ms: None,
        };
        // download measured, upload None -> egress resolution fails.
        assert!(plan_for(&rule, Some(&agg(900.0, None))).is_err());
    }
}
