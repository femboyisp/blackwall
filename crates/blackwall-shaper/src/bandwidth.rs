//! Parse a bandwidth literal into megabits per second.

use crate::error::ShaperError;

/// Parse `"1000mbit"`, `"1000Mbit"`, or `"1000"` into megabits/sec.
pub fn parse_bandwidth(s: &str) -> Result<u32, ShaperError> {
    let trimmed = s.trim();
    let digits = trimmed
        .trim_end_matches("mbit")
        .trim_end_matches("Mbit")
        .trim_end_matches("MBit")
        .trim();
    digits
        .parse::<u32>()
        .map_err(|_| ShaperError::Resolve(format!("invalid bandwidth: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bandwidth_forms() {
        assert_eq!(parse_bandwidth("1000mbit").unwrap(), 1000);
        assert_eq!(parse_bandwidth("940Mbit").unwrap(), 940);
        assert_eq!(parse_bandwidth("500").unwrap(), 500);
        assert!(parse_bandwidth("fast").is_err());
    }
}
