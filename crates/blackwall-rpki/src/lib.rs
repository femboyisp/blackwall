//! Pure RPKI pre-announce cross-check logic for RTBH blackholes.
//!
//! At M1 (arming) an RTBH mitigation announces a `/32`/`/128`
//! "more-specific" blackhole route. If the covering ROA's `maxLength` is
//! shorter than that (a common, legitimate anti-deaggregation ROA), the
//! more-specific is RPKI-**invalid** and validating upstreams silently drop
//! it — the blackhole never takes effect. This crate holds the pure,
//! I/O-free pieces of the cross-check against a
//! [Routinator](https://nlnetlabs.nl/projects/routinator/) 0.14.2
//! `/api/v1/validity` endpoint: the more-specific former, the response
//! classifier, and the request-URL builder. The HTTP fetch and periodic
//! task live in `blackwalld` (not here), so this crate stays trivially unit
//! testable and never performs network I/O.
//!
//! This crate has no I/O of its own; that is a design invariant, not an
//! implementation detail — keep it that way.

use serde::Deserialize;

/// The RPKI validity state of a single announced prefix, as classified from
/// a Routinator `/api/v1/validity` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkiState {
    /// A covering ROA authorizes this exact origin ASN and prefix length.
    Valid,
    /// A covering ROA exists but does not authorize this origin ASN and/or
    /// prefix length (e.g. the ROA's `maxLength` is shorter than `/32`).
    /// Validating upstreams will drop an announcement in this state.
    Invalid,
    /// No covering ROA exists for this prefix at all.
    NotFound,
}

/// The Routinator response could not be parsed into a recognized
/// [`RpkiState`].
///
/// This covers malformed JSON, a missing `validated_route.validity.state`
/// path, and any `state` string outside the pinned Routinator 0.14.2
/// contract (`"valid"`/`"invalid"`/`"not-found"`) — including RIPE's
/// `"unknown"` and any future schema drift. Callers must treat this as
/// "validator down" and fail **open** (skip the check, don't silently treat
/// it as valid), never as a silent pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not parse RPKI validity response")]
pub struct RpkiParseError;

/// Deserialization shape for a Routinator 0.14.2 `/api/v1/validity`
/// response. Only the fields the classifier needs are modeled; the response
/// carries more (`route.origin_asn`, `route.prefix`, `reason`, ...).
#[derive(Debug, Deserialize)]
struct ValidityResponse {
    validated_route: Option<ValidatedRoute>,
}

#[derive(Debug, Deserialize)]
struct ValidatedRoute {
    validity: Validity,
}

#[derive(Debug, Deserialize)]
struct Validity {
    state: String,
}

/// Classify a Routinator `/api/v1/validity` JSON response body.
///
/// Reads `validated_route.validity.state` and maps `"valid"` → [`RpkiState::Valid`],
/// `"invalid"` → [`RpkiState::Invalid`], `"not-found"` → [`RpkiState::NotFound`].
/// Any other value, or a missing/malformed `validated_route`/`validity`/`state`
/// path (including RIPE's `"unknown"` or a future schema change), returns
/// [`RpkiParseError`] so the caller fails open.
///
/// # Errors
///
/// Returns [`RpkiParseError`] if `json` is not valid JSON, does not contain
/// the expected `validated_route.validity.state` path, or `state` is not
/// one of the three recognized values.
pub fn classify(json: &str) -> Result<RpkiState, RpkiParseError> {
    let response: ValidityResponse = serde_json::from_str(json).map_err(|_| RpkiParseError)?;
    let validated_route = response.validated_route.ok_or(RpkiParseError)?;
    match validated_route.validity.state.as_str() {
        "valid" => Ok(RpkiState::Valid),
        "invalid" => Ok(RpkiState::Invalid),
        "not-found" => Ok(RpkiState::NotFound),
        _ => Err(RpkiParseError),
    }
}

/// Form the "host more-specific" of `net`: the network address at host
/// prefix length (`/32` for IPv4, `/128` for IPv6). This is the exact route
/// an RTBH mitigation announces, and the one that must be checked against
/// RPKI — a covering ROA that authorizes the wider `net` does not
/// necessarily authorize this narrower announcement (a `maxLength` shorter
/// than the host length makes it RPKI-invalid).
pub fn host_more_specific(net: &ipnet::IpNet) -> ipnet::IpNet {
    match net {
        ipnet::IpNet::V4(v4) => ipnet::IpNet::V4(
            ipnet::Ipv4Net::new(v4.network(), 32).expect("32 is a valid IPv4 prefix length"),
        ),
        ipnet::IpNet::V6(v6) => ipnet::IpNet::V6(
            ipnet::Ipv6Net::new(v6.network(), 128).expect("128 is a valid IPv6 prefix length"),
        ),
    }
}

/// Build the Routinator `/api/v1/validity` request URL for `ms` announced
/// from `asn`.
///
/// `base` is the validator's base URL with no trailing slash (e.g.
/// `http://h:8323`, from the `rpki-validator=` config directive). `ms` is
/// typically the output of [`host_more_specific`].
pub fn validity_url(base: &str, asn: u32, ms: &ipnet::IpNet) -> String {
    format!("{base}/api/v1/validity/AS{asn}/{ms}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfx(s: &str) -> ipnet::IpNet {
        s.parse().expect("valid prefix")
    }

    #[test]
    fn host_more_specific_v4_and_v6() {
        assert_eq!(
            host_more_specific(&pfx("94.156.238.0/24")),
            pfx("94.156.238.0/32")
        );
        assert_eq!(
            host_more_specific(&pfx("2a12:9b00:b00b::/48")),
            pfx("2a12:9b00:b00b::/128")
        );
    }

    #[test]
    fn host_more_specific_is_idempotent_on_already_host_length() {
        assert_eq!(
            host_more_specific(&pfx("203.0.113.5/32")),
            pfx("203.0.113.5/32")
        );
        assert_eq!(
            host_more_specific(&pfx("2001:db8::1/128")),
            pfx("2001:db8::1/128")
        );
    }

    #[test]
    fn host_more_specific_masks_host_bits() {
        // A non-network address (host bits set) must be masked down to the
        // network address, not just have its prefix length changed.
        assert_eq!(
            host_more_specific(&pfx("94.156.238.5/24")),
            pfx("94.156.238.0/32")
        );
    }

    #[test]
    fn classify_routinator_states() {
        let valid = r#"{"validated_route":{"route":{"origin_asn":"AS214806","prefix":"94.156.238.0/32"},"validity":{"state":"valid"}}}"#;
        let invalid = r#"{"validated_route":{"validity":{"state":"invalid"}}}"#;
        let nf = r#"{"validated_route":{"validity":{"state":"not-found"}}}"#;
        assert_eq!(classify(valid).unwrap(), RpkiState::Valid);
        assert_eq!(classify(invalid).unwrap(), RpkiState::Invalid);
        assert_eq!(classify(nf).unwrap(), RpkiState::NotFound);
        assert!(
            classify(r#"{"validated_route":{"validity":{"state":"unknown"}}}"#).is_err(),
            "RIPE 'unknown' / drift → err → fail-open"
        );
        assert!(classify("{}").is_err());
    }

    #[test]
    fn classify_rejects_malformed_json() {
        assert!(classify("not json").is_err());
        assert!(classify("").is_err());
    }

    #[test]
    fn classify_rejects_missing_validity() {
        assert!(classify(r#"{"validated_route":{}}"#).is_err());
    }

    #[test]
    fn validity_url_form() {
        assert_eq!(
            validity_url("http://h:8323", 214806, &pfx("94.156.238.0/32")),
            "http://h:8323/api/v1/validity/AS214806/94.156.238.0/32"
        );
    }

    #[test]
    fn validity_url_v6_form() {
        assert_eq!(
            validity_url("http://h:8323", 214806, &pfx("2a12:9b00:b00b::/128")),
            "http://h:8323/api/v1/validity/AS214806/2a12:9b00:b00b::/128"
        );
    }
}
