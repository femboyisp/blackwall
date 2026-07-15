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
//! classifier, and the request-URL builder. The periodic *task* (the tokio
//! loop that drives the checks on an interval) lives in `blackwalld`, not
//! here.
//!
//! The one deliberate exception to "no I/O" is the [`fetch`] module: it
//! owns the actual `reqwest` HTTP call to the validator and is the sole,
//! isolated I/O boundary of this crate — kept intentionally small,
//! coverage-excluded, and free of any classification/formation logic of its
//! own. Everything else in this crate (the classifier, the more-specific
//! former, the URL builder, [`aggregate_report`], [`RpkiWarnState`]) is pure
//! and trivially unit-testable; that separation is the design invariant to
//! keep, not the absence of a `fetch` module.

use std::collections::HashMap;

use serde::Deserialize;

mod fetch;
pub use fetch::{build_client, check_once, fetch_validity, FetchError};

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

/// The aggregate result of one [`fetch::check_once`] pass over a set of
/// RTBH-eligible prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpkiReport {
    /// Whether the validator itself was reachable during this pass. See
    /// [`aggregate_report`] for exactly how this is derived from the
    /// per-prefix fetch outcomes.
    pub validator_up: bool,
    /// The classified state of each checked prefix (already reduced to its
    /// host more-specific — see [`host_more_specific`]). Only prefixes whose
    /// fetch+classify succeeded are present; a prefix whose check failed is
    /// omitted (its state is unknown, not assumed valid or invalid).
    pub per_prefix: Vec<(ipnet::IpNet, RpkiState)>,
}

/// Aggregate the raw fetch+classify outcome of each checked prefix into an
/// [`RpkiReport`].
///
/// This is deliberately the *pure* half of [`fetch::check_once`] — the I/O
/// (the actual HTTP fetch) lives in the coverage-excluded `fetch` module;
/// this function only reasons about the `Result`s that I/O already produced,
/// so it is unit-tested directly.
///
/// **Validator-reachability rule** (documented here, not just in code, since
/// it's a judgment call): `validator_up` is `true` if AT LEAST ONE checked
/// prefix's fetch succeeded at the transport/parse level, and `false` only
/// when EVERY fetch failed — i.e. the validator is reported down only when
/// it is genuinely unreachable for the whole pass, not merely for one flaky
/// lookup among several successes. An empty prefix set has nothing to
/// disprove reachability, so it reports `validator_up: true` (nothing to
/// fail open on). A per-prefix fetch error always means that prefix's state
/// is unknown, so it's dropped from `per_prefix` rather than guessed at —
/// this per-prefix fail-open is unconditional and independent of the
/// aggregate `validator_up` verdict.
pub fn aggregate_report<E>(results: Vec<(ipnet::IpNet, Result<RpkiState, E>)>) -> RpkiReport {
    let validator_up = results.is_empty() || results.iter().any(|(_, r)| r.is_ok());
    let per_prefix = results
        .into_iter()
        .filter_map(|(net, r)| r.ok().map(|state| (net, state)))
        .collect();
    RpkiReport {
        validator_up,
        per_prefix,
    }
}

/// Tracks previously-observed RPKI validator reachability and per-prefix
/// validity state so the periodic checker (in `blackwalld`) can WARN only on
/// a state **transition**, never on a steady-state repeat — a standing RPKI
/// gap (e.g. a ROA with a short `maxLength`) must not spam the log every
/// `rpki-check-interval` forever.
///
/// This is the pure, unit-tested dedup core; the periodic tokio task that
/// drives it lives in `blackwalld` (coverage-excluded I/O glue).
#[derive(Debug, Clone)]
pub struct RpkiWarnState {
    validator_up: bool,
    prefixes: HashMap<ipnet::IpNet, RpkiState>,
}

impl Default for RpkiWarnState {
    /// Starts assuming the validator is reachable (`true`) and with no prior
    /// per-prefix observations — so the very first down/invalid observation
    /// after startup is treated as a transition and warns, rather than being
    /// silently absorbed as "no change from an unknown baseline".
    fn default() -> Self {
        Self {
            validator_up: true,
            prefixes: HashMap::new(),
        }
    }
}

impl RpkiWarnState {
    /// Record the validator's reachability observed on this check pass.
    ///
    /// Returns `true` only on an up→down transition — "you should WARN
    /// now". A down→down repeat and an up→up repeat both return `false` (no
    /// change worth logging again); a down→up recovery also returns `false`,
    /// but the transition is still recorded — the caller should log that
    /// case as an INFO, not a WARN.
    pub fn observe_validator_up(&mut self, up: bool) -> bool {
        let should_warn = self.validator_up && !up;
        self.validator_up = up;
        should_warn
    }

    /// Record the validity state observed for `net` on this check pass.
    ///
    /// Returns `true` — "you should WARN now" — when `state` is
    /// [`RpkiState::Invalid`] or [`RpkiState::NotFound`] (a state that would
    /// cause a validating upstream to drop the blackhole announcement) **and**
    /// it is either the first observation of `net` or different from the
    /// previously observed state for `net`. A repeat of the same bad state
    /// returns `false` (already warned, don't spam). A transition to
    /// [`RpkiState::Valid`] — a recovery — always returns `false`: it is
    /// still recorded (so a later regression is detected as a fresh
    /// transition), but recovering is good news, not a WARN; the caller
    /// should log it as an INFO instead.
    pub fn observe_prefix(&mut self, net: ipnet::IpNet, state: RpkiState) -> bool {
        let prev = self.prefixes.insert(net, state);
        state != RpkiState::Valid && prev != Some(state)
    }
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

    #[test]
    fn warns_only_on_state_transition() {
        let mut st = RpkiWarnState::default();
        // first observation of an invalid prefix → warn
        assert!(st.observe_prefix(pfx("94.156.238.0/24"), RpkiState::Invalid)); // returns true = "should warn"
                                                                                // same state next interval → no warn
        assert!(!st.observe_prefix(pfx("94.156.238.0/24"), RpkiState::Invalid));
        // recovers to valid → (info, not warn) → observe returns false-for-warn but records the change
        assert!(!st.observe_prefix(pfx("94.156.238.0/24"), RpkiState::Valid));
        // validator down→up→down transitions warn once each
        assert!(st.observe_validator_up(false)); // up(default)→down = warn
        assert!(!st.observe_validator_up(false)); // still down = no warn
        assert!(!st.observe_validator_up(true)); // recovery = info, not warn
        assert!(st.observe_validator_up(false)); // down again = warn
    }

    #[test]
    fn observe_prefix_warns_on_worse_or_different_bad_state_not_on_repeat() {
        let mut st = RpkiWarnState::default();
        let net = pfx("94.156.238.0/32");
        // first bad observation warns
        assert!(st.observe_prefix(net, RpkiState::NotFound));
        // same bad state repeated → no warn
        assert!(!st.observe_prefix(net, RpkiState::NotFound));
        // a *different* bad state → warn (still bad, but changed)
        assert!(st.observe_prefix(net, RpkiState::Invalid));
        // first observation of a prefix that is immediately valid → no warn
        let other = pfx("203.0.113.0/32");
        assert!(!st.observe_prefix(other, RpkiState::Valid));
        // repeated valid → still no warn
        assert!(!st.observe_prefix(other, RpkiState::Valid));
    }

    #[test]
    fn observe_prefix_tracks_each_prefix_independently() {
        let mut st = RpkiWarnState::default();
        let a = pfx("94.156.238.0/32");
        let b = pfx("203.0.113.5/32");
        assert!(st.observe_prefix(a, RpkiState::Invalid));
        // a different, previously-unseen prefix warns on its own first observation
        assert!(st.observe_prefix(b, RpkiState::NotFound));
        // repeating `a`'s state doesn't warn, `b` is untouched by it
        assert!(!st.observe_prefix(a, RpkiState::Invalid));
    }

    #[test]
    fn aggregate_report_validator_up_when_first_fetch_succeeds() {
        let net = pfx("94.156.238.0/32");
        let results: Vec<(ipnet::IpNet, Result<RpkiState, ()>)> = vec![
            (net, Ok(RpkiState::Invalid)),
            (pfx("203.0.113.0/32"), Err(())),
        ];
        let report = aggregate_report(results);
        assert!(report.validator_up);
        // the failed second prefix is omitted, not guessed at
        assert_eq!(report.per_prefix, vec![(net, RpkiState::Invalid)]);
    }

    #[test]
    fn aggregate_report_validator_up_when_only_a_later_fetch_succeeds() {
        // A single flaky lookup FIRST in the list must not report the
        // validator down when a later fetch in the same pass succeeds.
        let results: Vec<(ipnet::IpNet, Result<RpkiState, ()>)> = vec![
            (pfx("94.156.238.0/32"), Err(())),
            (pfx("203.0.113.0/32"), Ok(RpkiState::Valid)),
        ];
        let report = aggregate_report(results);
        assert!(
            report.validator_up,
            "at least one fetch succeeded, so the validator is up"
        );
        assert_eq!(
            report.per_prefix,
            vec![(pfx("203.0.113.0/32"), RpkiState::Valid)]
        );
    }

    #[test]
    fn aggregate_report_validator_down_only_when_every_fetch_fails() {
        let results: Vec<(ipnet::IpNet, Result<RpkiState, ()>)> = vec![
            (pfx("94.156.238.0/32"), Err(())),
            (pfx("203.0.113.0/32"), Err(())),
        ];
        let report = aggregate_report(results);
        assert!(
            !report.validator_up,
            "every fetch failed, so the validator is genuinely unreachable"
        );
        assert!(report.per_prefix.is_empty());
    }

    #[test]
    fn aggregate_report_empty_prefix_set_is_validator_up() {
        let report: RpkiReport =
            aggregate_report(Vec::<(ipnet::IpNet, Result<RpkiState, ()>)>::new());
        assert!(report.validator_up);
        assert!(report.per_prefix.is_empty());
    }
}
