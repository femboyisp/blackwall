//! The HTTP fetch against a live Routinator `/api/v1/validity` endpoint, and
//! the per-check-pass driver that runs it over a set of prefixes.
//!
//! This is the crate's one carve-out from its "no I/O" invariant (see the
//! crate-level docs) — kept in its own file, coverage-excluded, so the rest
//! of the crate stays trivially unit testable. `aggregate_report` (the pure
//! half of [`check_once`]) lives in `lib.rs` and *is* unit tested.

use std::time::Duration;

use crate::{aggregate_report, classify, host_more_specific, validity_url, RpkiParseError};
use crate::{RpkiReport, RpkiState};

/// A request/HTTP/timeout/parse failure while checking one prefix against
/// the RPKI validator. Any variant means "treat this prefix (and, per
/// [`aggregate_report`]'s rule, possibly the whole validator) as down" — the
/// caller must fail **open**, never panic, never silently treat it as valid.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The request itself failed: DNS, connect, TLS, the 5s timeout, or a
    /// non-2xx HTTP status.
    #[error("RPKI validator request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The request succeeded but the response body did not parse into a
    /// recognized [`RpkiState`] (see [`classify`]).
    #[error("RPKI validator response could not be parsed: {0}")]
    Parse(#[from] RpkiParseError),
}

/// The per-request timeout for a single validity check. Short and fixed —
/// this runs on a periodic background task, never the mitigation hot path,
/// but a hung validator must not stall the check pass indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a default [`reqwest::Client`] for the periodic RPKI check task.
///
/// A thin re-export so callers (`blackwalld`'s periodic task) never need
/// `reqwest` as a direct dependency themselves — it stays confined to this
/// crate's coverage-excluded I/O boundary. Build once at task startup and
/// reuse it across every [`check_once`] pass (connection reuse).
#[must_use]
pub fn build_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// `GET url` and classify the response body via [`classify`].
///
/// Any request/HTTP/timeout error, or a `classify` parse error, is returned
/// as [`FetchError`] — never a panic, never a silent pass. The caller (the
/// periodic checker in `blackwalld`) maps this to `blackwall_rpki_validator_up 0`.
///
/// # Errors
///
/// Returns [`FetchError::Request`] on any transport/HTTP-status/timeout
/// failure, or [`FetchError::Parse`] if the response body did not parse into
/// a recognized [`RpkiState`].
pub async fn fetch_validity(client: &reqwest::Client, url: &str) -> Result<RpkiState, FetchError> {
    let response = client
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?
        .error_for_status()?;
    let body = response.text().await?;
    Ok(classify(&body)?)
}

/// Run one RPKI validity check pass: form the host more-specific of each of
/// `prefixes`, fetch+classify each against `base` (the validator's base URL)
/// for `asn` (the querying/announcing ASN, `RtbhPolicy.local_asn`), and
/// aggregate the results (see [`aggregate_report`] for the validator-up
/// rule).
///
/// Never panics: every fetch failure becomes an omitted `per_prefix` entry
/// and, per [`aggregate_report`], may flip `validator_up` to `false` — this
/// function fails open, it never blocks a mitigation.
pub async fn check_once(
    client: &reqwest::Client,
    base: &str,
    asn: u32,
    prefixes: &[ipnet::IpNet],
) -> RpkiReport {
    let mut results = Vec::with_capacity(prefixes.len());
    for net in prefixes {
        let ms = host_more_specific(net);
        let url = validity_url(base, asn, &ms);
        let outcome = fetch_validity(client, &url).await;
        results.push((ms, outcome));
    }
    aggregate_report(results)
}
