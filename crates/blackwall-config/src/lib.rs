//! Parser for the Blackwall configuration DSL.

mod error;
mod lexer;
mod parser;

pub use error::ConfigError;

use blackwall_core::Policy;
use std::path::Path;

/// Parse policy from an in-memory config string.
pub fn parse_str(input: &str) -> Result<Policy, ConfigError> {
    parser::parse(&lexer::lex(input))
}

/// Parse policy from a config file on disk.
pub fn parse_file(path: &Path) -> Result<Policy, ConfigError> {
    let text = std::fs::read_to_string(path)?;
    parse_str(&text)
}

/// Parse a config file and validate it (`Policy::resolve()`), so a
/// semantically invalid config (address outside prefixes, duplicate
/// ownership, duplicate service) fails at load rather than at apply. Used by
/// load-time paths (`flow`, `bird-config`).
pub fn parse_and_resolve(path: &Path) -> Result<Policy, ConfigError> {
    let policy = parse_file(path)?;
    policy.resolve().map_err(ConfigError::Resolve)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only sibling of [`parse_and_resolve`] that parses from an
    /// in-memory string instead of a file, mirroring its parse-then-resolve
    /// behavior for unit tests that don't want to touch the filesystem.
    fn parse_and_resolve_str(input: &str) -> Result<Policy, ConfigError> {
        let policy = parse_str(input)?;
        policy.resolve().map_err(ConfigError::Resolve)?;
        Ok(policy)
    }

    #[test]
    fn parse_str_round_trips_through_resolve() {
        let policy = parse_str(
            "interface wan eth0\nipv4 203.0.113.0/24\ndefault deception\n\
             tenant acme {\n owns 203.0.113.5\n allow tcp 443 host\n}\n",
        )
        .expect("valid");
        let resolved = policy.resolve().expect("resolvable");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].port, 443);
    }

    #[test]
    fn parse_and_resolve_rejects_out_of_prefix_ownership() {
        let cfg = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n owns 198.51.100.7\n}\n";
        let err = parse_and_resolve_str(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::Resolve(_)));
    }

    #[test]
    fn parse_and_resolve_ok_for_flow_only_config() {
        let cfg = "interface wan eth0\nipv4 203.0.113.0/24\nshadow\n";
        assert!(parse_and_resolve_str(cfg).is_ok());
    }
}
