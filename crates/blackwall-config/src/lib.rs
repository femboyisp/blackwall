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

#[cfg(test)]
mod tests {
    use super::*;

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
}
