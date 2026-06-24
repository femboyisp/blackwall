//! Errors produced while parsing the Blackwall config DSL.

/// A configuration parse error, always carrying the 1-based source line.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A token was not what the grammar expected at this point.
    #[error("line {line}: expected {expected}, found '{found}'")]
    UnexpectedToken {
        /// 1-based source line.
        line: usize,
        /// The offending token.
        found: String,
        /// A human description of what was expected.
        expected: &'static str,
    },
    /// A line started with a word that is not a known directive.
    #[error("line {line}: unknown directive '{word}'")]
    UnknownDirective {
        /// 1-based source line.
        line: usize,
        /// The unrecognized leading word.
        word: String,
    },
    /// A value (CIDR, IP, port, target) failed to parse.
    #[error("line {line}: invalid {what}: '{value}'")]
    BadValue {
        /// 1-based source line.
        line: usize,
        /// What kind of value failed.
        what: &'static str,
        /// The raw text.
        value: String,
    },
    /// The config file could not be read.
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
}
