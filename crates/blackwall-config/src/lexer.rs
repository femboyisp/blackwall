//! A trivial line/word tokenizer for the config DSL. Strips `#` comments and
//! blank lines, splits each remaining line into whitespace-separated words,
//! and keeps the 1-based line number for diagnostics.

/// One non-blank, non-comment source line broken into words.
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    /// 1-based line number in the original source.
    pub number: usize,
    /// Whitespace-separated words, commas preserved as part of words.
    pub words: Vec<String>,
}

/// Tokenize `input` into significant lines.
pub fn lex(input: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for (idx, raw) in input.lines().enumerate() {
        let without_comment = match raw.find('#') {
            Some(pos) => &raw[..pos],
            None => raw,
        };
        let words: Vec<String> = without_comment
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if !words.is_empty() {
            out.push(Line {
                number: idx + 1,
                words,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_comments_and_blanks() {
        let lines = lex("interface wan eth0\n\n# a comment\nipv4 203.0.113.0/24 # trailing\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].number, 1);
        assert_eq!(lines[0].words, vec!["interface", "wan", "eth0"]);
        assert_eq!(lines[1].number, 4);
        assert_eq!(lines[1].words, vec!["ipv4", "203.0.113.0/24"]);
    }
}
