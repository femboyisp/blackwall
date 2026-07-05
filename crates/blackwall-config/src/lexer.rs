//! A trivial line/word tokenizer for the config DSL. Strips `#` comments and
//! blank lines, joins backslash-continued lines, splits each remaining logical
//! line into whitespace-separated words, and keeps the 1-based line number of
//! the (first physical) line for diagnostics.

/// One non-blank, non-comment source line broken into words.
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    /// 1-based line number in the original source.
    pub number: usize,
    /// Whitespace-separated words, commas preserved as part of words.
    pub words: Vec<String>,
}

/// Tokenize `input` into significant lines.
///
/// A physical line whose (comment-stripped) content ends with a backslash `\`
/// continues onto the next physical line; the joined logical line reports the
/// number of its first physical line.
pub fn lex(input: &str) -> Vec<Line> {
    let mut out = Vec::new();
    // Accumulator for a run of backslash-continued physical lines: the 1-based
    // number of the first line, plus the words gathered so far.
    let mut pending: Option<(usize, Vec<String>)> = None;

    for (idx, raw) in input.lines().enumerate() {
        let without_comment = match raw.find('#') {
            Some(pos) => &raw[..pos],
            None => raw,
        };
        // A trailing backslash (after stripping the comment and trailing space)
        // marks continuation; drop it before splitting into words.
        let trimmed = without_comment.trim_end();
        let continues = trimmed.ends_with('\\');
        let content = if continues {
            &trimmed[..trimmed.len() - 1]
        } else {
            without_comment
        };

        let words = content.split_whitespace().map(str::to_owned);
        match &mut pending {
            Some((_, acc)) => acc.extend(words),
            None => pending = Some((idx + 1, words.collect())),
        }

        if !continues {
            if let Some((number, acc)) = pending.take() {
                if !acc.is_empty() {
                    out.push(Line { number, words: acc });
                }
            }
        }
    }

    // A trailing backslash on the final line has nothing to continue onto; emit
    // whatever was accumulated so the content is not silently dropped.
    if let Some((number, acc)) = pending.take() {
        if !acc.is_empty() {
            out.push(Line { number, words: acc });
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

    #[test]
    fn joins_backslash_continued_lines() {
        let lines = lex("rtbh peer=10.0.0.2 local-as=1 \\\n     peer-as=1 md5=secret\n");
        assert_eq!(lines.len(), 1);
        // Reports the first physical line's number.
        assert_eq!(lines[0].number, 1);
        assert_eq!(
            lines[0].words,
            vec![
                "rtbh",
                "peer=10.0.0.2",
                "local-as=1",
                "peer-as=1",
                "md5=secret"
            ]
        );
    }

    #[test]
    fn continuation_works_across_three_lines_and_with_trailing_comment() {
        let lines = lex("a b \\  # keep going\n  c \\\n  d\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].number, 1);
        assert_eq!(lines[0].words, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn trailing_backslash_on_last_line_is_not_dropped() {
        let lines = lex("interface wan eth0 \\\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].words, vec!["interface", "wan", "eth0"]);
    }
}
