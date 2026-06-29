//! Pure evaluation of an assertion against captured command output.

use crate::topology::model::Matcher;

/// Captured result of running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Process exit code.
    pub exit: i32,
}

/// Outcome of evaluating one assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The assertion held.
    Pass,
    /// The assertion failed, with a human-readable reason.
    Fail(String),
}

/// Evaluate `matcher` against `cap`.
#[must_use]
pub fn evaluate(matcher: &Matcher, cap: &Captured) -> StepOutcome {
    match matcher {
        Matcher::Contains(needle) => {
            if cap.stdout.contains(needle.as_str()) {
                StepOutcome::Pass
            } else {
                StepOutcome::Fail(format!("stdout does not contain `{needle}`"))
            }
        }
        Matcher::Equals(want) => {
            if cap.stdout.trim() == want {
                StepOutcome::Pass
            } else {
                StepOutcome::Fail(format!("stdout `{}` != `{want}`", cap.stdout.trim()))
            }
        }
        Matcher::Exit(code) => {
            if cap.exit == *code {
                StepOutcome::Pass
            } else {
                StepOutcome::Fail(format!("exit {} != {code}", cap.exit))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::model::Matcher;

    fn cap(stdout: &str, exit: i32) -> Captured {
        Captured { stdout: stdout.to_owned(), stderr: String::new(), exit }
    }

    #[test]
    fn contains_passes_and_fails() {
        assert_eq!(evaluate(&Matcher::Contains("203.0.113.7/32".to_owned()), &cap("... 203.0.113.7/32 ...", 0)), StepOutcome::Pass);
        assert!(matches!(evaluate(&Matcher::Contains("x".to_owned()), &cap("y", 0)), StepOutcome::Fail(_)));
    }

    #[test]
    fn equals_trims_stdout() {
        assert_eq!(evaluate(&Matcher::Equals("ok".to_owned()), &cap("  ok\n", 0)), StepOutcome::Pass);
        assert!(matches!(evaluate(&Matcher::Equals("ok".to_owned()), &cap("nope", 0)), StepOutcome::Fail(_)));
    }

    #[test]
    fn exit_matches_code() {
        assert_eq!(evaluate(&Matcher::Exit(0), &cap("", 0)), StepOutcome::Pass);
        assert!(matches!(evaluate(&Matcher::Exit(0), &cap("", 1)), StepOutcome::Fail(_)));
    }
}
