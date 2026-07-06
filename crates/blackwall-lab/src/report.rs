//! Serialize run results to JUnit XML and TAP.

use crate::assert::StepOutcome;

/// Result of one scenario step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    /// Step label.
    pub name: String,
    /// Pass/fail outcome.
    pub outcome: StepOutcome,
}

/// Results for one scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioResult {
    /// Scenario name.
    pub name: String,
    /// Step results in order.
    pub steps: Vec<StepResult>,
}

/// Results for a whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// Scenario results in order.
    pub scenarios: Vec<ScenarioResult>,
}

/// Escape the five XML predefined entities.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Serialize a [`RunReport`] as JUnit XML.
#[must_use]
pub fn to_junit(report: &RunReport) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
    for sc in &report.scenarios {
        let failures = sc
            .steps
            .iter()
            .filter(|s| matches!(s.outcome, StepOutcome::Fail(_)))
            .count();
        out.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
            xml_escape(&sc.name),
            sc.steps.len(),
            failures,
        ));
        for step in &sc.steps {
            match &step.outcome {
                StepOutcome::Pass => {
                    out.push_str(&format!(
                        "    <testcase name=\"{}\"/>\n",
                        xml_escape(&step.name)
                    ));
                }
                StepOutcome::Fail(reason) => {
                    out.push_str(&format!(
                        "    <testcase name=\"{}\">\n",
                        xml_escape(&step.name)
                    ));
                    out.push_str(&format!(
                        "      <failure>{}</failure>\n",
                        xml_escape(reason)
                    ));
                    out.push_str("    </testcase>\n");
                }
            }
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// Build the TAP version/plan header for a run with `total` steps.
///
/// Split out of [`to_tap`] so `lab test` can print the header up front and
/// stream each step's result as it completes (blackwall#88 diagnostics): a
/// hang mid-run then shows every step up to the stall instead of emitting
/// nothing until the run finishes or the job cap kills it.
#[must_use]
pub fn tap_header(total: usize) -> String {
    format!("TAP version 13\n1..{total}\n")
}

/// Build one TAP result line (plus, on failure, its `# <reason>` comment) for
/// step number `n` (1-based) of a run.
///
/// Companion to [`tap_header`] for incremental TAP streaming; see that
/// function's docs.
#[must_use]
pub fn tap_step_line(n: usize, step: &StepResult) -> String {
    match &step.outcome {
        StepOutcome::Pass => format!("ok {n} - {}\n", step.name),
        StepOutcome::Fail(reason) => format!("not ok {n} - {}\n# {reason}\n", step.name),
    }
}

/// Serialize a [`RunReport`] as TAP version 13.
#[must_use]
pub fn to_tap(report: &RunReport) -> String {
    let total: usize = report.scenarios.iter().map(|s| s.steps.len()).sum();
    let mut out = tap_header(total);
    let mut n = 0_usize;
    for sc in &report.scenarios {
        for step in &sc.steps {
            n += 1;
            out.push_str(&tap_step_line(n, step));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assert::StepOutcome;

    fn sample() -> RunReport {
        RunReport {
            scenarios: vec![ScenarioResult {
                name: "announces-host-route".to_owned(),
                steps: vec![
                    StepResult {
                        name: "wait bgp-established".to_owned(),
                        outcome: StepOutcome::Pass,
                    },
                    StepResult {
                        name: "assert route <present>".to_owned(),
                        outcome: StepOutcome::Fail("stdout does not contain `x`".to_owned()),
                    },
                ],
            }],
        }
    }

    #[test]
    fn junit_is_byte_exact() {
        let expected = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<testsuites>\n",
            "  <testsuite name=\"announces-host-route\" tests=\"2\" failures=\"1\">\n",
            "    <testcase name=\"wait bgp-established\"/>\n",
            "    <testcase name=\"assert route &lt;present&gt;\">\n",
            "      <failure>stdout does not contain `x`</failure>\n",
            "    </testcase>\n",
            "  </testsuite>\n",
            "</testsuites>\n",
        );
        assert_eq!(to_junit(&sample()), expected);
    }

    #[test]
    fn tap_is_byte_exact() {
        let expected = "TAP version 13\n\
1..2\n\
ok 1 - wait bgp-established\n\
not ok 2 - assert route <present>\n\
# stdout does not contain `x`\n";
        assert_eq!(to_tap(&sample()), expected);
    }

    #[test]
    fn tap_header_reports_the_plan_line() {
        assert_eq!(tap_header(0), "TAP version 13\n1..0\n");
        assert_eq!(tap_header(3), "TAP version 13\n1..3\n");
    }

    #[test]
    fn tap_step_line_pass() {
        let step = StepResult {
            name: "wait bgp-established".to_owned(),
            outcome: StepOutcome::Pass,
        };
        assert_eq!(tap_step_line(1, &step), "ok 1 - wait bgp-established\n");
    }

    #[test]
    fn tap_step_line_fail_includes_reason() {
        let step = StepResult {
            name: "assert route <present>".to_owned(),
            outcome: StepOutcome::Fail("stdout does not contain `x`".to_owned()),
        };
        assert_eq!(
            tap_step_line(2, &step),
            "not ok 2 - assert route <present>\n# stdout does not contain `x`\n"
        );
    }

    #[test]
    fn header_plus_step_lines_equals_to_tap() {
        let report = sample();
        let total: usize = report.scenarios.iter().map(|s| s.steps.len()).sum();
        let mut streamed = tap_header(total);
        let mut n = 0_usize;
        for sc in &report.scenarios {
            for step in &sc.steps {
                n += 1;
                streamed.push_str(&tap_step_line(n, step));
            }
        }
        assert_eq!(streamed, to_tap(&report));
    }
}
