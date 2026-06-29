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
                    out.push_str(&format!("      <failure>{}</failure>\n", xml_escape(reason)));
                    out.push_str("    </testcase>\n");
                }
            }
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// Serialize a [`RunReport`] as TAP version 13.
#[must_use]
pub fn to_tap(report: &RunReport) -> String {
    let mut out = String::from("TAP version 13\n");
    let total: usize = report.scenarios.iter().map(|s| s.steps.len()).sum();
    out.push_str(&format!("1..{total}\n"));
    let mut n = 0_usize;
    for sc in &report.scenarios {
        for step in &sc.steps {
            n += 1;
            match &step.outcome {
                StepOutcome::Pass => out.push_str(&format!("ok {n} - {}\n", step.name)),
                StepOutcome::Fail(reason) => {
                    out.push_str(&format!("not ok {n} - {}\n", step.name));
                    out.push_str(&format!("# {reason}\n"));
                }
            }
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
                        outcome: StepOutcome::Fail(
                            "stdout does not contain `x`".to_owned(),
                        ),
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
}
