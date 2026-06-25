//! Executes the `tc`/`ip` commands. Root-bound (`CAP_NET_ADMIN`); the command
//! contents come from the unit-tested builders in `command.rs`.

use crate::command::{egress_commands, ingress_commands, teardown_commands};
use crate::error::ShaperError;
use crate::plan::ShapePlan;
use std::process::Command;

/// Apply `plan`, using IFB device `ifb` for ingress. Tears down any prior
/// shaping on the interface first (best-effort) so re-application is idempotent.
pub fn apply(plan: &ShapePlan, ifb: &str) -> Result<(), ShaperError> {
    for cmd in teardown_commands(&plan.iface, ifb) {
        let _ = run(&cmd, true);
    }
    for cmd in egress_commands(plan) {
        run(&cmd, false)?;
    }
    for cmd in ingress_commands(plan, ifb) {
        run(&cmd, false)?;
    }
    Ok(())
}

fn run(cmd: &[String], ignore_failure: bool) -> Result<(), ShaperError> {
    let Some((program, args)) = cmd.split_first() else {
        return Ok(());
    };
    let status = Command::new(program).args(args).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) if ignore_failure => {
            tracing::debug!(
                cmd = cmd.join(" "),
                code = s.code(),
                "ignored shaping cmd failure"
            );
            Ok(())
        }
        Ok(s) => Err(ShaperError::Command(format!(
            "`{}` exited {:?}",
            cmd.join(" "),
            s.code()
        ))),
        Err(e) if ignore_failure => {
            tracing::debug!(cmd = cmd.join(" "), %e, "ignored shaping cmd error");
            Ok(())
        }
        Err(e) => Err(ShaperError::Command(format!("`{}`: {e}", cmd.join(" ")))),
    }
}
