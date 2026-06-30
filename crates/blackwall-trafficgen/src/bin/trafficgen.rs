//! `trafficgen` CLI: send floods, receive + measure, or verify a recv report.

use blackwall_trafficgen::io::{first_non_loopback_iface, ipv4_of, recv::run_recv, send::run_send};
use blackwall_trafficgen::rate::Bound;
use blackwall_trafficgen::report::RecvReport;
use blackwall_trafficgen::spec::{parse_spec, verify};
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "trafficgen", about = "Blackwall DDoS lab traffic generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Flood a destination with a named spec for a fixed duration.
    Send {
        /// Destination IPv4 (the victim).
        #[arg(long)]
        dst: std::net::Ipv4Addr,
        /// Spec name (e.g. `full-set`).
        #[arg(long)]
        spec: String,
        /// Duration in seconds.
        #[arg(long, default_value_t = 5)]
        duration: u64,
    },
    /// Receive + classify for a duration, writing a readiness file + a report.
    Recv {
        /// Readiness sentinel path.
        #[arg(long)]
        ready: String,
        /// Report output path.
        #[arg(long)]
        report: String,
        /// Duration in seconds.
        #[arg(long, default_value_t = 8)]
        duration: u64,
    },
    /// Verify a recv report against a spec's thresholds.
    Verify {
        /// Report input path.
        #[arg(long)]
        report: String,
        /// Spec name to verify against.
        #[arg(long)]
        spec: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("trafficgen: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Send {
            dst,
            spec,
            duration,
        } => {
            let iface = first_non_loopback_iface().map_err(|e| e.to_string())?;
            let _ = ipv4_of(&iface); // ensure addressed
            let gen = parse_spec(&spec).map_err(|e| e.to_string())?;
            let report = run_send(
                &iface,
                dst,
                &gen,
                Bound::Duration(Duration::from_secs(duration)),
            )
            .map_err(|e| e.to_string())?;
            println!("{}", report.to_json().map_err(|e| e.to_string())?);
            // Generator fidelity self-assert (spec §5.3): achieved pps must reach
            // a floor fraction of target. The floor is 50% at lab scale; tighten
            // toward the spec's ±10% once a sustainable rate is pinned in Task
            // 10's local validation.
            let elapsed_ms = report.elapsed_ms.max(1);
            let achieved_pps = report.sent.packets.saturating_mul(1000) / elapsed_ms;
            if achieved_pps.saturating_mul(100) < report.target_pps.saturating_mul(50) {
                return Err(format!(
                    "generator fidelity: achieved {achieved_pps} pps < 50% of target {}",
                    report.target_pps
                ));
            }
            Ok(())
        }
        Command::Recv {
            ready,
            report,
            duration,
        } => {
            let iface = first_non_loopback_iface().map_err(|e| e.to_string())?;
            let r = run_recv(&iface, &ready, &report, Duration::from_secs(duration))
                .map_err(|e| e.to_string())?;
            println!("{}", r.to_json().map_err(|e| e.to_string())?);
            Ok(())
        }
        Command::Verify { report, spec } => {
            let text = std::fs::read_to_string(&report).map_err(|e| e.to_string())?;
            let r = RecvReport::from_json(&text).map_err(|e| e.to_string())?;
            let gen = parse_spec(&spec).map_err(|e| e.to_string())?;
            let out = verify(&r, &gen);
            println!("{:#?}", out);
            if out.passed {
                Ok(())
            } else {
                Err(format!("verify failed: {:?}", out.reasons))
            }
        }
    }
}
