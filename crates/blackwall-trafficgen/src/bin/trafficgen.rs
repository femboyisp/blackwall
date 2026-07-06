//! `trafficgen` CLI: send floods, receive + measure, or verify a recv report.

use blackwall_trafficgen::io::{first_non_loopback_iface, recv::run_recv, send::run_send};
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
        /// Destination L4 port for the spec's patterns (default 80; e.g. a
        /// stateless-tier port under test).
        #[arg(long, default_value_t = 80)]
        dst_port: u16,
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
    /// Flood a port with concurrent completed TCP connections; self-asserts the
    /// engine's drop-at-cap (served > 0 AND some dropped/failed).
    ConnectFlood {
        /// Destination IPv4 (the victim).
        #[arg(long)]
        dst: std::net::Ipv4Addr,
        /// Destination port (a deception port, e.g. 22).
        #[arg(long)]
        port: u16,
        /// Number of concurrent connections.
        #[arg(long)]
        concurrency: usize,
        /// Duration in seconds.
        #[arg(long, default_value_t = 8)]
        duration: u64,
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
            dst_port,
        } => {
            let iface = first_non_loopback_iface().map_err(|e| e.to_string())?;
            let gen = parse_spec(&spec).map_err(|e| e.to_string())?;
            let report = run_send(
                &iface,
                dst,
                dst_port,
                &gen,
                Bound::Duration(Duration::from_secs(duration)),
            )
            .map_err(|e| e.to_string())?;
            println!("{}", report.to_json().map_err(|e| e.to_string())?);
            // Generator fidelity self-assert (spec §5.3): achieved pps must reach
            // at least 50% of target. This is a deliberately conservative floor
            // for increment 1 — the sustainable userspace AF_PACKET rate is
            // environment-dependent (CI vs bare metal), so the gate proves the
            // generator is not grossly under-delivering rather than asserting a
            // tight band. Tightening once the rate is measured on CI is a
            // tracked follow-up.
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
        Command::ConnectFlood {
            dst,
            port,
            concurrency,
            duration,
        } => {
            use blackwall_trafficgen::io::connect::run_connect_flood;
            use blackwall_trafficgen::spec::connect_flood_ok;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let report = rt.block_on(run_connect_flood(
                dst,
                port,
                concurrency,
                Duration::from_secs(duration),
            ));
            println!("{}", report.to_json().map_err(|e| e.to_string())?);
            if connect_flood_ok(&report) {
                Ok(())
            } else {
                Err(format!(
                    "connect-flood: not (alive AND bounded): {report:?}"
                ))
            }
        }
    }
}
