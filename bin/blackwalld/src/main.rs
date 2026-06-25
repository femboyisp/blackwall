//! The Blackwall daemon/CLI entry point.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use blackwall_deception::transport::{run_nfqueue, serve, TproxyListener};
use blackwall_deception::{default_registry, EngineLimits, SharedBanners};
use blackwall_state::SessionRow;
use tokio::sync::mpsc;

/// Blackwall deception firewall control binary.
#[derive(Parser)]
#[command(name = "blackwalld", version)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a config and print the nftables ruleset as JSON.
    Render {
        /// Path to the Blackwall config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Parse a config, persist it, and apply the ruleset to the kernel.
    Apply {
        /// Path to the Blackwall config file.
        #[arg(long)]
        config: PathBuf,
        /// PostgreSQL connection URL.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Apply the ruleset and start the deception engine (requires CAP_NET_ADMIN).
    Run {
        /// Path to the Blackwall config file.
        #[arg(long)]
        config: PathBuf,
        /// PostgreSQL connection URL.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Path to the banner definitions file.
        #[arg(long)]
        banners: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Core dispatch logic; returns `Err` on any failure.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Render { config } => {
            let policy = blackwall_config::parse_file(&config)?;
            let json = blackwall_nft::ruleset_json(&policy)?;
            println!("{json}");
            Ok(())
        }
        Command::Apply {
            config,
            database_url,
        } => {
            let policy = blackwall_config::parse_file(&config)?;
            let store = blackwall_state::Store::connect(&database_url).await?;
            store.migrate().await?;
            let n = store.apply_policy(&policy, "blackwalld").await?;
            tracing::info!(services = n, "policy persisted");
            blackwall_nft::apply(&policy)?;
            tracing::info!("ruleset applied");
            tracing::warn!(
                "deception/forwarding enforcement is NOT yet active (Milestone 2); \
                 the applied ruleset classifies structure only and does not yet \
                 protect services — NFQUEUE redirect and real-service DNAT rules \
                 are deferred to Milestone 2"
            );
            Ok(())
        }
        Command::Run {
            config,
            database_url,
            banners,
        } => {
            // TPROXY and NFQUEUE both require CAP_NET_ADMIN; warn unconditionally
            // so the operator knows what is needed even before a bind failure.
            tracing::warn!(
                "TPROXY listener and NFQUEUE loop require CAP_NET_ADMIN; \
                 if the engine fails to start, re-run as root or with the \
                 appropriate capability granted"
            );

            let policy = blackwall_config::parse_file(&config)?;
            blackwall_nft::apply(&policy)?;
            tracing::info!("ruleset applied");

            let store = blackwall_state::Store::connect(&database_url).await?;
            store.migrate().await?;

            let shared = SharedBanners::load(&banners)?;
            let registry = std::sync::Arc::new(default_registry(shared.clone()));
            // Reload banners on file change (best-effort; a parse error keeps the old set).
            let watch_path = banners.clone();
            let watch_shared = shared.clone();
            let mut watcher =
                notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                    if res.is_ok() {
                        if let Err(err) = watch_shared.reload(&watch_path) {
                            tracing::warn!(%err, "banner reload failed");
                        } else {
                            tracing::info!("banners reloaded");
                        }
                    }
                })?;
            notify::Watcher::watch(&mut watcher, &banners, notify::RecursiveMode::NonRecursive)?;

            // TPROXY listener binds on port 61000 (ENGINE_TPROXY_PORT in blackwall-nft).
            let listener_v4 = TproxyListener::bind("0.0.0.0:61000".parse()?)?;

            // Attempt to bind an IPv6 TPROXY listener for the ip6 tproxy nft rule.
            let listener_v6 = match TproxyListener::bind("[::]:61000".parse()?) {
                Ok(v6_listener) => Some(v6_listener),
                Err(err) => {
                    tracing::warn!(
                        %err,
                        "failed to bind IPv6 TPROXY listener on [::]:61000 \
                         (IPv6 may be disabled on this host); continuing with IPv4 only"
                    );
                    None
                }
            };

            let (tx, mut rx) = mpsc::channel(256);

            let mut transports = tokio::task::JoinSet::new();
            transports.spawn(serve(
                listener_v4,
                registry.clone(),
                tx.clone(),
                EngineLimits::default(),
            ));
            let has_v6 = listener_v6.is_some();
            if let Some(v6) = listener_v6 {
                transports.spawn(serve(
                    v6,
                    registry.clone(),
                    tx.clone(),
                    EngineLimits::default(),
                ));
            }
            transports.spawn(async move {
                // run_nfqueue is blocking/sync; run it on a blocking thread.
                let _ = tokio::task::spawn_blocking(|| {
                    if let Err(err) = run_nfqueue(0) {
                        tracing::error!(%err, "nfqueue loop exited");
                    }
                })
                .await;
            });

            // Drop the controller's tx so the drain loop terminates when all serve clones are gone.
            drop(tx);

            if has_v6 {
                tracing::info!(
                    "deception engine running (TPROXY 0.0.0.0:61000 + [::]:61000, NFQUEUE 0)"
                );
            } else {
                tracing::info!("deception engine running (TPROXY 0.0.0.0:61000, NFQUEUE 0)");
            }

            let drain = async {
                while let Some(rec) = rx.recv().await {
                    let row = SessionRow {
                        local_addr: rec.meta.local.ip(),
                        local_port: rec.meta.local.port(),
                        peer_addr: rec.meta.peer.ip(),
                        proto: rec.meta.proto.to_string(),
                        emulator: rec.emulator,
                        bytes_in: i64::try_from(rec.outcome.bytes_in).unwrap_or(i64::MAX),
                        bytes_out: i64::try_from(rec.outcome.bytes_out).unwrap_or(i64::MAX),
                        note: rec.outcome.note,
                    };
                    if let Err(err) = store.record_session(&row).await {
                        tracing::warn!(%err, "failed to record deception session");
                    }
                }
            };

            tokio::select! {
                _ = drain => {
                    tracing::warn!("session channel closed; all transports exited");
                }
                joined = transports.join_next() => {
                    tracing::error!(?joined, "a transport task exited; shutting down");
                }
            }
            Err("deception engine transport exited".into())
        }
    }
}
