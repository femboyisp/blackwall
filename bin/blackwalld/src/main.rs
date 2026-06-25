//! The Blackwall daemon/CLI entry point.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use blackwall_deception::transport::{run_nfqueue, serve, TproxyListener};
use blackwall_deception::{default_registry, EngineLimits, SharedBanners};
use blackwall_discovery::IncusClient;
use blackwall_speedtest::providers::{
    CloudflareProvider, FastProvider, LibreSpeedProvider, OoklaProvider,
};
use blackwall_speedtest::{Speedtest, SpeedtestConfig, SpeedtestProvider};
use blackwall_state::SessionRow;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::sleep;

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
    /// Run a multi-provider network speed test and print results as JSON.
    Speedtest {
        /// LibreSpeed backend server URL.
        ///
        /// Defaults to `https://lon.speedtest.clouvider.net` (a well-known public
        /// LibreSpeed instance operated by Clouvider).  Pass a different URL to
        /// test against your own LibreSpeed deployment.
        #[arg(long, default_value = "https://lon.speedtest.clouvider.net")]
        librespeed_server: String,
        /// Maximum bytes per measurement window (overrides SpeedtestConfig default).
        #[arg(long)]
        max_bytes: Option<u64>,
        /// Per-request timeout in seconds (overrides SpeedtestConfig default).
        #[arg(long)]
        timeout_secs: Option<u64>,
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
        /// Also scan host sockets from /proc/net when building the discovered set.
        #[arg(long)]
        discover_host: bool,
        /// Path to the Incus unix socket.
        #[arg(long, default_value = "/var/lib/incus/unix.socket")]
        incus_socket: PathBuf,
        /// How often (in seconds) to re-run the speedtest and re-apply Auto shaping rules.
        ///
        /// Defaults to 21600 (6 hours).  Only relevant when at least one shaping rule uses
        /// `Auto` bandwidth.
        #[arg(long, default_value_t = 21_600_u64)]
        shape_interval_secs: u64,
        /// LibreSpeed backend server URL used when running speedtests for Auto shaping rules.
        ///
        /// Defaults to `https://lon.speedtest.clouvider.net`.  Pass a different URL to test
        /// against your own LibreSpeed deployment.
        #[arg(long, default_value = "https://lon.speedtest.clouvider.net")]
        librespeed_server: String,
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

/// Apply the effective policy derived from `base` merged with `discovered`.
///
/// Calls [`blackwall_discovery::reconcile`] to compute the effective policy,
/// persists it via [`blackwall_state::Store::apply_policy`], and then pushes it
/// to the kernel via [`blackwall_nft::apply`].
async fn apply_effective(
    base: &blackwall_core::Policy,
    discovered: &[blackwall_discovery::DiscoveredService],
    store: &blackwall_state::Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let effective = blackwall_discovery::reconcile(base, discovered);
    store.apply_policy(&effective, "discovery").await?;
    blackwall_nft::apply(&effective)?;
    Ok(())
}

/// Build the discovered-service list from host sockets and/or an Incus client.
///
/// If `discover_host` is true, scans `/proc/net` sockets and converts them to
/// [`blackwall_discovery::DiscoveredService`] entries with
/// [`blackwall_core::ServiceTarget::Host`].  If `incus` is `Some`, calls
/// `list_instances` and expands each instance via
/// [`blackwall_discovery::instance_services`].
async fn build_discovered(
    discover_host: bool,
    incus: Option<&blackwall_discovery::UnixIncusClient>,
) -> Vec<blackwall_discovery::DiscoveredService> {
    use blackwall_core::ServiceTarget;
    use blackwall_discovery::{DiscoveredService, DiscoverySource};

    let mut discovered: Vec<DiscoveredService> = Vec::new();

    if discover_host {
        match blackwall_discovery::scan_host_sockets(std::path::Path::new("/proc")) {
            Ok(sockets) => {
                for sock in sockets {
                    discovered.push(DiscoveredService {
                        addr: sock.addr,
                        proto: sock.proto,
                        port: sock.port,
                        target: ServiceTarget::Host,
                        source: DiscoverySource::Host,
                    });
                }
            }
            Err(err) => {
                tracing::warn!(%err, "host socket scan failed; skipping host discovery");
            }
        }
    }

    if let Some(client) = incus {
        match client.list_instances().await {
            Ok(instances) => {
                for inst in &instances {
                    discovered.extend(blackwall_discovery::instance_services(inst));
                }
            }
            Err(err) => {
                tracing::warn!(%err, "Incus list_instances failed; skipping Incus discovery");
            }
        }
    }

    discovered
}

/// Build the four speedtest providers used for Auto shaping rules.
///
/// Returns a `Vec<Arc<dyn SpeedtestProvider>>` containing Cloudflare, LibreSpeed (at
/// `librespeed_server`), Fast.com, and Ookla, in that order.
fn build_speedtest_providers(librespeed_server: &str) -> Vec<Arc<dyn SpeedtestProvider>> {
    vec![
        Arc::new(CloudflareProvider::new()),
        Arc::new(LibreSpeedProvider::new(librespeed_server.to_owned())),
        Arc::new(FastProvider::new()),
        Arc::new(OoklaProvider::new()),
    ]
}

/// Apply CAKE shaping derived from `policy.shaping`.
///
/// For rules where both directions are `Fixed`, the plan is computed and applied synchronously.
/// For rules containing any `Auto` direction a speedtest is run first, then the plan is applied.
/// After the initial apply a detached `tokio::spawn` loop re-tunes every `interval_secs`
/// seconds; failures inside that loop are logged as warnings and never propagate to the caller.
async fn apply_shaping(
    policy: &blackwall_core::Policy,
    librespeed_server: String,
    interval_secs: u64,
) {
    use blackwall_core::ShapeBandwidth;
    use std::time::Duration;

    for (i, rule) in policy.shaping.iter().enumerate() {
        let ifb = format!("ifb{i}");
        let needs_speedtest = matches!(rule.download, ShapeBandwidth::Auto)
            || matches!(rule.upload, ShapeBandwidth::Auto);

        if needs_speedtest {
            // Run an initial speedtest and apply the plan.
            let providers = build_speedtest_providers(&librespeed_server);
            let runner = Speedtest::new(providers);
            match runner.run(&SpeedtestConfig::default()).await {
                Err(err) => {
                    tracing::warn!(%err, iface = rule.iface, "initial speedtest failed; skipping Auto shaping for this rule");
                }
                Ok(aggregate) => match blackwall_shaper::plan_for(rule, Some(&aggregate)) {
                    Err(err) => {
                        tracing::warn!(%err, iface = rule.iface, "plan_for failed; skipping Auto shaping for this rule");
                    }
                    Ok(plan) => {
                        tracing::info!(
                            iface = %plan.iface,
                            ingress_mbit = plan.ingress_mbit,
                            egress_mbit = plan.egress_mbit,
                            "applying CAKE shaping (Auto)"
                        );
                        if let Err(err) = blackwall_shaper::apply(&plan, &ifb) {
                            tracing::warn!(%err, iface = rule.iface, "shaper apply failed");
                        }
                    }
                },
            }

            // Spawn a detached re-tune loop; failures never affect the engine.
            let rule_clone = rule.clone();
            let librespeed_clone = librespeed_server.clone();
            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(interval_secs)).await;
                    let providers = build_speedtest_providers(&librespeed_clone);
                    let runner = Speedtest::new(providers);
                    match runner.run(&SpeedtestConfig::default()).await {
                        Err(err) => {
                            tracing::warn!(%err, iface = rule_clone.iface, "re-tune speedtest failed; keeping previous shaping");
                        }
                        Ok(aggregate) => {
                            match blackwall_shaper::plan_for(&rule_clone, Some(&aggregate)) {
                                Err(err) => {
                                    tracing::warn!(%err, iface = rule_clone.iface, "re-tune plan_for failed; keeping previous shaping");
                                }
                                Ok(plan) => {
                                    tracing::info!(
                                        iface = %plan.iface,
                                        ingress_mbit = plan.ingress_mbit,
                                        egress_mbit = plan.egress_mbit,
                                        "re-applied CAKE shaping (Auto)"
                                    );
                                    if let Err(err) = blackwall_shaper::apply(&plan, &ifb) {
                                        tracing::warn!(%err, iface = rule_clone.iface, "re-tune shaper apply failed; keeping previous shaping");
                                    }
                                }
                            }
                        }
                    }
                }
            });
        } else {
            // Both directions are Fixed; apply once, no speedtest needed.
            match blackwall_shaper::plan_for(rule, None) {
                Err(err) => {
                    tracing::warn!(%err, iface = rule.iface, "plan_for failed for Fixed shaping rule");
                }
                Ok(plan) => {
                    tracing::info!(
                        iface = %plan.iface,
                        ingress_mbit = plan.ingress_mbit,
                        egress_mbit = plan.egress_mbit,
                        "applying CAKE shaping (Fixed)"
                    );
                    if let Err(err) = blackwall_shaper::apply(&plan, &ifb) {
                        tracing::warn!(%err, iface = rule.iface, "shaper apply failed");
                    }
                }
            }
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
        Command::Speedtest {
            librespeed_server,
            max_bytes,
            timeout_secs,
        } => {
            let providers: Vec<Arc<dyn SpeedtestProvider>> = vec![
                Arc::new(CloudflareProvider::new()),
                Arc::new(LibreSpeedProvider::new(librespeed_server)),
                Arc::new(FastProvider::new()),
                Arc::new(OoklaProvider::new()),
            ];
            let mut cfg = SpeedtestConfig::default();
            if let Some(b) = max_bytes {
                cfg.max_bytes = b;
            }
            if let Some(t) = timeout_secs {
                cfg.timeout = std::time::Duration::from_secs(t);
            }
            let runner = Speedtest::new(providers);
            match runner.run(&cfg).await {
                Ok(aggregate) => {
                    println!("{}", serde_json::to_string_pretty(&aggregate)?);
                    Ok(())
                }
                Err(blackwall_speedtest::SpeedtestError::NoResult) => {
                    eprintln!(
                        "speedtest: all providers returned no result; check network connectivity"
                    );
                    Err("speedtest produced no result".into())
                }
                Err(err) => Err(err.into()),
            }
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
            discover_host,
            incus_socket,
            shape_interval_secs,
            librespeed_server,
        } => {
            // TPROXY and NFQUEUE both require CAP_NET_ADMIN; warn unconditionally
            // so the operator knows what is needed even before a bind failure.
            tracing::warn!(
                "TPROXY listener and NFQUEUE loop require CAP_NET_ADMIN; \
                 if the engine fails to start, re-run as root or with the \
                 appropriate capability granted"
            );

            let policy = blackwall_config::parse_file(&config)?;

            // Connect and migrate the store early so discovery can persist its results.
            let store = blackwall_state::Store::connect(&database_url).await?;
            store.migrate().await?;

            // Attempt to connect to Incus; log a warning and continue without it on failure.
            let incus_client = match blackwall_discovery::UnixIncusClient::connect(&incus_socket) {
                Ok(client) => {
                    tracing::info!(socket = %incus_socket.display(), "connected to Incus");
                    Some(client)
                }
                Err(err) => {
                    tracing::warn!(
                        %err,
                        socket = %incus_socket.display(),
                        "failed to connect to Incus; continuing with base policy only"
                    );
                    None
                }
            };

            // Build the initial discovered set and apply the reconciled effective policy.
            let initial_discovered = build_discovered(discover_host, incus_client.as_ref()).await;
            apply_effective(&policy, &initial_discovered, &store).await?;
            tracing::info!(
                services = initial_discovered.len(),
                "initial effective policy applied"
            );

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

            // Spawn the Incus discovery event loop as a supervised task (non-fatal exit).
            if let Some(mut client) = incus_client {
                let policy_for_task = policy.clone();
                let store_for_task = store.clone();
                tokio::spawn(async move {
                    loop {
                        match client.next_event().await {
                            Ok(Some(ev)) => {
                                use blackwall_discovery::InstanceChange;
                                match ev.change {
                                    InstanceChange::Started
                                    | InstanceChange::Stopped
                                    | InstanceChange::Updated => {
                                        tracing::info!(
                                            instance = %ev.instance,
                                            change = ?ev.change,
                                            "Incus lifecycle event; reconciling"
                                        );
                                        let discovered =
                                            build_discovered(discover_host, Some(&client)).await;
                                        if let Err(err) = apply_effective(
                                            &policy_for_task,
                                            &discovered,
                                            &store_for_task,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                %err,
                                                "reconcile after Incus event failed"
                                            );
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                tracing::warn!("Incus event stream ended; discovery loop exiting");
                                break;
                            }
                            Err(blackwall_discovery::DiscoveryError::Parse(msg)) => {
                                tracing::warn!(%msg, "skipping malformed Incus event");
                                continue;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    %err,
                                    "Incus event stream error; discovery stopping"
                                );
                                break;
                            }
                        }
                    }
                });
            }

            // Apply CAKE shaping for each rule in policy.shaping.
            // Rules with both directions Fixed are applied once; any rule with an Auto direction
            // runs an initial speedtest and then spawns a detached re-tune loop.
            apply_shaping(&policy, librespeed_server, shape_interval_secs).await;

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
