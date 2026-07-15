//! The Blackwall daemon/CLI entry point.

mod api;
mod metrics;
mod shadow;

use clap::{Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use blackwall_deception::transport::{
    BannerLookup, DeceptionTransport, NfqueueTransport, StatelessMetrics, TproxyListener,
    TproxyTransport,
};
use blackwall_deception::{default_registry, CookieKey, EngineLimits, SharedBanners};
use blackwall_discovery::IncusClient;
use blackwall_speedtest::providers::{
    CloudflareProvider, FastProvider, LibreSpeedProvider, OoklaProvider,
};
use blackwall_speedtest::{Speedtest, SpeedtestConfig, SpeedtestProvider, SpeedtestSource};
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
    /// Parse a config and print the generated BIRD iBGP include.
    BirdConfig {
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
        /// Bind the test to this local source IP (e.g. 203.0.113.5).
        #[arg(long)]
        source_ip: Option<std::net::IpAddr>,
        /// Bind the test to this interface (Linux SO_BINDTODEVICE; needs CAP_NET_RAW).
        #[arg(long)]
        interface: Option<String>,
    },
    /// Run the sFlow collector and volumetric attack detector.
    Flow {
        /// Policy config file (its prefixes scope which destinations are detection candidates).
        #[arg(long)]
        config: std::path::PathBuf,
        /// UDP listen address for sFlow datagrams.
        #[arg(long, default_value = "0.0.0.0:6343")]
        listen: std::net::SocketAddr,
        /// Per-destination packets-per-second threshold.
        #[arg(long)]
        pps_threshold: f64,
        /// Per-destination bits-per-second threshold. NOTE: computed from the sFlow
        /// L2 frame length (includes the Ethernet header), so calibrate against L2
        /// bytes, not L3 payload.
        #[arg(long)]
        bps_threshold: f64,
        /// Sliding window in seconds.
        #[arg(long, default_value_t = 10)]
        window_secs: u64,
        /// Hold-down in seconds before clearing a detection.
        #[arg(long, default_value_t = 30)]
        hold_down_secs: u64,
        /// Minimum raw sFlow samples in-window before a detection may open (guards
        /// sampling-variance false positives). 0 disables the gate.
        #[arg(long, default_value_t = 8)]
        min_samples: usize,
        /// Ceiling multiplier applied to an agent's expected sampling rate when
        /// its reported rate is high. A reported rate above `expected * 4` is
        /// trusted (adaptive samplers legitimately raise their rate under load)
        /// up to `expected * max_sampling_factor`, and only clamped down beyond
        /// that ceiling — never clamped down to `expected` itself, which would
        /// mask a real flood as a false negative.
        #[arg(long, default_value_t = 64)]
        max_sampling_factor: u32,
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
    /// Queue RTBH operator intent, or inspect the announced mirror / intent queue.
    ///
    /// The CLI never talks to BGP directly: it only appends to (or reads) the
    /// `rtbh_requests`/`rtbh_blackholes` tables. A running `blackwalld flow`
    /// daemon (with an `rtbh` config block) is the sole applier of intent.
    Rtbh {
        /// Which RTBH action to perform.
        #[command(subcommand)]
        action: RtbhCmd,
    },
    /// Queue FlowSpec operator intent, or inspect the mirror / intent queue.
    ///
    /// Like `rtbh`, the CLI never talks to BGP directly: it only appends to
    /// (or reads) the `flowspec_requests`/`flowspec_rules` tables. A running
    /// `blackwalld flow` daemon (with `rtbh` + `flowspec` config blocks) is the
    /// sole applier of intent.
    Flowspec {
        /// Which FlowSpec action to perform.
        #[command(subcommand)]
        action: FlowspecCmd,
    },
    /// Queue XDP fast-path operator intent, or inspect the active map mirror.
    ///
    /// Like `rtbh`/`flowspec`, the CLI never touches the eBPF maps directly: it
    /// only appends to (or reads) the `xdp_requests`/`xdp_entries` tables. A
    /// running `blackwalld flow` daemon (with an `xdp` config block) is the sole
    /// applier of intent — it drains pending requests and programs the maps.
    Xdp {
        /// Which XDP action to perform.
        #[command(subcommand)]
        action: XdpCmd,
    },
    /// POP sensor (hsflowd) config generation.
    Sensor {
        /// Which sensor action to perform.
        #[command(subcommand)]
        action: SensorCmd,
    },
}

/// Operator actions for the `sensor` subcommand.
#[derive(Subcommand)]
enum SensorCmd {
    /// Render an `hsflowd.conf` for each `pop` entry in the flow config.
    ///
    /// Prints one commented block per POP to stdout; redirect/split the output
    /// to populate each POP's `/etc/hsflowd.conf`.
    RenderHsflowd {
        /// Path to the Blackwall (flow) config file (its `pop` directives are
        /// the source of each agent's sampling rate).
        #[arg(long)]
        config: PathBuf,
        /// The home `flow` daemon's sFlow collector address (`ip:port`), same
        /// as the `flow --listen` address.
        #[arg(long)]
        collector: SocketAddr,
        /// The network device each POP's hsflowd should sample (e.g. `eth0`).
        #[arg(long)]
        iface: String,
    },
}

/// Operator actions for the `xdp` subcommand.
#[derive(Subcommand)]
enum XdpCmd {
    /// Queue a source-blocklist add for the network `target` (drop all traffic).
    ///
    /// Warns (but still queues) if `target` overlaps an own prefix — blocking
    /// your own space is a self-inflicted denial of service; the daemon will
    /// reject such a request when it drains it.
    Block {
        /// The network to drop (e.g. `198.51.100.0/24` or a bare host address).
        target: ipnet::IpNet,
        /// Path to the Blackwall config file (must contain an `xdp` block).
        #[arg(long)]
        config: PathBuf,
        /// Attribution for the request; defaults to `$USER@<hostname>`.
        #[arg(long)]
        operator: Option<String>,
    },
    /// Queue a source-blocklist remove for the network `target`.
    Unblock {
        /// The network to stop dropping.
        target: ipnet::IpNet,
    },
    /// Queue a per-source rate limit for attacker source `ip`.
    RateLimit {
        /// The attacker source address to rate-limit.
        ip: IpAddr,
        /// Sustained packets-per-second cap.
        pps: u64,
        /// Burst bucket size in packets; defaults to `pps` when omitted.
        burst: Option<u64>,
        /// Path to the Blackwall config file (must contain an `xdp` block).
        #[arg(long)]
        config: PathBuf,
        /// Attribution for the request; defaults to `$USER@<hostname>`.
        #[arg(long)]
        operator: Option<String>,
    },
    /// Queue a rate-limit clear for attacker source `ip`.
    ClearRate {
        /// The attacker source address to stop rate-limiting.
        ip: IpAddr,
    },
    /// List the active `xdp_entries` map mirror.
    List,
    /// Print active-entry counts from the DB mirror.
    ///
    /// Live per-CPU packet counters (dropped/passed) are exported by the running
    /// daemon's Prometheus `/metrics` endpoint, not here — the CLI has no handle
    /// to the attached maps.
    Stats,
    /// Capture the packets the XDP program acted on, writing a pcap stream.
    ///
    /// Opens the running `flow` daemon's pinned capture ring (`CAPTURE`),
    /// switches capture on, drains up to `--count` records (or for `--duration`
    /// seconds, default 10 s), and writes them as a classic-format pcap to
    /// `--out` (or stdout). Each packet carries the up-to-96-byte L2 snapshot the
    /// program saw; the verdict/reason are recorded in the daemon's `/metrics`
    /// totals. Capture is switched back off automatically on exit.
    ///
    /// Requires a `blackwalld flow` daemon with XDP attached (it pins the ring);
    /// run this as root so it can open the pinned bpffs maps. Link-type is
    /// Ethernet, so the output opens directly in `tcpdump -r`/`wireshark`.
    Capture {
        /// Stop after capturing this many packets (mutually exclusive with
        /// `--duration`).
        #[arg(long, conflicts_with = "duration")]
        count: Option<usize>,
        /// Capture for this many seconds (mutually exclusive with `--count`;
        /// defaults to 10 s when neither is given).
        #[arg(long)]
        duration: Option<u64>,
        /// Write the pcap here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// bpffs directory the daemon pinned the capture maps under.
        #[arg(long, default_value = blackwall_xdp::DEFAULT_CAPTURE_PIN_DIR)]
        pin_dir: PathBuf,
    },
}

/// Operator actions for the `rtbh` subcommand.
#[derive(Subcommand)]
enum RtbhCmd {
    /// Queue a blackhole-add request for `ip`.
    ///
    /// Rejected up front (before any database connection) if `ip` falls
    /// outside the config's `ipv4`/`ipv6` prefixes, or if the config's `rtbh`
    /// block has no next-hop configured for `ip`'s address family.
    Add {
        /// The target address to blackhole.
        ip: IpAddr,
        /// Path to the Blackwall config file (must contain an `rtbh` block).
        #[arg(long)]
        config: PathBuf,
        /// Attribution for the request; defaults to `$USER@<hostname>`.
        #[arg(long)]
        operator: Option<String>,
    },
    /// Queue a blackhole-remove request for `ip`.
    Remove {
        /// The target address to un-blackhole.
        ip: IpAddr,
    },
    /// List the announced blackhole mirror (and, optionally, the intent queue).
    List {
        /// Also print the `rtbh_requests` operator intent queue.
        #[arg(long)]
        requests: bool,
    },
}

/// Operator actions for the `flowspec` subcommand.
#[derive(Subcommand)]
enum FlowspecCmd {
    /// Queue a FlowSpec-add request for the flow `ip proto port`.
    ///
    /// Rejected up front (before any database connection) if `ip` falls
    /// outside the config's FlowSpec-eligible prefixes.
    Add {
        /// The victim address to rate-limit.
        ip: IpAddr,
        /// IP protocol number (e.g. 17 = UDP, 6 = TCP).
        proto: u8,
        /// Destination port.
        port: u16,
        /// Traffic-rate action in bytes/sec; `0.0` = drop.
        #[arg(long, default_value_t = 0.0)]
        rate: f32,
        /// Path to the Blackwall config file (must contain a `flowspec` block).
        #[arg(long)]
        config: PathBuf,
        /// Attribution for the request; defaults to `$USER@<hostname>`.
        #[arg(long)]
        operator: Option<String>,
    },
    /// Queue a FlowSpec-remove request for the flow `ip proto port`.
    Remove {
        /// The victim address to stop rate-limiting.
        ip: IpAddr,
        /// IP protocol number.
        proto: u8,
        /// Destination port.
        port: u16,
    },
    /// List the announced FlowSpec mirror (and, optionally, the intent queue).
    List {
        /// Also print the `flowspec_requests` operator intent queue.
        #[arg(long)]
        requests: bool,
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
/// pushes it to the kernel via [`blackwall_nft::apply`], and then records it via
/// [`blackwall_state::Store::apply_policy`].
///
/// The kernel is applied *before* the DB write on purpose: the nft ruleset is
/// the safety-critical side (it actually classifies traffic), so on a partial
/// failure the running data plane must reflect the latest computed policy even
/// if the DB record lags. The reverse order would leave the kernel enforcing a
/// stale policy while the DB claims the new one is applied. Both are idempotent,
/// so the next event re-applies cleanly either way.
async fn apply_effective(
    base: &blackwall_core::Policy,
    discovered: &[blackwall_discovery::DiscoveredService],
    store: &blackwall_state::Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let effective = blackwall_discovery::reconcile(base, discovered);
    blackwall_nft::apply(&effective)?;
    store.apply_policy(&effective, "discovery").await?;
    Ok(())
}

/// Drain the Incus lifecycle event stream, reconciling on each relevant event.
///
/// Returns when the stream ends (`Ok(None)`) or errors, so the caller can
/// reconnect. Malformed events are logged and skipped without ending the stream.
async fn drain_incus_events(
    client: &mut blackwall_discovery::UnixIncusClient,
    discover_host: bool,
    base: &blackwall_core::Policy,
    store: &blackwall_state::Store,
) {
    use blackwall_discovery::{DiscoveryError, InstanceChange};
    loop {
        match client.next_event().await {
            Ok(Some(ev)) => match ev.change {
                InstanceChange::Started | InstanceChange::Stopped | InstanceChange::Updated => {
                    tracing::info!(
                        instance = %ev.instance,
                        change = ?ev.change,
                        "Incus lifecycle event; reconciling"
                    );
                    let discovered = build_discovered(discover_host, Some(&*client)).await;
                    if let Err(err) = apply_effective(base, &discovered, store).await {
                        tracing::warn!(%err, "reconcile after Incus event failed");
                    }
                }
            },
            Ok(None) => {
                tracing::warn!("Incus event stream ended; will reconnect");
                return;
            }
            Err(DiscoveryError::Parse(msg)) => {
                tracing::warn!(%msg, "skipping malformed Incus event");
            }
            Err(err) => {
                tracing::warn!(%err, "Incus event stream error; will reconnect");
                return;
            }
        }
    }
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
/// `librespeed_server`), Fast.com, and Ookla, in that order.  Each provider is
/// constructed with `source` so measurements are bound to the requested local IP or
/// interface.
fn build_speedtest_providers(
    librespeed_server: &str,
    source: &SpeedtestSource,
) -> Vec<Arc<dyn SpeedtestProvider>> {
    vec![
        Arc::new(CloudflareProvider::with_source(source.clone())),
        Arc::new(LibreSpeedProvider::with_source(
            librespeed_server.to_owned(),
            source.clone(),
        )),
        Arc::new(FastProvider::with_source(source.clone())),
        Arc::new(OoklaProvider::with_source(source.clone())),
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
            let providers = build_speedtest_providers(
                &librespeed_server,
                &SpeedtestSource::Iface(rule.iface.clone()),
            );
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
                    let providers = build_speedtest_providers(
                        &librespeed_clone,
                        &SpeedtestSource::Iface(rule_clone.iface.clone()),
                    );
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

/// Process-start [`Instant`](std::time::Instant) base, captured once on first
/// use, so [`mono_now`] returns a stable monotonic clock for the process's
/// lifetime (the RTBH controller's injected `mono_now` clock).
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Monotonic milliseconds since the process started.
fn mono_now() -> u64 {
    let start = *PROCESS_START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Wall-clock milliseconds since the Unix epoch (the RTBH journal's `at_ms`).
fn wall_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Default RTBH request attribution: `$USER@<hostname>`, falling back to
/// `"unknown"`/`"unknown-host"` when either is unavailable.
fn default_operator() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned());
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned());
    format!("{user}@{host}")
}

/// Build an [`blackwall_rtbh::RtbhConfig`] from the policy's prefixes and the
/// config's `rtbh` block. Shared by the CLI's eligibility pre-check and the
/// `flow` daemon's manager wiring, so both agree on what is eligible.
fn rtbh_config_from(
    policy: &blackwall_core::Policy,
    rtbh: &blackwall_core::RtbhPolicy,
) -> blackwall_rtbh::RtbhConfig {
    blackwall_rtbh::RtbhConfig {
        eligible_prefixes: policy.prefixes.clone(),
        blackhole_communities: rtbh.blackhole_communities.clone(),
        next_hop_v4: rtbh.next_hop_v4,
        next_hop_v6: rtbh.next_hop_v6,
        max_blackholes: rtbh.max_blackholes,
        hold_down: rtbh.hold_down,
        max_ttl: rtbh.max_ttl,
        protected_prefixes: policy.protected_prefixes.clone(),
    }
}

/// Build a [`blackwall_rtbh::FlowSpecConfig`] from the policy's prefixes and the
/// config's `flowspec` block. Shared by the CLI's eligibility pre-check and the
/// `flow` daemon's manager wiring, so both agree on what is eligible. FlowSpec
/// reuses `Policy.prefixes` for eligibility (no separate next-hop/peer fields).
fn flowspec_config_from(
    policy: &blackwall_core::Policy,
    fs: &blackwall_core::FlowSpecPolicy,
) -> blackwall_rtbh::FlowSpecConfig {
    blackwall_rtbh::FlowSpecConfig {
        eligible_prefixes: policy.prefixes.clone(),
        max_rules: fs.max_rules,
        hold_down: fs.hold_down,
        max_ttl: fs.max_ttl,
        protected_prefixes: policy.protected_prefixes.clone(),
    }
}

/// Construct a host route (`/32` for IPv4, `/128` for IPv6) for `target`.
///
/// Local mirror of `blackwall_rtbh`'s crate-private `host_prefix`, used to
/// rebuild a FlowSpec destination match from a stored victim address.
fn host_prefix(target: IpAddr) -> ipnet::IpNet {
    match target {
        IpAddr::V4(a) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(a, 32).expect("v4 /32")),
        IpAddr::V6(a) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(a, 128).expect("v6 /128")),
    }
}

/// Single-owner RTBH reconcile loop: applies auto detection events as they
/// arrive on `rx`, and on a 1 s tick, calls [`blackwall_rtbh::RtbhManager::tick`]
/// (completing deferred clears/TTL expiries — mandatory, see the module docs)
/// and then re-reads every `status = 'pending'` row from `rtbh_requests`,
/// applying each as `manual_add`/`manual_remove` and recording the outcome
/// back onto the request row.
///
/// The drain is purely status-driven: it is not an id watermark, so a
/// restart re-reads only genuinely-pending intent (queued-while-down or
/// still capacity-deferred), never replaying `applied`/`rejected` history
/// (which would re-announce, and transiently null-route, already-removed
/// targets). A capacity-deferred add is left `pending`, so it is retried
/// automatically on the next tick's re-read — no separate in-memory FIFO is
/// needed.
///
/// Fail fast if the config's managed interface does not exist. Otherwise the
/// rendered `iifname` match silently never fires and the box classifies no
/// traffic — a common, hard-to-diagnose deployment footgun.
fn ensure_interface_exists(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    if std::path::Path::new(&format!("/sys/class/net/{iface}")).exists() {
        Ok(())
    } else {
        Err(format!(
            "configured interface `{iface}` does not exist \
             (check the `interface` directive) — the ruleset would classify no traffic"
        )
        .into())
    }
}

/// Fail fast if any configured flowtable device is missing: nft rejects a
/// flowtable that references a non-existent device, so the whole ruleset apply
/// would fail (leaving nothing installed) with a less obvious error.
fn ensure_flowtable_devices_exist(
    policy: &blackwall_core::Policy,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ft) = &policy.flowtable {
        for dev in &ft.devices {
            if !std::path::Path::new(&format!("/sys/class/net/{dev}")).exists() {
                return Err(format!(
                    "flowtable device `{dev}` does not exist \
                     (check the `flowtable devices=` directive)"
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Resolve when the process is asked to stop: SIGTERM (e.g. `systemctl stop`) or
/// SIGINT (Ctrl-C). Used to trigger a graceful deception-engine shutdown.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).ok();
    let term = async {
        match term.as_mut() {
            Some(s) => {
                s.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = term => {}
    }
}

/// Listen for SIGUSR1 and fan a one-shot disarm command out to every
/// RTBH/FlowSpec/XDP manager task via `disarm_tx` (C5: in-daemon kill
/// switch).
///
/// Each manager task withdraws its own active mitigations and switches to
/// record-only on receipt (see [`rtbh_manager_task`]/[`flowspec_manager_task`]/
/// [`xdp_manager_task`]'s `disarm_rx` arm); this task only relays the signal
/// and flips the shared `blackwall_armed` gauge to `0`. One-way: a second
/// SIGUSR1 re-broadcasts, but every manager's own `disarm` is idempotent (a
/// no-op once already disarmed), and there is no re-arm signal — only a
/// restart clears it. Detached for the process's lifetime (mirrors
/// [`bgp_supervisor`]); if the signal handler fails to install (rare — e.g.
/// exhausted signalfd resources), this logs once and returns, leaving
/// SIGTERM/SIGINT shutdown (handled separately by [`wait_for_shutdown`])
/// unaffected.
async fn disarm_signal_task(
    disarm_tx: tokio::sync::broadcast::Sender<()>,
    armed: std::sync::Arc<std::sync::atomic::AtomicU8>,
) {
    use tokio::signal::unix::{signal, SignalKind};
    let Ok(mut usr1) = signal(SignalKind::user_defined1()) else {
        tracing::warn!(
            "failed to install SIGUSR1 handler; in-daemon disarm (C5) is unavailable this run"
        );
        return;
    };
    loop {
        if usr1.recv().await.is_none() {
            return;
        }
        tracing::warn!(
            "WARN: DISARMED — SIGUSR1 received: withdrawing all mitigations, now recording only (one-way; restart to re-arm)"
        );
        armed.store(0, std::sync::atomic::Ordering::Relaxed);
        // No receivers (e.g. no rtbh/flowspec/xdp block configured) is not
        // an error — there is simply nothing to disarm.
        let _ = disarm_tx.send(());
    }
}

/// Observe the BGP session and log loudly when it leaves `Established` — a down
/// session means auto-mitigations are not reaching the peer (issue #79). Purely
/// observational; the session task drives reconnect itself. Exits when the
/// session task is gone (the watch sender drops).
async fn bgp_supervisor(mut states: tokio::sync::watch::Receiver<blackwall_bgp::SessionState>) {
    let mut established = false;
    loop {
        if states.changed().await.is_err() {
            return;
        }
        let state = *states.borrow_and_update();
        match (established, state) {
            (false, blackwall_bgp::SessionState::Established) => {
                established = true;
                tracing::info!("BGP session established");
            }
            (true, blackwall_bgp::SessionState::Established) => {}
            (true, _) => {
                established = false;
                tracing::warn!(
                    ?state,
                    "BGP session DOWN — mitigations are not reaching the peer"
                );
            }
            _ => {}
        }
    }
}

/// The `/metrics` gauges/counters one `*_manager_task` copies its manager's
/// per-tick snapshot into, bundled into a single argument so
/// `rtbh_manager_task`/`flowspec_manager_task`/`xdp_manager_task` each take
/// one metrics parameter instead of threading the same handful of `Arc`s
/// individually (prep refactor for #194 C1 — pure plumbing, no behavior
/// change).
#[derive(Clone)]
struct PlaneMetrics {
    /// Anycast self-protection (C1) skip counter, shared across all three
    /// planes — this task writes only its own field (see
    /// [`shadow::ProtectedSkippedMetrics`]'s per-plane fields).
    protected: Arc<shadow::ProtectedSkippedMetrics>,
    /// This plane's dedicated apply-failure counter (C2).
    apply_failures: Arc<std::sync::atomic::AtomicU64>,
    /// Shared cross-plane rate-cap (C6) skip counters; `None` for XDP, which
    /// has no shared rate limiter to report against.
    ratecapped: Option<Arc<shadow::RatecappedMetrics>>,
    /// This plane's dedicated reapply-pending gauge (issue #194 C1).
    reapply_pending: Arc<std::sync::atomic::AtomicUsize>,
}

/// Runs until `rx` is closed (i.e. for the process's lifetime, since the
/// paired `ChannelSink`'s sender is held by the running collector).
async fn rtbh_manager_task<B, J>(
    mut manager: blackwall_rtbh::RtbhManager<B, J>,
    mut rx: mpsc::Receiver<blackwall_flow::DetectionEvent>,
    request_store: std::sync::Arc<blackwall_state::Store>,
    metrics: PlaneMetrics,
    mut disarm_rx: tokio::sync::broadcast::Receiver<()>,
) where
    B: blackwall_rtbh::manager::BgpExecutor + Send + 'static,
    J: blackwall_rtbh::manager::BlackholeJournal + Send + 'static,
{
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    // Once `disarm_tx` (held by `disarm_signal_task`) is gone — e.g. SIGUSR1
    // registration failed at startup — `disarm_rx.recv()` would return
    // `Err(Closed)` on every poll forever; without this guard that turns
    // into a busy loop (the branch is always immediately ready). Once
    // observed, the `if` precondition below permanently disables polling
    // this branch, so the task falls back to `rx`/`ticker` only.
    let mut disarm_open = true;
    loop {
        tokio::select! {
            maybe_ev = rx.recv() => {
                match maybe_ev {
                    Some(ev) => manager.apply_event(&ev, mono_now(), wall_now()).await,
                    None => {
                        tracing::warn!("RTBH: detection-event channel closed; manager task exiting");
                        return;
                    }
                }
            }
            disarmed = disarm_rx.recv(), if disarm_open => {
                // C5: withdraw every active blackhole and switch to
                // record-only. A `Lagged` delivery still means "disarm was
                // requested" (the payload is `()`, nothing to miss), so it
                // is treated the same as `Ok`.
                match disarmed {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("RTBH: DISARMED — mitigations withdrawn, now recording only");
                        manager.disarm(mono_now()).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        disarm_open = false;
                    }
                }
            }
            _ = ticker.tick() => {
                // Mandatory: without this, a `Cleared` arriving before hold-down
                // elapses is deferred and never completed.
                manager.tick(mono_now(), wall_now()).await;

                metrics.protected.rtbh.store(
                    manager.protected_skipped(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                metrics.apply_failures.store(
                    manager.apply_failures(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if let Some(ratecapped) = &metrics.ratecapped {
                    ratecapped
                        .rtbh
                        .store(manager.ratecapped(), std::sync::atomic::Ordering::Relaxed);
                }
                metrics.reapply_pending.store(
                    manager.reapply_pending(),
                    std::sync::atomic::Ordering::Relaxed,
                );

                match request_store.pending_requests().await {
                    Ok(reqs) => {
                        for req in reqs {
                            apply_request(&mut manager, &request_store, req).await;
                        }
                    }
                    Err(err) => tracing::warn!(%err, "RTBH: failed to read pending rtbh_requests"),
                }
            }
        }
    }
}

/// Apply one pending `rtbh_requests` row and record its outcome.
///
/// For `"add"`: `Applied` marks the row `applied`; `Deferred` leaves the row
/// `pending` untouched (it is naturally retried on the next tick's
/// `pending_requests` read); `Rejected` marks the row `rejected` with the
/// reason. For `"remove"`: withdraws the target, then supersedes any other
/// still-pending `add` for the same target (the operator's remove is the
/// newer intent and must win over a not-yet-applied add), then marks this
/// row `applied`.
async fn apply_request<B, J>(
    manager: &mut blackwall_rtbh::RtbhManager<B, J>,
    request_store: &blackwall_state::Store,
    req: blackwall_state::RtbhRequestRow,
) where
    B: blackwall_rtbh::manager::BgpExecutor + Send + 'static,
    J: blackwall_rtbh::manager::BlackholeJournal + Send + 'static,
{
    match req.action.as_str() {
        "add" => match manager.apply_add(req.target, mono_now(), wall_now()).await {
            blackwall_rtbh::ApplyOutcome::Applied => {
                if let Err(err) = request_store
                    .set_request_status(req.id, "applied", None)
                    .await
                {
                    tracing::warn!(%err, id = req.id, "RTBH: failed to set request status");
                }
            }
            blackwall_rtbh::ApplyOutcome::Deferred => {
                // Leave `pending`; picked up again on the next tick.
            }
            blackwall_rtbh::ApplyOutcome::Rejected(reason) => {
                if let Err(err) = request_store
                    .set_request_status(req.id, "rejected", Some(&reason))
                    .await
                {
                    tracing::warn!(%err, id = req.id, "RTBH: failed to set request status");
                }
            }
        },
        "remove" => {
            manager
                .apply_remove(req.target, mono_now(), wall_now())
                .await;
            // Cancel any other still-pending add for the same target: the
            // operator's remove is the newer intent, so a pending add must
            // not later announce this target once capacity frees.
            if let Err(err) = request_store
                .supersede_pending_adds(req.target, req.id)
                .await
            {
                tracing::warn!(%err, target = %req.target, "RTBH: failed to supersede pending adds");
            }
            if let Err(err) = request_store
                .set_request_status(req.id, "applied", None)
                .await
            {
                tracing::warn!(%err, id = req.id, "RTBH: failed to set request status");
            }
        }
        other => {
            tracing::warn!(
                action = other,
                id = req.id,
                "RTBH: unknown request action; ignoring"
            );
        }
    }
}

/// Single-owner FlowSpec reconcile loop: the FlowSpec analogue of
/// [`rtbh_manager_task`]. Applies auto mitigation events as they arrive on
/// `rx` (an `Open`/`Update`/`Clear` from the collector's [`SelectorSink`]),
/// and on a 1 s tick calls [`blackwall_rtbh::FlowSpecManager::tick`] (deferred
/// clears / TTL expiry — mandatory) then drains every `status = 'pending'` row
/// from `flowspec_requests` via [`apply_flowspec_request`].
///
/// Runs until `rx` is closed (i.e. for the process's lifetime, since the
/// paired `SelectorSink`'s sender is held by the running collector).
async fn flowspec_manager_task<B, J>(
    mut manager: blackwall_rtbh::FlowSpecManager<B, J>,
    mut rx: mpsc::Receiver<blackwall_flow::FlowMitigationEvent>,
    request_store: std::sync::Arc<blackwall_state::Store>,
    metrics: PlaneMetrics,
    mut disarm_rx: tokio::sync::broadcast::Receiver<()>,
) where
    B: blackwall_rtbh::manager::BgpExecutor + Send + 'static,
    J: blackwall_rtbh::flowspec_manager::FlowSpecJournal + Send + 'static,
{
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    // See the matching guard in `rtbh_manager_task` for why this exists.
    let mut disarm_open = true;
    loop {
        tokio::select! {
            maybe_ev = rx.recv() => {
                match maybe_ev {
                    Some(blackwall_flow::FlowMitigationEvent::Open { target, rules }) => {
                        manager.apply_open(target, &rules, mono_now(), wall_now()).await;
                    }
                    Some(blackwall_flow::FlowMitigationEvent::Update { target }) => {
                        // `apply_updated` is synchronous (in-memory refresh only).
                        manager.apply_updated(target, mono_now());
                    }
                    Some(blackwall_flow::FlowMitigationEvent::Clear { target }) => {
                        manager.apply_clear(target, mono_now(), wall_now()).await;
                    }
                    None => {
                        tracing::warn!("FlowSpec: event channel closed; manager task exiting");
                        return;
                    }
                }
            }
            disarmed = disarm_rx.recv(), if disarm_open => {
                // C5: see the matching arm in `rtbh_manager_task` for why a
                // `Lagged` delivery still counts as "disarm was requested".
                match disarmed {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("FlowSpec: DISARMED — mitigations withdrawn, now recording only");
                        manager.disarm(mono_now()).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        disarm_open = false;
                    }
                }
            }
            _ = ticker.tick() => {
                // Mandatory: completes deferred clears / TTL expiry.
                manager.tick(mono_now(), wall_now()).await;

                metrics.protected.flowspec.store(
                    manager.protected_skipped(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                metrics.apply_failures.store(
                    manager.apply_failures(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if let Some(ratecapped) = &metrics.ratecapped {
                    ratecapped.flowspec.store(
                        manager.ratecapped(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                metrics.reapply_pending.store(
                    manager.reapply_pending(),
                    std::sync::atomic::Ordering::Relaxed,
                );

                match request_store.pending_flowspec_requests().await {
                    Ok(reqs) => {
                        for req in reqs {
                            apply_flowspec_request(&mut manager, &request_store, req).await;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(%err, "FlowSpec: failed to read pending flowspec_requests");
                    }
                }
            }
        }
    }
}

/// Apply one pending `flowspec_requests` row and record its outcome — the
/// FlowSpec analogue of [`apply_request`].
///
/// For `"add"`: `Applied` marks the row `applied`; `Deferred` leaves the row
/// `pending` (retried on the next tick); `Rejected` marks it `rejected` with
/// the reason. For `"remove"`: withdraws the flow, supersedes any other
/// still-pending `add` for the same flow key, then marks this row `applied`.
async fn apply_flowspec_request<B, J>(
    manager: &mut blackwall_rtbh::FlowSpecManager<B, J>,
    request_store: &blackwall_state::Store,
    req: blackwall_state::FlowSpecRequestRow,
) where
    B: blackwall_rtbh::manager::BgpExecutor + Send + 'static,
    J: blackwall_rtbh::flowspec_manager::FlowSpecJournal + Send + 'static,
{
    let rule = blackwall_bgp::FlowSpecRule {
        dst: host_prefix(req.dst),
        protocol: Some(req.proto),
        dst_port: Some(req.dst_port),
        action: blackwall_bgp::FlowAction::TrafficRate(req.rate),
    };
    match req.action.as_str() {
        "add" => match manager.apply_add(rule, mono_now(), wall_now()).await {
            blackwall_rtbh::ApplyOutcome::Applied => {
                if let Err(err) = request_store
                    .set_flowspec_request_status(req.id, "applied", None)
                    .await
                {
                    tracing::warn!(%err, id = req.id, "FlowSpec: failed to set request status");
                }
            }
            blackwall_rtbh::ApplyOutcome::Deferred => {
                // Leave `pending`; picked up again on the next tick.
            }
            blackwall_rtbh::ApplyOutcome::Rejected(reason) => {
                if let Err(err) = request_store
                    .set_flowspec_request_status(req.id, "rejected", Some(&reason))
                    .await
                {
                    tracing::warn!(%err, id = req.id, "FlowSpec: failed to set request status");
                }
            }
        },
        "remove" => {
            manager.apply_remove(rule, mono_now(), wall_now()).await;
            // The operator's remove is the newer intent: cancel any earlier
            // still-pending add for the same flow key.
            if let Err(err) = request_store
                .supersede_pending_flowspec_adds(req.dst, req.proto, req.dst_port, req.id)
                .await
            {
                tracing::warn!(%err, dst = %req.dst, "FlowSpec: failed to supersede pending adds");
            }
            if let Err(err) = request_store
                .set_flowspec_request_status(req.id, "applied", None)
                .await
            {
                tracing::warn!(%err, id = req.id, "FlowSpec: failed to set request status");
            }
        }
        other => {
            tracing::warn!(
                action = other,
                id = req.id,
                "FlowSpec: unknown request action; ignoring"
            );
        }
    }
}

/// Combined cap on active XDP entries (blocks + rate limits) the controller
/// will install. Kept at or below the smallest binding eBPF map (`BLOCK_V4`/
/// `BLOCK_V6` are 65 536-entry tries; `RATE` is far larger) so a full
/// controller can never overflow a map.
const XDP_MAX_ENTRIES: usize = 65_536;

/// The [`blackwall_xdp::manager::XdpManager`] the daemon runs: an executor
/// that is either the live attached data plane or (in shadow mode)
/// [`shadow::XdpExec::Shadow`], plus a journal `J` that is the Postgres
/// mirror ([`blackwall_state::PgXdpJournal`]) live, or the all-no-op
/// [`blackwall_xdp::NoOpXdpJournal`] in shadow (so the mirror stays empty).
type DaemonXdpManager<J> = blackwall_xdp::manager::XdpManager<shadow::XdpExec, J>;

/// Build an [`ipnet::IpNet`] from a stored address + optional prefix length,
/// falling back to a host route (`/32`/`/128`) when the length is absent.
fn xdp_net_from(target: IpAddr, prefixlen: Option<u8>) -> Option<ipnet::IpNet> {
    match prefixlen {
        Some(len) => ipnet::IpNet::new(target, len).ok(),
        None => Some(host_prefix(target)),
    }
}

/// Map an active `xdp_entries` mirror row back to a controller action + origin
/// for [`blackwall_xdp::manager::XdpManager::reapply_active`] on restart.
fn xdp_entry_to_action(
    row: &blackwall_state::XdpEntryRow,
) -> Option<(blackwall_xdp::XdpAction, blackwall_xdp::XdpOrigin)> {
    let origin = match row.origin.as_str() {
        "manual" => blackwall_xdp::XdpOrigin::Manual,
        _ => blackwall_xdp::XdpOrigin::Auto,
    };
    let action = match row.kind.as_str() {
        "block" => blackwall_xdp::XdpAction::Block {
            net: xdp_net_from(row.target, row.prefixlen)?,
        },
        "rate_limit" => {
            let pps = row.rate_pps?;
            blackwall_xdp::XdpAction::RateLimit {
                src: row.target,
                pps,
                burst: row.burst.unwrap_or(pps),
                victim: row.victim,
            }
        }
        other => {
            tracing::warn!(
                kind = other,
                "XDP: unknown xdp_entries kind; skipping rehydrate row"
            );
            return None;
        }
    };
    Some((action, origin))
}

/// Single-owner XDP reconcile loop: the XDP analogue of [`rtbh_manager_task`].
///
/// Applies auto detection events as they arrive on `rx` (fed by the
/// [`blackwall_xdp::XdpMitigationSink`] in the collector's fanout) when
/// `auto_enabled`, and on a 1 s tick calls
/// [`blackwall_xdp::manager::XdpManager::tick`] (draining any journal
/// mirror-retries) then drains every `status = 'pending'` row from
/// `xdp_requests` via [`apply_xdp_request`].
///
/// When `auto_enabled` is false (no `default-rate-limit` configured) detection
/// events are still drained off the channel but ignored — only operator CLI
/// requests populate the maps. Runs until `rx` is closed.
async fn xdp_manager_task<J>(
    mut manager: DaemonXdpManager<J>,
    mut rx: mpsc::Receiver<blackwall_flow::DetectionEvent>,
    request_store: std::sync::Arc<blackwall_state::Store>,
    auto_enabled: bool,
    metrics: PlaneMetrics,
    mut disarm_rx: tokio::sync::broadcast::Receiver<()>,
) where
    J: blackwall_xdp::XdpJournal + 'static,
{
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    // See the matching guard in `rtbh_manager_task` for why this exists.
    let mut disarm_open = true;
    loop {
        tokio::select! {
            maybe_ev = rx.recv() => {
                match maybe_ev {
                    Some(ev) => {
                        if auto_enabled {
                            manager.on_detection(&ev, wall_now()).await;
                        }
                    }
                    None => {
                        tracing::warn!("XDP: detection-event channel closed; manager task exiting");
                        return;
                    }
                }
            }
            disarmed = disarm_rx.recv(), if disarm_open => {
                // C5: see the matching arm in `rtbh_manager_task` for why a
                // `Lagged` delivery still counts as "disarm was requested".
                match disarmed {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("XDP: DISARMED — mitigations withdrawn, now recording only");
                        manager.disarm(mono_now()).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        disarm_open = false;
                    }
                }
            }
            _ = ticker.tick() => {
                // Drains any journal mirror-writes queued by a transient DB blip.
                manager.tick().await;

                metrics.protected.xdp.store(
                    manager.protected_skipped(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                metrics.apply_failures.store(
                    manager.apply_failures(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                metrics.reapply_pending.store(
                    manager.reapply_pending(),
                    std::sync::atomic::Ordering::Relaxed,
                );

                match request_store.xdp_pending_requests().await {
                    Ok(reqs) => {
                        for req in reqs {
                            apply_xdp_request(&mut manager, &request_store, req).await;
                        }
                    }
                    Err(err) => tracing::warn!(%err, "XDP: failed to read pending xdp_requests"),
                }
            }
        }
    }
}

/// Default banner the AF_XDP UDP responder reflects to every redirected port
/// (sub-project B3.2). The reflection-amplification guard in
/// [`blackwall_deception::transport::udp_l2_response`] truncates it to at most
/// the request's own payload length, so it can never amplify.
///
/// This is a deliberately minimal banner source: the flow daemon (`Command::Flow`)
/// runs no deception engine and holds no live banner store (unlike `Command::Run`),
/// so B3.2 ships a single static payload for all AF_XDP-redirected UDP ports.
/// Per-port banners (wiring the deception banner store into the flow daemon) are
/// a follow-up.
const AFXDP_UDP_BANNER: &[u8] = b"blackwall\n";

/// Dedicated blocking-thread receive loop for the AF_XDP UDP responder
/// (sub-project B3.2). Binds an `AF_XDP` socket on `iface` RX queue 0, registers
/// it into the `XSKS` map, installs the `REDIRECT_PORT` set, then answers every
/// redirected IPv4 UDP datagram with the reflection-safe
/// [`blackwall_deception::transport::udp_l2_response`] builder, transmitting the
/// reply **zero-copy** over the same socket's TX ring.
///
/// Non-fatal: any setup failure logs a warning and returns, leaving the AF_XDP
/// UDP fast path inert (the box keeps running). The loop exits promptly once
/// `stop` is set (checked between each bounded `recv_one` poll). Queue 0 only;
/// multi-queue is a follow-up.
fn afxdp_udp_responder_loop(
    iface: &str,
    dataplane: &Arc<blackwall_xdp::XdpDataplane>,
    ports: &[u16],
    banner: &[u8],
    responses: &std::sync::atomic::AtomicU64,
    stop: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;

    let mut sock = match blackwall_xdp::AfXdpSocket::bind(iface, 0) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(
                %err, interface = %iface,
                "XDP: AF_XDP UDP responder bind failed; responder disabled"
            );
            return;
        }
    };
    // SAFETY: `sock` owns the AF_XDP socket fd and lives for the whole loop
    // below (dropped only on return, after the last map use), so it satisfies
    // `register_xsk`'s requirement that the fd outlive its registration.
    if let Err(err) = unsafe { dataplane.register_xsk(sock.queue_id(), sock.raw_fd()) } {
        tracing::warn!(%err, "XDP: AF_XDP UDP responder xsk registration failed; responder disabled");
        return;
    }
    // Install the redirect ports only after the socket is registered, so no UDP
    // is diverted to an empty XSKS slot during startup.
    if let Err(err) = dataplane.set_redirect_ports(ports) {
        tracing::warn!(%err, "XDP: AF_XDP UDP responder redirect-port install failed; responder disabled");
        return;
    }
    tracing::info!(
        interface = %iface, ports = ports.len(),
        "XDP: AF_XDP UDP responder active on queue 0"
    );

    let mut frame = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        match sock.recv_one(200, &mut frame) {
            Ok(true) => {
                // Reflection-safe reply (IPv4 UDP only). `None` = not IPv4 UDP,
                // or the reflection guard declined (empty request payload) —
                // drop silently.
                if let Some(reply) = blackwall_deception::transport::udp_l2_response(&frame, banner)
                {
                    match sock.send(&reply) {
                        Ok(()) => {
                            responses.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(err) => {
                            tracing::debug!(%err, "XDP: AF_XDP UDP reply send failed; dropping")
                        }
                    }
                }
            }
            Ok(false) => {} // poll timeout: loop back and re-check `stop`.
            Err(err) => {
                tracing::warn!(%err, "XDP: AF_XDP UDP responder receive error; stopping responder");
                break;
            }
        }
    }
    tracing::info!("XDP: AF_XDP UDP responder stopped");
}

/// Apply one pending `xdp_requests` row and record its outcome — the XDP
/// analogue of [`apply_request`].
///
/// `block`/`rate_limit`: `Applied` marks the row `applied`; `Deferred` leaves
/// it `pending` (retried on the next tick); `Rejected` marks it `rejected`.
/// `unblock`/`clear_rate`: always applies, then marks `applied`. Unknown
/// actions are logged and left untouched.
async fn apply_xdp_request<J>(
    manager: &mut DaemonXdpManager<J>,
    request_store: &blackwall_state::Store,
    req: blackwall_state::XdpRequestRow,
) where
    J: blackwall_xdp::XdpJournal,
{
    use blackwall_xdp::manager::ApplyOutcome;

    let mark = |id: i64, status: &'static str| async move {
        if let Err(err) = request_store.xdp_mark_request(id, status).await {
            tracing::warn!(%err, id, status, "XDP: failed to set request status");
        }
    };

    match req.action.as_str() {
        "block" => {
            let Some(net) = xdp_net_from(req.target, req.prefixlen) else {
                tracing::warn!(target = %req.target, "XDP: bad block prefix; rejecting request");
                mark(req.id, "rejected").await;
                return;
            };
            match manager.apply_add(net, wall_now()).await {
                ApplyOutcome::Applied => mark(req.id, "applied").await,
                ApplyOutcome::Deferred => { /* leave pending; retried next tick */ }
                ApplyOutcome::Rejected(reason) => {
                    tracing::warn!(%reason, %net, "XDP: block request rejected");
                    mark(req.id, "rejected").await;
                }
            }
        }
        "unblock" => {
            let Some(net) = xdp_net_from(req.target, req.prefixlen) else {
                tracing::warn!(target = %req.target, "XDP: bad unblock prefix; rejecting request");
                mark(req.id, "rejected").await;
                return;
            };
            manager.apply_remove(net, wall_now()).await;
            mark(req.id, "applied").await;
        }
        "clear_rate" => {
            manager.apply_clear_rate(req.target, wall_now()).await;
            mark(req.id, "applied").await;
        }
        "rate_limit" => {
            let Some(pps) = req.rate_pps else {
                tracing::warn!(target = %req.target, "XDP: rate_limit request has no pps; rejecting");
                mark(req.id, "rejected").await;
                return;
            };
            let burst = req.burst.unwrap_or(pps);
            match manager
                .apply_rate_limit(req.target, pps, burst, wall_now())
                .await
            {
                ApplyOutcome::Applied => mark(req.id, "applied").await,
                ApplyOutcome::Deferred => { /* leave pending; retried next tick */ }
                ApplyOutcome::Rejected(reason) => {
                    tracing::warn!(%reason, target = %req.target, "XDP: rate_limit request rejected");
                    mark(req.id, "rejected").await;
                }
            }
        }
        other => {
            tracing::warn!(
                action = other,
                id = req.id,
                "XDP: unknown request action; ignoring"
            );
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
        Command::BirdConfig { config } => {
            let policy = blackwall_config::parse_and_resolve(&config)?;
            match blackwall_bgp::render_bird_ibgp(&policy) {
                Ok(s) => {
                    print!("{s}");
                    Ok(())
                }
                Err(e) => Err(format!("bird-config: {e}").into()),
            }
        }
        Command::Speedtest {
            librespeed_server,
            max_bytes,
            timeout_secs,
            source_ip,
            interface,
        } => {
            let source = match (source_ip, interface) {
                (Some(ip), Some(_)) => {
                    tracing::warn!("both --source-ip and --interface given; using --source-ip");
                    SpeedtestSource::Ip(ip)
                }
                (Some(ip), None) => SpeedtestSource::Ip(ip),
                (None, Some(name)) => SpeedtestSource::Iface(name),
                (None, None) => SpeedtestSource::Default,
            };
            let providers = build_speedtest_providers(&librespeed_server, &source);
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
        Command::Flow {
            config,
            listen,
            pps_threshold,
            bps_threshold,
            window_secs,
            hold_down_secs,
            min_samples,
            max_sampling_factor,
        } => {
            let policy = blackwall_config::parse_and_resolve(&config)?;
            if policy.shadow {
                tracing::warn!(
                    "SHADOW MODE — mitigations are LOGGED, NOT APPLIED (RTBH/FlowSpec/XDP)"
                );
            }
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "DATABASE_URL must be set for the flow detector")?;
            let store = std::sync::Arc::new(blackwall_state::Store::connect(&database_url).await?);
            store.migrate().await?;
            let agents = blackwall_flow::AgentRegistry::from_entries(&policy.pops);
            let detector_config = blackwall_flow::DetectorConfig {
                pps_threshold,
                bps_threshold,
                window_ms: window_secs * 1000,
                hold_down_ms: hold_down_secs * 1000,
                min_samples,
                max_sampling_factor,
            };
            let detector = blackwall_flow::ThresholdDetector::new(
                policy.prefixes.clone(),
                detector_config,
                agents,
            );

            // Collector counters (sFlow datagrams / decode errors) for /metrics.
            let collector_metrics = std::sync::Arc::new(blackwall_flow::CollectorMetrics::new());
            // Per-agent (POP) telemetry snapshot, refreshed once per collector
            // tick and read by /metrics; the detector itself is owned by
            // `run_collector` behind `Box<dyn Detector>` so this is the only
            // way the metrics endpoint can see it.
            let agent_snapshot: std::sync::Arc<std::sync::Mutex<Vec<blackwall_flow::AgentStat>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            // Captured inside the rtbh arm below so /metrics can report session state.
            let mut bgp_for_metrics: Option<blackwall_bgp::BgpHandle> = None;
            // Shared shadow-mode counters: fed by the RTBH/FlowSpec managers
            // below (when `policy.shadow`) and by the XDP shadow gate, read by
            // the metrics endpoint. Built unconditionally — harmless all-zero
            // counters when shadow mode is off.
            let shadow_metrics = std::sync::Arc::new(shadow::ShadowMetrics::default());
            // Shared anycast self-protection (C1) skip counters: each manager
            // task below copies its controller's `protected_skipped()` value
            // in here on every tick, in BOTH shadow and live sessions (unlike
            // `shadow_metrics`, this guard is not shadow-specific). Built
            // unconditionally — harmless all-zero counters when RTBH/FlowSpec/
            // XDP aren't configured.
            let protected_skipped_metrics =
                std::sync::Arc::new(shadow::ProtectedSkippedMetrics::default());
            // RTBH announces that failed at the BGP executor and were rolled
            // back (C2): copied from `RtbhManager::apply_failures` on every
            // tick, mirroring `protected_skipped_metrics` above. Built
            // unconditionally — harmless all-zero counter when no `rtbh`
            // block is configured.
            let rtbh_apply_failure_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            // FlowSpec announces that failed at the BGP executor and were
            // rolled back (C2): copied from `FlowSpecManager::apply_failures`
            // on every tick, mirroring `rtbh_apply_failure_metrics` above.
            // Built unconditionally — harmless all-zero counter when no
            // `flowspec` block is configured.
            let flowspec_apply_failure_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            // XDP executor (eBPF-map) applies that failed and were rolled
            // back (C2): copied from `XdpManager::apply_failures` on every
            // tick, mirroring `rtbh_apply_failure_metrics` above. Built
            // unconditionally — harmless all-zero counter when no `xdp`
            // block is configured.
            let xdp_apply_failure_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            // C6 cross-plane new-mitigation rate cap skip counters: copied
            // from `RtbhManager`/`FlowSpecManager::ratecapped` on every tick,
            // mirroring `protected_skipped_metrics` above. Built
            // unconditionally — harmless all-zero counters when no `rtbh`
            // block is configured or `max-new-per-min` is unset.
            let ratecapped_metrics = std::sync::Arc::new(shadow::RatecappedMetrics::default());
            // `rehydrate` re-announces queued for a self-heal retry after a
            // failed BGP announce on restart (issue #194): copied from
            // `RtbhManager::reapply_pending` on every tick, mirroring
            // `rtbh_apply_failure_metrics` above. Built unconditionally —
            // harmless all-zero gauge when no `rtbh` block is configured.
            let rtbh_reapply_pending_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // `rehydrate` re-announces queued for a self-heal retry after a
            // failed BGP announce on restart (issue #194): copied from
            // `FlowSpecManager::reapply_pending` on every tick, mirroring
            // `rtbh_reapply_pending_metrics` above. Built unconditionally —
            // harmless all-zero gauge when no `flowspec` block is configured.
            let flowspec_reapply_pending_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // `reapply_active` re-applies queued for a self-heal retry after
            // a failed executor apply on restart (issue #194): copied from
            // `blackwall_xdp::manager::XdpManager::reapply_pending` on every
            // tick, mirroring `rtbh_reapply_pending_metrics` above. Built
            // unconditionally — harmless all-zero gauge when no `xdp` block
            // is configured.
            let xdp_reapply_pending_metrics =
                std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // Bundled per-plane `/metrics` argument for the three
            // `*_manager_task`s (prep refactor for #194 C1 — see
            // `PlaneMetrics`'s doc comment). XDP has no shared rate limiter,
            // so its `ratecapped` is `None`.
            let rtbh_plane_metrics = PlaneMetrics {
                protected: protected_skipped_metrics.clone(),
                apply_failures: rtbh_apply_failure_metrics.clone(),
                ratecapped: Some(ratecapped_metrics.clone()),
                reapply_pending: rtbh_reapply_pending_metrics.clone(),
            };
            let flowspec_plane_metrics = PlaneMetrics {
                protected: protected_skipped_metrics.clone(),
                apply_failures: flowspec_apply_failure_metrics.clone(),
                ratecapped: Some(ratecapped_metrics.clone()),
                reapply_pending: flowspec_reapply_pending_metrics.clone(),
            };
            let xdp_plane_metrics = PlaneMetrics {
                protected: protected_skipped_metrics.clone(),
                apply_failures: xdp_apply_failure_metrics.clone(),
                ratecapped: None,
                reapply_pending: xdp_reapply_pending_metrics.clone(),
            };
            // In-daemon disarm kill switch (C5): `blackwall_armed` starts at
            // 1 (live) or 0 (shadow) and is flipped to 0 exactly once, on a
            // SIGUSR1 disarm — there is no path back to 1 short of a
            // restart. `disarm_tx` is the broadcast sender the SIGUSR1
            // listener (spawned below, once every manager task below has
            // subscribed) uses to fan a single disarm command out to every
            // RTBH/FlowSpec/XDP manager task; each subscribes via
            // `disarm_tx.subscribe()` when it is spawned.
            let blackwall_armed =
                std::sync::Arc::new(std::sync::atomic::AtomicU8::new(u8::from(!policy.shadow)));
            let (disarm_tx, _disarm_rx) = tokio::sync::broadcast::channel::<()>(8);

            let sink: std::sync::Arc<dyn blackwall_flow::MitigationSink> = match policy.rtbh.clone()
            {
                None => std::sync::Arc::new(blackwall_state::PgMitigationSink::new(store.clone())),
                Some(rtbh) => {
                    let pg_sink: std::sync::Arc<dyn blackwall_flow::MitigationSink> =
                        std::sync::Arc::new(blackwall_state::PgMitigationSink::new(store.clone()));

                    let controller =
                        blackwall_rtbh::RtbhController::new(rtbh_config_from(&policy, &rtbh));
                    let channel_cap = rtbh.max_blackholes.max(1024);
                    let (tx, rx) = mpsc::channel::<blackwall_flow::DetectionEvent>(channel_cap);

                    // C6 cross-plane rate cap on new mitigations: ONE limiter
                    // built from the rtbh block's `max-new-per-min` knob,
                    // shared between RTBH and FlowSpec below (FlowSpec reuses
                    // this block). Only wired on the live path (`!policy.shadow`)
                    // — under shadow nothing is really announced, so
                    // rate-capping would only corrupt the would-mitigate
                    // signal; `None` here (either shadow, or the knob absent)
                    // means neither manager ever gets `.with_rate_limiter`
                    // called, so both stay unlimited (non-breaking default).
                    let rate_limiter: Option<
                        std::sync::Arc<std::sync::Mutex<blackwall_rtbh::ArmingRateLimiter>>,
                    > = if policy.shadow {
                        None
                    } else {
                        rtbh.max_new_per_min.map(|n| {
                            std::sync::Arc::new(std::sync::Mutex::new(
                                blackwall_rtbh::ArmingRateLimiter::new(n),
                            ))
                        })
                    };

                    // The live BGP handle, threaded to the FlowSpec
                    // construction below so its live branch reuses this same
                    // iBGP session. `None` in shadow mode (no real session is
                    // spawned) — which is exactly what the FlowSpec match keys
                    // off, so there is no implicit cross-block invariant.
                    let live_bgp: Option<blackwall_bgp::BgpHandle> = if policy.shadow {
                        let recorder =
                            shadow::AuditShadowRecorder::new(store.clone(), shadow_metrics.clone());
                        let exec = blackwall_rtbh::ShadowBgpExecutor::new(recorder);
                        let manager = blackwall_rtbh::RtbhManager::new(
                            controller,
                            exec,
                            blackwall_rtbh::NoOpJournal,
                        );
                        // No rehydrate: the shadow mirror is intentionally
                        // empty — nothing was ever really announced, so there
                        // is nothing to replay.
                        tokio::spawn(rtbh_manager_task(
                            manager,
                            rx,
                            store.clone(),
                            rtbh_plane_metrics.clone(),
                            disarm_tx.subscribe(),
                        ));
                        None
                    } else {
                        let peer = blackwall_bgp::PeerConfig {
                            local_asn: rtbh.local_asn,
                            peer_asn: rtbh.peer_asn,
                            peer_addr: rtbh.peer_addr,
                            router_id: rtbh.router_id,
                            hold_time: 90,
                            md5: rtbh.md5.as_ref().map(|s| s.reveal().to_owned()),
                            gtsm_hops: rtbh.gtsm_hops,
                            local_addr: rtbh.local_addr,
                        };
                        // `BgpHandle` is a cloneable mpsc sender; both the RTBH
                        // and (optionally) FlowSpec managers share the one
                        // iBGP session.
                        let (bgp, _bgp_join) = blackwall_bgp::spawn(peer)?;
                        // Supervise the session: log loudly when it leaves
                        // Established (mitigations aren't reaching the peer)
                        // — issue #79.
                        tokio::spawn(bgp_supervisor(bgp.state_watch()));
                        bgp_for_metrics = Some(bgp.clone());
                        let journal: blackwall_state::Store = (*store).clone();
                        let mut manager =
                            blackwall_rtbh::RtbhManager::new(controller, bgp.clone(), journal);
                        if let Some(limiter) = &rate_limiter {
                            manager = manager.with_rate_limiter(limiter.clone());
                        }

                        // Rehydrate the controller from the announced mirror
                        // before this session starts accepting new
                        // detections/requests.
                        let mirror = store.list_active_blackholes().await?;
                        let rehydrate_rows: Vec<(IpAddr, u64, blackwall_rtbh::BlackholeOrigin)> =
                            mirror
                                .into_iter()
                                .map(|row| {
                                    let origin = match row.origin.as_str() {
                                        "manual" => blackwall_rtbh::BlackholeOrigin::Manual,
                                        _ => blackwall_rtbh::BlackholeOrigin::Auto,
                                    };
                                    (row.target, row.announced_at_ms, origin)
                                })
                                .collect();
                        manager.rehydrate(rehydrate_rows, mono_now()).await;

                        tokio::spawn(rtbh_manager_task(
                            manager,
                            rx,
                            store.clone(),
                            rtbh_plane_metrics.clone(),
                            disarm_tx.subscribe(),
                        ));
                        Some(bgp)
                    };

                    match policy.flowspec.clone() {
                        // RTBH-only: today's behaviour, Fanout([Pg, Channel→rtbh]).
                        None => {
                            let channel_sink: std::sync::Arc<dyn blackwall_flow::MitigationSink> =
                                std::sync::Arc::new(blackwall_flow::ChannelSink::new(tx));
                            std::sync::Arc::new(blackwall_flow::FanoutSink(vec![
                                pg_sink,
                                channel_sink,
                            ]))
                        }
                        // RTBH + FlowSpec: build a second single-owner manager
                        // (shadow or, off the SAME live BGP session, real) and
                        // route detections through a SelectorSink instead of
                        // the plain RTBH ChannelSink.
                        Some(fs) => {
                            let fs_controller = blackwall_rtbh::FlowSpecController::new(
                                flowspec_config_from(&policy, &fs),
                            );
                            let fs_cap = fs.max_rules.max(1024);
                            let (fs_tx, fs_rx) =
                                mpsc::channel::<blackwall_flow::FlowMitigationEvent>(fs_cap);

                            // Reuse the live BGP handle from the RTBH branch
                            // (`Some` on the live path, `None` in shadow mode).
                            // Matching the real value here removes the earlier
                            // cross-block `.expect()` on `bgp_for_metrics`.
                            match live_bgp {
                                None => {
                                    let recorder = shadow::AuditShadowRecorder::new(
                                        store.clone(),
                                        shadow_metrics.clone(),
                                    );
                                    let exec = blackwall_rtbh::ShadowBgpExecutor::new(recorder);
                                    let fs_manager = blackwall_rtbh::FlowSpecManager::new(
                                        fs_controller,
                                        exec,
                                        blackwall_rtbh::NoOpJournal,
                                    );
                                    // No rehydrate: shadow mirror stays empty.
                                    tokio::spawn(flowspec_manager_task(
                                        fs_manager,
                                        fs_rx,
                                        store.clone(),
                                        flowspec_plane_metrics.clone(),
                                        disarm_tx.subscribe(),
                                    ));
                                }
                                Some(bgp) => {
                                    let fs_journal: blackwall_state::Store = (*store).clone();
                                    let mut fs_manager = blackwall_rtbh::FlowSpecManager::new(
                                        fs_controller,
                                        bgp,
                                        fs_journal,
                                    );
                                    // FlowSpec reuses the rtbh block's
                                    // `max-new-per-min` knob: the SAME shared
                                    // limiter as the RTBH manager above, so
                                    // ONE cap governs the combined
                                    // cross-plane announce rate (C6).
                                    if let Some(limiter) = &rate_limiter {
                                        fs_manager = fs_manager.with_rate_limiter(limiter.clone());
                                    }

                                    // Rehydrate FlowSpec rules from the announced mirror.
                                    let fs_mirror = store.list_active_flowspec().await?;
                                    let fs_rehydrate: Vec<(
                                        blackwall_bgp::FlowSpecRule,
                                        u64,
                                        blackwall_rtbh::BlackholeOrigin,
                                    )> = fs_mirror
                                        .into_iter()
                                        .map(|row| {
                                            let origin = match row.origin.as_str() {
                                                "manual" => blackwall_rtbh::BlackholeOrigin::Manual,
                                                _ => blackwall_rtbh::BlackholeOrigin::Auto,
                                            };
                                            let rule = blackwall_bgp::FlowSpecRule {
                                                dst: host_prefix(row.dst),
                                                protocol: Some(row.proto),
                                                dst_port: Some(row.dst_port),
                                                action: blackwall_bgp::FlowAction::TrafficRate(
                                                    row.rate,
                                                ),
                                            };
                                            (rule, row.announced_at_ms, origin)
                                        })
                                        .collect();
                                    fs_manager.rehydrate(fs_rehydrate, mono_now()).await;

                                    tokio::spawn(flowspec_manager_task(
                                        fs_manager,
                                        fs_rx,
                                        store.clone(),
                                        flowspec_plane_metrics.clone(),
                                        disarm_tx.subscribe(),
                                    ));
                                }
                            }

                            let selection = blackwall_flow::SelectionConfig {
                                concentration: fs.concentration,
                                max_flows: fs.max_flows,
                                rate: fs.rate,
                            };
                            let selector: std::sync::Arc<dyn blackwall_flow::MitigationSink> =
                                std::sync::Arc::new(blackwall_flow::SelectorSink::new(
                                    fs_tx, tx, selection,
                                ));
                            std::sync::Arc::new(blackwall_flow::FanoutSink(vec![pg_sink, selector]))
                        }
                    }
                }
            };

            // XDP fast path: when configured, attach the eBPF program and spawn
            // the single-owner manager, then fan the detection stream into it
            // (alongside the existing sink). NON-FATAL: a failed attach logs a
            // warning and continues with XDP disabled — the box still runs.
            let mut xdp_for_metrics: Option<Arc<blackwall_xdp::XdpDataplane>> = None;
            let mut xdp_shutdown: Option<(
                tokio::task::JoinHandle<()>,
                Arc<blackwall_xdp::XdpDataplane>,
            )> = None;
            // AF_XDP UDP responder (B3.2): the shared replies-sent counter (for
            // `/metrics`) and the dedicated blocking thread's stop flag + join
            // handle (for graceful teardown), populated when `afxdp-udp-ports`
            // is configured and the responder thread spawns.
            let mut afxdp_udp_metric: Option<Arc<std::sync::atomic::AtomicU64>> = None;
            let mut afxdp_responder: Option<(
                std::thread::JoinHandle<()>,
                Arc<std::sync::atomic::AtomicBool>,
            )> = None;
            let sink = if let Some(xdp_cfg) = policy.xdp.clone() {
                let iface = xdp_cfg
                    .interface
                    .clone()
                    .unwrap_or_else(|| policy.interface.clone());
                match blackwall_xdp::XdpDataplane::attach(&iface, xdp_cfg.mode) {
                    Err(err) => {
                        tracing::warn!(
                            %err,
                            interface = %iface,
                            "XDP: attach failed; continuing with XDP disabled"
                        );
                        sink
                    }
                    Ok(mut dataplane) => {
                        // XDP SYN-cookie fast path: only activated when
                        // `cookie-ports` is configured (empty leaves the fast
                        // path inert; the eBPF SYN handler falls through to
                        // `XDP_PASS`, per B2.3a/b's fail-closed design). Uses
                        // the SAME Postgres-shared secret as the userspace
                        // deception tier (`store.cookie_secret()`, B2.3c-1),
                        // so a cookie minted by either tier validates in the
                        // other, and the box's own managed prefixes as the
                        // protected space. NON-FATAL like the rest of this
                        // attach path: a failure logs a warning and leaves the
                        // fast path inert rather than aborting the daemon.
                        if !xdp_cfg.cookie_ports.is_empty() {
                            match store.cookie_secret().await {
                                Ok(secret) => {
                                    let activated = dataplane
                                        .set_cookie_key(secret)
                                        .and_then(|()| {
                                            dataplane.set_protected_prefixes(&policy.prefixes)
                                        })
                                        .and_then(|()| {
                                            dataplane.set_protected_ports(&xdp_cfg.cookie_ports)
                                        });
                                    match activated {
                                        Ok(()) => tracing::info!(
                                            ports = xdp_cfg.cookie_ports.len(),
                                            prefixes = policy.prefixes.len(),
                                            "XDP: SYN-cookie fast path activated"
                                        ),
                                        Err(err) => tracing::warn!(
                                            %err,
                                            "XDP: SYN-cookie map load failed; continuing \
                                             with fast path inert"
                                        ),
                                    }
                                }
                                Err(err) => tracing::warn!(
                                    %err,
                                    "XDP: failed to load SYN-cookie secret; continuing \
                                     with fast path inert"
                                ),
                            }
                        }

                        let dataplane = Arc::new(dataplane);
                        xdp_for_metrics = Some(dataplane.clone());

                        // AF_XDP UDP responder fast path (B3.2): only activated
                        // when `afxdp-udp-ports` is configured (empty leaves it
                        // disabled — nothing is redirected, per B3.1's
                        // fail-closed design). Runs on a dedicated blocking
                        // thread (AF_XDP recv/poll must not block the async
                        // runtime); binds the socket, registers it into `XSKS`,
                        // installs the redirect ports and answers redirected UDP
                        // at line rate. NON-FATAL like the rest of this attach
                        // path.
                        if !xdp_cfg.afxdp_udp_ports.is_empty() {
                            let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
                            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let dp = dataplane.clone();
                            let iface_t = iface.clone();
                            let ports_t = xdp_cfg.afxdp_udp_ports.clone();
                            let counter_t = counter.clone();
                            let stop_t = stop.clone();
                            // Operator-configured banner (`afxdp-udp-banner=`),
                            // falling back to the built-in placeholder. Owned so
                            // the responder thread can outlive `xdp_cfg`.
                            let banner_t: Vec<u8> = xdp_cfg
                                .afxdp_udp_banner
                                .clone()
                                .unwrap_or_else(|| AFXDP_UDP_BANNER.to_vec());
                            match std::thread::Builder::new()
                                .name("afxdp-udp-responder".to_owned())
                                .spawn(move || {
                                    afxdp_udp_responder_loop(
                                        &iface_t, &dp, &ports_t, &banner_t, &counter_t, &stop_t,
                                    );
                                }) {
                                Ok(handle) => {
                                    afxdp_udp_metric = Some(counter);
                                    afxdp_responder = Some((handle, stop));
                                    tracing::info!(
                                        ports = xdp_cfg.afxdp_udp_ports.len(),
                                        "XDP: AF_XDP UDP responder thread spawned"
                                    );
                                }
                                Err(err) => tracing::warn!(
                                    %err,
                                    "XDP: failed to spawn AF_XDP UDP responder thread; \
                                     responder disabled"
                                ),
                            }
                        }

                        // `None` default-rate-limit means "no auto mitigation":
                        // detections are drained but ignored; only operator CLI
                        // requests populate the maps.
                        let auto_enabled = xdp_cfg.default_rate_limit_pps.is_some();
                        let default_pps = xdp_cfg.default_rate_limit_pps.unwrap_or(1);
                        let controller = blackwall_xdp::XdpController::new(
                            policy.prefixes.clone(),
                            XDP_MAX_ENTRIES,
                            default_pps,
                            policy.protected_prefixes.clone(),
                        );
                        let (xdp_tx, xdp_rx) =
                            mpsc::channel::<blackwall_flow::DetectionEvent>(4096);

                        // Shadow mode swaps BOTH I/O seams of the manager, so
                        // the session touches neither the eBPF maps nor the
                        // `xdp_entries` mirror:
                        //   * executor  → `ShadowXdpExecutor` (records + meters,
                        //     never writes a map), and
                        //   * journal    → `NoOpXdpJournal` (persists nothing),
                        // and it SKIPS rehydrate — the shadow mirror is
                        // intentionally empty, so there is nothing to reapply
                        // (and reapplying would re-log stale rows as "would
                        // mitigate"). This mirrors the RTBH/FlowSpec shadow
                        // arms. When `!policy.shadow`, the live path
                        // (`XdpExec::Live` + `PgXdpJournal` + rehydrate) is
                        // exactly as before.
                        let handle = if policy.shadow {
                            let executor = shadow::XdpExec::Shadow(shadow::ShadowXdpExecutor::new(
                                store.clone(),
                                shadow_metrics.clone(),
                            ));
                            let manager = blackwall_xdp::manager::XdpManager::new(
                                controller,
                                executor,
                                blackwall_xdp::NoOpXdpJournal,
                            );
                            // No rehydrate: the shadow mirror is intentionally empty.
                            tokio::spawn(xdp_manager_task(
                                manager,
                                xdp_rx,
                                store.clone(),
                                auto_enabled,
                                xdp_plane_metrics.clone(),
                                disarm_tx.subscribe(),
                            ))
                        } else {
                            let executor = shadow::XdpExec::Live(dataplane.clone());
                            let journal = blackwall_state::PgXdpJournal::new(store.clone());
                            let mut manager = blackwall_xdp::manager::XdpManager::new(
                                controller, executor, journal,
                            );

                            // Rehydrate the controller + maps from the active
                            // mirror (blocks and rate limits, burst included)
                            // before this session accepts new detections/requests.
                            let rows: Vec<_> = store
                                .xdp_active()
                                .await?
                                .iter()
                                .filter_map(xdp_entry_to_action)
                                .collect();
                            manager.reapply_active(rows).await;

                            tokio::spawn(xdp_manager_task(
                                manager,
                                xdp_rx,
                                store.clone(),
                                auto_enabled,
                                xdp_plane_metrics.clone(),
                                disarm_tx.subscribe(),
                            ))
                        };
                        xdp_shutdown = Some((handle, dataplane));

                        tracing::info!(interface = %iface, auto = auto_enabled, "XDP data plane attached");
                        let xdp_sink: Arc<dyn blackwall_flow::MitigationSink> =
                            Arc::new(blackwall_xdp::XdpMitigationSink::new(xdp_tx));
                        Arc::new(blackwall_flow::FanoutSink(vec![sink, xdp_sink]))
                    }
                }
            } else {
                sink
            };

            // C5: every RTBH/FlowSpec/XDP manager task above has now
            // subscribed to `disarm_tx`, so it is safe to start listening
            // for the operator's SIGUSR1 disarm signal.
            tokio::spawn(disarm_signal_task(disarm_tx, blackwall_armed.clone()));

            // Optional Prometheus metrics endpoint.
            if let Some(metrics_listen) = policy.metrics_listen {
                let sources = metrics::MetricsSources {
                    store: store.clone(),
                    bgp: bgp_for_metrics,
                    collector: Some(collector_metrics.clone()),
                    inflight: None,
                    xdp: xdp_for_metrics.clone(),
                    stateless: None,
                    afxdp_udp_responses: afxdp_udp_metric.clone(),
                    agent_stats: Some(agent_snapshot.clone()),
                    shadow: Some(shadow_metrics.clone()),
                    protected_skipped: Some(protected_skipped_metrics.clone()),
                    ratecapped: Some(ratecapped_metrics.clone()),
                    rtbh_apply_failures: Some(rtbh_apply_failure_metrics.clone()),
                    flowspec_apply_failures: Some(flowspec_apply_failure_metrics.clone()),
                    xdp_apply_failures: Some(xdp_apply_failure_metrics.clone()),
                    rtbh_reapply_pending: Some(rtbh_reapply_pending_metrics.clone()),
                    flowspec_reapply_pending: Some(flowspec_reapply_pending_metrics.clone()),
                    xdp_reapply_pending: Some(xdp_reapply_pending_metrics.clone()),
                    armed: Some(blackwall_armed.clone()),
                };
                tokio::spawn(metrics::metrics_server(metrics_listen, sources));
            }

            tracing::info!(%listen, "sflow collector starting");
            let collector = blackwall_flow::run_collector(
                listen,
                Box::new(detector),
                sink,
                1000,
                Some(collector_metrics),
                Some(agent_snapshot),
            );
            let run_result = match xdp_shutdown {
                // With XDP attached, race the collector against a shutdown signal
                // so we can best-effort detach the data plane (drop the handle,
                // which releases the eBPF link) instead of leaving it attached.
                Some((handle, dataplane)) => {
                    tokio::select! {
                        r = collector => r,
                        () = wait_for_shutdown() => {
                            tracing::info!("shutdown signal received; detaching XDP data plane (best-effort)");
                            handle.abort();
                            drop(dataplane);
                            Ok(())
                        }
                    }
                }
                None => collector.await,
            };

            // Stop the AF_XDP UDP responder thread gracefully: set its flag and
            // join (it wakes from its bounded poll within ~200 ms). Best-effort
            // — the process is exiting either way.
            if let Some((handle, stop)) = afxdp_responder {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = handle.join();
            }
            run_result?;
            Ok(())
        }
        Command::Apply {
            config,
            database_url,
        } => {
            let policy = blackwall_config::parse_file(&config)?;
            ensure_interface_exists(&policy.interface)?;
            ensure_flowtable_devices_exist(&policy)?;
            let store = blackwall_state::Store::connect(&database_url).await?;
            store.migrate().await?;
            let n = store.apply_policy(&policy, "blackwalld").await?;
            tracing::info!(services = n, "policy persisted");
            blackwall_nft::apply(&policy)?;
            tracing::info!("deception ruleset + TPROXY policy route applied");
            tracing::warn!(
                "`apply` installs the ruleset only — run `blackwalld run` for the \
                 honeypot engine to answer the diverted deception traffic. \
                 Real-service DNAT is not yet implemented: declared real services \
                 are accepted to the host stack, not forwarded to a backend."
            );
            Ok(())
        }
        Command::Rtbh { action } => run_rtbh(action).await,
        Command::Flowspec { action } => run_flowspec(action).await,
        Command::Xdp { action } => run_xdp(action).await,
        Command::Sensor { action } => run_sensor(action),
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
            ensure_interface_exists(&policy.interface)?;
            ensure_flowtable_devices_exist(&policy)?;

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

            let (shared, _banner_watcher) = if let Some(flux_cfg) = &policy.banner_flux {
                // Flux mode: rotation drives banners; file watcher is not used.
                let pool = blackwall_deception::BannerPool::from_dir(&flux_cfg.dir)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let flux = blackwall_deception::BannerFlux::seeded(pool, flux_cfg.period, now);
                let shared = flux.shared();
                // Detached, non-fatal rotation task (NOT in the transports JoinSet).
                tokio::spawn(async move {
                    loop {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        flux.apply(now);
                        tokio::time::sleep(flux.next_delay(now)).await;
                    }
                });
                (shared, None)
            } else {
                // Static mode: load banners from file and watch for changes.
                let shared = SharedBanners::load(&banners)?;
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
                notify::Watcher::watch(
                    &mut watcher,
                    &banners,
                    notify::RecursiveMode::NonRecursive,
                )?;
                (shared, Some(watcher))
            };
            let registry = std::sync::Arc::new(default_registry(shared.clone()));

            // Stateless SYN-cookie tier wiring: the cookie secret is shared
            // (via Postgres) with the in-XDP fast path (`blackwalld flow`),
            // so a cookie minted by either tier validates in the other. A
            // banner lookup serves the same banner store the interactive
            // tier uses, keyed by destination port. Inert until the nft
            // classifier routes deception TCP here (C2c follow-on); built
            // eagerly so the responder is ready when it is.
            let secret = store.cookie_secret().await?;
            tracing::info!("SYN-cookie secret loaded from shared store");
            let cookie_key = CookieKey::new(secret);
            let banners_for_nfqueue = shared.clone();
            let banner_lookup: BannerLookup =
                Box::new(move |port: u16| banners_for_nfqueue.current().banner_for(port).to_vec());

            // Engine wiring (port/queue/limits) is a single source of truth in the
            // policy: the nft rules point at exactly these values.
            let tproxy_port = policy.engine.tproxy_port;
            let nfqueue_num = policy.engine.nfqueue_num;
            let engine_limits = EngineLimits {
                max_concurrent: policy.engine.max_concurrent,
                session_timeout: std::time::Duration::from_secs(policy.engine.session_timeout_secs),
            };

            // TPROXY listener binds on the configured engine port.
            let listener_v4 =
                TproxyListener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), tproxy_port))?;

            // Attempt to bind an IPv6 TPROXY listener for the ip6 tproxy nft rule.
            let listener_v6 = match TproxyListener::bind(SocketAddr::new(
                Ipv6Addr::UNSPECIFIED.into(),
                tproxy_port,
            )) {
                Ok(v6_listener) => Some(v6_listener),
                Err(err) => {
                    tracing::warn!(
                        %err,
                        port = tproxy_port,
                        "failed to bind IPv6 TPROXY listener (IPv6 may be disabled on \
                         this host); continuing with IPv4 only"
                    );
                    None
                }
            };

            let (tx, mut rx) = mpsc::channel(256);

            // Live in-flight deception-session gauge (shared with /metrics).
            let inflight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // Stateless SYN-cookie / UDP responder counters (shared with /metrics).
            let stateless_metrics = std::sync::Arc::new(StatelessMetrics::new());

            // Build the uniform list of transports (interactive TPROXY
            // listener(s) + the stateless NFQUEUE responder) and supervise
            // them all through `DeceptionTransport`, exactly as the two were
            // spawned individually before: same tasks, same `JoinSet`, same
            // teardown semantics.
            let has_v6 = listener_v6.is_some();
            let mut deception_transports: Vec<Box<dyn DeceptionTransport>> =
                vec![Box::new(TproxyTransport::new(
                    listener_v4,
                    registry.clone(),
                    tx.clone(),
                    engine_limits,
                    inflight.clone(),
                ))];
            if let Some(v6) = listener_v6 {
                deception_transports.push(Box::new(TproxyTransport::new(
                    v6,
                    registry.clone(),
                    tx.clone(),
                    engine_limits,
                    inflight.clone(),
                )));
            }
            deception_transports.push(Box::new(NfqueueTransport::new(
                nfqueue_num,
                cookie_key,
                banner_lookup,
                stateless_metrics.clone(),
            )));

            // Optional Prometheus metrics endpoint (deception gauges).
            if let Some(metrics_listen) = policy.metrics_listen {
                let sources = metrics::MetricsSources {
                    store: std::sync::Arc::new(store.clone()),
                    bgp: None,
                    collector: None,
                    inflight: Some(inflight.clone()),
                    xdp: None,
                    stateless: Some(stateless_metrics.clone()),
                    afxdp_udp_responses: None,
                    agent_stats: None,
                    shadow: None,
                    protected_skipped: None,
                    ratecapped: None,
                    rtbh_apply_failures: None,
                    flowspec_apply_failures: None,
                    xdp_apply_failures: None,
                    rtbh_reapply_pending: None,
                    flowspec_reapply_pending: None,
                    xdp_reapply_pending: None,
                    armed: None,
                };
                tokio::spawn(metrics::metrics_server(metrics_listen, sources));
            }

            // Optional read-only control API.
            if let Some(api_cfg) = policy.api.clone() {
                let store_for_api = std::sync::Arc::new(store.clone());
                tokio::spawn(api::serve_api(api_cfg, store_for_api));
            }

            let mut transports = tokio::task::JoinSet::new();
            for transport in deception_transports {
                tracing::debug!(name = transport.name(), "spawning deception transport");
                transports.spawn(async move { transport.run().await });
            }

            // Spawn the Incus discovery loop as a supervised task that reconnects
            // forever. Without this, an Incus restart ends the event stream and
            // discovery would go permanently stale. Spawns even when the initial
            // connect failed, so a late Incus start is also picked up.
            {
                let policy_for_task = policy.clone();
                let store_for_task = store.clone();
                let socket_for_task = incus_socket.clone();
                let mut current = incus_client;
                tokio::spawn(async move {
                    let mut backoff = std::time::Duration::from_secs(1);
                    let max_backoff = std::time::Duration::from_secs(30);
                    loop {
                        // Ensure we have a connected client, reconnecting with
                        // exponential backoff. On a fresh connection, do a
                        // catch-up reconcile so events missed while disconnected
                        // are not lost.
                        let mut client = match current.take() {
                            Some(c) => c,
                            None => loop {
                                sleep(backoff).await;
                                match blackwall_discovery::UnixIncusClient::connect(
                                    &socket_for_task,
                                ) {
                                    Ok(c) => {
                                        backoff = std::time::Duration::from_secs(1);
                                        tracing::info!(
                                            socket = %socket_for_task.display(),
                                            "reconnected to Incus; re-reconciling"
                                        );
                                        let discovered =
                                            build_discovered(discover_host, Some(&c)).await;
                                        if let Err(err) = apply_effective(
                                            &policy_for_task,
                                            &discovered,
                                            &store_for_task,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                %err,
                                                "catch-up reconcile after Incus reconnect failed"
                                            );
                                        }
                                        break c;
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            %err,
                                            ?backoff,
                                            "Incus reconnect failed; retrying"
                                        );
                                        backoff = (backoff * 2).min(max_backoff);
                                    }
                                }
                            },
                        };
                        drain_incus_events(
                            &mut client,
                            discover_host,
                            &policy_for_task,
                            &store_for_task,
                        )
                        .await;
                        // Stream ended/errored: drop the client and reconnect.
                    }
                });
            }

            // Apply CAKE shaping for each rule in policy.shaping.
            // Rules with both directions Fixed are applied once; any rule with an Auto direction
            // runs an initial speedtest and then spawns a detached re-tune loop.
            apply_shaping(&policy, librespeed_server, shape_interval_secs).await;

            // dns-flux: load key + pool (fatal on failure), then push each period.
            if let Some(dns_cfg) = policy.dns_flux.clone() {
                // Fatal at startup: bad key or a prefix too small for `count`.
                let key = blackwall_dns::read_tsig_key(&dns_cfg.tsig_path)?;
                let pool = blackwall_dns::flux_pool(&dns_cfg.prefix, dns_cfg.count)?;
                tokio::spawn(async move {
                    loop {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let ips = blackwall_dns::flux_window(
                            &pool,
                            dns_cfg.set,
                            now,
                            dns_cfg.period.as_secs(),
                        );
                        let plan = blackwall_dns::build_update(dns_cfg.ttl, &ips);
                        match blackwall_dns::send_update(
                            dns_cfg.server,
                            &dns_cfg.zone,
                            &dns_cfg.name,
                            &plan,
                            &key,
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::info!(name = %dns_cfg.name, count = ips.len(), "dns-flux updated")
                            }
                            Err(err) => {
                                tracing::warn!(%err, "dns-flux update failed; will retry next period")
                            }
                        }
                        tokio::time::sleep(blackwall_dns::next_boundary_delay(
                            now,
                            dns_cfg.period.as_secs(),
                        ))
                        .await;
                    }
                });
            }

            // Drop the controller's tx so the drain loop terminates when all serve clones are gone.
            drop(tx);

            if has_v6 {
                tracing::info!(
                    port = tproxy_port,
                    nfqueue = nfqueue_num,
                    "deception engine running (TPROXY 0.0.0.0 + [::] on port, NFQUEUE)"
                );
            } else {
                tracing::info!(
                    port = tproxy_port,
                    nfqueue = nfqueue_num,
                    "deception engine running (TPROXY 0.0.0.0 on port, NFQUEUE)"
                );
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

            let clean = tokio::select! {
                _ = drain => {
                    tracing::warn!("session channel closed; all transports exited");
                    false
                }
                joined = transports.join_next() => {
                    tracing::error!(?joined, "a transport task exited; shutting down");
                    false
                }
                () = wait_for_shutdown() => {
                    tracing::info!("shutdown signal received; stopping deception engine");
                    true
                }
            };
            // Remove the dataplane so the box stops diverting deception traffic to
            // the now-dead engine (leaving it would black-hole the address space).
            tracing::info!("removing deception ruleset + TPROXY policy route");
            blackwall_nft::teardown();
            // Force-exit: the `run_nfqueue` blocking task never returns, so a
            // normal return would hang the runtime's shutdown waiting on it.
            std::process::exit(if clean { 0 } else { 1 });
        }
    }
}

/// Dispatch one `rtbh` subcommand.
async fn run_rtbh(action: RtbhCmd) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RtbhCmd::Add {
            ip,
            config,
            operator,
        } => rtbh_add(ip, &config, operator).await,
        RtbhCmd::Remove { ip } => rtbh_remove(ip).await,
        RtbhCmd::List { requests } => rtbh_list(requests).await,
    }
}

/// `rtbh add`: reject `ip` up front (no database connection made yet) if it
/// falls outside the config's eligible prefixes or has no next-hop for its
/// address family; otherwise queue an `"add"` intent row.
async fn rtbh_add(
    ip: IpAddr,
    config: &std::path::Path,
    operator: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = blackwall_config::parse_file(config)?;
    let Some(rtbh) = policy.rtbh.clone() else {
        return Err("config has no `rtbh` block; RTBH is not enabled".into());
    };
    let controller = blackwall_rtbh::RtbhController::new(rtbh_config_from(&policy, &rtbh));
    if !controller.is_eligible(ip) {
        return Err(format!("{ip} is outside the configured RTBH-eligible prefixes").into());
    }
    if !controller.has_next_hop(ip) {
        return Err(format!("no RTBH next-hop is configured for {ip}'s address family").into());
    }

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an rtbh request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let created_by = operator.unwrap_or_else(default_operator);
    let id = store.enqueue_request(ip, "add", &created_by).await?;
    println!("queued (request {id}); the running daemon will announce it.");
    Ok(())
}

/// `rtbh remove`: queue a `"remove"` intent row.
async fn rtbh_remove(ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an rtbh request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let id = store
        .enqueue_request(ip, "remove", &default_operator())
        .await?;
    println!("queued (request {id}); the running daemon will withdraw it.");
    Ok(())
}

/// `rtbh list`: print the announced-blackhole mirror, and (with `--requests`)
/// the operator intent queue.
async fn rtbh_list(requests: bool) -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set to list rtbh state")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;

    let active = store.list_active_blackholes().await?;
    let now = wall_now();
    println!("{:<40} {:<8} AGE", "TARGET", "ORIGIN");
    for row in &active {
        let age_secs = now.saturating_sub(row.announced_at_ms) / 1000;
        println!("{:<40} {:<8} {age_secs}s", row.target, row.origin);
    }

    if requests {
        println!();
        println!(
            "{:<6} {:<40} {:<8} {:<10} NOTE",
            "ID", "TARGET", "ACTION", "STATUS"
        );
        for row in store.list_requests(None).await? {
            println!(
                "{:<6} {:<40} {:<8} {:<10} {}",
                row.id,
                row.target,
                row.action,
                row.status,
                row.note.as_deref().unwrap_or("")
            );
        }
    }
    Ok(())
}

/// Dispatch one `flowspec` subcommand.
async fn run_flowspec(action: FlowspecCmd) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        FlowspecCmd::Add {
            ip,
            proto,
            port,
            rate,
            config,
            operator,
        } => flowspec_add(ip, proto, port, rate, &config, operator).await,
        FlowspecCmd::Remove { ip, proto, port } => flowspec_remove(ip, proto, port).await,
        FlowspecCmd::List { requests } => flowspec_list(requests).await,
    }
}

/// `flowspec add`: reject the flow up front (no database connection made yet)
/// if `ip` falls outside the config's FlowSpec-eligible prefixes; otherwise
/// queue an `"add"` intent row. Unlike RTBH there is no next-hop check.
async fn flowspec_add(
    ip: IpAddr,
    proto: u8,
    port: u16,
    rate: f32,
    config: &std::path::Path,
    operator: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = blackwall_config::parse_file(config)?;
    let Some(fs) = policy.flowspec.clone() else {
        return Err("config has no `flowspec` block; FlowSpec is not enabled".into());
    };
    let controller = blackwall_rtbh::FlowSpecController::new(flowspec_config_from(&policy, &fs));
    if !controller.is_eligible(ip) {
        return Err(format!("{ip} is outside the configured FlowSpec-eligible prefixes").into());
    }

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue a flowspec request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let created_by = operator.unwrap_or_else(default_operator);
    let id = store
        .enqueue_flowspec_request(ip, proto, port, rate, "add", &created_by)
        .await?;
    println!("queued (request {id}); the running daemon will announce it.");
    Ok(())
}

/// `flowspec remove`: queue a `"remove"` intent row (rate `0.0`).
async fn flowspec_remove(
    ip: IpAddr,
    proto: u8,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue a flowspec request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let id = store
        .enqueue_flowspec_request(ip, proto, port, 0.0, "remove", &default_operator())
        .await?;
    println!("queued (request {id}); the running daemon will withdraw it.");
    Ok(())
}

/// `flowspec list`: print the announced-FlowSpec mirror, and (with
/// `--requests`) the operator intent queue.
async fn flowspec_list(requests: bool) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to list flowspec state")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;

    let active = store.list_active_flowspec().await?;
    let now = wall_now();
    println!(
        "{:<40} {:<6} {:<6} {:<12} {:<8} AGE",
        "DST", "PROTO", "PORT", "RATE", "ORIGIN"
    );
    for row in &active {
        let age_secs = now.saturating_sub(row.announced_at_ms) / 1000;
        println!(
            "{:<40} {:<6} {:<6} {:<12} {:<8} {age_secs}s",
            row.dst, row.proto, row.dst_port, row.rate, row.origin
        );
    }

    if requests {
        println!();
        println!(
            "{:<6} {:<40} {:<6} {:<6} {:<8} {:<10} NOTE",
            "ID", "DST", "PROTO", "PORT", "ACTION", "STATUS"
        );
        for row in store.list_flowspec_requests(None).await? {
            println!(
                "{:<6} {:<40} {:<6} {:<6} {:<8} {:<10} {}",
                row.id,
                row.dst,
                row.proto,
                row.dst_port,
                row.action,
                row.status,
                row.note.as_deref().unwrap_or("")
            );
        }
    }
    Ok(())
}

/// Dispatch one `xdp` subcommand.
async fn run_xdp(action: XdpCmd) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        XdpCmd::Block {
            target,
            config,
            operator,
        } => xdp_block(target, &config, operator).await,
        XdpCmd::Unblock { target } => xdp_unblock(target).await,
        XdpCmd::RateLimit {
            ip,
            pps,
            burst,
            config,
            operator,
        } => xdp_rate_limit(ip, pps, burst, &config, operator).await,
        XdpCmd::ClearRate { ip } => xdp_clear_rate(ip).await,
        XdpCmd::List => xdp_list().await,
        XdpCmd::Stats => xdp_stats().await,
        XdpCmd::Capture {
            count,
            duration,
            out,
            pin_dir,
        } => xdp_capture(count, duration, out, &pin_dir).await,
    }
}

/// Dispatch one `sensor` subcommand.
fn run_sensor(action: SensorCmd) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        SensorCmd::RenderHsflowd {
            config,
            collector,
            iface,
        } => sensor_render_hsflowd(&config, collector, &iface),
    }
}

/// `sensor render-hsflowd`: parse `config` and print an `hsflowd.conf` block
/// for each `pop` entry, addressed at `collector` and sampling `iface`.
///
/// This is CLI glue over [`blackwall_core::render_hsflowd_conf`] (which is
/// unit-tested); it is coverage-excluded like the rest of the CLI dispatch
/// layer.
fn sensor_render_hsflowd(
    config: &std::path::Path,
    collector: SocketAddr,
    iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = blackwall_config::parse_file(config)?;
    let collector_ip = collector.ip().to_string();
    let collector_port = collector.port();
    for pop in &policy.pops {
        println!("# --- POP {} (agent {}) ---", pop.name, pop.agent);
        println!(
            "{}",
            blackwall_core::render_hsflowd_conf(iface, &collector_ip, collector_port, pop.sampling)
        );
    }
    Ok(())
}

/// Require an `xdp` block in `config`, returning the parsed policy so a CLI
/// pre-check can consult `policy.prefixes` before touching the database.
fn require_xdp(
    config: &std::path::Path,
) -> Result<blackwall_core::Policy, Box<dyn std::error::Error>> {
    let policy = blackwall_config::parse_file(config)?;
    if policy.xdp.is_none() {
        return Err("config has no `xdp` block; XDP is not enabled".into());
    }
    Ok(policy)
}

/// `xdp block`: queue a `"block"` intent row for the network `target`. Warns
/// (but still queues) if `target` overlaps an own prefix — the daemon rejects
/// such a self-DoS when it drains the request.
async fn xdp_block(
    target: ipnet::IpNet,
    config: &std::path::Path,
    operator: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = require_xdp(config)?;
    if policy
        .prefixes
        .iter()
        .any(|p| p.contains(&target) || target.contains(p))
    {
        tracing::warn!(
            %target,
            "xdp block: target overlaps an own prefix — this is a self-inflicted \
             denial of service; the daemon will reject it"
        );
    }

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an xdp request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let created_by = operator.unwrap_or_else(default_operator);
    let id = store
        .xdp_enqueue_request(
            "block",
            target.addr(),
            Some(target.prefix_len()),
            None,
            None,
            &created_by,
        )
        .await?;
    println!("queued (request {id}); the running daemon will program the map.");
    Ok(())
}

/// `xdp unblock`: queue an `"unblock"` intent row for the network `target`.
async fn xdp_unblock(target: ipnet::IpNet) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an xdp request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let id = store
        .xdp_enqueue_request(
            "unblock",
            target.addr(),
            Some(target.prefix_len()),
            None,
            None,
            &default_operator(),
        )
        .await?;
    println!("queued (request {id}); the running daemon will remove the map entry.");
    Ok(())
}

/// `xdp rate-limit`: queue a `"rate_limit"` intent row for source `ip`. `burst`
/// defaults to `pps` when omitted.
async fn xdp_rate_limit(
    ip: IpAddr,
    pps: u64,
    burst: Option<u64>,
    config: &std::path::Path,
    operator: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_xdp(config)?;
    if pps == 0 {
        return Err("rate-limit pps must be >= 1".into());
    }

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an xdp request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let created_by = operator.unwrap_or_else(default_operator);
    let id = store
        .xdp_enqueue_request(
            "rate_limit",
            ip,
            None,
            Some(pps),
            Some(burst.unwrap_or(pps)),
            &created_by,
        )
        .await?;
    println!("queued (request {id}); the running daemon will program the map.");
    Ok(())
}

/// `xdp clear-rate`: queue a `"clear_rate"` intent row for source `ip`.
async fn xdp_clear_rate(ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to queue an xdp request")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;
    let id = store
        .xdp_enqueue_request("clear_rate", ip, None, None, None, &default_operator())
        .await?;
    println!("queued (request {id}); the running daemon will remove the map entry.");
    Ok(())
}

/// `xdp list`: print the active `xdp_entries` map mirror.
async fn xdp_list() -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set to list xdp state")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;

    println!(
        "{:<12} {:<40} {:<10} {:<10} {:<8}",
        "KIND", "TARGET", "PPS", "BURST", "ORIGIN"
    );
    for row in store.xdp_active().await? {
        let target = match row.prefixlen {
            Some(len) => format!("{}/{len}", row.target),
            None => row.target.to_string(),
        };
        let pps = row
            .rate_pps
            .map_or_else(|| "-".to_owned(), |v| v.to_string());
        let burst = row.burst.map_or_else(|| "-".to_owned(), |v| v.to_string());
        println!(
            "{:<12} {target:<40} {pps:<10} {burst:<10} {:<8}",
            row.kind, row.origin
        );
    }
    Ok(())
}

/// `xdp stats`: print active-entry counts from the DB mirror. Live per-CPU
/// packet counters live in the running daemon's `/metrics` endpoint.
async fn xdp_stats() -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set to read xdp stats")?;
    let store = blackwall_state::Store::connect(&database_url).await?;
    store.migrate().await?;

    let active = store.xdp_active().await?;
    let blocks = active.iter().filter(|r| r.kind == "block").count();
    let rate_limits = active.iter().filter(|r| r.kind == "rate_limit").count();
    println!("blocked_entries    {blocks}");
    println!("ratelimit_entries  {rate_limits}");
    println!(
        "(live per-CPU packet counters — dropped/passed — are exported by the \
         running daemon's /metrics endpoint)"
    );
    Ok(())
}

/// `xdp capture`: open the running daemon's pinned capture ring, drain up to
/// `count` records (or for `duration` seconds, default 10 s), and write them as
/// pcap to `out` (or stdout). Capture is switched on when the ring is opened and
/// off again when the [`blackwall_xdp::XdpCapture`] handle drops on return.
///
/// The ring is drained in a poll loop (the ring read is non-blocking); records
/// that parse are collected until the count or duration limit is reached, then
/// serialised with the pure [`blackwall_xdp::to_pcap`] encoder.
async fn xdp_capture(
    count: Option<usize>,
    duration: Option<u64>,
    out: Option<PathBuf>,
    pin_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    // Default to a 10 s capture window when neither bound is given.
    let deadline = match (count, duration) {
        (Some(_), _) => None,
        (None, Some(secs)) => Some(Instant::now() + Duration::from_secs(secs)),
        (None, None) => Some(Instant::now() + Duration::from_secs(10)),
    };

    let mut capture = blackwall_xdp::XdpCapture::open(pin_dir).map_err(|e| {
        format!(
            "opening capture ring under {}: {e} (is a `blackwalld flow` daemon with XDP running?)",
            pin_dir.display()
        )
    })?;

    let mut packets: Vec<blackwall_xdp::CapturedPacket> = Vec::new();
    loop {
        capture.drain(&mut packets);
        if let Some(n) = count {
            if packets.len() >= n {
                packets.truncate(n);
                break;
            }
        }
        if let Some(when) = deadline {
            if Instant::now() >= when {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let pcap = blackwall_xdp::to_pcap(&packets);
    match out {
        Some(path) => {
            std::fs::write(&path, &pcap)?;
            eprintln!("captured {} packets -> {}", packets.len(), path.display());
        }
        None => {
            std::io::stdout().write_all(&pcap)?;
            std::io::stdout().flush()?;
            eprintln!("captured {} packets (pcap on stdout)", packets.len());
        }
    }
    Ok(())
}
