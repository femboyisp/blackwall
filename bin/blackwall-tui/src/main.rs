//! Blackwall TUI (Phase 1): a read-only, Blackwall-themed terminal dashboard
//! over the read control API and the Prometheus `:9100` endpoint. No
//! write/mutating call lives anywhere in this binary — see
//! `blackwall_client::{ApiClient, MetricsClient}`, both `GET`-only.
//!
//! This file is the only I/O in the crate (terminal setup + the tokio
//! refresh loop) and is excluded from the coverage gate
//! (`scripts/coverage.sh`), matching the repo's `*_net.rs`/`api.rs`
//! convention: it needs a live terminal and a live daemon to exercise. Every
//! piece of actual logic — layout, rendering, staleness, rate math — lives
//! in tested modules (`app.rs`, `panels/*.rs`, and `blackwall_client`).

mod app;
mod panels;
mod theme;

use app::AppState;
use blackwall_client::{ApiClient, MetricsClient};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Terminal;
use std::io;
use std::time::{Duration, Instant};
use theme::Theme;

/// Blackwall TUI (Phase 1) — read-only dashboard.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Base URL of the read control API (e.g. `http://127.0.0.1:8080`).
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    api_url: String,
    /// Full URL of the Prometheus metrics endpoint.
    #[arg(long, default_value = "http://127.0.0.1:9100/metrics")]
    metrics_url: String,
    /// Bearer token for the control API, if it requires auth.
    #[arg(long, env = "BLACKWALL_API_TOKEN")]
    token: Option<String>,
    /// Metrics scrape interval, in milliseconds.
    #[arg(long, default_value_t = 1500)]
    metrics_interval_ms: u64,
    /// Control-API entity refresh interval, in milliseconds.
    #[arg(long, default_value_t = 5000)]
    api_interval_ms: u64,
}

fn draw(f: &mut ratatui::Frame<'_>, app: &AppState, theme: &Theme) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    panels::header::render(f, root[0], app, theme);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root[1]);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    panels::throughput::render(f, top[0], app, theme);
    panels::peerings::render(f, top[1], app, theme);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    panels::rtbh::render(f, bottom[0], app, theme);
    panels::sessions::render(f, bottom[1], app, theme);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let api_base = reqwest::Url::parse(&args.api_url)?;
    let metrics_url = reqwest::Url::parse(&args.metrics_url)?;
    let api = ApiClient::new(api_base, args.token.clone());
    let metrics = MetricsClient::new(metrics_url);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal, &api, &metrics, &args).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    api: &ApiClient,
    metrics: &MetricsClient,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let theme = Theme::blackwall();
    let mut app = AppState::default();

    let metrics_interval = Duration::from_millis(args.metrics_interval_ms);
    let api_interval = Duration::from_millis(args.api_interval_ms);
    let mut metrics_ticker = tokio::time::interval(metrics_interval);
    let mut api_ticker = tokio::time::interval(api_interval);
    let start = Instant::now();

    // Prime the API-derived panels once immediately, so they aren't empty
    // for a full `api_interval` after start.
    refresh_api(&mut app, api, start).await;

    loop {
        terminal.draw(|f| draw(f, &app, &theme))?;

        tokio::select! {
            _ = metrics_ticker.tick() => {
                match metrics.fetch().await {
                    Ok(snapshot) => app.apply_metrics(snapshot, start.elapsed().as_secs_f64()),
                    Err(err) => {
                        tracing_stub_log(&format!("metrics fetch failed: {err}"));
                    }
                }
            }
            _ = api_ticker.tick() => {
                refresh_api(&mut app, api, start).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                app.tick_ages(start.elapsed());
                if poll_quit()? {
                    return Ok(());
                }
            }
        }
    }
}

/// Refresh the API-derived panels (RTBH, deception sessions); a failure on
/// either leaves the last-known-good entities on screen and simply skips
/// the `api_age` reset — `tick_ages` then lets the stale badge count up
/// rather than the panel going blank on one bad scrape.
async fn refresh_api(app: &mut AppState, api: &ApiClient, start: Instant) {
    let rtbh = api.rtbh().await;
    let sessions = api.sessions().await;
    if let (Ok(rtbh), Ok(sessions)) = (rtbh, sessions) {
        app.apply_api(rtbh, sessions, start.elapsed().as_secs_f64());
    }
}

/// A non-blocking check for `q`/`Esc`/`Ctrl-C`.
fn poll_quit() -> io::Result<bool> {
    if event::poll(Duration::from_millis(0))? {
        if let Event::Key(key) = event::read()? {
            let is_ctrl_c =
                key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
            if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc || is_ctrl_c {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Placeholder for a real logger; kept out of `tracing` setup for Phase 1's
/// scope (a scrape failure only degrades the affected panel's staleness
/// badge, it doesn't need a log pipeline yet).
fn tracing_stub_log(_msg: &str) {}
