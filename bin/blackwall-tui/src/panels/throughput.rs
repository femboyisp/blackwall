//! Live bps/pps derived from the sampled-traffic counters (Task 1).

use crate::app::AppState;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Human-scaled `bits/s` (`b`, `kb`, `Mb`, `Gb`).
fn fmt_bps(bps: f64) -> String {
    const UNITS: [&str; 4] = ["b", "kb", "Mb", "Gb"];
    let mut v = bps;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.1} {}/s", UNITS[unit])
}

/// Render the throughput panel: bps/pps, dimmed with a `stale`/`OFFLINE`
/// badge once `app.metrics_stale()`.
pub fn render(f: &mut Frame<'_>, area: Rect, app: &AppState, theme: &Theme) {
    let border_style = Style::default().fg(theme.red);
    let block = Block::default()
        .title("Throughput")
        .borders(Borders::ALL)
        .border_style(border_style);

    let text_style = if app.metrics_stale() {
        Style::default().fg(theme.dim_ember)
    } else {
        Style::default().fg(theme.fg)
    };

    let mut lines = match app.throughput {
        Some(t) => vec![
            Line::from(Span::styled(format!("bps: {}", fmt_bps(t.bps)), text_style)),
            Line::from(Span::styled(format!("pps: {:.1}/s", t.pps), text_style)),
        ],
        None => vec![Line::from(Span::styled(
            "awaiting first sample...",
            text_style,
        ))],
    };

    if app.metrics_stale() {
        let age = app.metrics_age.as_secs();
        let badge = if age > 60 {
            "OFFLINE".to_string()
        } else {
            format!("stale {age}s")
        };
        lines.push(Line::from(Span::styled(
            badge,
            Style::default().fg(theme.hot).add_modifier(Modifier::BOLD),
        )));
    }

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_client::views::Throughput;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::time::Duration;

    fn rendered_text(app: &AppState) -> String {
        let backend = TestBackend::new(40, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), app, &Theme::blackwall()))
            .unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn shows_bps_and_pps_when_fresh() {
        let app = AppState {
            throughput: Some(Throughput {
                bps: 4000.0,
                pps: 5.0,
            }),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("4.0 kb/s"));
        assert!(text.contains("5.0/s"));
        assert!(!text.contains("stale"));
    }

    #[test]
    fn shows_stale_badge_when_metrics_are_old() {
        let app = AppState {
            throughput: Some(Throughput { bps: 0.0, pps: 0.0 }),
            metrics_age: Duration::from_secs(15),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("stale") || text.contains("15s"));
    }

    #[test]
    fn shows_offline_when_very_stale() {
        let app = AppState {
            metrics_age: Duration::from_secs(90),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("OFFLINE"));
    }

    #[test]
    fn shows_placeholder_before_first_sample() {
        let app = AppState::default();
        let text = rendered_text(&app);
        assert!(text.contains("awaiting first sample"));
    }
}
