//! The BGP peerings panel: each session's peer, decoded FSM state, and
//! reconnect count.

use crate::app::AppState;
use crate::theme::Theme;
use blackwall_client::views::BgpState;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

/// The display label for a decoded [`BgpState`].
fn state_label(s: BgpState) -> &'static str {
    match s {
        BgpState::Idle => "Idle",
        BgpState::Connect => "Connect",
        BgpState::Active => "Active",
        BgpState::OpenSent => "OpenSent",
        BgpState::OpenConfirm => "OpenConfirm",
        BgpState::Established => "Established",
        BgpState::Unknown => "Unknown",
    }
}

/// Render the peerings table. Rows dim and a `stale Ns`/`OFFLINE` badge
/// appears in the title once `app.metrics_stale()`.
pub fn render(f: &mut Frame<'_>, area: Rect, app: &AppState, theme: &Theme) {
    let stale = app.metrics_stale();
    let row_style = if stale {
        Style::default().fg(theme.dim_ember)
    } else {
        Style::default().fg(theme.fg)
    };
    let established_style = if stale {
        row_style
    } else {
        Style::default().fg(theme.hot)
    };

    let rows: Vec<Row<'_>> = app
        .peers
        .iter()
        .map(|p| {
            let style = if p.state == BgpState::Established {
                established_style
            } else {
                row_style
            };
            Row::new(vec![
                Cell::from(p.peer.clone()),
                Cell::from(state_label(p.state)),
                Cell::from(p.reconnects.to_string()),
            ])
            .style(style)
        })
        .collect();

    let mut title = "Peerings".to_string();
    if stale {
        let age = app.metrics_age.as_secs();
        if age > 60 {
            title.push_str(" [OFFLINE]");
        } else {
            title.push_str(&format!(" [stale {age}s]"));
        }
    }

    let title_style = if stale {
        Style::default().fg(theme.hot).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.red)
    };

    let block = Block::default()
        .title(Span::styled(title, title_style))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.red));

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(30),
        Constraint::Percentage(30),
    ];
    let header = Row::new(vec![
        Cell::from("Peer"),
        Cell::from("State"),
        Cell::from("Reconnects"),
    ])
    .style(Style::default().fg(theme.red).add_modifier(Modifier::BOLD));

    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![Cell::from(Line::from(Span::styled(
                "no BGP session reporting",
                row_style,
            )))])],
            [Constraint::Percentage(100)],
        )
        .block(block)
    } else {
        Table::new(rows, widths).header(header).block(block)
    };
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_client::views::BgpPeer;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::time::Duration;

    fn rendered_text(app: &AppState) -> String {
        let backend = TestBackend::new(60, 12);
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
    fn peerings_panel_shows_state_and_stale_badge() {
        let app = AppState {
            peers: vec![BgpPeer {
                peer: "10.0.0.1".into(),
                state: BgpState::Established,
                reconnects: 0,
            }],
            metrics_age: Duration::from_secs(12),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("10.0.0.1"));
        assert!(text.contains("Established"));
        assert!(text.contains("stale") || text.contains("12s"));
    }

    #[test]
    fn shows_placeholder_when_no_peers() {
        let app = AppState::default();
        let text = rendered_text(&app);
        assert!(text.contains("no BGP session reporting"));
    }

    #[test]
    fn fresh_peers_render_without_stale_badge() {
        let app = AppState {
            peers: vec![BgpPeer {
                peer: "upstream".into(),
                state: BgpState::Established,
                reconnects: 2,
            }],
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("upstream"));
        assert!(text.contains('2'));
        assert!(!text.contains("stale"));
        assert!(!text.contains("OFFLINE"));
    }
}
