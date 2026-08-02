//! Active RTBH blackholes (`GET /v1/mitigations/rtbh`), rendered straight
//! from the shared `blackwall_api::dto::RtbhDto`.

use crate::app::AppState;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

/// Render the RTBH panel: one row per active blackhole. Rows dim and the
/// title carries a `stale Ns`/`OFFLINE` badge once `app.api_stale()`.
pub fn render(f: &mut Frame<'_>, area: Rect, app: &AppState, theme: &Theme) {
    let stale = app.api_stale();
    let row_style = if stale {
        Style::default().fg(theme.dim_ember)
    } else {
        Style::default().fg(theme.fg)
    };

    let rows: Vec<Row<'_>> = app
        .rtbh
        .iter()
        .map(|r| {
            let withdrawn = match r.withdrawn_at_ms {
                Some(_) => "withdrawn",
                None => "active",
            };
            Row::new(vec![
                Cell::from(r.target.to_string()),
                Cell::from(r.origin.clone()),
                Cell::from(withdrawn),
            ])
            .style(row_style)
        })
        .collect();

    let mut title = "RTBH".to_string();
    if stale {
        let age = app.api_age.as_secs();
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
        Cell::from("Target"),
        Cell::from("Origin"),
        Cell::from("Status"),
    ])
    .style(Style::default().fg(theme.red).add_modifier(Modifier::BOLD));

    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![Cell::from("no active RTBH blackholes")])],
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
    use blackwall_api::dto::RtbhDto;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::{IpAddr, Ipv4Addr};
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
    fn shows_active_blackhole_row() {
        let app = AppState {
            rtbh: vec![RtbhDto {
                target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                origin: "api:admin".into(),
                announced_at_ms: 1_000,
                withdrawn_at_ms: None,
            }],
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("203.0.113.5"));
        assert!(text.contains("api:admin"));
        assert!(text.contains("active"));
    }

    #[test]
    fn shows_placeholder_when_empty() {
        let app = AppState::default();
        let text = rendered_text(&app);
        assert!(text.contains("no active RTBH blackholes"));
    }

    #[test]
    fn shows_stale_badge_when_api_is_old() {
        let app = AppState {
            api_age: Duration::from_secs(20),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("stale") || text.contains("20s"));
    }
}
