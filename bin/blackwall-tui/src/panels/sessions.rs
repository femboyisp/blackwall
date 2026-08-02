//! Recent deception sessions (`GET /v1/sessions`), rendered straight from
//! the shared `blackwall_api::dto::SessionDto`.

use crate::app::AppState;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

/// Render the deception-sessions panel. Rows dim and the title carries a
/// `stale Ns`/`OFFLINE` badge once `app.api_stale()`.
pub fn render(f: &mut Frame<'_>, area: Rect, app: &AppState, theme: &Theme) {
    let stale = app.api_stale();
    let row_style = if stale {
        Style::default().fg(theme.dim_ember)
    } else {
        Style::default().fg(theme.fg)
    };

    let rows: Vec<Row<'_>> = app
        .sessions
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(s.peer_addr.to_string()),
                Cell::from(s.proto.clone()),
                Cell::from(s.emulator.clone()),
                Cell::from(format!("{}/{}", s.bytes_in, s.bytes_out)),
            ])
            .style(row_style)
        })
        .collect();

    let mut title = "Deception Sessions".to_string();
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
        Constraint::Percentage(30),
        Constraint::Percentage(15),
        Constraint::Percentage(25),
        Constraint::Percentage(30),
    ];
    let header = Row::new(vec![
        Cell::from("Peer"),
        Cell::from("Proto"),
        Cell::from("Emulator"),
        Cell::from("Bytes in/out"),
    ])
    .style(Style::default().fg(theme.red).add_modifier(Modifier::BOLD));

    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![Cell::from("no deception sessions recorded")])],
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
    use blackwall_api::dto::SessionDto;
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

    fn sample_session() -> SessionDto {
        SessionDto {
            local_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            local_port: 22,
            peer_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            proto: "tcp".into(),
            emulator: "ssh".into(),
            bytes_in: 128,
            bytes_out: 64,
            note: None,
        }
    }

    #[test]
    fn shows_session_row() {
        let app = AppState {
            sessions: vec![sample_session()],
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("203.0.113.9"));
        assert!(text.contains("ssh"));
        assert!(text.contains("128/64"));
    }

    #[test]
    fn shows_placeholder_when_empty() {
        let app = AppState::default();
        let text = rendered_text(&app);
        assert!(text.contains("no deception sessions recorded"));
    }

    #[test]
    fn shows_stale_badge_when_api_is_old() {
        let app = AppState {
            api_age: Duration::from_secs(30),
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("stale") || text.contains("30s"));
    }
}
