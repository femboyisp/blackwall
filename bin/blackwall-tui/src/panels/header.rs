//! The top banner: the daemon's mitigation state, `ARMED` or `SHADOW`.

use crate::app::AppState;
use crate::theme::Theme;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// Render the header: `BLACKWALL` in the primary red, plus a hot-highlighted
/// `ARMED` or dim-ember `SHADOW` badge reflecting `app.armed`.
pub fn render(f: &mut Frame<'_>, area: Rect, app: &AppState, theme: &Theme) {
    let (badge_text, badge_style) = if app.armed {
        (
            "ARMED",
            Style::default().fg(theme.hot).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            "SHADOW",
            Style::default()
                .fg(theme.dim_ember)
                .add_modifier(Modifier::BOLD),
        )
    };

    let line = Line::from(vec![
        Span::styled(
            "BLACKWALL ",
            Style::default().fg(theme.red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(badge_text, badge_style),
    ]);

    let p = Paragraph::new(line)
        .alignment(Alignment::Left)
        .style(Style::default().bg(theme.bg));
    f.render_widget(p, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn rendered_text(app: &AppState) -> String {
        let backend = TestBackend::new(40, 3);
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
    fn shows_armed_when_armed() {
        let app = AppState {
            armed: true,
            ..Default::default()
        };
        let text = rendered_text(&app);
        assert!(text.contains("BLACKWALL"));
        assert!(text.contains("ARMED"));
        assert!(!text.contains("SHADOW"));
    }

    #[test]
    fn shows_shadow_when_not_armed() {
        let app = AppState::default();
        let text = rendered_text(&app);
        assert!(text.contains("SHADOW"));
    }
}
