//! The Blackwall TUI's single source of color truth. Every panel renders
//! using a [`Theme`] value — no panel module defines its own `Color`
//! literal, so the whole dashboard stays visually consistent and a palette
//! change is a one-file edit.

use ratatui::style::Color;

/// The constrained truecolor palette: background, the two accent reds, and
/// a hot highlight. See the Global Constraints in the implementation plan
/// for the exact hex values this mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Panel/background fill: `#0a0000`.
    pub bg: Color,
    /// The primary "blackwall red" accent — panel borders, titles: `#ff1e2d`.
    pub red: Color,
    /// Dim ember — secondary text, inactive/dim state: `#8b0f16`.
    pub dim_ember: Color,
    /// Hot highlight — alerts, stale badges, emphasis: `#ff6b6b`.
    pub hot: Color,
    /// Normal readable text. Not part of the plan's named palette, but
    /// still centralized here rather than hardcoded per-panel.
    pub fg: Color,
}

impl Theme {
    /// The one Blackwall TUI palette.
    #[must_use]
    pub const fn blackwall() -> Self {
        Self {
            bg: Color::Rgb(0x0a, 0x00, 0x00),
            red: Color::Rgb(0xff, 0x1e, 0x2d),
            dim_ember: Color::Rgb(0x8b, 0x0f, 0x16),
            hot: Color::Rgb(0xff, 0x6b, 0x6b),
            fg: Color::Rgb(0xe0, 0xe0, 0xe0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackwall_palette_matches_the_spec_hex_values() {
        let t = Theme::blackwall();
        assert_eq!(t.bg, Color::Rgb(0x0a, 0x00, 0x00));
        assert_eq!(t.red, Color::Rgb(0xff, 0x1e, 0x2d));
        assert_eq!(t.dim_ember, Color::Rgb(0x8b, 0x0f, 0x16));
        assert_eq!(t.hot, Color::Rgb(0xff, 0x6b, 0x6b));
    }
}
