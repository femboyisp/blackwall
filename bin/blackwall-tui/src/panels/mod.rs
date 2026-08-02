//! One module per dashboard panel. Each exposes a single `render(f, area,
//! app, theme)` function: pure rendering from [`crate::app::AppState`], no
//! I/O, fully exercisable with `ratatui::backend::TestBackend`.

pub mod header;
pub mod peerings;
pub mod rtbh;
pub mod sessions;
pub mod throughput;
