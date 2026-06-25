//! Blackwall's deception engine: terminates deception traffic and answers it
//! with realistic, interactive protocol emulators.

mod conn;
mod emulator;
mod error;

pub mod emulators;
pub mod transport;

pub use conn::{AsyncStream, DeceptionConn, DeceptionMeta};
pub use emulator::{EmulatorOutcome, EmulatorRegistry, ServiceEmulator};
pub use error::DeceptionError;
