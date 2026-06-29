//! Blackwall lab harness: declare a netns topology, run scenario assertions,
//! and emit machine-checkable pass/fail.
//!
//! The crate is split pure-core / thin-IO: every module except [`exec`],
//! [`cli`], and the `lab` binary is pure and unit-tested; `exec`/`cli` shell
//! out to the kernel and are coverage-excluded.

pub mod addr;
pub mod error;
pub mod render;
pub mod topology;

pub use error::LabError;
