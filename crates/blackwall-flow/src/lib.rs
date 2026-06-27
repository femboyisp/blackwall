//! Flow-based DDoS detection for Blackwall: decode sampled flow exports and
//! flag volumetric attacks against the operator's prefixes.

mod detector;
mod error;
mod observation;
mod sflow;

pub use detector::{AttackKind, Detection, DetectionEvent, Detector, Severity, ThresholdDetector};
pub use error::FlowError;
pub use observation::FlowObservation;
pub use sflow::decode_datagram;
