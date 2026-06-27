//! Flow-based DDoS detection for Blackwall: decode sampled flow exports and
//! flag volumetric attacks against the operator's prefixes.

mod collector_net;
mod detector;
mod error;
mod observation;
mod sflow;
mod sink;

pub use collector_net::run_collector;
pub use detector::{AttackKind, Detection, DetectionEvent, Detector, Severity, ThresholdDetector};
pub use error::FlowError;
pub use observation::FlowObservation;
pub use sflow::decode_datagram;
pub use sink::{LogSink, MitigationSink};
