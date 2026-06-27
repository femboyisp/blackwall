//! Flow-based DDoS detection for Blackwall: decode sampled flow exports and
//! flag volumetric attacks against the operator's prefixes.

mod error;
mod observation;
mod sflow;

pub use error::FlowError;
pub use observation::FlowObservation;
pub use sflow::decode_datagram;
