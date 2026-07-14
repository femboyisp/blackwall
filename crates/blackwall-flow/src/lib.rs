//! Flow-based DDoS detection for Blackwall: decode sampled flow exports and
//! flag volumetric attacks against the operator's prefixes.

mod agents;
mod collector_net;
mod detector;
mod error;
mod metrics;
mod observation;
mod select;
mod sflow;
mod sink;

pub use agents::AgentRegistry;
pub use collector_net::{monotonic_now_ms, run_collector};
pub use detector::{
    AgentStat, AttackKind, Detection, DetectionEvent, Detector, DetectorConfig, Severity,
    ThresholdDetector,
};
pub use error::FlowError;
pub use metrics::CollectorMetrics;
pub use observation::FlowObservation;
pub use select::{select, FlowRule, Mitigation, SelectionConfig};
pub use sflow::decode_datagram;
pub use sink::{
    ChannelSink, FanoutSink, FlowMitigationEvent, LogSink, MitigationSink, SelectorSink,
};
