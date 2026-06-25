//! Service discovery for Blackwall: find what the host and Incus instances
//! expose, and reconcile it into the effective firewall policy.

mod error;
mod host;
mod incus_model;
mod proc_io;
mod reconcile;

pub use error::DiscoveryError;
pub use host::{parse_proc_net, ListeningSocket};
pub use incus_model::{instance_services, parse_instance, parse_ports, Instance};
pub use proc_io::scan_host_sockets;
pub use reconcile::{reconcile, DiscoveredService, DiscoverySource};
