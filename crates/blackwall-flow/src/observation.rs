//! A single sampled packet observation, decoded from a flow export.

use std::net::IpAddr;

/// One sampled packet, carrying the sampling rate it represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowObservation {
    /// Source IP of the sampled packet.
    pub src: IpAddr,
    /// Destination IP of the sampled packet.
    pub dst: IpAddr,
    /// IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP, …).
    pub proto: u8,
    /// Source transport port (0 if not applicable).
    pub src_port: u16,
    /// Destination transport port (0 if not applicable).
    pub dst_port: u16,
    /// Original on-wire frame length of the sampled packet.
    pub frame_len: u32,
    /// Sampling rate: this sample represents ~`sampling_rate` real packets.
    pub sampling_rate: u32,
    /// TCP flag bits (0 if not TCP).
    pub tcp_flags: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn observation_is_copy_and_eq() {
        let o = FlowObservation {
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            proto: 17,
            src_port: 1234,
            dst_port: 53,
            frame_len: 1500,
            sampling_rate: 1024,
            tcp_flags: 0,
        };
        let copy = o; // Copy
        assert_eq!(o, copy);
    }
}
