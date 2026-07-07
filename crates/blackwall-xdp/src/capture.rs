//! Live capture-ring reader for the XDP data plane (sub-project B4.1).
//!
//! [`XdpCapture`] opens the `CAPTURE` ring buffer and `CAPTURE_ENABLED` flag —
//! which the running `flow` daemon pins to bpffs (see
//! [`XdpDataplane::pin_capture_maps`](crate::XdpDataplane::pin_capture_maps)) —
//! from their pinned paths, switches capture **on**, drains the packet records
//! the eBPF program pushes, and switches capture **off** again on stop/drop. The
//! drained records are parsed with the pure [`crate::pcap::parse_record`] and can
//! be serialised to pcap with [`crate::pcap::to_pcap`].
//!
//! This module is the I/O boundary for capture: every method is an aya
//! map/ring syscall against live pinned maps, so — like [`crate::dataplane`] and
//! [`crate::afxdp`] — it is **coverage-excluded**. All of the tested logic (pcap
//! encoding, record parsing) lives in the pure [`crate::pcap`] module.

use crate::dataplane::XdpError;
use crate::pcap::{parse_record, CapturedPacket};
use aya::maps::{HashMap, Map, MapData, RingBuf};
use std::path::Path;

/// Default bpffs directory the daemon pins the capture maps under, and the
/// default the `blackwalld xdp capture` CLI opens them from. Both sides share
/// this constant so an operator needs no configuration for the common case.
pub const DEFAULT_CAPTURE_PIN_DIR: &str = "/sys/fs/bpf/blackwall";

/// Pinned filename of the `CAPTURE` ring under [`DEFAULT_CAPTURE_PIN_DIR`].
pub const CAPTURE_RING_PIN: &str = "capture_ring";
/// Pinned filename of the `CAPTURE_ENABLED` flag under [`DEFAULT_CAPTURE_PIN_DIR`].
pub const CAPTURE_ENABLED_PIN: &str = "capture_enabled";

/// Fixed key of the sole `CAPTURE_ENABLED` entry (mirrors the eBPF
/// `CAPTURE_ENABLED_SLOT`).
const CAPTURE_ENABLED_SLOT: u32 = 0;
/// Flag value meaning "capture on".
const CAPTURE_ON: u8 = 1;

/// A live handle to the XDP capture ring plus its on/off flag.
///
/// Constructing one with [`XdpCapture::open`] sets the flag **on** so the eBPF
/// program begins pushing packet records; [`XdpCapture::drain`] pulls the
/// available records; dropping (or [`XdpCapture::stop`]) clears the flag so the
/// program stops capturing. Because the flag lives in a pinned map shared with
/// the daemon, capture is self-limiting: it is only ever on while a reader
/// holds this handle.
pub struct XdpCapture {
    /// The capture ring, drained record-by-record.
    ring: RingBuf<MapData>,
    /// The single-entry on/off flag map.
    flag: HashMap<MapData, u32, u8>,
}

impl XdpCapture {
    /// Open the pinned capture ring + flag from `dir` and switch capture on.
    ///
    /// `dir` is the bpffs directory the daemon pinned the maps under (typically
    /// [`DEFAULT_CAPTURE_PIN_DIR`]); it must contain the [`CAPTURE_RING_PIN`] and
    /// [`CAPTURE_ENABLED_PIN`] pins, which only exist while a `flow` daemon with
    /// XDP attached is running.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if either pinned map is missing (no daemon
    /// running / capture unsupported) or cannot be opened, or if enabling the
    /// flag fails.
    pub fn open(dir: &Path) -> Result<Self, XdpError> {
        let ring_pin = dir.join(CAPTURE_RING_PIN);
        let flag_pin = dir.join(CAPTURE_ENABLED_PIN);

        let ring_data = MapData::from_pin(&ring_pin).map_err(|e| {
            XdpError::Map(format!("open capture ring pin {}: {e}", ring_pin.display()))
        })?;
        let ring = RingBuf::try_from(Map::RingBuf(ring_data))
            .map_err(|e| XdpError::Map(format!("capture ring: {e}")))?;

        let flag_data = MapData::from_pin(&flag_pin).map_err(|e| {
            XdpError::Map(format!("open capture flag pin {}: {e}", flag_pin.display()))
        })?;
        let mut flag = HashMap::<_, u32, u8>::try_from(Map::HashMap(flag_data))
            .map_err(|e| XdpError::Map(format!("capture flag: {e}")))?;

        flag.insert(CAPTURE_ENABLED_SLOT, CAPTURE_ON, 0)
            .map_err(|e| XdpError::Map(format!("enable capture: {e}")))?;

        Ok(Self { ring, flag })
    }

    /// Drain all currently-available records into `out`, parsing each with the
    /// pure [`parse_record`]. Records that fail to parse (corrupt/short ring
    /// items) are skipped. Non-blocking: returns once the ring is momentarily
    /// empty, so callers poll it in a loop until their count/duration is met.
    pub fn drain(&mut self, out: &mut Vec<CapturedPacket>) {
        while let Some(item) = self.ring.next() {
            if let Some(pkt) = parse_record(&item) {
                out.push(pkt);
            }
        }
    }

    /// Switch capture off by clearing the flag. Idempotent; errors are ignored
    /// (best-effort — the process is typically exiting).
    pub fn stop(&mut self) {
        let _ = self.flag.remove(&CAPTURE_ENABLED_SLOT);
    }
}

impl Drop for XdpCapture {
    fn drop(&mut self) {
        // Always leave capture disabled when the reader goes away, so a crashed
        // or Ctrl-C'd `xdp capture` never leaves the eBPF program capturing.
        self.stop();
    }
}
