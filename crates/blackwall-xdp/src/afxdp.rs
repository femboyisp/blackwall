//! AF_XDP zero-copy/copy-mode receiver (sub-project B3.1).
//!
//! This is the userspace half of the B3.1 spike: it owns a UMEM region and the
//! four AF_XDP rings (fill / completion / RX / TX) for one `(interface, RX
//! queue)`, binds an `AF_XDP` socket to that queue, and exposes the socket's fd
//! so it can be registered into the eBPF `XSKS` [`XskMap`](aya::maps::XskMap) via
//! [`crate::XdpDataplane::register_xsk`]. Once registered, the in-kernel
//! `xdp_filter` redirect fast path (packets whose UDP destination port is in
//! `REDIRECT_PORT`) hands matching frames straight to this receiver, ahead of
//! the kernel network stack.
//!
//! aya 0.13 provides only the `XSKMAP` binding, not the socket/UMEM/ring
//! machinery; that comes from the pure-Rust [`xdpilone`] crate (no
//! libbpf/libxdp-sys C dependency). This module is the sole I/O boundary for
//! AF_XDP and is **coverage-excluded** (see `scripts/coverage.sh`): every call
//! is a syscall requiring `CAP_NET_ADMIN`/`CAP_NET_RAW` and a live interface, so
//! it is exercised by the root veth integration test rather than unit tests.
//!
//! # Mode
//!
//! The socket binds in **copy mode** ([`SocketConfig::XDP_BIND_COPY`]): veth (and
//! most virtual devices) do not support AF_XDP zero-copy, and copy mode is the
//! portable foundation. B3.2 can opt a real NIC into zero-copy by dropping that
//! bind flag where the driver supports `XDP_SETUP_XSK_POOL`.

use core::ffi::CStr;
use std::num::NonZeroU32;
use std::os::fd::RawFd;
use std::ptr::NonNull;

use xdpilone::{DeviceQueue, IfInfo, RingRx, Socket, SocketConfig, Umem, UmemConfig, User};

/// Frame (chunk) size in the UMEM, in bytes. A power of two comfortably larger
/// than a 1500-byte MTU frame; also the kernel's per-chunk stride.
const FRAME_SIZE: u32 = 4096;
/// Number of frames (chunks) carved out of the UMEM region.
const FRAME_COUNT: u32 = 64;
/// Fill / completion / RX ring depth (must be a power of two per the kernel).
const RING_SIZE: u32 = 32;

/// An error setting up or receiving on the AF_XDP socket.
#[derive(Debug, thiserror::Error)]
pub enum AfXdpError {
    /// `mmap`/`munmap` of the UMEM region failed.
    #[error("AF_XDP UMEM mmap error: {0}")]
    Mmap(String),
    /// The interface name was not valid (embedded NUL or unknown interface).
    #[error("AF_XDP interface error: {0}")]
    Interface(String),
    /// An xdpilone socket/ring setup call failed.
    #[error("AF_XDP setup error: {0}")]
    Setup(String),
    /// A `poll`/receive syscall failed.
    #[error("AF_XDP receive error: {0}")]
    Receive(String),
}

/// A page-aligned anonymous `mmap` region backing the UMEM.
///
/// Owns the mapping and `munmap`s it on drop. Placed **last** in
/// [`AfXdpReceiver`]'s field order so the rings and socket (which point into this
/// memory) are torn down before the mapping is released.
struct UmemRegion {
    ptr: NonNull<u8>,
    len: usize,
}

impl UmemRegion {
    /// Map `len` bytes of anonymous, page-aligned, read/write memory.
    fn new(len: usize) -> Result<Self, AfXdpError> {
        // SAFETY: a standard anonymous private mapping request; `mmap` returns a
        // fresh, page-aligned region of `len` writable bytes or `MAP_FAILED`.
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(AfXdpError::Mmap(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        // SAFETY: `mmap` did not return `MAP_FAILED`, so `raw` is non-null.
        let ptr = unsafe { NonNull::new_unchecked(raw.cast::<u8>()) };
        Ok(Self { ptr, len })
    }

    /// The mapping as a `NonNull<[u8]>` for [`Umem::new`].
    fn as_slice_ptr(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }
}

impl Drop for UmemRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` are the exact values returned by our `mmap`; the
        // rings and socket that referenced this memory are already dropped (this
        // field is last in declaration order).
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// A bound AF_XDP receiver for one `(interface, RX queue)`.
///
/// Construct with [`AfXdpReceiver::bind`], register its [`raw_fd`](Self::raw_fd)
/// into the eBPF `XSKS` map, then drain redirected frames with
/// [`recv_one`](Self::recv_one).
pub struct AfXdpReceiver {
    /// RX queue id this socket is bound to (the `XSKS` map index to register at).
    queue_id: u32,
    /// UMEM handle, retained so its socket-fd / registration stays alive for the
    /// lifetime of the derived rings.
    _umem: Umem,
    /// The fill/completion device queue; also drives RX wakeups.
    device: DeviceQueue,
    /// The mapped RX ring; source of received descriptors and the socket fd.
    rx: RingRx,
    /// Retained so the bound rx/tx socket configuration stays alive.
    _user: User,
    /// Cached UMEM base pointer for reading received frame bytes directly.
    base: NonNull<u8>,
    /// Backing mapping; dropped last so the rings unmap cleanly (see field order).
    _region: UmemRegion,
}

impl AfXdpReceiver {
    /// Bind an `AF_XDP` socket to `ifname`'s RX queue `queue_id` in copy mode and
    /// prime its fill ring, ready to receive redirected frames.
    ///
    /// # Errors
    ///
    /// Returns an [`AfXdpError`] variant if the UMEM cannot be mapped, the
    /// interface is unknown, or any socket/ring setup syscall fails.
    pub fn bind(ifname: &str, queue_id: u32) -> Result<Self, AfXdpError> {
        let region = UmemRegion::new(
            usize::try_from(FRAME_COUNT * FRAME_SIZE).expect("UMEM size fits in usize"),
        )?;

        let config = UmemConfig {
            fill_size: RING_SIZE,
            complete_size: RING_SIZE,
            frame_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
        };
        // SAFETY: `region` is page-aligned (fresh `mmap`), sized for
        // `FRAME_COUNT * FRAME_SIZE` bytes, and kept alive by `Self` for at least
        // as long as `umem` and the rings derived from it.
        let umem = unsafe { Umem::new(config, region.as_slice_ptr()) }
            .map_err(|e| AfXdpError::Setup(e.to_string()))?;

        let mut info = IfInfo::invalid();
        let cname =
            std::ffi::CString::new(ifname).map_err(|e| AfXdpError::Interface(e.to_string()))?;
        let cstr = CStr::from_bytes_with_nul(cname.as_bytes_with_nul())
            .map_err(|e| AfXdpError::Interface(e.to_string()))?;
        info.from_name(cstr)
            .map_err(|e| AfXdpError::Interface(e.to_string()))?;
        info.set_queue(queue_id);

        let sock =
            Socket::with_shared(&info, &umem).map_err(|e| AfXdpError::Setup(e.to_string()))?;
        let device = umem
            .fq_cq(&sock)
            .map_err(|e| AfXdpError::Setup(e.to_string()))?;

        let user = umem
            .rx_tx(
                &sock,
                &SocketConfig {
                    rx_size: NonZeroU32::new(RING_SIZE),
                    tx_size: None,
                    bind_flags: SocketConfig::XDP_BIND_COPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
                },
            )
            .map_err(|e| AfXdpError::Setup(e.to_string()))?;

        let rx = user
            .map_rx()
            .map_err(|e| AfXdpError::Setup(e.to_string()))?;
        umem.bind(&user)
            .map_err(|e| AfXdpError::Setup(e.to_string()))?;

        let base = region.ptr;
        let mut receiver = Self {
            queue_id,
            _umem: umem,
            device,
            rx,
            _user: user,
            base,
            _region: region,
        };
        receiver.prime_fill_ring();
        Ok(receiver)
    }

    /// The RX queue id this socket is bound to (register it into `XSKS` at this
    /// index so redirect delivers frames arriving on this queue).
    #[must_use]
    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// The raw fd of the bound `AF_XDP` socket, for registration into the eBPF
    /// `XSKS` map via [`crate::XdpDataplane::register_xsk`]. The fd stays owned by
    /// this receiver; the map only stores it, so the receiver must outlive the
    /// registration.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.rx.as_raw_fd()
    }

    /// Hand the kernel every fill-ring slot, pointing at the first [`RING_SIZE`]
    /// UMEM chunks, so it has buffers to copy redirected frames into.
    fn prime_fill_ring(&mut self) {
        let mut fill = self.device.fill(RING_SIZE);
        let offsets = (0..RING_SIZE).map(|i| u64::from(i) * u64::from(FRAME_SIZE));
        fill.insert(offsets);
        fill.commit();
    }

    /// Poll up to `timeout_ms` for one redirected frame; on success copy its bytes
    /// into `out` (cleared first) and recycle its chunk back to the fill ring.
    ///
    /// Returns `Ok(true)` if a frame was received, `Ok(false)` on timeout.
    ///
    /// # Errors
    ///
    /// Returns [`AfXdpError::Receive`] if the `poll` syscall fails.
    pub fn recv_one(&mut self, timeout_ms: i32, out: &mut Vec<u8>) -> Result<bool, AfXdpError> {
        // Copy mode + NEED_WAKEUP: nudge the kernel to move fill buffers through
        // the RX path before we block in `poll`.
        if self.device.needs_wakeup() {
            self.device.wake();
        }

        let mut pfd = libc::pollfd {
            fd: self.rx.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a single valid `pollfd`; `poll` reads/writes exactly
        // this one-element array.
        let rc = unsafe { libc::poll(core::ptr::addr_of_mut!(pfd), 1, timeout_ms) };
        if rc < 0 {
            return Err(AfXdpError::Receive(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let mut chunk_offset: Option<u64> = None;
        {
            let mut reader = self.rx.receive(1);
            if let Some(desc) = reader.read() {
                let start = usize::try_from(desc.addr).unwrap_or(usize::MAX);
                let len = usize::try_from(desc.len).unwrap_or(0);
                out.clear();
                // SAFETY: `desc` came from the kernel for a chunk we filled inside
                // this UMEM; `[start, start+len)` therefore lies within the mapped
                // region, and the bytes are initialized by the copy-mode RX path.
                let frame =
                    unsafe { core::slice::from_raw_parts(self.base.as_ptr().add(start), len) };
                out.extend_from_slice(frame);
                reader.release();
                chunk_offset = Some(desc.addr - (desc.addr % u64::from(FRAME_SIZE)));
            }
        }

        match chunk_offset {
            Some(offset) => {
                let mut fill = self.device.fill(1);
                fill.insert_once(offset);
                fill.commit();
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
