//! What the DMA-capable disk drivers (`ata`'s bus-master path, `virtio_blk`) share: physically
//! contiguous memory a device can read and write, and waiting for a device to finish.
//!
//! **Waiting is interrupt-driven with a polling fallback.** `wait_until` always decides
//! completion from the device's own state (the `done` closure); an interrupt only wakes the CPU
//! early. With interrupts enabled -- boot, and oxfs's `module_init`, where a fresh format writes
//! hundreds of MiB -- it sleeps in `hlt` until the device's completion interrupt (or at worst the
//! next 100 Hz timer tick, if that interrupt is lost or shared-line edges merge). Inside a
//! syscall, where `SFMASK` masks interrupts, `hlt` would never wake (CLAUDE.md, "Real networking"
//! gotcha 2), so it spins on the device state instead. Both are bounded by a `tsc` deadline.

use x86_64::instructions::interrupts;
use x86_64::structures::paging::{FrameAllocator, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::cpu::tsc;

/// A physically contiguous, zeroed buffer, reached through the HHDM.
pub struct DmaBuffer {
    pub phys: PhysAddr,
    pub virt: VirtAddr,
    pub len: usize,
}

impl DmaBuffer {
    /// `pages` physically contiguous frames, or `None`. With `below_4g`, the whole buffer must
    /// sit below 4 GiB (for 32-bit DMA addresses, like IDE's PRD entries). Frames from a
    /// discontiguous start are abandoned, as `drivers::rtl8139`'s ring allocation does: this runs a
    /// few times at boot, never at run time.
    pub fn alloc(
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
        phys_mem_offset: VirtAddr,
        pages: usize,
        below_4g: bool,
    ) -> Option<DmaBuffer> {
        let mut start = frame_allocator.allocate_frame()?.start_address();
        let mut have = 1;
        let mut attempts = 0;
        while have < pages {
            let frame = frame_allocator.allocate_frame()?.start_address();
            if frame == start + have as u64 * 4096 {
                have += 1;
                continue;
            }
            attempts += 1;
            if attempts > 8 {
                return None;
            }
            start = frame;
            have = 1;
        }
        let len = pages * 4096;
        if below_4g && start.as_u64() + len as u64 > 1 << 32 {
            return None;
        }
        let virt = phys_mem_offset + start.as_u64();
        // SAFETY: freshly allocated frames, reached through the HHDM, owned by nobody else.
        unsafe { core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, len) };
        Some(DmaBuffer { phys: start, virt, len })
    }

    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.virt.as_mut_ptr()
    }

    /// `len` bytes at `offset`.
    ///
    /// # Safety
    /// The device must not be writing the range meanwhile.
    pub unsafe fn slice_mut(&self, offset: usize, len: usize) -> &mut [u8] {
        assert!(offset + len <= self.len);
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr::<u8>().add(offset), len) }
    }
}

/// Waits until `done()` holds, for up to `timeout_ms`: sleeping in `hlt` between checks when
/// interrupts are enabled, spinning when they're masked (see the module doc). `false` on timeout.
pub fn wait_until(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = tsc::now() + tsc::ms_to_cycles(timeout_ms);
    let sleep = interrupts::are_enabled();
    loop {
        if sleep {
            // Checked with interrupts off, then `sti; hlt` atomically: a completion interrupt
            // landing between the check and the `hlt` still wakes it.
            interrupts::disable();
            if done() {
                interrupts::enable();
                return true;
            }
            interrupts::enable_and_hlt();
        } else {
            if done() {
                return true;
            }
            core::hint::spin_loop();
        }
        if tsc::now() >= deadline {
            return done();
        }
    }
}
