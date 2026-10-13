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

/// `wait_until` for a disk transfer (`OxideBSD-doc/RAM_FLOOR.md` §3.5.1). In a process (a system
/// call, with interrupts masked), the process sleeps through the scheduler instead of spinning,
/// so others run while the disk works -- when called under the filesystem lock from a caller
/// holding no spin lock (`fs::fslock::may_sleep`); otherwise, and with no process (boot), it's
/// `wait_until`. Marked `WaitingForDisk` only after `done()` was checked with interrupts still
/// masked, so the completion interrupt can't slip in between and be lost.
/// The disk's interrupt handler wakes it (`wake_disk_waiters`), and so does every timer tick, in
/// case an interrupt is lost; each wake re-checks. Uninterruptible: signals don't wake it.
pub fn wait_for_disk(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    use crate::process::{self, BlockReason, ProcState, scheduler};
    let pid = scheduler::current_pid();
    if pid == 0 || !crate::fs::fslock::may_sleep() {
        return wait_until(timeout_ms, done);
    }
    let deadline = tsc::now() + tsc::ms_to_cycles(timeout_ms);
    loop {
        let finished = interrupts::without_interrupts(|| {
            if done() {
                return true;
            }
            if let Some(p) = process::table().lock().get_mut(&pid) {
                p.state = ProcState::Blocked(BlockReason::WaitingForDisk);
            }
            false
        });
        if finished {
            return true;
        }
        // Asleep inside the filesystem, holding its lock: what `fslock::busy` reports, so an
        // interrupt handler doesn't run filesystem code on top of the half-done operation.
        crate::fs::fslock::set_owner_asleep(true);
        scheduler::schedule();
        crate::fs::fslock::set_owner_asleep(false);
        if tsc::now() >= deadline {
            return done();
        }
    }
}

/// Wakes every process waiting for a disk transfer (`wait_for_disk`); each re-checks its own.
/// Called from the disks' interrupt handlers and the timer's.
pub fn wake_disk_waiters(table: &mut alloc::collections::BTreeMap<crate::process::Pid, alloc::boxed::Box<crate::process::Process>>) {
    use crate::process::{BlockReason, ProcState, scheduler};
    for (&pid, p) in table.iter_mut() {
        if p.state == ProcState::Blocked(BlockReason::WaitingForDisk) {
            p.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
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
