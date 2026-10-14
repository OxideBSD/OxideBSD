//! Reference counts of private user frames (OxideBSD-doc `COW.md` §2), for copy-on-write fork.
//!
//! A frame's entry counts its **extra** sharers: `0` while it's mapped privately by at most one
//! address space (every private frame, until fork shares one), `n` while `n + 1` address spaces
//! map it. Storing the extras, not the total, means nothing that maps a fresh private page has to
//! count it: only fork (`share`) and the paths that drop a private mapping (`release`) and the
//! copy-on-write fault (`sole_owner`) touch it.
//!
//! A dense array of `AtomicU16`, one per frame up to the highest usable one, allocated from the
//! heap at boot: 2 bytes a frame (64 KiB at 128 MB). Atomic, so the page fault handler reads and
//! updates it without a lock.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use x86_64::structures::paging::{PhysFrame, Size4KiB};

static REFS: spin::Once<&'static [AtomicU16]> = spin::Once::new();

/// One past the highest usable frame number, recorded by the frame allocator's `init`.
pub(super) static FRAME_LIMIT: AtomicU64 = AtomicU64::new(0);

/// Allocates the array; once, after the heap exists.
pub fn init() {
    let frames = FRAME_LIMIT.load(Ordering::Relaxed) as usize;
    REFS.call_once(|| {
        let v: Vec<AtomicU16> = (0..frames).map(|_| AtomicU16::new(0)).collect();
        Box::leak(v.into_boxed_slice())
    });
}

fn slot(frame: PhysFrame<Size4KiB>) -> &'static AtomicU16 {
    let refs = REFS.get().expect("memory::refs used before init");
    &refs[(frame.start_address().as_u64() / 4096) as usize]
}

/// Records one more address space mapping `frame` privately (fork). `Err` when the count is
/// full: the caller fails the fork (`EAGAIN`, COW.md §2.3).
pub fn share(frame: PhysFrame<Size4KiB>) -> Result<(), ()> {
    slot(frame)
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1).filter(|&n| n < u16::MAX))
        .map(|_| ())
        .map_err(|_| ())
}

/// Drops one private mapping of `frame` (teardown, `munmap`, a copy-on-write copy replacing it):
/// `true` when it was the last, and the caller frees the frame.
pub fn release(frame: PhysFrame<Size4KiB>) -> bool {
    slot(frame)
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_err()
}

/// Whether no other address space maps `frame`: a copy-on-write fault can then just make it
/// writable again (COW.md §4.1).
pub fn sole_owner(frame: PhysFrame<Size4KiB>) -> bool {
    slot(frame).load(Ordering::Relaxed) == 0
}
