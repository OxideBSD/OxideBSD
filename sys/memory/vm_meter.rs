//! Memory and process totals (OxideBSD-doc `SYSCTL.md` §10): `vm.stats.vm.*`, `vm.vmtotal`,
//! `hw.usermem` and `sysinfo(2)`'s `freeram`, from FreeBSD's `vm_meter.c`.
//!
//! Exact, not estimated: free and in-use frames come from the frame allocator's own count, and the
//! frames mapped into processes from walking every live address space's user page tables at the
//! moment of reading. What's in use and not a process's is the kernel's (wired): heap, stacks,
//! page tables, modules, DMA buffers.

use alloc::collections::BTreeSet;

use crate::process::ProcState;

pub(crate) struct Stats {
    /// Usable pages (`v_page_count`).
    pub page_count: u64,
    pub free: u64,
    pub wired: u64,
    /// Pages mapped into processes, shared ones counted once (`v_user_count`).
    pub user: u64,
    /// Of `user`, pages shared between processes (SysV shared memory, `MAP_SHARED` files).
    pub shared: u64,
    /// Threads runnable, waiting for the disk, and sleeping (`t_rq`, `t_dw`, `t_sl`).
    pub runnable: u64,
    pub disk_wait: u64,
    pub sleeping: u64,
}

pub(crate) fn stats() -> Stats {
    let (page_count, in_use) = super::frame_counts();
    let pmo = super::phys_mem_offset();
    let mut shared_frames = BTreeSet::new();
    let mut spaces = BTreeSet::new();
    let (mut user, mut runnable, mut sleeping) = (0, 0, 0);
    {
        let table = crate::process::table().lock();
        for proc in table.values() {
            match proc.state {
                ProcState::Ready | ProcState::Running => runnable += 1,
                // Disk waits spin inside the system call rather than block: none are counted.
                ProcState::Blocked(_) => sleeping += 1,
                _ => {}
            }
            if let Some(space) = &proc.address_space
                && spaces.insert(space.id())
            {
                user += space.count_user_frames(pmo, &mut shared_frames);
            }
        }
    }
    let free = page_count.saturating_sub(in_use);
    Stats {
        page_count,
        free,
        wired: in_use.saturating_sub(user),
        user,
        shared: shared_frames.len() as u64,
        runnable,
        disk_wait: 0,
        sleeping,
    }
}
