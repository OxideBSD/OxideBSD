//! Access to user memory from the kernel (`OxideBSD-doc/USERMEM.md`).
//!
//! Kernel code never dereferences a user pointer: it copies through `copyin`/`copyout` and their
//! `_val`/`_vec` forms, which fail with `EFAULT` instead of faulting. The user range is
//! `[VM_MINUSER, VM_MAXUSER)`. Nothing kernel-only may be mapped inside it, so a bounds check plus
//! fault recovery (`fixup_fault`) is enough to validate a user pointer (USERMEM.md §3.2, §5).
//! `check_user_range_layout` enforces that at boot.

use alloc::vec;
use alloc::vec::Vec;

use x86_64::VirtAddr;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::structures::paging::{OffsetPageTable, PageTable, PageTableFlags};

use crate::syscall::EFAULT;

/// Lowest user address: page zero stays unmapped, so a NULL dereference faults (as on the BSDs).
/// Fixed-address binaries load as low as `0x20_0000` (lld's default, e.g. on-target clang).
pub const VM_MINUSER: u64 = 0x1000;

/// The longest path a system call copies in, NUL included (musl's `PATH_MAX`); longer is
/// `ENAMETOOLONG` (USERMEM.md decision 2).
pub const PATH_MAX: usize = 4096;

/// End of the user range: the end of the canonical lower half.
pub const VM_MAXUSER: u64 = 0x8000_0000_0000;

/// Walks the lower half of the active page tables and panics if any kernel-only page lies in
/// `[VM_MINUSER, VM_MAXUSER)`. Run once at the end of `crate::init`, after the last boot-time
/// mapping and before any process exists.
pub fn check_user_range_layout(mapper: &OffsetPageTable) {
    let offset = mapper.phys_offset();
    // Only the lower half (L4 entries 0..256) can hold user addresses.
    walk(mapper.level_4_table(), 4, 0, offset, 256);
}

fn walk(table: &PageTable, level: u8, base: u64, offset: VirtAddr, entries: usize) {
    let span = 1u64 << (12 + 9 * (level as u32 - 1));
    for (i, entry) in table.iter().enumerate().take(entries) {
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }
        let start = base + i as u64 * span;
        let leaf = level == 1 || flags.contains(PageTableFlags::HUGE_PAGE);
        if leaf {
            let end = start + span;
            if !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                && start < VM_MAXUSER
                && end > VM_MINUSER
            {
                panic!(
                    "kernel-only mapping {:#x}..{:#x} lies in the user range {:#x}..{:#x} \
                     (USERMEM.md section 5.1)",
                    start, end, VM_MINUSER, VM_MAXUSER
                );
            }
            continue;
        }
        // SAFETY: a present, non-leaf entry points at a live page table, and the whole of
        // physical memory is mapped at `offset`. Read-only, at boot, before any other CPU or
        // process could change the tables.
        let child = unsafe { &*(offset + entry.addr().as_u64()).as_ptr::<PageTable>() };
        walk(child, level - 1, start, offset, 512);
    }
}

// ---- The copy loop and its fault fixup -------------------------------------------------------
//
// `usercopy_raw(dst, src, len)` copies `len` bytes with `rep movsb` and returns 0. A page fault
// while it runs (the user side is unmapped or read-only) resumes at `usercopy_fault`
// (`fixup_fault`), which returns `EFAULT`: the routine pushes nothing, so the fault frame's
// stack pointer still points at the caller's return address. The labels bracket only the
// instruction that touches user memory.
core::arch::global_asm!(
    ".pushsection .text.oxidebsd_usercopy,\"ax\",@progbits",
    ".global usercopy_raw",
    "usercopy_raw:",
    "    cld",
    "    mov rcx, rdx",
    "usercopy_access_start:",
    "    rep movsb",
    "usercopy_access_end:",
    "    xor eax, eax",
    "    ret",
    "usercopy_fault:",
    "    mov eax, 14", // EFAULT
    "    ret",
    ".global usercopy_access_start",
    ".global usercopy_access_end",
    ".global usercopy_fault",
    ".popsection",
);

unsafe extern "C" {
    fn usercopy_raw(dst: *mut u8, src: *const u8, len: usize) -> u64;
    static usercopy_access_start: u8;
    static usercopy_access_end: u8;
    static usercopy_fault: u8;
}

/// Called by the page fault handler for a fault in ring 0 that stack growth didn't resolve:
/// when it happened inside a copy routine, on a user address, the routine resumes at its fault
/// label and returns `EFAULT`. Returns whether it did.
pub fn fixup_fault(frame: &mut InterruptStackFrame, fault_addr: u64) -> bool {
    let rip = frame.instruction_pointer.as_u64();
    let start = (&raw const usercopy_access_start) as u64;
    let end = (&raw const usercopy_access_end) as u64;
    if !(start..end).contains(&rip) || fault_addr >= VM_MAXUSER {
        return false;
    }
    let fault = VirtAddr::new((&raw const usercopy_fault) as u64);
    // SAFETY: only the resume address changes, to the copy routine's own fault label, which
    // returns from the routine with the stack exactly as the faulting instruction left it.
    unsafe { frame.as_mut().update(|f| f.instruction_pointer = fault) };
    true
}

// ---- The interface ---------------------------------------------------------------------------

/// An address that came from user space. It can't be dereferenced: only copied through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPtr(u64);

impl UserPtr {
    pub const fn new(addr: u64) -> Self {
        UserPtr(addr)
    }
    pub const fn addr(self) -> u64 {
        self.0
    }
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
    /// The address `bytes` further on (wrapping: the range check catches overflow).
    pub const fn add(self, bytes: u64) -> Self {
        UserPtr(self.0.wrapping_add(bytes))
    }
}

/// Types for which every byte pattern is a valid value and which have no padding, so they can be
/// copied in from, and out to, user memory as raw bytes.
///
/// # Safety
///
/// The implementing type must have no padding bytes (copying one out would leak kernel memory)
/// and no invalid bit patterns (copying one in could create an invalid value).
pub unsafe trait Pod: Copy {}

macro_rules! pod {
    ($($t:ty),*) => { $(unsafe impl Pod for $t {})* };
}
pod!(u8, u16, u32, u64, i8, i16, i32, i64, usize, isize);
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// Whether `[addr, addr + len)` lies in the user range (USERMEM.md §3.2, §3.3).
fn check_range(addr: u64, len: usize) -> Result<(), u64> {
    if len == 0 {
        return Ok(());
    }
    let end = addr.checked_add(len as u64).ok_or(EFAULT)?;
    if addr < VM_MINUSER || end > VM_MAXUSER {
        return Err(EFAULT);
    }
    Ok(())
}

/// Copies `dst.len()` bytes from user memory at `src`.
pub fn copyin(src: UserPtr, dst: &mut [u8]) -> Result<(), u64> {
    check_range(src.0, dst.len())?;
    // SAFETY: `dst` is a kernel buffer of exactly that length; the user side is in the user
    // range, and a fault on it returns EFAULT instead of faulting the kernel.
    match unsafe { usercopy_raw(dst.as_mut_ptr(), src.0 as *const u8, dst.len()) } {
        0 => Ok(()),
        e => Err(e),
    }
}

/// Copies `src` to user memory at `dst`.
pub fn copyout(src: &[u8], dst: UserPtr) -> Result<(), u64> {
    check_range(dst.0, src.len())?;
    // SAFETY: as in `copyin`, the other way round.
    match unsafe { usercopy_raw(dst.0 as *mut u8, src.as_ptr(), src.len()) } {
        0 => Ok(()),
        e => Err(e),
    }
}

/// Copies one value in from user memory.
pub fn copyin_val<T: Pod>(src: UserPtr) -> Result<T, u64> {
    let mut v = core::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: a zeroed T's bytes, viewed as bytes; T is Pod, so any bytes copied in are valid.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>())
    };
    copyin(src, bytes)?;
    // SAFETY: every byte is initialized (zeroed, then overwritten) and T is Pod.
    Ok(unsafe { v.assume_init() })
}

/// Copies one value out to user memory.
pub fn copyout_val<T: Pod>(v: &T, dst: UserPtr) -> Result<(), u64> {
    // SAFETY: T is Pod, so it has no padding: all its bytes are initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts((v as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    copyout(bytes, dst)
}

/// Copies `len` bytes in, at most `max`: `too_long` (the caller's errno, e.g. `ENAMETOOLONG`)
/// when `len` exceeds it. For this ABI's length-prefixed arguments (paths, `RawAtPath`).
pub fn copyin_vec(src: UserPtr, len: usize, max: usize, too_long: u64) -> Result<Vec<u8>, u64> {
    if len > max {
        return Err(too_long);
    }
    let mut v = vec![0u8; len];
    copyin(src, &mut v)?;
    Ok(v)
}

/// `copyin` for modules (`sys/module.rs`'s symbol table): 0, or a positive errno.
pub(crate) extern "C" fn oxidebsd_copyin(src: u64, dst: *mut u8, len: usize) -> u64 {
    // SAFETY: the module passes its own buffer of `len` bytes.
    let dst = unsafe { core::slice::from_raw_parts_mut(dst, len) };
    copyin(UserPtr::new(src), dst).err().unwrap_or(0)
}

/// `copyout` for modules: 0, or a positive errno.
pub(crate) extern "C" fn oxidebsd_copyout(src: *const u8, len: usize, dst: u64) -> u64 {
    // SAFETY: the module passes its own buffer of `len` bytes.
    let src = unsafe { core::slice::from_raw_parts(src, len) };
    copyout(src, UserPtr::new(dst)).err().unwrap_or(0)
}
