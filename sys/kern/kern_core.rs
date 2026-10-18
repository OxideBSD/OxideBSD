//! Core dumps (FreeBSD's `kern_sig.c` `coredump`, `imgact_elf.c`'s writer): a process killed by
//! a signal whose default action is to dump core (POSIX's "A" signals: `SIGQUIT`, `SIGILL`,
//! `SIGTRAP`, `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGSEGV`, `SIGSYS`, `SIGXCPU`, `SIGXFSZ`) writes an
//! ELF `ET_CORE` file of its memory and registers, in its own context as it dies, before it's
//! torn down.
//!
//! The file is `kern.corefile` (`%N.core` by default: `%N` the program's name, `%P` its pid, `%U`
//! its user ID, `%H` the host name, `%%` a percent sign), relative to the process's working
//! directory, mode 0600, never through a symbolic link nor onto a file with other links or another
//! owner. Nothing is written with `kern.coredump` 0, a zero `RLIMIT_CORE` or a core that would
//! pass it, or for a process whose credentials changed (set-ID: its memory may hold what its user
//! may not read) unless `kern.sugid_coredump` is 1.
//!
//! The layout is Linux's (notes owned by `CORE`: `NT_PRSTATUS`, `NT_FPREGSET`, `NT_PRPSINFO`,
//! `NT_AUXV`), which the debuggers read for an x86-64 ELF core, then one `PT_LOAD` per mapping of
//! the process's map (`vm_map`): readable ones with their pages (unresident ones as zeros), the
//! stack from its lowest page in use, the kernel's own pages and device memory left out.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use crate::kern::subr_uio::{IoSeg, Uio, UioRw, UioSeg};
use crate::process::vm_map::{PROT_EXEC, PROT_READ, PROT_WRITE, VmEntry, VmKind};
use crate::process::Pid;

/// `kern.coredump`: whether cores are written at all.
pub(crate) static COREDUMP: AtomicBool = AtomicBool::new(true);
/// `kern.sugid_coredump`: whether a process whose credentials changed may dump.
pub(crate) static SUGID_COREDUMP: AtomicBool = AtomicBool::new(false);
/// `kern.corefile`: the file name pattern.
pub(crate) static CORENAME: Mutex<Vec<u8>> = Mutex::new(Vec::new());

const DEFAULT_CORENAME: &[u8] = b"%N.core";

/// `kern.corefile`'s value.
pub(crate) fn corename() -> Vec<u8> {
    let n = CORENAME.lock();
    if n.is_empty() { DEFAULT_CORENAME.to_vec() } else { n.clone() }
}

/// The user registers in the order of Linux's `struct user_regs_struct` (`NT_PRSTATUS`'s
/// `pr_reg`): r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags
/// rsp ss fs_base gs_base ds es fs gs.
pub(crate) type UserRegs = [u64; 27];

pub(crate) const USER_CS: u64 = 0x2b;
pub(crate) const USER_SS: u64 = 0x23;

/// The registers of each process's last ring-3 fault, kept by the fault handler: a signal a fault
/// raised is delivered through the fault trampoline's system call, whose frame no longer holds
/// the faulting `rip` (and `rax`, `rcx`, `r11`).
static FAULT_REGS: Mutex<BTreeMap<Pid, UserRegs>> = Mutex::new(BTreeMap::new());

/// Called by the fault handler for every ring-3 fault it turns into a signal.
pub(crate) fn note_fault(pid: Pid, regs: UserRegs) {
    FAULT_REGS.lock().insert(pid, regs);
}

/// `pid`'s last fault's registers, taken.
pub(crate) fn take_fault(pid: Pid) -> Option<UserRegs> {
    FAULT_REGS.lock().remove(&pid)
}

/// Forgets `pid`'s fault registers (it exited).
pub(crate) fn forget(pid: Pid) {
    FAULT_REGS.lock().remove(&pid);
}

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_FPREGSET: u32 = 2;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const PAGE: u64 = 4096;

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// One ELF note, its name `CORE`, padded to 4 bytes as the x86-64 cores are.
fn note(out: &mut Vec<u8>, kind: u32, desc: &[u8]) {
    put32(out, 5);
    put32(out, desc.len() as u32);
    put32(out, kind);
    out.extend_from_slice(b"CORE\0\0\0\0");
    out.extend_from_slice(desc);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// A `struct timeval` of `ticks` clock ticks.
fn timeval(out: &mut Vec<u8>, ticks: u64) {
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    put64(out, ticks / hz);
    put64(out, (ticks % hz) * (1_000_000 / hz));
}

/// What the dump needs of the process, read under the process table's lock.
struct Snapshot {
    tgid: Pid,
    ppid: Pid,
    pgid: Pid,
    sid: Pid,
    uid: u32,
    gid: u32,
    setid: bool,
    limit: u64,
    comm: Vec<u8>,
    cmdline: Vec<u8>,
    nice: i32,
    blocked: u64,
    pending: u64,
    times: [u64; 4],
    stack_top: u64,
    entries: Vec<(u64, VmEntry)>,
}

fn snapshot(pid: Pid) -> Option<Snapshot> {
    let table = crate::process::table().lock();
    let p = table.get(&pid)?;
    let cred = p.shared.lock().cred.clone();
    let entries = p.address_space.as_ref()?.vm().map.iter().map(|(s, e)| (s, *e)).collect();
    Some(Snapshot {
        tgid: p.tgid,
        ppid: p.parent.unwrap_or(0),
        pgid: p.pgid,
        sid: p.sid,
        uid: cred.ruid,
        gid: cred.rgid,
        setid: cred.sugid,
        limit: p.rlimits[crate::process::limits::RLIMIT_CORE].0,
        comm: p.comm.clone(),
        cmdline: p.cmdline.clone(),
        nice: p.nice,
        blocked: p.blocked_signals,
        pending: p.pending_signals,
        times: [
            p.cpu_ticks.saturating_sub(p.sys_ticks),
            p.sys_ticks,
            p.child_cpu_ticks.saturating_sub(p.child_sys_ticks),
            p.child_sys_ticks,
        ],
        stack_top: p.user_stack_top.as_u64(),
        entries,
    })
}

/// `kern.corefile` expanded for this process.
fn core_path(s: &Snapshot) -> Vec<u8> {
    let pattern = corename();
    let mut out = Vec::new();
    let mut it = pattern.iter();
    let dec = |out: &mut Vec<u8>, v: u64| {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut n = v;
        loop {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        out.extend_from_slice(&buf[i..]);
    };
    while let Some(&c) = it.next() {
        if c != b'%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some(b'N') => out.extend_from_slice(&s.comm),
            Some(b'P') => dec(&mut out, s.tgid),
            Some(b'U') => dec(&mut out, s.uid as u64),
            Some(b'H') => out.extend_from_slice(&crate::syscall::ffi::hostname()),
            Some(b'%') => out.push(b'%'),
            Some(&o) => {
                out.push(b'%');
                out.push(o);
            }
            None => out.push(b'%'),
        }
    }
    out
}

/// Whether the page at `va` has a frame (or a page cache page) in the running address space.
fn resident(va: u64) -> bool {
    use x86_64::structures::paging::mapper::{Translate, TranslateResult};
    let phys_offset = crate::memory::phys_mem_offset();
    let (l4, _) = x86_64::registers::control::Cr3::read();
    // SAFETY: the running address space's table, only read.
    let table = unsafe { &mut *(phys_offset + l4.start_address().as_u64()).as_mut_ptr() };
    // SAFETY: as above.
    let mapper = unsafe { x86_64::structures::paging::OffsetPageTable::new(table, phys_offset) };
    if matches!(mapper.translate(x86_64::VirtAddr::new(va)), TranslateResult::Mapped { .. }) {
        return true;
    }
    crate::memory::address_space::leaf_entry(
        // SAFETY: as above.
        unsafe { &mut *(phys_offset + l4.start_address().as_u64()).as_mut_ptr() },
        phys_offset,
        x86_64::VirtAddr::new(va),
    )
    .is_some_and(|e| crate::memory::address_space::file_entry(e).is_some())
}

/// The range of an entry the core holds: all of a readable mapping; for the stack, from its
/// lowest page in use; nothing for the rest.
fn dumped_range(start: u64, e: &VmEntry) -> (u64, u64) {
    if e.prot & PROT_READ == 0 || matches!(e.kind, VmKind::Kernel | VmKind::Phys) {
        return (start, start);
    }
    if e.kind == VmKind::Stack {
        let mut va = start;
        while va < e.end && !resident(va) {
            va += PAGE;
        }
        return (va, e.end);
    }
    (start, e.end)
}

/// The auxiliary vector the program started with, read back from its stack.
fn auxv(stack_top: u64) -> Vec<u8> {
    use crate::memory::usercopy::{UserPtr, copyin_val};
    let read = |a: u64| -> Option<u64> { copyin_val::<u64>(UserPtr::new(a)).ok() };
    let mut out = Vec::new();
    let Some(argc) = read(stack_top) else { return out };
    // argc, argv[0..argc], NULL, envp..., NULL, then the auxv pairs.
    let mut p = stack_top + 8 + (argc + 1) * 8;
    for _ in 0..4096 {
        match read(p) {
            Some(0) => break,
            Some(_) => p += 8,
            None => return out,
        }
    }
    p += 8;
    for _ in 0..512 {
        let (Some(k), Some(v)) = (read(p), read(p + 8)) else { break };
        put64(&mut out, k);
        put64(&mut out, v);
        p += 16;
        if k == 0 {
            break;
        }
    }
    out
}

/// Writes the core of `pid` (the running process), killed by `sig`, whose user registers are
/// `regs` (a fault's, when the signal came from one: `fault_regs`). Returns whether a core was
/// written. Runs in the dying process, which may sleep here on the disk.
pub(crate) fn coredump(pid: Pid, sig: u64, regs: UserRegs) -> bool {
    if !COREDUMP.load(Ordering::Relaxed) {
        return false;
    }
    let Some(s) = snapshot(pid) else { return false };
    if s.setid && !SUGID_COREDUMP.load(Ordering::Relaxed) || s.limit == 0 {
        return false;
    }

    // The notes.
    let mut notes = Vec::new();
    let mut prstatus = Vec::with_capacity(336);
    put32(&mut prstatus, sig as u32); // pr_info.si_signo
    put32(&mut prstatus, 0); // si_code
    put32(&mut prstatus, 0); // si_errno
    put16(&mut prstatus, sig as u16); // pr_cursig
    put16(&mut prstatus, 0);
    put64(&mut prstatus, s.pending);
    put64(&mut prstatus, s.blocked);
    for id in [pid, s.ppid, s.pgid, s.sid] {
        put32(&mut prstatus, id as u32);
    }
    for t in s.times {
        timeval(&mut prstatus, t);
    }
    for r in regs {
        put64(&mut prstatus, r);
    }
    put32(&mut prstatus, 1); // pr_fpvalid
    put32(&mut prstatus, 0);
    note(&mut notes, NT_PRSTATUS, &prstatus);

    let mut fx = crate::cpu::fpu::FxSaveArea([0; 512]);
    // SAFETY: a 512-byte, 16-aligned save area of our own.
    unsafe { crate::cpu::fpu::save(&mut fx) };
    note(&mut notes, NT_FPREGSET, &fx.0);

    let mut psinfo = Vec::with_capacity(136);
    psinfo.extend_from_slice(&[b'R', b'R', 0, s.nice as i8 as u8, 0, 0, 0, 0]);
    put64(&mut psinfo, 0); // pr_flag
    put32(&mut psinfo, s.uid);
    put32(&mut psinfo, s.gid);
    for id in [pid, s.ppid, s.pgid, s.sid] {
        put32(&mut psinfo, id as u32);
    }
    let mut fname = [0u8; 16];
    let n = s.comm.len().min(15);
    fname[..n].copy_from_slice(&s.comm[..n]);
    psinfo.extend_from_slice(&fname);
    let mut args = [0u8; 80];
    let n = s.cmdline.len().min(79);
    args[..n].copy_from_slice(&s.cmdline[..n]);
    for b in &mut args[..n] {
        if *b == 0 {
            *b = b' ';
        }
    }
    psinfo.extend_from_slice(&args);
    note(&mut notes, NT_PRPSINFO, &psinfo);
    let aux = auxv(s.stack_top);
    if !aux.is_empty() {
        note(&mut notes, NT_AUXV, &aux);
    }

    // The segments, and where each goes in the file (page-aligned, after the headers and notes).
    let segs: Vec<(u64, VmEntry, u64, u64)> = s
        .entries
        .iter()
        .filter(|(_, e)| e.kind != VmKind::Kernel)
        .map(|&(start, e)| {
            let (from, to) = dumped_range(start, &e);
            (start, e, from, to)
        })
        .collect();
    let phnum = 1 + segs.len() as u64;
    let notes_off = 64 + phnum * 56;
    let mut data_off = (notes_off + notes.len() as u64).next_multiple_of(PAGE);
    let mut header = Vec::new();
    // Elf64_Ehdr.
    header.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put16(&mut header, 4); // ET_CORE
    put16(&mut header, 62); // EM_X86_64
    put32(&mut header, 1);
    put64(&mut header, 0); // e_entry
    put64(&mut header, 64); // e_phoff
    put64(&mut header, 0); // e_shoff
    put32(&mut header, 0); // e_flags
    put16(&mut header, 64);
    put16(&mut header, 56);
    put16(&mut header, phnum as u16);
    put16(&mut header, 0);
    put16(&mut header, 0);
    put16(&mut header, 0);
    // PT_NOTE.
    put32(&mut header, PT_NOTE);
    put32(&mut header, 0);
    put64(&mut header, notes_off);
    put64(&mut header, 0);
    put64(&mut header, 0);
    put64(&mut header, notes.len() as u64);
    put64(&mut header, 0);
    put64(&mut header, 4);
    let mut placed = Vec::with_capacity(segs.len());
    for &(start, e, from, to) in &segs {
        let flags = (if e.prot & PROT_READ != 0 { 4 } else { 0 })
            | (if e.prot & PROT_WRITE != 0 { 2 } else { 0 })
            | (if e.prot & PROT_EXEC != 0 { 1 } else { 0 });
        put32(&mut header, PT_LOAD);
        put32(&mut header, flags);
        put64(&mut header, data_off);
        put64(&mut header, from.max(start));
        put64(&mut header, 0);
        put64(&mut header, to - from);
        put64(&mut header, e.end - from.max(start));
        put64(&mut header, PAGE);
        placed.push((data_off, from, to));
        data_off += to - from;
    }
    if data_off > s.limit {
        return false; // FreeBSD writes no core past RLIMIT_CORE
    }
    header.extend_from_slice(&notes);

    write_core(&core_path(&s), s.uid, &header, notes_off as usize, &placed)
}

/// Creates the core file and writes the headers and notes (`head`, the notes at `notes_off`), then
/// each `(file offset, from, to)` range of the running process's memory.
fn write_core(path: &[u8], uid: u32, head: &[u8], notes_off: usize, placed: &[(u64, u64, u64)]) -> bool {
    use crate::kern::vfs_vnops::{O_CREAT, O_NOFOLLOW, O_TRUNC};
    use crate::kern::vnode_if::{vop_close, vop_getattr, vop_write};
    const O_WRONLY: u64 = 1;
    let _ = notes_off;
    let cred = crate::kern::vfs_subr::current_ucred();
    let oflags = O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW;
    let Ok(vp) = crate::kern::vfs_vnops::vn_open(path, core::ptr::null_mut(), oflags, 0o600) else {
        return false;
    };
    let fflag = crate::fs::fd::open_flag(oflags);
    let finish = |vp: *mut vfs_if::Vnode, ok: bool| -> bool {
        // SAFETY: vn_open counted us as a writer of the file.
        unsafe { (*crate::kern::vfs_vnops::object_vp(vp)).v_writecount -= 1 };
        vop_close(vp, fflag, &cred);
        crate::kern::vfs_subr::vrele(vp);
        ok
    };
    // Only a regular file of the process's own with this one name (a planted link to another file
    // would otherwise be overwritten with this process's memory).
    match vop_getattr(vp) {
        Ok(va) if va.va_type == vfs_if::VREG && va.va_nlink == 1 && va.va_uid == uid => {}
        _ => return finish(vp, false),
    }
    let write_at = |offset: u64, data: &[u8]| -> bool {
        let Ok(mut uio) =
            Uio::new(alloc::vec![IoSeg { base: data.as_ptr() as u64, len: data.len() as u64 }], UioRw::Write, UioSeg::Kernel, offset)
        else {
            return false;
        };
        vop_write(vp, &mut uio as *mut Uio as u64, 0, &cred).is_ok_and(|n| n == data.len())
    };
    if !write_at(0, head) {
        return finish(vp, false);
    }
    let mut page = alloc::vec![0u8; PAGE as usize];
    for &(off, from, to) in placed {
        let mut va = from;
        while va < to {
            // A page that can't be read (past a file's end, never touched) goes in as zeros.
            if crate::memory::usercopy::copyin(crate::memory::usercopy::UserPtr::new(va), &mut page).is_err() {
                page.fill(0);
            }
            if !write_at(off + (va - from), &page) {
                return finish(vp, false);
            }
            va += PAGE;
        }
    }
    finish(vp, true)
}
