//! The entry area: the code and data a trap or `syscall` from ring 3 touches before the kernel's
//! own page tables are in place, and again after they're gone on the way back.
//!
//! Under KPTI (`OxideBSD-doc/THREAT_MODEL.md` §3.4) a process runs on page tables that map almost
//! nothing of the kernel, so whatever runs first after a ring-3 trap or `syscall` must be mapped
//! there too. The linker gathers it into page-aligned ranges of its own:
//!
//! - **text** (`.text.entry*`): `cpu::trap`'s stubs and `trap_common`, and `syscall`'s entry and
//!   return path.
//! - **data** (`.data.entry*`): what the CPU reads on its own during a transition (the GDT, the
//!   TSS, the IDT), the stacks it lands on (`ENTRY_STACK`, the IST stacks), and the variables the
//!   entry code reads (`gdt::CURRENT_RSP0`, `SYSCALL_RSP_SCRATCH`).
//!
//! A trap from ring 3 lands on `ENTRY_STACK` (`TSS.RSP0`, fixed), and `trap_common` moves its
//! frame over to the process's own kernel stack before calling into Rust; a return to ring 3 moves
//! the hardware frame back onto `ENTRY_STACK` before the `iretq`. `syscall`'s return does the same
//! before its `sysretq`. Per-process kernel stacks are never touched while ring 3's page tables
//! could be loaded.

use core::ops::Range;

/// The stack every ring-3 trap lands on (`TSS.RSP0`). Only ever holds a hardware frame and a
/// couple of registers on their way to or from the process's kernel stack.
pub const ENTRY_STACK_SIZE: usize = 4096;

/// `static mut`, so it's writable rather than `.rodata` (CLAUDE.md, Memory).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.entry")]
static mut ENTRY_STACK: EntryStack = EntryStack([0; ENTRY_STACK_SIZE]);

#[repr(C, align(16))]
struct EntryStack([u8; ENTRY_STACK_SIZE]);

/// The top of `ENTRY_STACK`, where `TSS.RSP0` points.
pub fn entry_stack_top() -> u64 {
    (&raw const ENTRY_STACK) as u64 + ENTRY_STACK_SIZE as u64
}

/// KPTI state the entry/exit assembly reads, all in the entry data so it's mapped in a process's
/// user table (`cpu::pti`). `PTI_ON` is 1 once isolation is on; the asm switches CR3 only then.
/// `KERNEL_CR3`/`USER_CR3` are the two `CR3` values for the current process, set at context switch
/// (`AddressSpace::activate`): kernel on entry, user on the way back to ring 3.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.entry")]
pub static mut PTI_ON: u8 = 0;
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.entry")]
pub static mut KERNEL_CR3: u64 = 0;
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.entry")]
pub static mut USER_CR3: u64 = 0;

/// Turns the entry/exit CR3 switch on. Called once, after `pti::decide` settles on isolation and
/// the entry template and first user table exist.
pub fn enable_switch() {
    // SAFETY: a plain store, single-core, before the first ring-3 entry that would read it.
    unsafe { PTI_ON = 1 };
}

/// Records the current process's two CR3 values for the entry asm. `user` equals `kernel` for an
/// address space with no separate user table (KPTI off, or the kernel's own space), which makes
/// the asm's switch a no-op write it skips anyway via `PTI_ON`.
pub fn set_active_cr3(kernel: u64, user: u64) {
    // SAFETY: plain stores, single-core, with interrupts off at the one caller (context switch).
    unsafe {
        KERNEL_CR3 = kernel;
        USER_CR3 = user;
    }
}

/// The current process's user and kernel CR3 values (`set_active_cr3`), for the page-fault
/// handler's lazy L4 mirror.
pub fn active_cr3() -> (u64, u64) {
    // SAFETY: plain reads of values only written at context switch, single-core.
    unsafe { (KERNEL_CR3, USER_CR3) }
}

unsafe extern "C" {
    static __entry_text_start: u8;
    static __entry_text_end: u8;
    static __entry_data_start: u8;
    static __entry_data_end: u8;
    static trap_common: u8;
    static trap_common_paranoid: u8;
    static syscall_return_tail: u8;
}

/// The entry area's code.
pub fn text() -> Range<u64> {
    (&raw const __entry_text_start) as u64..(&raw const __entry_text_end) as u64
}

/// The entry area's data.
pub fn data() -> Range<u64> {
    (&raw const __entry_data_start) as u64..(&raw const __entry_data_end) as u64
}

/// Checks at boot that everything the entry path touches really landed in the entry area: a
/// symbol left out (a section name typo, a new static without its `link_section`) would only show
/// up under KPTI, as a triple fault on the first trap.
pub fn check() {
    let text = text();
    let data = data();
    assert!(text.start % 4096 == 0 && text.end % 4096 == 0 && !text.is_empty());
    assert!(data.start % 4096 == 0 && data.end % 4096 == 0 && !data.is_empty());

    let mut code = [
        ("trap_common", (&raw const trap_common) as u64),
        ("trap_common_paranoid", (&raw const trap_common_paranoid) as u64),
        ("syscall_entry", crate::syscall::syscall_entry as *const () as u64),
        ("syscall_return_tail", (&raw const syscall_return_tail) as u64),
    ]
    .into_iter()
    .chain(crate::cpu::trap::stub_addresses().map(|a| ("a trap stub", a)));
    if let Some((name, addr)) = code.find(|&(_, a)| !text.contains(&a)) {
        panic!("[entry] {name} at {addr:#x} is outside the entry text {text:#x?}");
    }

    let own = [
        ("ENTRY_STACK", (&raw const ENTRY_STACK) as u64..entry_stack_top()),
        ("the IDT", crate::cpu::trap::idt_range()),
        ("SYSCALL_RSP_SCRATCH", crate::syscall::rsp_scratch_range()),
    ];
    for (name, range) in own.into_iter().chain(crate::cpu::gdt::entry_data()) {
        if range.start < data.start || range.end > data.end {
            panic!("[entry] {name} {range:#x?} is outside the entry data {data:#x?}");
        }
    }
    crate::serial_println!(
        "[entry] entry text {:#x}..{:#x} ({} pages), data {:#x}..{:#x} ({} pages)",
        text.start,
        text.end,
        (text.end - text.start) / 4096,
        data.start,
        data.end,
        (data.end - data.start) / 4096
    );
}
