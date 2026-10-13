//! Trap entry: the IDT, one assembly stub per vector, and the `TrapFrame` they build.
//!
//! Every interrupt and exception enters through a stub that pushes a dummy error code (when the CPU
//! didn't push one) and the vector number, then jumps to `trap_common`. That pushes every
//! general-purpose register, so the stack holds a complete `TrapFrame`, and calls `trap_dispatch`
//! with a pointer to it. Returning pops it all back and `iretq`s, so a handler that edits the frame
//! (a new `rip`, a register) changes what the interrupted code resumes with. FreeBSD's `trapframe`
//! is the same idea.
//!
//! A trap from ring 3 lands on the entry stack (`cpu::entry`), not the process's kernel stack:
//! `trap_common` moves the frame over before building the rest, and the way back to ring 3 moves
//! the hardware part back onto the entry stack for the `iretq`. All of it is entry text.
//!
//! The handlers themselves live in `interrupts`; this file only gets the CPU there and back.

use core::arch::global_asm;
use core::mem::size_of;
use core::ops::Range;

use x86_64::VirtAddr;
use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;

use crate::cpu::entry::ENTRY_STACK_SIZE;
use crate::cpu::gdt::{self, DOUBLE_FAULT_IST_INDEX, MACHINE_CHECK_IST_INDEX, NMI_IST_INDEX};

/// The vectors with a stub of their own: the 32 exceptions and the 16 legacy PIC lines. Every
/// higher vector shares `trap_stub_spurious`, which reports itself as `SPURIOUS_VECTOR`.
pub const STUB_VECTORS: usize = 48;

/// What `trap_stub_spurious` pushes as its vector: nothing raises 255 here (the PICs are remapped
/// to 32-47, and there's no local APIC in use), so seeing it means a stray interrupt.
pub const SPURIOUS_VECTOR: u64 = 255;

/// The interrupted context, as `trap_common` leaves it on the stack. Field order is the reverse of
/// the push order (the last register pushed is at the lowest address); the last five fields are
/// the frame the CPU itself pushed.
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    /// The CPU's error code, or 0 for a vector that has none.
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// The CPU aligns RSP to 16 before pushing its frame, so a frame that's a multiple of 16 bytes
// (22 * 8 = 176) leaves `trap_common`'s `call` 16-byte aligned, as the System V ABI wants.
const _: () = assert!(size_of::<TrapFrame>() == 22 * 8);

impl TrapFrame {
    /// Whether the trap interrupted ring 3 (the saved `CS`'s RPL).
    pub fn from_user(&self) -> bool {
        self.cs & 0x3 == 3
    }
}

/// Whether the CPU pushes an error code for exception `vector` (Intel SDM vol. 3 §6.15):
/// `#DF`, `#TS`, `#NP`, `#SS`, `#GP`, `#PF`, `#AC`, `#CP`, `#VC`, `#SX`.
const fn has_error_code(vector: usize) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

/// Defines `trap_stub_<n>` for every listed vector, plus `TRAP_STUBS`, their addresses in order.
/// `err` vectors get their error code from the CPU; `noerr` ones push a zero in its place, so the
/// frame has one shape.
macro_rules! trap_stubs {
    (@code err) => { "" };
    (@code noerr) => { "push 0" };
    (@target normal) => { "jmp trap_common" };
    (@target paranoid) => { "jmp trap_common_paranoid" };
    (@has_err err) => { true };
    (@has_err noerr) => { false };
    ($($vector:literal $kind:ident $target:ident),* $(,)?) => {
        global_asm!(
            ".pushsection .text.entry.trap_stubs, \"ax\"",
            $(
                concat!("trap_stub_", stringify!($vector), ":"),
                trap_stubs!(@code $kind),
                concat!("push ", stringify!($vector)),
                trap_stubs!(@target $target),
            )*
            "trap_stub_spurious:",
            "push 0",
            "push 255",
            "jmp trap_common",
            ".popsection",
            ".pushsection .rodata.trap, \"a\"",
            ".balign 8",
            ".global TRAP_STUBS",
            "TRAP_STUBS:",
            $( concat!(".quad trap_stub_", stringify!($vector)), )*
            ".quad trap_stub_spurious",
            ".popsection",
        );
        // The list above must name every stub vector, in order, with the right kind.
        const _: () = {
            let listed: &[(usize, bool)] = &[$(($vector, trap_stubs!(@has_err $kind))),*];
            assert!(listed.len() == STUB_VECTORS);
            let mut i = 0;
            while i < listed.len() {
                assert!(listed[i].0 == i);
                assert!(listed[i].1 == has_error_code(i));
                i += 1;
            }
        };
    };
}

trap_stubs! {
    0 noerr normal, 1 noerr normal, 2 noerr paranoid, 3 noerr normal,
    4 noerr normal, 5 noerr normal, 6 noerr normal, 7 noerr normal,
    8 err paranoid, 9 noerr normal, 10 err normal, 11 err normal,
    12 err normal, 13 err normal, 14 err normal, 15 noerr normal,
    16 noerr normal, 17 err normal, 18 noerr paranoid, 19 noerr normal,
    20 noerr normal, 21 err normal, 22 noerr normal, 23 noerr normal,
    24 noerr normal, 25 noerr normal, 26 noerr normal, 27 noerr normal,
    28 noerr normal, 29 err normal, 30 err normal, 31 noerr normal,
    32 noerr normal, 33 noerr normal, 34 noerr normal, 35 noerr normal,
    36 noerr normal, 37 noerr normal, 38 noerr normal, 39 noerr normal,
    40 noerr normal, 41 noerr normal, 42 noerr normal, 43 noerr normal,
    44 noerr normal, 45 noerr normal, 46 noerr normal, 47 noerr normal,
}

global_asm!(
    ".pushsection .text.entry.trap_common, \"ax\"",
    ".global trap_common",
    "trap_common:",
    // From ring 3, the CPU switched to the entry stack (TSS.RSP0). Move what's on it (the vector,
    // the error code and the CPU's five-word frame) to this process's own kernel stack, to the
    // very place the CPU would have put it, then carry on as for a trap from ring 0.
    "test byte ptr [rsp + 24], 3", // the saved CS's RPL
    "jz 2f",
    "push rdi",
    // KPTI: switch to the kernel table before reading CURRENT_RSP0 or the process stack, neither
    // of which the user table maps. rax is a free scratch here (saved and restored around it).
    "cmp byte ptr [PTI_ON], 0",
    "je 4f",
    "push rax",
    "mov rax, [KERNEL_CR3]",
    "mov cr3, rax",
    "pop rax",
    "4:",
    "mov rdi, rsp",
    "mov rsp, [CURRENT_RSP0]",
    "push qword ptr [rdi + 56]", // ss
    "push qword ptr [rdi + 48]", // rsp
    "push qword ptr [rdi + 40]", // rflags
    "push qword ptr [rdi + 32]", // cs
    "push qword ptr [rdi + 24]", // rip
    "push qword ptr [rdi + 16]", // error code
    "push qword ptr [rdi + 8]",  // vector
    "mov rdi, [rdi]",
    "2:",
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // The System V ABI wants DF clear at a call; ring 3 (or an interrupted `rep movs` backwards)
    // may have left it set, and an interrupt doesn't clear it.
    "cld",
    "mov rdi, rsp",
    "call trap_dispatch",
    // Resumes the TrapFrame at RSP: the way back from every trap, and `usermode::jump_to_usermode`'s
    // way into ring 3.
    ".global trap_return",
    "trap_return:",
    "test byte ptr [rsp + {cs}], 3",
    "jnz 3f",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    // The vector and error code.
    "add rsp, 16",
    "iretq",
    // To ring 3: restore everything but RDI, which then carries the frame over to the entry
    // stack, so the `iretq` doesn't read the process's kernel stack.
    "3:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    // [rsp] is now the saved RDI; RSI..RAX, the vector and error code, then the CPU's frame follow.
    "mov rsi, [rsp + 8]",
    "mov rdx, [rsp + 16]",
    "mov rcx, [rsp + 24]",
    "mov rbx, [rsp + 32]",
    "mov rax, [rsp + 40]",
    "mov rdi, rsp",
    "lea rsp, [rip + ENTRY_STACK + {entry_stack_size}]",
    "push qword ptr [rdi + 96]", // ss
    "push qword ptr [rdi + 88]", // rsp
    "push qword ptr [rdi + 80]", // rflags
    "push qword ptr [rdi + 72]", // cs
    "push qword ptr [rdi + 64]", // rip
    "push qword ptr [rdi]",      // stage the user RDI on the entry stack (last process-stack read)
    // KPTI: to the user table before iretq; everything below reads only the entry stack. RDI is
    // the scratch, then restored from the entry stack.
    "cmp byte ptr [PTI_ON], 0",
    "je 5f",
    "mov rdi, [USER_CR3]",
    "mov cr3, rdi",
    "5:",
    "pop rdi",
    "iretq",
    ".popsection",
    cs = const core::mem::offset_of!(TrapFrame, cs),
    entry_stack_size = const ENTRY_STACK_SIZE,
);

// NMI, #DF and #MC enter here instead of `trap_common`. They run on an IST stack (mapped in every
// user table) and can fire while the user table is loaded -- in ring 3, or in the sliver of ring-0
// entry/exit code before or after the CR3 switch. So this path reads CR3, loads the kernel table,
// runs the handler, then restores whatever CR3 was live, rather than assuming the ring tells it
// which table is loaded. It stays on the IST stack throughout (these handlers only count or reboot
// -- they never reschedule or deliver a signal), so there's no process-stack copy. Single core, so
// the saved CR3 lives safely in a callee-saved register across the one call.
global_asm!(
    ".pushsection .text.entry.trap_paranoid, \"ax\"",
    ".global trap_common_paranoid",
    "trap_common_paranoid:",
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "cld",
    // Save the live CR3 in rbx (callee-saved, so it survives the call) and load the kernel table.
    // The interrupted rbx is already on the stack above, so the frame dispatch sees is correct.
    "mov rbx, cr3",
    "cmp byte ptr [PTI_ON], 0",
    "je 2f",
    "mov rax, [KERNEL_CR3]",
    "mov cr3, rax",
    "2:",
    "mov rdi, rsp",
    "call trap_dispatch",
    // Restore exactly the CR3 that was live on entry (user if interrupted ring 3 or an entry/exit
    // window, kernel otherwise), then the registers and the interrupted frame.
    "cmp byte ptr [PTI_ON], 0",
    "je 3f",
    "mov cr3, rbx",
    "3:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    "add rsp, 16", // vector and error code
    "iretq",
    ".popsection",
);

unsafe extern "C" {
    static TRAP_STUBS: [u64; STUB_VECTORS + 1];
}

/// Called by `trap_common` with the frame it just built.
#[unsafe(no_mangle)]
extern "C" fn trap_dispatch(frame: &mut TrapFrame) {
    // First, as at every entry (`cpu::smap`): ring 3 may have left AC set.
    crate::cpu::smap::clac();
    crate::cpu::interrupts::dispatch(frame);
}

/// One 16-byte IDT gate (Intel SDM vol. 3 §6.14.1).
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    /// Bits 0-2: the IST slot (1-7), or 0 for none.
    ist: u8,
    /// Present, DPL, and type `0xE` (a 64-bit interrupt gate: IF is cleared on entry).
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl Gate {
    const MISSING: Gate = Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: u64, selector: u16, dpl: u8, ist: u8) -> Gate {
        Gate {
            offset_low: handler as u16,
            selector,
            ist,
            attributes: 0x80 | (dpl << 5) | 0xE,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

/// The IDT: the CPU reads it on every trap, so it's entry data.
#[repr(C, align(4096))]
struct Idt([Gate; 256]);

/// `static mut`: filled in once by `init`, then only read by the CPU.
#[unsafe(link_section = ".data.entry")]
static mut IDT: Idt = Idt([Gate::MISSING; 256]);

/// Where the IDT sits, for `entry::check`.
pub fn idt_range() -> Range<u64> {
    let idt = (&raw const IDT) as u64;
    idt..idt + size_of::<Idt>() as u64
}

/// Every stub's address, for `entry::check`.
pub fn stub_addresses() -> impl Iterator<Item = u64> {
    // SAFETY: TRAP_STUBS is a read-only table emitted above.
    unsafe { &*(&raw const TRAP_STUBS) }.iter().copied()
}

/// Builds the IDT and loads it. Every vector gets a gate: an exception or IRQ its own stub, the
/// rest the spurious one. Only `#BP` is open to ring 3's `int n` (DPL 3, so `int3` raises it
/// rather than a `#GP`); every other gate is DPL 0, so `int n` on it from ring 3 is a `#GP`.
pub fn init() {
    let selector = gdt::kernel_code_selector().0;
    // SAFETY: TRAP_STUBS is a read-only table emitted above.
    let stubs = unsafe { &*(&raw const TRAP_STUBS) };
    // SAFETY: single-threaded boot; nothing has loaded the IDT yet.
    let idt = unsafe { &mut *(&raw mut IDT) };
    for (vector, gate) in idt.0.iter_mut().enumerate() {
        let handler = stubs[vector.min(STUB_VECTORS)];
        let dpl = if vector == 3 { 3 } else { 0 };
        // Known-good stacks of their own (see `gdt`'s IST slots).
        let ist = match vector {
            2 => NMI_IST_INDEX as u8 + 1,
            8 => DOUBLE_FAULT_IST_INDEX as u8 + 1,
            18 => MACHINE_CHECK_IST_INDEX as u8 + 1,
            _ => 0,
        };
        *gate = Gate::new(handler, selector, dpl, ist);
    }
    let pointer = DescriptorTablePointer {
        limit: (size_of::<Idt>() - 1) as u16,
        base: VirtAddr::new((&raw const IDT) as u64),
    };
    // SAFETY: the table is static and fully built; every gate points at a stub above.
    unsafe { lidt(&pointer) };
}
