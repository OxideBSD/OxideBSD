//! The GDT, the TSS and the ring-0 stacks the CPU switches to on its own.
//!
//! All of it lives in the entry area's data (`cpu::entry`): the CPU reads the GDT and TSS during
//! every privilege change, and the IST stacks are taken by traps that can arrive while a process's
//! own page tables are still loaded.

use core::ops::Range;

use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel;

use crate::serial_println;

/// IST slots (`TaskStateSegment::interrupt_stack_table` indices; an IDT gate names slot + 1).
/// Each of these traps gets a known-good stack of its own: `#DF` because it's usually a kernel
/// stack overflow, NMI and `#MC` because they can arrive anywhere, including between the return
/// path's `pop rsp` and its `sysretq`, when `RSP` is already the user's.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const NMI_IST_INDEX: u16 = 1;
pub const MACHINE_CHECK_IST_INDEX: u16 = 2;

const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;
const NMI_STACK_SIZE: usize = 4096 * 4;
const MACHINE_CHECK_STACK_SIZE: usize = 4096 * 4;

#[repr(C, align(16))]
struct Stack<const N: usize>([u8; N]);

impl<const N: usize> Stack<N> {
    const fn new() -> Self {
        Stack([0; N])
    }
}

/// Everything here, in one place in the entry data.
#[repr(C)]
struct CpuTables {
    gdt: GlobalDescriptorTable,
    tss: TaskStateSegment,
    double_fault_stack: Stack<DOUBLE_FAULT_STACK_SIZE>,
    nmi_stack: Stack<NMI_STACK_SIZE>,
    machine_check_stack: Stack<MACHINE_CHECK_STACK_SIZE>,
}

/// `static mut`: the CPU writes the stacks (and the TSS descriptor's busy bit), invisibly to the
/// compiler, so it must not be placed in `.rodata` (CLAUDE.md, Memory). Filled in once by `init`.
#[unsafe(link_section = ".data.entry")]
static mut TABLES: CpuTables = CpuTables {
    gdt: GlobalDescriptorTable::new(),
    tss: TaskStateSegment::new(),
    double_fault_stack: Stack::new(),
    nmi_stack: Stack::new(),
    machine_check_stack: Stack::new(),
};

// The selectors `init` must produce. Order matters: SYSCALL/SYSRETQ (sys/syscall/mod.rs)
// derive their selectors from IA32_STAR at fixed offsets, which only works with kernel code,
// kernel data, a placeholder, user data and user code adjacent and in exactly this order.
const KERNEL_CODE: SegmentSelector = SegmentSelector::new(1, PrivilegeLevel::Ring0);
const KERNEL_DATA: SegmentSelector = SegmentSelector::new(2, PrivilegeLevel::Ring0);
const USER_DATA: SegmentSelector = SegmentSelector::new(4, PrivilegeLevel::Ring3);
const USER_CODE: SegmentSelector = SegmentSelector::new(5, PrivilegeLevel::Ring3);
const TSS_SELECTOR: SegmentSelector = SegmentSelector::new(6, PrivilegeLevel::Ring0);

fn stack_top<const N: usize>(stack: *mut Stack<N>) -> VirtAddr {
    VirtAddr::new(stack as u64 + N as u64)
}

pub fn init() {
    // SAFETY: single-threaded boot, before anything has loaded this GDT or TSS.
    let tables = unsafe { &mut *(&raw mut TABLES) };
    // The TSS is packed: its arrays are copied out, filled and stored whole.
    let mut ist = tables.tss.interrupt_stack_table;
    ist[DOUBLE_FAULT_IST_INDEX as usize] = stack_top(&raw mut tables.double_fault_stack);
    ist[NMI_IST_INDEX as usize] = stack_top(&raw mut tables.nmi_stack);
    ist[MACHINE_CHECK_IST_INDEX as usize] = stack_top(&raw mut tables.machine_check_stack);
    tables.tss.interrupt_stack_table = ist;
    // Every ring-3 trap lands on the entry stack; `trap_common` moves it to the process's own.
    let mut rsp = tables.tss.privilege_stack_table;
    rsp[0] = VirtAddr::new(crate::cpu::entry::entry_stack_top());
    tables.tss.privilege_stack_table = rsp;

    let gdt = &mut tables.gdt;
    assert_eq!(gdt.append(Descriptor::kernel_code_segment()), KERNEL_CODE);
    assert_eq!(gdt.append(Descriptor::kernel_data_segment()), KERNEL_DATA);
    // SYSRETQ's offsets need a slot here (a 32-bit user code segment, for a SYSRET without REX.W,
    // which this kernel never does): only its position matters.
    gdt.append(Descriptor::user_code_segment());
    assert_eq!(gdt.append(Descriptor::user_data_segment()), USER_DATA);
    assert_eq!(gdt.append(Descriptor::user_code_segment()), USER_CODE);
    // SAFETY: the TSS is a static, so the descriptor's base stays valid.
    let tss = unsafe { Descriptor::tss_segment_unchecked(&raw const tables.tss) };
    assert_eq!(gdt.append(tss), TSS_SELECTOR);

    // SAFETY: the GDT is a static, fully built above, and never rebuilt.
    unsafe {
        gdt.load_unsafe();
        CS::set_reg(KERNEL_CODE);
        SS::set_reg(KERNEL_DATA);
        load_tss(TSS_SELECTOR);
    }
    serial_println!(
        "[boot] GDT/TSS loaded (IST stacks: #DF {}, NMI {}, #MC {} bytes)",
        DOUBLE_FAULT_STACK_SIZE,
        NMI_STACK_SIZE,
        MACHINE_CHECK_STACK_SIZE
    );
}

/// The ring 3 code segment selector, for building an `iretq` frame into user mode.
pub fn user_code_selector() -> SegmentSelector {
    USER_CODE
}

/// The ring 3 data segment selector, for building an `iretq` frame into user mode.
pub fn user_data_selector() -> SegmentSelector {
    USER_DATA
}

/// The ring 0 code segment selector — needed by `sys/syscall.rs` to program `IA32_STAR`.
pub fn kernel_code_selector() -> SegmentSelector {
    KERNEL_CODE
}

/// The ring 0 data segment selector — needed by `sys/syscall.rs` to program `IA32_STAR`.
pub fn kernel_data_selector() -> SegmentSelector {
    KERNEL_DATA
}

/// The current process's kernel stack top. `SYSCALL` doesn't switch stacks, so
/// `syscall_entry` loads `RSP` from here; a ring-3 trap lands on the entry stack, and
/// `trap_common` moves its frame here. Read only from asm, by name; `static mut` so a write the
/// compiler sees no read of isn't dropped.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.entry")]
static mut CURRENT_RSP0: u64 = 0;

/// Makes `rsp0` the kernel stack the next ring-3 trap or `syscall` runs on. The scheduler calls
/// this on every context switch, before `switch_context`.
pub fn set_kernel_stack(rsp0: VirtAddr) {
    // SAFETY: a plain store; on this single-core kernel the scheduler calls this with interrupts
    // off, and the entry code only reads it from ring 3 entries.
    unsafe { CURRENT_RSP0 = rsp0.as_u64() };
}

/// Where this file's entry data sits, for `entry::check`.
pub fn entry_data() -> [(&'static str, Range<u64>); 2] {
    let tables = (&raw const TABLES) as u64;
    let rsp0 = (&raw const CURRENT_RSP0) as u64;
    [
        ("the GDT, TSS and IST stacks", tables..tables + size_of::<CpuTables>() as u64),
        ("CURRENT_RSP0", rsp0..rsp0 + 8),
    ]
}
