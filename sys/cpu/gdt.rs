use spin::Lazy;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

use crate::serial_println;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const STACK_SIZE: usize = 4096 * 5;

/// Index into `TaskStateSegment::privilege_stack_table` for ring 0 (RSP0): the stack the CPU
/// switches to automatically on any interrupt/exception that fires while running in ring 3.
/// Without this set, such a transition uses `RSP0 = 0` — a crash the instant any user-mode code
/// takes an interrupt.
const KERNEL_STACK_INDEX: usize = 0;

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        // `static mut` (not `static`) is load-bearing here: the only pointer ever taken to this
        // is a *const one, so as far as the Rust/LLVM optimizer can see, this data is never
        // written and is free to be interned into read-only .rodata. It's actually written by
        // the CPU pushing an interrupt frame onto it in hardware, invisible to that analysis —
        // `static mut` (mutable-by-definition) forces genuinely writable .bss placement instead.
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

        let stack_start = VirtAddr::from_ptr(&raw mut STACK);
        stack_start + STACK_SIZE as u64
    };
    tss.privilege_stack_table[KERNEL_STACK_INDEX] = {
        // See the comment on the IST stack above — same reasoning applies here.
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

        let stack_start = VirtAddr::from_ptr(&raw mut STACK);
        stack_start + STACK_SIZE as u64
    };
    tss
});

struct Selectors {
    kernel_code_selector: SegmentSelector,
    kernel_data_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    // Order matters: SYSCALL/SYSRETQ (see sys/syscall.rs) reconstruct target segment
    // selectors from IA32_STAR using fixed offsets from two base values, which only works if
    // kernel_code/kernel_data/[placeholder]/user_data/user_code stay in exactly this order and
    // adjacency. `Descriptor::user_*_segment` are already tagged Ring 3 (DPL 3), and
    // `GlobalDescriptorTable::append` bakes the descriptor's DPL into the returned selector's RPL
    // bits.
    let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());
    // Reserves the GDT slot SYSRETQ's fixed offset scheme needs 8 bytes before
    // user_data_selector — historically a 32-bit-compat user code segment, but since this kernel
    // only ever uses SYSRETQ (64-bit), that slot's *contents* are never actually loaded by
    // hardware. Its selector value is never used past this point; only its position matters.
    let _syscall_compat_placeholder = gdt.append(Descriptor::user_code_segment());
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));
    (
        gdt,
        Selectors {
            kernel_code_selector,
            kernel_data_selector,
            user_data_selector,
            user_code_selector,
            tss_selector,
        },
    )
});

pub fn init() {
    serial_println!(
        "[boot] loading GDT/TSS (double-fault stack at IST[{}], ring-0 stack at RSP0, {} bytes \
         each)",
        DOUBLE_FAULT_IST_INDEX,
        STACK_SIZE
    );
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.kernel_code_selector);
        SS::set_reg(GDT.1.kernel_data_selector);
        load_tss(GDT.1.tss_selector);
    }
    serial_println!("[boot] GDT/TSS loaded");
}

/// The ring 3 code segment selector, for building an `iretq` frame into user mode.
pub fn user_code_selector() -> SegmentSelector {
    GDT.1.user_code_selector
}

/// The ring 3 data segment selector, for building an `iretq` frame into user mode.
pub fn user_data_selector() -> SegmentSelector {
    GDT.1.user_data_selector
}

/// The ring 0 code segment selector — needed by `sys/syscall.rs` to program `IA32_STAR`.
pub fn kernel_code_selector() -> SegmentSelector {
    GDT.1.kernel_code_selector
}

/// The ring 0 data segment selector — needed by `sys/syscall.rs` to program `IA32_STAR`.
pub fn kernel_data_selector() -> SegmentSelector {
    GDT.1.kernel_data_selector
}

/// Mirrors `TSS.privilege_stack_table[0]` (see `set_kernel_stack` below) in a plain, directly
/// asm-readable location. `SYSCALL` — unlike an interrupt gate + TSS `RSP0` — does **not**
/// automatically switch onto the kernel stack named there; `sys/syscall.rs`'s entry stub has to
/// do that switch itself, in raw assembly, before it can push anything. It can't read the TSS
/// directly (`TSS` is a private `spin::Lazy`, and dereferencing a `Lazy` runs its own
/// initialization logic — not something raw asm can do), so this `static` exists purely to give
/// that stub a fixed, flat memory location to `mov rsp, [CURRENT_RSP0]` from — same idiom as the
/// old `src/linux_syscall.rs`'s (now-retired) `KERNEL_RSP_TOP`/`USER_RSP_SCRATCH` no-mangle
/// statics. `static mut`, not `static`, for the same reason as `TSS`'s own stacks above: it's
/// written here from ordinary Rust code (visible to the optimizer) but only ever *read* from
/// asm — the risk isn't "interned into .rodata" here, it's the opposite one documented on
/// `modules/fat32`'s `DISK`/`CURRENT_DIR_CLUSTER` (a write with no Rust-visible read can be
/// proven dead) — but `syscall.rs`'s `global_asm!` reading it is invisible to that analysis too,
/// so it gets the same `static mut` treatment defensively.
#[unsafe(no_mangle)]
static mut CURRENT_RSP0: u64 = 0;

/// Repoints `TSS`'s RSP0 (`privilege_stack_table[0]`) at `rsp0` — the stack the CPU automatically
/// switches to on the *next* ring-3→ring-0 transition caused by an interrupt or exception (and,
/// via the `CURRENT_RSP0` mirror above, the stack `sys/syscall.rs`'s own entry stub manually
/// switches to for a `SYSCALL`-triggered entry, which gets no automatic switch at all). The
/// scheduler (`src/scheduler.rs`) calls this on every context switch, right before
/// `switch_context`, so that a trap or syscall firing while the incoming process runs in ring 3
/// lands on *its* kernel stack, not whichever process's stack happened to be running previously.
///
/// # Safety requirements satisfied here, not by the caller
///
/// `Lazy<TaskStateSegment>::deref` only hands out `&TaskStateSegment`, not `&mut` — `spin::Lazy`
/// has no `DerefMut`. This takes `TSS`'s address (fixed for the process's lifetime: `Lazy` never
/// moves its storage once forced, and the GDT's TSS descriptor bakes that fixed linear address in
/// at `init` time, so mutating this field in place is picked up by the CPU with no `ltr`
/// re-execution needed) and writes through a raw pointer instead. Sound because nothing else ever
/// holds a live `&TaskStateSegment` across this call: the scheduler only calls this with
/// interrupts disabled, and this is a single-core kernel.
pub fn set_kernel_stack(rsp0: VirtAddr) {
    let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
    unsafe {
        (*tss_ptr).privilege_stack_table[0] = rsp0;
        CURRENT_RSP0 = rsp0.as_u64();
    }
}
