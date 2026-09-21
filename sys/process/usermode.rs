//! The one-way transition from ring 0 into ring 3.

use core::arch::asm;

use x86_64::VirtAddr;

use crate::cpu::gdt::{user_code_selector, user_data_selector};

/// RFLAGS value used for the jump: bit 1 is a reserved bit that must always read as 1, and
/// `INTERRUPT_FLAG` (bit 9) keeps interrupts enabled in user mode — otherwise the timer could
/// never preempt a runaway user program, and `SYSCALL` would be the only way back into the kernel.
///
/// `pub(crate)`, not private: `sys/syscall.rs`'s `redirect_frame` (used by `sys_execve`) reuses
/// this exact value when handing a process a fresh program image, rather than trusting whatever
/// flags (direction flag, debug flags, ...) the old program happened to leave behind.
pub(crate) const USER_RFLAGS: u64 = 0x202;

/// Jumps into ring 3 at `entry`, running on `user_stack_top`, by hand-building an `iretq` frame.
///
/// This is genuinely one-way: `iretq` never returns to its caller here. The kernel only regains
/// control via an interrupt, exception, or syscall (see `sys/syscall.rs`) firing while this code
/// runs — and even `SYS_EXIT` doesn't "return" in the traditional sense, since there's still no
/// scheduler to resume anything; it just idles the whole system. See the `ring3-smoke` demo
/// (`regress/ring3-smoke/src/main.rs`) and `sys/main.rs`'s `run_ring3_smoke_demo`.
///
/// # Safety
///
/// The currently-active address space (whatever `CR3` points at) must already have `entry` mapped
/// present + user-accessible + executable, and `user_stack_top` mapped present + user-accessible +
/// writable (both true after `elf::load` and a matching user-stack mapping into the same address
/// space). `gdt::init` must have already run, so `TSS`'s RSP0 is set — without it, the first
/// interrupt or exception that fires while this code is running in ring 3 has nowhere valid to
/// switch to.
pub unsafe fn jump_to_usermode(entry: VirtAddr, user_stack_top: VirtAddr) -> ! {
    let code_selector = u64::from(user_code_selector().0);
    let data_selector = u64::from(user_data_selector().0);

    unsafe {
        asm!(
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov fs, {data_sel:x}",
            "mov gs, {data_sel:x}",
            "push {data_sel}",   // SS
            "push {stack_top}",  // RSP
            "push {rflags}",     // RFLAGS
            "push {code_sel}",   // CS
            "push {entry}",      // RIP
            "iretq",
            data_sel = in(reg) data_selector,
            stack_top = in(reg) user_stack_top.as_u64(),
            rflags = in(reg) USER_RFLAGS,
            code_sel = in(reg) code_selector,
            entry = in(reg) entry.as_u64(),
            options(noreturn),
        );
    }
}
