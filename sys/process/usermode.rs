//! The one-way transition from ring 0 into ring 3.

use core::arch::asm;

use x86_64::VirtAddr;

use crate::cpu::gdt::{user_code_selector, user_data_selector};
use crate::cpu::trap::TrapFrame;

/// RFLAGS value used for the jump: bit 1 is a reserved bit that must always read as 1, and
/// `INTERRUPT_FLAG` (bit 9) keeps interrupts enabled in user mode — otherwise the timer could
/// never preempt a runaway user program, and `SYSCALL` would be the only way back into the kernel.
///
/// `pub(crate)`, not private: `sys/syscall.rs`'s `redirect_frame` (used by `sys_execve`) reuses
/// this exact value when handing a process a fresh program image, rather than trusting whatever
/// flags (direction flag, debug flags, ...) the old program happened to leave behind.
pub(crate) const USER_RFLAGS: u64 = 0x202;

/// Jumps into ring 3 at `entry`, running on `user_stack_top`, through `cpu::trap`'s
/// `trap_return` with a frame built here: the same way back to ring 3 as every trap, so it also
/// goes through the entry stack (`cpu::entry`). Every general-purpose register starts at zero, so
/// nothing the kernel had in them reaches the new program.
///
/// One-way: the kernel only regains control via an interrupt, exception, or syscall.
///
/// # Safety
///
/// The currently-active address space must have `entry` mapped user-executable and
/// `user_stack_top` mapped user-writable (both true after `elf::load` and a matching user-stack
/// mapping), and `gdt::set_kernel_stack` must name this process's kernel stack.
pub unsafe fn jump_to_usermode(entry: VirtAddr, user_stack_top: VirtAddr) -> ! {
    let data_selector = u64::from(user_data_selector().0);
    let frame = TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: entry.as_u64(),
        cs: u64::from(user_code_selector().0),
        rflags: USER_RFLAGS,
        rsp: user_stack_top.as_u64(),
        ss: data_selector,
    };

    // SAFETY: `frame` is a complete ring-3 TrapFrame; everything below it on this stack is dead,
    // since this never returns.
    unsafe {
        asm!(
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov fs, {data_sel:x}",
            "mov gs, {data_sel:x}",
            "mov rsp, {frame}",
            "jmp trap_return",
            data_sel = in(reg) data_selector,
            frame = in(reg) &frame as *const TrapFrame,
            options(noreturn),
        );
    }
}
