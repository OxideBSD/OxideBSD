//! Registers `vfork(2)` (OxideBSD-doc `COW.md` §7), system call 586. The work is kernel-resident
//! (`process::do_vfork`).
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_vfork(a0: u64, a1: u64, a2: u64, a3: u64) -> i64;
}

const SYS_VFORK: u64 = 586;

extern "C" fn handle_vfork(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_vfork(a0, a1, a2, a3) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_VFORK, handle_vfork);
    }
    let message = "[module] vfork: module_init running (registered SYS_VFORK)\n";
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
    0
}
