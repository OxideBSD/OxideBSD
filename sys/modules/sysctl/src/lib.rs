//! Registers `sysctl(2)` (OxideBSD-doc `SYSCTL.md` §4), system call 583. The tree and its
//! variables are kernel-resident (`sys/kern/kern_sysctl.rs`): a module can't use `alloc`.
//!
//! The call's six arguments don't fit the native ABI's four registers, so `sysctl(3)` passes one
//! pointer to `{ name, namelen, oldp, oldlenp, newp, newlen }`.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_sysctl(args: u64) -> i64;
}

const SYS_SYSCTL: u64 = 583;

extern "C" fn handle_sysctl(args: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sysctl(args) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_SYSCTL, handle_sysctl);
    }
    let message = "[module] sysctl: module_init running (registered SYS_SYSCTL)\n";
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
    0
}
