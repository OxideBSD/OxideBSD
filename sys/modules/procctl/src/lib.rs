//! Registers `procctl(2)` (OxideBSD-doc `COW.md` §6.3), system call 585. The commands are
//! kernel-resident (`sys/kern/kern_procctl.rs`).
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_procctl(idtype: u64, id: u64, cmd: u64, data: u64) -> i64;
}

const SYS_PROCCTL: u64 = 585;

extern "C" fn handle_procctl(idtype: u64, id: u64, cmd: u64, data: u64) -> i64 {
    unsafe { oxidebsd_sys_procctl(idtype, id, cmd, data) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_PROCCTL, handle_procctl);
    }
    let message = "[module] procctl: module_init running (registered SYS_PROCCTL)\n";
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
    0
}
