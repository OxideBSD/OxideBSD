//! Registers the system calls every descriptor answers (OxideBSD-doc `VFS.md` §6.4): `close` (6),
//! `lseek` (8), `fdatasync` (75), `ioctl` (124), `fstat` (126), `fsync` (471) and `ftruncate`
//! (473), and `sync` (472) over every mount. The work is the kernel's (`kern::kern_descrip`, `syscall::ffi::sys_ioctl`), through each
//! file's operations (`fs::fd::FileOps`). The VFS's other calls join it as they move to the kernel
//! (`VFS.md` §11 step 2: `namei`, `nmount`, `unmount`). Since step 2b it also registers every
//! path call (`open`, `stat`, `mkdir`, `rename`, `getdents`, `nmount`, ...), from the kernel's
//! table (`oxidebsd_vfs_syscall`).
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_close(fd: u64, a1: u64, a2: u64, a3: u64) -> i64;
    fn oxidebsd_sys_lseek(fd: u64, offset: u64, whence: u64, a3: u64) -> i64;
    fn oxidebsd_sys_fstat(fd: u64, buf: u64, a2: u64, a3: u64) -> i64;
    fn oxidebsd_sys_ftruncate(fd: u64, length: u64, a2: u64, a3: u64) -> i64;
    fn oxidebsd_sys_fsync(fd: u64, a1: u64, a2: u64, a3: u64) -> i64;
    fn oxidebsd_sys_fdatasync(fd: u64, a1: u64, a2: u64, a3: u64) -> i64;
    fn oxidebsd_sys_ioctl(fd: u64, request: u64, argp: u64) -> i64;
    fn oxidebsd_sys_sync(a0: u64, a1: u64, a2: u64, a3: u64) -> i64;
    /// Entry `i` of the kernel's path calls (`kern::vfs_syscalls`): handler, and its number.
    fn oxidebsd_vfs_syscall(i: u64, number: *mut u64) -> u64;
}

const SYS_CLOSE: u64 = 6;
const SYS_LSEEK: u64 = 8;
const SYS_FDATASYNC: u64 = 75;
const SYS_IOCTL: u64 = 124;
const SYS_FSTAT: u64 = 126;
const SYS_FSYNC: u64 = 471;
const SYS_FTRUNCATE: u64 = 473;
const SYS_SYNC: u64 = 472;

extern "C" fn handle_close(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_close(a0, a1, a2, a3) }
}

extern "C" fn handle_lseek(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_lseek(a0, a1, a2, a3) }
}

extern "C" fn handle_fstat(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_fstat(a0, a1, a2, a3) }
}

extern "C" fn handle_ftruncate(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_ftruncate(a0, a1, a2, a3) }
}

extern "C" fn handle_fsync(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_fsync(a0, a1, a2, a3) }
}

extern "C" fn handle_fdatasync(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_fdatasync(a0, a1, a2, a3) }
}

extern "C" fn handle_sync(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sync(a0, a1, a2, a3) }
}

extern "C" fn handle_ioctl(fd: u64, request: u64, argp: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_ioctl(fd, request, argp) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    let calls: [(u64, extern "C" fn(u64, u64, u64, u64) -> i64); 8] = [
        (SYS_CLOSE, handle_close),
        (SYS_LSEEK, handle_lseek),
        (SYS_FDATASYNC, handle_fdatasync),
        (SYS_IOCTL, handle_ioctl),
        (SYS_FSTAT, handle_fstat),
        (SYS_FSYNC, handle_fsync),
        (SYS_FTRUNCATE, handle_ftruncate),
        (SYS_SYNC, handle_sync),
    ];
    for (number, handler) in calls {
        unsafe { oxidebsd_register_syscall(number, handler) };
    }
    // The path calls (`open`, `stat`, `mkdir`, `rename`, `nmount`, ...): the kernel's
    // `kern::vfs_syscalls`, named by its table.
    let mut i = 0;
    loop {
        let mut number = 0u64;
        let handler = unsafe { oxidebsd_vfs_syscall(i, &mut number) };
        if handler == 0 {
            break;
        }
        // SAFETY: the kernel hands out its own system call handlers.
        let handler: extern "C" fn(u64, u64, u64, u64) -> i64 = unsafe { core::mem::transmute(handler as usize) };
        unsafe { oxidebsd_register_syscall(number, handler) };
        i += 1;
    }
    let message = "[module] vfs: module_init running (registered SYS_CLOSE/SYS_LSEEK/SYS_FDATASYNC/SYS_IOCTL/SYS_FSTAT/SYS_FSYNC/SYS_FTRUNCATE/SYS_SYNC and the path calls)\n";
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
    0
}
