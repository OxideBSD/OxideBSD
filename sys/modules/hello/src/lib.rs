//! The first, deliberately trivial OxideBSD kernel module — proves the dynamic module loader
//! (`sys/module.rs`) can relocate real, independently-compiled code into the running kernel,
//! resolve a call into the kernel's own exported API by name, and invoke `module_init`, before
//! anything more substantial (the native syscall ABI, FAT32) is built on top of it.
//!
//! Not linked with the kernel in any normal sense: this crate is compiled to a standalone
//! relocatable object (see `build.rs`'s `build_module_crate`), merged at build time against the
//! exact `core`/`alloc`/`compiler_builtins` the kernel's own `-Z build-std` produced, and only
//! resolved against the kernel's live symbol table at boot. See `CLAUDE.md`'s module-loading
//! section for the full design.
#![no_std]

unsafe extern "C" {
    /// Kernel-exported logging function (`sys/module.rs`) — writes `len` bytes at `ptr` to the
    /// kernel's serial/VGA console. Modules don't use `alloc`, so there's no `&str`/`String` to
    /// pass across the module boundary directly; a raw pointer + length is the simplest shape
    /// that survives relocation without needing a shared ABI crate (matches how the userland ELF
    /// boundary already hand-duplicates syscall constants rather than sharing a crate).
    fn oxidebsd_log(ptr: *const u8, len: u64);
}

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

/// Called by `sys/module.rs` once this module has been relocated and mapped. Return value is
/// logged by the loader; `0` means success by convention (no module actually fails to init yet,
/// so there's no real failure path to exercise here).
#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    log("[module] hello: module_init running\n");
    0
}
