//! Real process entry point: a raw `global_asm!` trampoline that captures the incoming `RSP`
//! (`argc`/`argv[]`/`envp[]`/`auxv[]`, per the System V AMD64 ABI's initial-stack layout, see
//! `sys/process/user_stack.rs`'s own `build()` for the kernel-side counterpart that lays this out)
//! *before* any Rust-generated function prologue can disturb it -- the same technique validated
//! live in `regress/pie-aslr-smoke/src/main.rs` before being formalized here.

/// Fixed cap on how many `argv[]` entries `parse_argv` records -- no `alloc` in a freestanding
/// binary like this one, so this is a plain stack array, not a `Vec`. Generous for any of the 12
/// native utilities this crate serves (none take anywhere close to 16 real arguments).
pub const MAX_ARGS: usize = 16;

/// Walks `argc` then `argv[0..argc]` off the real initial stack `stack_ptr` points at, returning a
/// fixed-size array of the first `MAX_ARGS` entries (as real, NUL-terminated C strings -- scanned
/// for their own length here, matching how a real libc's own `crt1` reads them) plus the real
/// count (capped at `MAX_ARGS`). Every returned slice is `'static`: the initial stack persists for
/// this process's entire lifetime.
pub fn parse_argv(stack_ptr: *const u64) -> ([&'static [u8]; MAX_ARGS], usize) {
    let argc = unsafe { *stack_ptr } as usize;
    let mut argv: [&'static [u8]; MAX_ARGS] = [&[]; MAX_ARGS];
    let n = argc.min(MAX_ARGS);
    for (i, slot) in argv.iter_mut().enumerate().take(n) {
        let ptr = unsafe { *stack_ptr.add(1 + i) } as *const u8;
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        *slot = unsafe { core::slice::from_raw_parts(ptr, len) };
    }
    (argv, n)
}

/// Expands to a real `_start` (a `global_asm!` trampoline landing in a `#[unsafe(no_mangle)]`
/// dispatcher that parses `argv` and calls `$main`) plus this crate's own `#[panic_handler]`
/// pull-in. `$main` must be `fn(&[&[u8]]) -> u64` (the real argv slice, including `argv[0]`; the
/// return value becomes this process's real exit code via `SYS_EXIT`).
#[macro_export]
macro_rules! entry_point {
    ($main:path) => {
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            "mov rdi, rsp",
            "and rsp, -16",
            "call {real_start}",
            "ud2",
            real_start = sym __oxlibc_real_start,
        );

        #[unsafe(no_mangle)]
        extern "C" fn __oxlibc_real_start(stack_ptr: *const u64) -> ! {
            let (argv, argc) = $crate::entry::parse_argv(stack_ptr);
            let code = $main(&argv[..argc]);
            $crate::exit::exit(code)
        }
    };
}
