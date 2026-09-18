/* Load base 0x10100000 -- next free slot past the stepped-by-0x100000 real-SYSCALL smoke test
 * sequence (userland/tcc-syscall-smoke/linker.ld's own comment has the full history), skipping
 * 0x10000000 itself since that collides with `src/process/lifecycle.rs`'s own real
 * `INTERP_LOAD_BASE`. Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1
 * LOAD` before trusting this if the kernel image has grown meaningfully since this was picked.
 * Distinct from `clang`'s own load base (built on the host, cross-compiled -- see build.rs's
 * `build_llvm_target_toolchain`) and `hello.elf`'s (compiled by `clang` itself at test run time,
 * wherever its own default link base lands it). */
ENTRY(_start)

SECTIONS
{
    . = 0x10100000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note*)
    }
}
