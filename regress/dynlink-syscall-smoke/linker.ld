/* Load base 0x10100000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... tcc-syscall-smoke 0xfd00000, access-syscall-smoke 0xfe00000,
 * pipe-backpressure-syscall-smoke 0xff00000 -- see regress/socketpair-syscall-smoke/linker.ld's
 * own comment for the full "why this address" story), stepped past 0x10000000 rather than
 * continuing directly from 0xff00000 -- 0x10000000 is where build.rs's `build_musl_sysroot_shared`
 * fixes the dynamic-linking milestone's own `libc.so`/interpreter, and this crate's own address
 * has no real reason to sit adjacent to it. Re-derive via
 * `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting this if the
 * kernel image has grown meaningfully since this was picked. This crate never coexists with
 * `dynlink-smoke.elf`/`libc.so` in the same address space -- it forks and execve's them into a
 * fresh child address space entirely, so no real collision risk exists either way. */
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
