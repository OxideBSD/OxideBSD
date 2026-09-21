/* Load base 0x10c00000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... sysv-sem-syscall-smoke 0x10b00000 -- see regress/socketpair-syscall-smoke/
 * linker.ld's own comment for the full "why this address" story). Re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting this if the kernel image
 * has grown meaningfully since this was picked.
 *
 * The explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` below is the same defensive workaround
 * every crate in this stepped sequence applies (see `regress/sa-siginfo-syscall-smoke/linker.ld`'s
 * own comment for the full story) -- this crate doesn't strictly need real writable globals, but
 * it's cheap insurance against the same `sys/process/elf.rs` PT_LOAD-segment-sharing-a-page issue
 * regardless. */
ENTRY(_start)

SECTIONS
{
    . = 0x10c00000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    . = ALIGN(0x1000);

    .got : {
        *(.got*)
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
