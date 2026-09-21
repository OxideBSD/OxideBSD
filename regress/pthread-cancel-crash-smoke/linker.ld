/* Load base 0x12500000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... pthread-syscall-smoke 0x12300000, sem-open-syscall-smoke 0x12400000, the
 * current highest -- see regress/socketpair-syscall-smoke/linker.ld's own comment for the full
 * "why this address" story). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd |
 * grep -A1 LOAD` before trusting this if the kernel image has grown meaningfully since this was
 * picked.
 *
 * This crate itself is a bare fork+execve+wait4 driver with no writable globals of its own worth
 * worrying about, but the explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` matches every other
 * smoke-test crate's own linker script regardless -- see `regress/sa-siginfo-syscall-smoke/
 * linker.ld`'s own comment for the real bug this guards against (a small binary's RW segment
 * silently sharing a page with the RX one, `sys/process/elf.rs`'s own documented "known
 * simplification": it doesn't union permission flags across `PT_LOAD` segments sharing one page). */
ENTRY(_start)

SECTIONS
{
    . = 0x12500000;

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
