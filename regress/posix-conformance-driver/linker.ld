/* Load base 0x10e00000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (sig-syscall-smoke 0x10d00000 most recently -- see
 * regress/socketpair-syscall-smoke/linker.ld's own comment for the full "why this address"
 * story). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before
 * trusting this if the kernel image has grown meaningfully since this was picked. */
ENTRY(_start)

SECTIONS
{
    . = 0x10e00000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    . = ALIGN(0x1000);

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
