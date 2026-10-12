/* Load base 0xfe00000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... needs-syscall2 0xfc00000, tcc-syscall-smoke 0xfd00000 -- see
 * regress/socketpair-syscall-smoke/linker.ld's own comment for the full "why this address"
 * story). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before
 * trusting this if the kernel image has grown meaningfully since this was picked. */
ENTRY(_start)

SECTIONS
{
    . = 0xfe00000;

    .text : {
        *(.text*)
    }

    /* W^X: code, read-only data and writable data never share a page. */
    . = ALIGN(4096);

    .rodata : {
        *(.rodata*)
    }

    . = ALIGN(4096);

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
