/* Load base 0xf200000 -- see regress/socketpair-syscall-smoke/linker.ld's own comment for the
 * full "why this address" story; each real-SYSCALL network smoke test gets its own base, stepped
 * by 0x100000 from there. */
ENTRY(_start)

SECTIONS
{
    . = 0xf200000;

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
