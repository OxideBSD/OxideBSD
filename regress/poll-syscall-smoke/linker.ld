/* Load base 0xf300000 -- see regress/socketpair-syscall-smoke/linker.ld's own comment for the
 * full "why this address" story; each real-SYSCALL network smoke test gets its own base, stepped
 * by 0x100000 from there. */
ENTRY(_start)

SECTIONS
{
    . = 0xf300000;

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
