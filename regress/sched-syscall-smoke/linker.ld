/* Load base 0x11100000 -- next in the stepped-by-0x100000 sequence, right after
 * regress/clock-syscall-smoke/linker.ld's own 0x11000000 (see that file's own comment for the full
 * "why this address" story). Confirmed clear as of this crate's own addition (kernel's own highest
 * LOAD segment currently ends well under 0x3000000). */
ENTRY(_start)

SECTIONS
{
    . = 0x11100000;

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
