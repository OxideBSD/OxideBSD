/* Load base 0x12f00000: next in the stepped-by-0x100000 sequence of the real-SYSCALL smoke
 * tests (see regress/socketpair-syscall-smoke/linker.ld). */
ENTRY(_start)

SECTIONS
{
    . = 0x12f00000;

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
