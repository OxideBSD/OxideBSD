/* Load base 0x13000000: next in the stepped-by-0x100000 sequence of the real-SYSCALL smoke
 * tests (see regress/socketpair-syscall-smoke/linker.ld). Each output section starts on its own
 * page, so no page holds both code and data (W^X: the test checks that data isn't executable). */
ENTRY(_start)

SECTIONS
{
    . = 0x13000000;

    .text : {
        *(.text*)
    }

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
