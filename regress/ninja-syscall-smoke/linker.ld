/* ninja-syscall-smoke: same load base as regress/clang-syscall-smoke (0x10100000) -- each test boots its own kernel,
 * so slots only need to be unique within one boot. See that file's comment for the history. */
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
