/* Load base 0x13200000: next in the stepped-by-0x100000 sequence of the real-SYSCALL smoke tests
 * (see regress/trap-syscall-smoke/linker.ld). Each output section starts on its own page (W^X). */
ENTRY(_start)

SECTIONS
{
    . = 0x13200000;

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
