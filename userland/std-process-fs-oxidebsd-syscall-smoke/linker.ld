/* Load base 0x12b00000 -- next free slot past userland/std-hello-oxidebsd-syscall-smoke's own
 * 0x12a00000 (the highest in this "-syscall-smoke" Rust family as of this crate's own addition).
 * Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting
 * this if the kernel image has grown meaningfully since. */
ENTRY(_start)

SECTIONS
{
    . = 0x12b00000;

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
