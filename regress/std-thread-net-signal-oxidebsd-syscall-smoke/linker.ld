/* Load base 0x12c00000 -- next free slot past regress/std-process-fs-oxidebsd-syscall-smoke's
 * own 0x12b00000 (the highest in this "-syscall-smoke" Rust family as of this crate's own
 * addition). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD`
 * before trusting this if the kernel image has grown meaningfully since. */
ENTRY(_start)

SECTIONS
{
    . = 0x12c00000;

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
