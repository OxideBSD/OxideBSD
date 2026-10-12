/* Load base 0x12800000 -- next free slot past regress/fb-mmap-syscall-smoke's own 0x12700000 as
 * of this crate's own addition. Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd |
 * grep -A1 LOAD` before trusting this if the kernel image has grown meaningfully since this was
 * picked. */
ENTRY(_start)

SECTIONS
{
    . = 0x12800000;

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
