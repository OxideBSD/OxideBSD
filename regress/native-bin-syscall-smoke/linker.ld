/* Load base 0x12e00000 -- next slot past the highest fixed userland address already in use
 * (0x12d00000, pie-aslr-driver) -- re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` (highest VirtAddr + MemSiz) before
 * trusting this if the kernel image has grown meaningfully since this was picked. A plain,
 * fixed-ET_EXEC test driver (pid 1); the utilities it exercises are the real PIE binaries. */
ENTRY(_start)

SECTIONS
{
    . = 0x12e00000;

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
