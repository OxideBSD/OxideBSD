/* Load base 0x12d00000 -- next slot past the highest fixed userland address already in use
 * (0x12c00000, see every other regress crate's own linker.ld) -- re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` (highest VirtAddr + MemSiz) before
 * trusting this if the kernel image has grown meaningfully since this was picked. A plain,
 * fixed-ET_EXEC binary (unlike its own sibling pie-aslr-smoke, which deliberately has no linker
 * script at all -- see that crate's own build.rs) since this one only orchestrates real
 * fork/execve/wait4 syscalls and never itself needs a kernel-assigned bias. */
ENTRY(_start)

SECTIONS
{
    . = 0x12d00000;

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
