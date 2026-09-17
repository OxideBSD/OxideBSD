/* Load base 0x12900000 -- next free slot past userland/keyevent-syscall-smoke's own 0x12800000
 * (the highest in this "-syscall-smoke" Rust family as of this crate's own addition), clear of
 * doomgeneric's 0x13000000 and the std-hello spike binary's own 0x14000000 (build.rs's
 * build_std_hello_spike -- a wholly separate address-space slot, since std-hello is `execve`'d as
 * its own process, not linked into this driver). Re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting this if the kernel image
 * has grown meaningfully since. */
ENTRY(_start)

SECTIONS
{
    . = 0x12900000;

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
