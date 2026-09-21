/* Load base 0xf000000: well clear of every existing fixed userland base (stsh 0x8000000,
 * fork-exec-smoke 0x8040000, ring3-smoke 0x8080000, musl-smoke 0x80c0000) and of the entire
 * BusyBox applet range (0x8100000-0xe200000, see build.rs's BUSYBOX_APPLETS/_PASS2 lists), while
 * staying well below MODULE_VA_BASE (0x10000000) -- see src/address_space.rs and CLAUDE.md's
 * "User-mode execution" section for why these ranges matter (a new address space shallow-copies
 * the kernel's own page tables, so this binary's segments must not collide with anything mapped
 * there). Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before
 * trusting this if the kernel image has grown meaningfully since this was picked. */
ENTRY(_start)

SECTIONS
{
    . = 0xf000000;

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
