/* Load base 0x12100000 -- clear of both the pilot's own embedded range (POSIX_TEST_LOAD_BASE =
 * 0x10f40000, stepping by 0x40000 across 68 entries -> ceiling ~0x12040000, see build.rs's own
 * write_posix_test_manifest) and t0's own 0x10f00000, not just "next in the stepped-by-0x100000
 * sequence" the way every earlier smoke-test crate's own linker.ld picked (that sequence tops out
 * at 0x10f00000, which the pilot range now starts right after). Re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting this if the kernel image
 * has grown meaningfully since this was picked.
 *
 * The explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` below is load-bearing, not cosmetic --
 * same fix `regress/sa-siginfo-syscall-smoke/linker.ld` already documents in full: this crate has
 * real writable globals, and without forcing them onto their own page, this tiny binary's RW
 * `.got`/`.data`/`.bss` `PT_LOAD` segment can share a physical page with the RX `.text`/`.rodata`
 * segment -- `sys/process/elf.rs`'s loader doesn't union permission flags across `PT_LOAD`
 * segments sharing one page (CLAUDE.md's own documented "known simplification"). */
ENTRY(_start)

SECTIONS
{
    . = 0x12100000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    . = ALIGN(0x1000);

    .got : {
        *(.got*)
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
