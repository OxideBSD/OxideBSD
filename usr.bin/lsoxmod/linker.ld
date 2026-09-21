/* Load base 0x80c0000 -- next slot in the "real seeded /bin utility" sequence (stsh 0x8000000,
 * fork-exec-smoke 0x8040000, ring3-smoke 0x8080000, each 0x40000 apart), not the separate
 * 0xf000000+-stepped sequence regress/*-syscall-smoke/ uses for tests/*.rs's own spawned test
 * binaries -- lsoxmod is a real embedded /bin executable (see sys/modules/oxfs/src/lib.rs's own
 * seed_file(bin, b"lsoxmod", ...) call), the same category stsh/ring3-smoke are in, not a test.
 * See regress/ring3-smoke/linker.ld's own comment for the full "why this address, and why it's
 * moved before" story -- re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd |
 * grep -A1 LOAD` (highest VirtAddr + MemSiz) before trusting this if the kernel image has grown
 * meaningfully since this was picked. */
ENTRY(_start)

SECTIONS
{
    . = 0x80c0000;

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
