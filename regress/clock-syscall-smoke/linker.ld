/* Load base 0x11000000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... sig-syscall-smoke 0x10d00000, posix-conformance-driver 0x10e00000,
 * rt-signal-syscall-smoke 0x10f00000 -- see regress/socketpair-syscall-smoke/linker.ld's own
 * comment for the full "why this address" story). Re-derive via `readelf -l
 * target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting this if the kernel image
 * has grown meaningfully since this was picked -- confirmed clear as of this crate's own addition
 * (kernel's own highest LOAD segment currently ends well under 0x3000000).
 *
 * The explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` below matches every other real-SYSCALL
 * smoke test's own linker script even though this crate has no writable statics of its own today
 * (everything's stack-local) -- cheap insurance against the exact `elf.rs` PT_LOAD-segment-sharing-
 * a-page bug `regress/sa-siginfo-syscall-smoke/linker.ld`/`regress/pause-syscall-smoke/linker.ld`
 * already document in full, the moment a future edit adds one. */
ENTRY(_start)

SECTIONS
{
    . = 0x11000000;

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
