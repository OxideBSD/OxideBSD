/* Load base 0x10f00000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established (... posix-conformance-driver 0x10e00000 -- see regress/socketpair-syscall-smoke/
 * linker.ld's own comment for the full "why this address" story). Deliberately *not* colliding
 * with build.rs's own POSIX_TEST_LOAD_BASE (also 0x10f00000, for the vendored Open POSIX Test Suite
 * pilot's host-compiled binaries) despite the shared address -- that range is only ever loaded via
 * a real fork+execve from a running `sh` inside a *different* boot (the posix-conformance-driver
 * scenario), never co-resident with this crate's own dedicated single-pid1-binary test boot. Still,
 * re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before trusting
 * this if the kernel image has grown meaningfully since this was picked.
 *
 * The explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` below is load-bearing, not cosmetic --
 * same fix `regress/sa-siginfo-syscall-smoke/linker.ld` already documents in full: this crate has
 * real writable globals (handler-invocation-order bookkeeping), and without forcing them onto
 * their own page, this tiny binary's RW `.got`/`.data`/`.bss` `PT_LOAD` segment can share a
 * physical page with the RX `.text`/`.rodata` segment -- `sys/process/elf.rs`'s loader doesn't
 * union permission flags across `PT_LOAD` segments sharing one page (CLAUDE.md's own documented
 * "known simplification"). */
ENTRY(_start)

SECTIONS
{
    . = 0x10f00000;

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
