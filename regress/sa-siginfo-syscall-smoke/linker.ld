/* Load base 0x10200000 -- next in the stepped-by-0x100000 sequence the real-SYSCALL smoke tests
 * established, right past dynlink-syscall-smoke's own 0x10100000 -- see
 * regress/socketpair-syscall-smoke/linker.ld's own comment for the full "why this address"
 * story. Re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD` before
 * trusting this if the kernel image has grown meaningfully since this was picked (currently tops
 * out well under 0x2000000, so 0x10200000 has enormous headroom).
 *
 * The explicit `ALIGN(0x1000)` before `.got`/`.data`/`.bss` below is load-bearing, not cosmetic --
 * this is the first userland crate in this codebase with real writable globals (the `AtomicBool`/
 * `AtomicI64`/... statics the SA_SIGINFO handler records into; every earlier `*-syscall-smoke`
 * crate keeps its own mutable state on the stack instead). Without it, this crate's tiny total
 * size let the RW `.got`/`.data`/`.bss` `PT_LOAD` segment share the same 4 KiB page as the RX
 * `.text`/`.rodata` segment -- and `sys/process/elf.rs`'s loader doesn't union permission flags
 * across `PT_LOAD` segments sharing one physical page (a real, already-documented "known
 * simplification" in CLAUDE.md's own user-mode-execution section), so the shared page silently
 * kept only the first segment's R/E flags. Found live: this crate's very first static write
 * page-faulted (`PROTECTION_VIOLATION | CAUSED_BY_WRITE | USER_MODE`) before the SA_SIGINFO logic
 * under test ever ran. Forcing the writable segment onto its own page is the narrow, kernel-side-
 * untouched fix -- see CLAUDE.md's own user-mode-execution section (`elf::load`'s doc bullet) for
 * the broader `elf.rs` flag-union gap this incidentally confirmed live, which stays a separate,
 * not-yet-scoped fix. */
ENTRY(_start)

SECTIONS
{
    . = 0x10200000;

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
