# OxideBSD 0.2.0

A real, usable snapshot of current progress on top of `0.1.x` — not a promise of API/ABI stability
between minors (`0.x` releases stay unstable). This release's focus was closing the gap to real
POSIX conformance and the foundational work that required (real threading, a real boot protocol
with UEFI support, real preemption, real memory reclaim). See `OxideBSD-doc/ROADMAP.md`/`CLAUDE.md`
for the full plan this project is working toward; `1.0.0` is reserved for the day OxideBSD can
rebuild itself from source with no host OS involved (see "Not in this release," below).

## What's new since 0.1.0

- **Real UEFI boot, via Limine.** Migrated off the BIOS-only, unmaintained `bootloader` v0.9 crate
  to the Limine boot protocol — a real hybrid BIOS+UEFI ISO, higher-half kernel placement, and a
  from-scratch framebuffer console (no more relying on `bootloader`'s guaranteed `0xb8000` VGA
  mapping). This is what makes real, non-QEMU hardware boot possible at all.
  - **Real USB input**: an xHCI host-controller driver plus a HID Boot Protocol keyboard — this
    kernel's first real-hardware (not just QEMU) input path, closing the gap for hardware with no
    PS/2 controller (e.g. a Surface Pro).
  - **A real framebuffer console** (`/dev/fb0`, real `mmap`-backed) and a general raw
    keyboard-event source, proven end-to-end by a real, playable port of Doom.
- **Real threading.** `clone(2)`, a genuinely unmodified `pthread_create()`/`pthread_join()` round
  trip, shared address spaces across a thread group, real `futex(2)` (including named/`pshared`
  POSIX semaphores across independent processes). This unlocked POSIX AIO for free (musl/glibc
  both implement it as userspace logic over a thread pool) and is the direct prerequisite for
  everything else in this release's POSIX conformance push.
- **Real ring-3 preemptive scheduling**, not just cooperative round-robin — a real per-process
  quantum, real `FXSAVE`/`FXRSTOR` across every context switch.
- **Real memory reclaim.** A discarded process's address-space frames are now actually freed (at
  exit, not deferred to `wait4`) instead of leaking forever; real `munmap()` returns its frames to
  the allocator instead of leaking them too. No copy-on-write fork yet, but the "no frame
  deallocation anywhere" gap from 0.1.0 is closed for the common case.
- **Real anonymous `PROT_NONE` + scoped `mprotect(2)`** — closes real pthread stack guard pages,
  previously a total no-op.
- **A real fault-to-signal delivery path.** A wild pointer dereference, `#GP`, or illegal
  instruction from any ring-3 program used to reboot the entire kernel; it now terminates just the
  offending process with the correct signal (`SIGSEGV`/`SIGBUS`/`SIGILL`), and a live, responsive
  prompt survives it.
- **A much deeper POSIX/BSD surface**: real `SIGCHLD` delivery, real job control (`SIGSTOP`/
  `SIGTSTP`/`SIGCONT`, `kill(-pgrp)`, colored interactive `hush`), real-time signal queuing,
  POSIX per-process timers, POSIX message queues, all of SysV IPC (message queues, semaphores,
  shared memory), `sigaltstack`/`pause`/`sigsuspend`/`getrandom`/`sysinfo`, real orphan
  reparenting to pid 1, and a real ACPI HPET-backed sub-tick timer overlay for POSIX timer overrun
  accounting.
- **Milestone 1 of real dynamic linking**: a genuinely dynamically-linked ELF, resolved and
  relocated by musl's own real `ld.so` running as the interpreter.
- **A much larger, more accurate POSIX conformance baseline.** The Open POSIX Test Suite pilot grew
  from a curated 488-file subset to the full ~1687-file corpus (`pthread_*`/`aio_*`/`lio_listio*`
  included now that real threading exists), with a supervised runner and a host-comparison script
  for an apples-to-apples baseline. Last measured: **90.3% raw pass rate / 94.6% excluding
  UNTESTED** — see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md` for the current number and full
  detail; most of the remaining gap is either genuinely-unimplemented optional features or
  confirmed, pre-existing bugs in this project's own vendored musl 1.2.6 (reproduced against
  unmodified host musl, not OxideBSD bugs).
- **Cleanup**: the original hand-written `stsh` shell and the FAT32 filesystem module — both
  superseded early on (by BusyBox's `hush` and `oxfs` respectively) and kept around only for their
  own build/self-check — have been removed entirely.

## Not in this release

- **No SMP.** Still single-core; real multi-core support is a substantial architectural
  undertaking slotted for a later release (see `OxideBSD-doc/ROADMAP.md`'s v0.5.0 entry) — large
  parts of this codebase's locking currently lean on "single core" as a correctness argument, not
  just a performance ceiling.
- **No package manager, no ports system.** Every binary in this image is baked in at build time by
  the host-side `build.rs`; there is no on-target mechanism yet to fetch, build, or install
  software after boot.
- **No self-hosting, no GCC/Clang.** `rustc`/`cargo` do not run under OxideBSD yet; the on-target
  `tcc` (TinyCC) C compiler works but GCC/Clang remain unstarted (both need real multi-process
  subprocess pipelines this release doesn't provide yet). The toolchain that builds this image is
  still entirely host-side.
- Other known kernel-level gaps: no copy-on-write fork (still a full eager copy), no IPv6, no real
  routing table, no module unload/reload. See `CLAUDE.md`'s "Known, deliberate gaps" and
  per-subsystem sections for the complete, current list.

## Building and running

Requires nightly Rust (pinned via `rust-toolchain.toml`), `qemu-system-x86_64` (plus OVMF firmware
for the default UEFI boot path), and a host C toolchain (musl-gcc is built from source as part of
the build; GNU `make` and a host C compiler are required to cross-build musl/BusyBox/TinyCC at
build time). `bootimage` is no longer needed — boot staging is handled by `scripts/qemu_runner.sh`.

```sh
cargo run           # stages a hybrid BIOS+UEFI ISO and boots it in QEMU, serial to stdio
cargo build         # kernel ELF only
cargo test           # integration tests (each boots its own QEMU instance)
```

Linux is the primary supported host; macOS/Windows are untested.
