# OxideBSD Roadmap

OxideBSD is a 100% Rust BSD-like operating system. The plan is three phases, each a prerequisite
for the next.

## Phase 1 — Minimal environment: a running, interactive kernel

**Goal:** a kernel that boots, stays up, and gives you a shell to type into — not just a kernel
that boots and halts.

**Status:** done. GDT/TSS/IDT with a dedicated double-fault stack, PIC-driven interrupts (timer +
keyboard), a heap allocator, a VGA console, and a real interactive shell all exist — see
`CLAUDE.md` for full detail. (`stsh`, the original hand-written shell described below, has since
been superseded as pid 1 by BusyBox's `hush` — see Phase 2.)

Milestones, roughly in dependency order:

- **CPU structures** — GDT, TSS, IDT, with exception handlers and a separate stack for double
  faults (a bug here otherwise triple-faults and silently reboots the VM).
- **Interrupts** — PIC (or APIC) initialization, a timer tick (PIT or APIC timer), and a keyboard
  IRQ handler.
- **Heap allocation** — a global allocator so `alloc` (`Vec`, `String`, `Box`, ...) is usable; a
  lot of later work assumes this exists.
- **Console output** — VGA text-mode buffer as the primary display (serial has been the console so
  far and can remain the logging/debug channel).
- **Keyboard input** — scancode-to-keycode translation (e.g. via the `pc-keyboard` crate) feeding
  a line-editing input buffer.
- **Shell** — a command loop that reads a line, dispatches to a small set of built-ins (`help`,
  `echo`, memory/heap stats, a deliberate panic for testing the panic handler, etc.), and loops
  forever instead of halting.

Phase 1 is "done" when the kernel boots into that shell and stays responsive to input indefinitely
— met.

## Phase 2 — Getting Rust running on it

**Goal:** run actual Rust programs under OxideBSD — not the kernel binary itself, but separate
programs the kernel loads and executes. The end target of this phase is running `rustc`/`cargo`
themselves as userland programs.

**Status:** far along, but not "done" by this phase's own stated bar. Every milestone below is
built except the last — a C libc (musl), not a Rust `std` port, ended up being the actual
libc/userland story that got this phase moving (see `CLAUDE.md`'s musl-port section), and
`rustc`/`cargo` running as OxideBSD processes hasn't been attempted yet. Current work (v0.2.0
closing the POSIX pilot gap, v0.3.0/v0.4.0 deepening the C-toolchain side of userland with
GCC/Clang and glibc — see "Release sequence" below) is deepening the existing C-based userland
story rather than attacking `rustc`/`std` directly — a deliberate detour, not abandonment of this
phase's actual goal.

Depends on phase 1's interactivity, plus:

- **Paging / address spaces** — real virtual memory, one address space per process, page fault
  handling. Done.
- **User/kernel privilege separation** — ring 3 execution, a context switch between processes.
  Done.
- **ELF loading** — load a separate binary from somewhere and execute it as a process. Done.
- **Syscall ABI** — a defined interface for user programs to ask the kernel for services (I/O,
  memory, process control). Done — OxideBSD's own native ABI, see `CLAUDE.md`'s Syscall ABI
  section.
- **A filesystem** — at minimum something to load programs from; doesn't need to be persistent to
  start (an in-memory/initrd-style filesystem is a reasonable first cut). Done and then some —
  `oxfs`, a real Unix-shaped inode/block filesystem with optional disk persistence, superseded an
  earlier, more limited FAT32 implementation.
- **A libc/std story for userland** — either a `#![no_std]`-only userland to start, or porting
  `std` to a custom `x86_64-unknown-oxidebsd` target (the harder but more useful path, since
  `rustc`/`cargo` assume `std`). Landed differently than either option here: a real port of musl
  (a C libc) to this kernel's native syscall ABI, which in turn let BusyBox and a real C compiler
  (`tcc`) run as userland. A Rust `std` port remains undone and is what this phase's "done" bar
  below still actually requires.

Phase 2 is "done" when `rustc` can run as an OxideBSD process and compile a program — not yet met.

## Phase 3 — Self-hosting: OxideBSD builds itself

**Goal:** close the loop — an OxideBSD instance can build a new, bootable OxideBSD image using
only tools running under OxideBSD itself, with no host OS involved.

**Status:** not started on the Rust-toolchain side this phase originally describes. The v0.3.0/
v0.4.0 goals below are a first step toward self-hosting from the C side instead — self-hosting
C-side toolchain components, retiring `tcc` for real GCC/Clang, and a real glibc port — ahead of,
not instead of, eventually closing this loop for `rustc`/`cargo` themselves.

- The full build toolchain (`rustc`, `cargo`, a linker, an assembler) running as userland programs.
- Enough of a POSIX/BSD-like surface (process spawning, file I/O, environment variables, pipes)
  for that toolchain to actually function, not just execute trivial programs.
- Build tooling to fetch/vendor the kernel and userland source trees and drive a full rebuild from
  within the running OS.
- A working bootstrap: boot an OxideBSD image, rebuild OxideBSD from source on it, boot the result.

## Release sequence: v0.2.0 → v0.3.0 → v0.4.0 → v0.5.0 → v0.6.0 → v0.7.0 → v0.8.0 → v0.9.0 → v0.10.0 → v0.11.0 → v1.0.0

As of 2026-09-04, the old single "v0.2.x goals" bucket below is split into separate, sequential
releases — each ships standalone rather than bundling everything into one v0.2.0. v0.5.0 onward
(added 2026-09-12) reflects the user's own longer-term plan past the original three-release split.

- **v0.2.0 — POSIX pilot compliance.** The current focus. **Concrete target (set 2026-09-08):
  >91% raw pass rate, >95% excluding UNTESTED**, on the full corpus via
  `scripts/run_posix_pilot_supervised.sh`. Close as much of the gap as practical
  between OxideBSD's own Open POSIX Test Suite pilot run and a real Unix baseline, using the full
  ~1687-file corpus (not a curated subset — see `CLAUDE.md`'s "POSIX pilot: full corpus expansion"
  section) as the measuring stick. **The real comparison target is literal UNIX and the BSDs
  (FreeBSD/NetBSD/OpenBSD), not Linux** — Linux/glibc is only used today because it's the one host
  actually available to measure against (`scripts/run_posix_pilot_host.sh`, manual/root-only); a
  real BSD-host run of the same corpus would be a truer number and isn't slotted yet (needs a BSD
  box/VM to run it on). Latest measured OxideBSD baseline (2026-09-07, a fresh `--reset`
  full-corpus run, `scripts/run_posix_pilot_supervised.sh`): **87.4%** raw pass rate / **92.8%**
  excluding UNTESTED (1474 PASS / 1686 total; 22 FAIL / 39 UNRESOLVED / 14 CRASH / 11 TIMEOUT / 29
  UNSUPPORTED / 97 UNTESTED — `shm_open/23-1.c` needed excluding again, a known, real single-core
  scheduling-throughput limit, not a new bug). Last real host-side comparison (2026-09-06, not
  re-run this session): the user's Artix (glibc/Linux) host at **89.5%** / **94.3%**, a ~2-point
  gap — the closest available proxy, not the actual target. Closing it means triaging the full
  corpus's own remaining FAIL/UNRESOLVED set, not growing the corpus further — it's already
  complete. Two clusters ruled out this session as real bugs (see `CLAUDE.md`'s own history and
  session memory for detail): `sigaction/17-{2,10,20,25,26}.c`'s FAILs were transient host-load
  timing flakiness (all 5 clean `PASS` in this same fresh run); `aio_suspend`'s 6 and `aio_cancel`'s
  4 UNRESOLVED are a real oxfs file-size-cap gap and an inherent test-timing race respectively,
  neither a quick fix. **Full POSIX syscall coverage** (every POSIX-mandated syscall, even where
  this ABI's own number/shape — see `CLAUDE.md`'s Syscall ABI section — diverges from Linux's or
  any real BSD's; not a promise to match Linux/BSD numbering or wire format) falls out of this same
  push, not a separate goal.
- **v0.3.0 — GCC and Clang self-hosted ports, plus a real Rust `std` target.** What v0.2.0 used to
  target before the 2026-09-04 re-scope (see `CLAUDE.md`'s TinyCC section for why this is a much
  bigger lift than TinyCC — real subprocess pipelines, likely real dynamic linking and threads
  beyond what exists today): self-hosting C-side toolchain components running on-target (moving
  further into Phase 3's "build itself" goal from the C side first), then retiring `tcc` once both
  GCC and Clang are real, working on-target ports — TinyCC was always the first/easiest target,
  never the intended long-term C compiler. **Deferred into this same "toolchain maturity" release
  (2026-09-09)**: a real Rust `std` target for OxideBSD userland — motivated by `rustrc` (the
  user's own from-scratch, OpenRC-inspired init system, `git@github.com:Pomsky2011/RustRC.git`,
  vendored as a submodule at `rustrc/`), which currently only boots as PID 1 on real `std` targets
  (Linux/FreeBSD/NetBSD, some via `-Z build-std`/`cargo-zigbuild` for Tier 2/3) and has no path onto
  OxideBSD without one. Recommended approach (not yet started): link `std` against the existing
  musl fork rather than a from-scratch syscall backend — most of `std::sys::pal::unix`'s own
  assumptions (real threads/futex-mutexes/TCP-UDP/fork-exec) already work correctly against it,
  verified extensively by this same release's own POSIX conformance push. Real work: a new hosted
  userland target spec (distinct from the kernel's own `panic=abort` one), a `sys::pal` backend for
  `target_os = "oxidebsd"` (a fork of Rust's own `library/` sources, same vendor-and-patch pattern
  as `third_party/musl`/`busybox`/`tinycc`), and — the biggest real unknown — a `libc`-crate fork
  declaring this ABI's own struct layouts/constants (it has zero knowledge of this target today).
  Defaulting userland `std` to `panic=abort` sidesteps real unwinding entirely, matching `rustrc`'s
  own existing `Cargo.toml` profile. Scope narrow at first: only what `rustrc` itself needs (process
  spawn/wait, signals, stdio, basic fs), not full `std` fidelity.
- **v0.4.0 — a real glibc port**, alongside (not replacing) the existing native-ABI musl port.
- **v0.5.0 — SMP.** Real multi-core support. A substantial architectural undertaking, not a
  bolt-on: huge parts of this codebase currently lean on "single core" as a real correctness
  argument, not just a performance ceiling — `IA32_SFMASK` clearing `IF` for a syscall's entire
  duration is the *entire* lock-safety reasoning behind most of this kernel's `spin::Mutex` usage
  (see `CLAUDE.md`'s syscall-ABI section), and several already-landed fixes (the scheduler-race
  fix in "Closing a real scheduler race...", `sched_yield/1-1.c`'s own resolution) explicitly
  depend on there being only one core to preempt at all. Real work: per-CPU GDT/TSS/IDT and
  kernel-stack state, genuine SMP-safe locking once two cores can actually execute kernel code
  simultaneously (not just take turns via preemption), ACPI/MADT parsing to discover other cores,
  a real AP (application processor) boot/startup sequence, and IPI-based scheduling/TLB shootdown.
  Not started.
- **v0.6.0 — self-hosting `rustc`/`cargo` on-target.** Distinct from v0.3.0's Rust `std` target
  (which only lets Rust *programs* run on OxideBSD, for `rustrc`'s sake): this is Phase 3's own
  "OxideBSD builds itself" goal, closed from the Rust side specifically — a real `rustc`+`cargo`+
  linker+assembler toolchain running *as OxideBSD userland processes*, capable of rebuilding
  OxideBSD's own kernel and userland from source, on-target, with no host OS involved. v0.3.0's
  `std` target work is the direct prerequisite this builds on (rustc/cargo are themselves real
  `std`-using Rust programs). Not started.
- **v0.7.0 — `oxlibc`.** OxideBSD's own from-scratch native libc (BSD-3-Clause licensed — a
  deliberate licensing choice, not a fork of `relibc` or anything else with different terms),
  standing alongside the existing vendored musl/glibc ports rather than replacing them outright.
  Long-term/deferred until this point in the sequence; not started.
- **v0.8.0 — the graphical update: more advanced graphics.** Builds directly on real
  groundwork already landed ahead of this release: a real `/dev/fb0` character device
  (`process::mm::do_mmap_fb` maps the actual framebuffer's physical MMIO frames into a userland
  process) and a real, general-purpose raw keyboard-event source (`SYS_GET_KEYEVENT`,
  `console::keyevents`) — both deliberately built as general infrastructure, not specific to any
  one program, and proven end-to-end by a real, playable port of Doom (via `doomgeneric`,
  `third_party/doomgeneric`). This future release is where that groundwork grows into something
  closer to a real desktop environment: real mouse support (currently entirely absent — no mouse
  driver exists anywhere in this kernel, PS/2 or USB), a real windowing/compositing model, and
  real display-mode negotiation beyond whatever Limine's boot-time GOP/VBE choice happens to be.
  Not started beyond the v0.2.0-era groundwork above.
- **v0.9.0 — the hardware support update.** Broader real hardware support by porting drivers from
  Linux/BSD sources (**license terms need real, per-driver scrutiny** — not a blanket "copy it
  over," since Linux's GPL and the BSDs' own licenses aren't interchangeable with this project's
  own). This is also the real-hardware readiness gate for actually switching the user's own
  Surface Pro over to OxideBSD as a daily driver (see `CLAUDE.md`'s USB/xHCI section — the Surface
  has no PS/2 controller at all, already closed — real WiFi/networking hardware and real graphics
  acceleration are the remaining pieces this release would need to close). Not started.
- **v0.10.0 — the package manager update.** A real package manager — no such infrastructure exists
  anywhere in this project today (BusyBox/tcc/musl/etc. are all baked into the kernel image itself
  via `build.rs`, not independently installable). Not started, not yet designed.
- **v0.11.0 — v1.0.0 prep.** A stabilization/hardening pass ahead of a real 1.0 release; specific
  scope not yet defined.

A separate idea — replacing some BusyBox utilities with Rust `uutils` ahead of GCC/Clang — was
raised and set aside: not a real dependency of GCC/Clang bring-up (unrelated subsystems), just a
possible future nice-to-have, not currently sequenced into this list.

**Real text editors: `nano` and real `vim`** — BusyBox's roster today only has the small `vi`
applet (see `docs/BUSYBOX_APPLETS.md`); `nano` and full (non-BusyBox) `vim` are separate ports, for
meaningfully better on-target text editing than the current applet-only story — not yet slotted
into a specific release above.

**`SCHED_SPORADIC` (POSIX Sporadic Server)** — the real-time scheduling policy behind
`sched_setscheduler`/`sched_setparam`'s 13 `UNSUPPORTED` `_POSIX_SPORADIC_SERVER`-gated
conformance files: a thread alternates between a normal and a low priority based on a real
execution-time budget/replenishment-period pair, bounding an aperiodic task's CPU share without
breaking periodic real-time schedulability analysis (an RTOS-space feature — QNX/VxWorks/RTEMS,
not something glibc or upstream musl implement either). Doesn't move the Linux/glibc comparison
number at all (real Linux distros are `UNSUPPORTED` here too) but would be a genuine feature this
kernel doesn't have. Real implementation needs an extended `struct sched_param` (musl header
patch), a per-thread budget/priority state machine, and timer-driven replenishment — a new
scheduling primitive, not a quick fix. Not yet slotted into a specific release.
