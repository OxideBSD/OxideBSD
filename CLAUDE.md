# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project

OxideBSD is a 100% Rust-based BSD-like OS, x86_64 only (see `OxideBSD-doc/ROADMAP.md` for phase history).
Current state:

- Boots via `bootloader` v0.9 + `bootimage`/QEMU. GDT/TSS/IDT with a dedicated double-fault
  stack, PIC-driven interrupts (timer + PS/2 keyboard), a VGA console mirroring serial, a heap
  allocator over bootloader-provided paging.
- Separate per-process address spaces, ELF64 loading, ring-3 execution, and a native BSD-style
  syscall ABI over `SYSCALL`/`SYSRETQ` (`src/syscall/mod.rs`) with carry-flag error signaling.
- A dynamic kernel module loader (`src/module.rs`) relocates `#![no_std]` code into the kernel at
  boot and resolves symbol references against a hand-curated kernel API. Syscall handlers are
  registered by modules, not hardcoded: `modules/native_abi/` (core syscalls), `modules/
  posix_compat/` (pipe/dup2/ioctl/setpgid/...), `modules/signal/` (kill/sigaction/...),
  `modules/oxfs/` (the live filesystem).
- `modules/oxfs/` is a real in-memory Unix-shaped inode/block filesystem (real names,
  multi-component paths, per-process cwd, no fixed file-size cap) — replaced `modules/fat32/`
  (8.3 names, one path component per call, fixed file cap), which still builds/self-checks via
  `cargo build` but is no longer loaded at boot.
- A real process table + scheduler (`src/process/`) with `fork`/`execve`/`wait4`/`getpid`, real
  `argv`/`envp` passthrough, blocking pipes, per-process signal delivery, real ring-3 preemption
  (see "Real preemptive scheduling"), and real threading (`clone(2)`/`pthread_create`, see "Real
  threading").
- pid 1 is BusyBox's `hush`, built against a patched musl fork — not the original hand-written
  `userland/stsh/` shell (still buildable, no longer wired up). 256 BusyBox applets run as
  standalone static binaries, `execve`'d individually (not a multi-call `busybox` binary
  dispatching on `argv[0]` — that passthrough exists now, but the roster hasn't been rebuilt to
  use it).
- A real networking stack (`src/drivers/pci.rs`, `src/net/*`, `modules/net/`): PCI + an rtl8139
  driver, Ethernet/ARP/IPv4/ICMP, UDP/TCP/raw-ICMP sockets, `poll(2)`, and real hostname
  resolution over musl's own DNS stub resolver (no DNS protocol code of its own) — see "Real
  networking" below.
- A real, on-target C compiler (`third_party/tinycc`, vendored TinyCC) — `tcc` runs as an ordinary
  seeded `/bin` binary and can genuinely compile+link a real C file against a real, seeded
  `/usr/include`/`/usr/lib` musl tree, producing a real runnable ELF — see "TinyCC" below. Real
  `futex(2)` and milestone 1 of real dynamic linking (`PT_INTERP`, see "Dynamic linking" below)
  also exist — but GCC/Clang remain unstarted: both need real multi-process subprocess pipelines
  (`cc1`/`as`/`ld` as separate `fork`+`execve`d binaries) neither of the above by itself provides.

Known, deliberate gaps: no pointer validation in `sys_read`/`sys_write`, no module unload/reload,
no *kernel-mode* preemption (real ring-3/user-mode preemption exists), no copy-on-write fork, no
frame deallocation for module-loaded code/SysV-shm-or-`MAP_SHARED`-owned frames (real reclaim
exists for the common case — a discarded process's own private address-space frames — see "POSIX
conformance pilot" below), `sys_read` on stdin is non-blocking (busy-polled by userland), no
general block-device-agnostic VFS/mount-table layer (a real ATA disk driver + oxfs mount/format
persistence + a scoped bind/tmpfs mount table exist now — see "Real disk persistence"/"Mount
table" — but only for oxfs's own fixed backing store), no IPv6, no real routing table (one
default-gateway rule only). See "BusyBox gap analysis" below for what's needed to go further.
Architecture decisions for remaining subsystems haven't been made — discuss with the user before
large structural commitments.

## Toolchain

- Nightly Rust, pinned via `rust-toolchain.toml`. Load-bearing unstable features: `-Z build-std`
  (no prebuilt std for the custom target), `-Z json-target-spec`, `-Z panic-abort-tests`.
- Requires `bootimage` (`cargo install bootimage`) and `qemu-system-x86_64` on `PATH`.
- `.cargo/config.toml` sets the default target to `x86_64-oxidebsd.json` and
  `runner = "bootimage runner"`.

## Commands

- `cargo build` — kernel ELF only
- `cargo bootimage` — bootable disk image
- `cargo run` — boot in QEMU, serial to stdio
- `cargo test` / `cargo test --test basic_boot` — each target boots its own QEMU instance (slow;
  no fast check path exists)
- `cargo clippy` / `cargo fmt`

These commands at the repo root only target the `oxidebsd` package. `userland/*` and `modules/*`
are separate workspace members that the root `build.rs` cross-builds as a side effect of building
`oxidebsd`. To build one directly: `--manifest-path <dir>/<name>/Cargo.toml --target-dir
target/userland` (or `target/modules`) — a separate target dir avoids a nested-cargo lock deadlock
against the outer build. `modules/fat32/` additionally needs `FAT32_IMAGE_PATH` set when built
this way (normally supplied by the root `build.rs`).

## Test architecture

No libtest — `no_std`, tests boot in QEMU and self-report via `src/qemu.rs` (writes to the
`isa-debug-exit` port; `test-success-exit-code` in `Cargo.toml` must stay in sync with
`QemuExitCode::Success`) and `src/console/serial.rs` (hand-rolled 16550 UART, read via `-serial
stdio`).

- `src/lib.rs` defines `no_std` test scaffolding (`custom_test_frameworks`, `#[test_case]`) and
  boots itself under `#[cfg(test)]`.
- `tests/*.rs` integration tests use `harness = false` — each defines its own `fn main()` via
  `entry_point!` and calls `exit_qemu()` directly.
- `tests/fork_wait.rs` + `userland/fork-exec-smoke/`: since `scheduler::start`/`process::do_exit`
  never return to a test's own `main`, it registers a syscall number (`9999`) directly via
  `oxidebsd::syscall::oxidebsd_register_syscall` (kept `pub` for this) whose handler calls
  `exit_qemu`.
- **Any test claiming to verify syscall-reachable code should spawn a real ELF and go through an
  actual `SYSCALL` instruction**, not call kernel handlers as plain Rust functions from a test's
  own `main()` — interrupts stay enabled and `ticks()` keeps advancing in the latter, hiding real
  bugs (see "Real networking" gotcha 2 below). Established pattern (`tests/*_syscall_smoke.rs` +
  `userland/*-syscall-smoke/`) for anything syscall-shaped added from here on.
- Anything needing live interactive keyboard input (real Ctrl+C→SIGINT, `su`/`login` prompts,
  `sulogin`/`getty` tty takeover, persistence surviving a real QEMU restart, any `reboot`/halt/
  poweroff success path) used to be flatly manual-QEMU-only — **partially superseded**: plain
  keystroke injection (typing, Ctrl+C/Ctrl+Z/held-key-for-autorepeat) genuinely can be scripted
  headlessly via the QEMU monitor's own `sendkey <combo> [hold-ms]` command (see the USB-input
  section's own `OXIDEBSD_QEMU_MONITOR` doc comment) — this is how a real Ctrl+C/Ctrl+D bug got
  found and confirmed fixed without a human at a display. Still genuinely manual-only: anything
  needing a real human *decision* mid-session (`su`/`login`/`sulogin` credential entry), and
  persistence-across-a-real-restart/`reboot`/halt/poweroff (there's no scripted way to observe the
  VM coming back up cleanly, only to send keys into an already-running one) — hand those to the
  user rather than trying to drive them via a backgrounded `cargo run`.

## Custom target spec (`x86_64-oxidebsd.json`)

- `target-pointer-width`/`target-c-int-width` must be numbers, not strings.
- Float returns need both `"features": "...,+soft-float"` and `"rustc-abi": "softfloat"`, or
  `core`/`compiler_builtins` fail to build.
- `panic-strategy: "abort"` is the only supported strategy — hence `-Z panic-abort-tests` in
  `.cargo/config.toml` (otherwise Cargo builds an unwind-based test harness and produces a second,
  ABI-incompatible `core`).
- SSE/MMX disabled, `disable-redzone: true` (interrupt handlers can't safely use either).

## Memory management (`src/memory/mod.rs`, `src/memory/allocator.rs`)

- `memory::init` walks `CR3` and adds `BootInfo::physical_memory_offset` to get a virtual pointer
  to the level-4 table. Call at most once — hands out a `&'static mut`.
- `memory::BootInfoFrameAllocator` bump-allocates from `BootInfo::memory_map`'s `Usable` regions.
  Holds plain `(region_index, frame_number)` cursor state, not a rebuilt-each-call iterator (the
  old approach was O(n²)). **A boxed-iterator "fix" is wrong, not just suboptimal**: this
  allocator is constructed *before* `allocator::init_heap` (which needs it to map the heap's own
  pages), so any heap allocation inside its own constructor panics with no heap yet to satisfy it.
  Gained a real `FrameDeallocator` impl later — see "POSIX conformance pilot" below.
- `allocator::init_heap` and `module::map_region` map freshly allocated pages with `.ignore()`,
  not `.flush()` — a never-before-mapped page has no stale TLB entry, and `invlpg` is individually
  trapped under QEMU's software TCG.
- The heap lives at a fixed VA (`allocator::HEAP_START`); size scales with detected RAM
  (`memory::usable_ram_bytes()`), clamped floor/ceiling (currently `1024` MiB ceiling, QEMU RAM
  `8192` MiB). Same RAM-scaling pattern for `process::kernel_stack_size()`/`user_stack_pages()`.
  NOT scaled: `modules/fat32`'s embedded image size, `module::MODULE_VA_BASE`/
  `MODULE_REGION_CEILING` (a VA-range limit from the relocation model, not RAM).
- Global allocator is `linked_list_allocator`'s `Heap` wrapped in a local `Locked<T>`
  (`spin::Mutex`), not the crate's own `LockedHeap` — avoids a second spinlock crate in the graph.

## User-mode execution (`src/memory/address_space.rs`, `src/process/elf.rs`, `src/process/usermode.rs`)

`process::spawn` builds the first process this way at boot; `process::do_execve` builds every
later one the same way, mid-syscall.

- Userland crates (`userland/*`) are separate workspace members; `build.rs`'s
  `build_userland_crate` cross-builds each into `target/userland/` and exposes `<NAME>_ELF_PATH`
  via `cargo:rustc-env` for `include_bytes!`. Each crate's `linker.ld` forces a distinct load base
  clear of the kernel image, heap, phys-mem-offset window, and `bootloader` v0.9's own
  identity-mapped low-memory region. **This floor moves as the kernel image grows** — surfaces as
  `Elf(MappingFailed)`/`PageAlreadyMapped` at `execve`/spawn time, not build time. Currently
  `0x4000000` (64 MiB). **Before adding a new binary or trusting this number**, re-derive it:
  `readelf -l target/x86_64-oxidebsd/debug/oxidebsd | grep -A1 LOAD`, take highest
  `VirtAddr + MemSiz`, round up with real headroom. `userland/musl-smoke/` isn't a Rust crate —
  built with `musl-gcc`, load base via `-Wl,-Ttext-segment=`.
- `AddressSpace::new` shallow-copies all 512 L4 entries from the currently active table — safe
  only when the active table's user-space content is empty (true only for boot spawn).
  `AddressSpace::fork`/`new_excluding_user` (live process) instead recursively walk the table
  using `USER_ACCESSIBLE` as the sole kernel-vs-user signal at any level.
- **`gdt.rs`'s ring-0 stacks must be `static mut`, not `static`.** A plain `static`, never written
  via a Rust `&mut`, gets interned into `.rodata` by the optimizer — causes a double/triple fault
  the instant an exception uses it. Any future stack added the same way needs the same treatment.
- **Every IDT gate a software interrupt (`int n`, `int3`, ...) can trigger from ring 3 needs
  `DPL = Ring3` explicitly** — gates default to `Ring0`. Wrong DPL manifests as a `#GP` on the IDT
  entry itself.
- **`elf::load` tracks already-mapped pages in a `BTreeMap<Page, PhysFrame>` for one call** —
  `PT_LOAD` segments align to `p_align`, not to each other, so small binaries routinely share a
  page across segments. Flags aren't unioned across segments sharing a page — **found live** via
  `userland/sa-siginfo-syscall-smoke` (first userland crate with real writable globals): a small
  RW segment sharing a page with an RX segment kept only the RX flags, so the first static write
  page-faulted. Worked around at the linker-script level for that crate (`. = ALIGN(0x1000);`
  before writable sections), not fixed in `elf.rs` — a real flag-union fix would help every future
  small binary with writable globals but wasn't done.
- Known simplification: no `NO_EXECUTE` on any ELF segment (would also need `EFER.NXE`).

## Syscall ABI (`src/syscall/`)

OxideBSD's own native, BSD-flavored ABI over `SYSCALL`/`SYSRETQ` — not Linux-compatible. Syscall
number in `RAX`, up to 4 args in `RDI`/`RSI`/`RDX`/`R10` (not `RCX`/`R11`, clobbered by `SYSCALL`
itself). Success/failure via the **carry flag** (`CF=0` success, value in `RAX`; `CF=1` failure,
positive errno in `RAX` — traditional BSD/x86 Unix convention). Pre-musl-port syscalls
(`SYS_EXIT=1`, `SYS_FORK=2`, `SYS_READ=3`, `SYS_WRITE=4`, `SYS_OPEN=5`, `SYS_CLOSE=6`,
`SYS_WAIT4=7`, `SYS_LSEEK=8`, `SYS_GETPID=20`, `SYS_EXECVE=59`) match real FreeBSD numbers as an
authenticity nod. Everything since is OxideBSD's own invention, picked for what porting
musl/BusyBox actually needed: `SYS_MMAP=100`...`SYS_UTIMENSAT=167`/`SYS_SETSID=112`/
`SYS_GETSID=177`/`SYS_SETGROUPS=178`/`SYS_MOUNT_BIND=174`/`SYS_MOUNT_TMPFS=175`/`SYS_UMOUNT2=176`
(the `100-178` batch: mmap/munmap/brk/fs_base/writev/pipe/dup2/getppid/getcwd/unlink/rmdir/
rename/kill/sigaction/sigprocmask/sigreturn/setpgid/getpgid/ioctl/dup/fstat/stat/lstat/getdents/
uname/clock_gettime/nanosleep/socket family/poll/socketpair/set_tid_address/fcntl/shutdown/readv/
readlink/symlink/setitimer/getitimer/uid-gid family/chmod/chown), then `SYS_FSYNC=471` through
`SYS_FSTATFS=477`, `SYS_PRLIMIT64=478` through `SYS_REBOOT=486`, `SYS_UMASK=487`, `SYS_LINK=488`,
`SYS_MKNOD=489`, `SYS_CHROOT=490`, `SYS_GETRUSAGE=491`, `SYS_MPROTECT=492`, the pre-reserved
`526`-`553` POSIX/SysV batch (see that section), `SYS_FAULT_PUMP=554`, `SYS_CLONE=555`,
`SYS_EXIT_GROUP=556`, `SYS_FUTEX_REQUEUE=557`; plus real
Linux numbers reused directly where confirmed dead in this musl fork (`fchmod=91`,
`sched_getaffinity=204`, `futex=202`). **Check `src/syscall/` and module sources for the current
highest number before assigning a new one.**

**Before picking a new syscall number**: grep every still-inert real-Linux value in
`third_party/musl/arch/x86_64/bits/syscall.h.in` for a live musl caller before reusing it — bit
twice already: `SYS_KILL`'s invented number collided with real Linux's inert `setgroups` (which
*did* have a live musl caller via `initgroups()`), silently misrouting `setgroups()` into
`kill(2)`; and a later batch continuing `100-178` collided with real, still-referenced numbers
(`__NR_gettid`, live in `src/thread/synccall.c`). Since this musl fork is frozen at tag `v1.2.6`,
`471`+ (past the highest real-Linux number `bits/syscall.h.in` ever inspects) is *permanently*
collision-free — continue new invented numbers from there, or from this ABI's own highest already-
assigned number, whichever is higher.

**A collision-free *number* doesn't mean a collision-free *name*.** `__NR_futex_requeue=557`
(correctly past 471) reused a macro *name* this same vendored header already defines elsewhere for
real Linux's own unrelated futex2-family syscall `456` — plain C `#define` redefinition let the
textually-later `456` silently win, so `unlock_requeue()`'s musl-side call issued syscall `456`
(never registered here) instead of `557`, permanently and silently breaking every private-condvar
chain-wake beyond the first directly-woken waiter (found live via `pthread_cond_broadcast/1-1.c`).
Check the macro *name* for a collision too, not just the number, when adding a new `__NR_*`.

errno **is meant to** use FreeBSD's values where Linux/BSD diverge, but whatever this file returns
via the carry-flag ABI becomes musl's raw `errno` directly (see `syscall_arch.h`'s `jnc`/`neg`
conversion) — it must match musl's own compiled-in `bits/errno.h`, not real FreeBSD.
`EBADF`/`EINVAL`/`ECHILD`/`ENOEXEC`/`EPIPE`/`ESRCH`/`ENOTTY` happen to be identical between
Linux/generic and FreeBSD. **Known, currently-wrong** (real FreeBSD values that don't match musl,
deliberately deferred — discuss scope before a sweeping renumbering): `src/net/udp.rs`'s
`ENOTSOCK=38` (musl: `88`), `EDESTADDRREQ=39` (musl: `89`), `EADDRINUSE=48` (musl: `98`),
`EHOSTUNREACH=65` (musl: `113`); `src/net/tcp.rs`'s
`EISCONN`/`ENOTCONN`/`ECONNREFUSED`/`ETIMEDOUT`/`EOPNOTSUPP`/`EADDRINUSE`/`EHOSTUNREACH`. **Already
fixed** (confirmed load-bearing by a live test): `src/syscall/mod.rs`'s
`EPROTONOSUPPORT=93`/`EAGAIN=11`/`ENOTSOCK=88`/`ENOSYS=38` (was FreeBSD's `78`; blocked `su`'s real
`ENOSYS`-fallback path), `tcp.rs`'s own `EAGAIN=11` (was `35`).

The number→handler mapping is a runtime registry (`SYSCALL_TABLE`, `Mutex<BTreeMap>`) populated by
`oxidebsd_register_syscall` from each module's `module_init` — not a hardcoded `match`. An
unregistered number logs `[boot] unrecognized syscall number N` and returns `ENOSYS`, the main
tool for discovering what a ported program's startup still needs.

- **`SYSRETQ`'s selector scheme forces GDT order.** `SYSRETQ` derives `SS`/`CS` from
  `IA32_STAR[63:48]` as `+8`/`+16` — user data must sit immediately before user code. `src/cpu/
  gdt.rs` order: kernel code, kernel data, unused placeholder, user data, user code, TSS. Don't
  reorder without redoing the `STAR` arithmetic; `Star::write` panics loudly if the GDT regresses.
- **No automatic stack switch on `SYSCALL` entry.** Control arrives at `syscall_entry` still on
  the user's own stack. `gdt::CURRENT_RSP0` (`static mut`, kept in sync by
  `gdt::set_kernel_stack` on every context switch) always names the current process's own kernel
  stack — required since two processes can be mid-syscall at once. No per-CPU `swapgs` —
  single-core only.
- `SyscallFrame`: the stub's pushed GPRs plus `user_rsp`. `rcx`/`r11` double as saved `RIP`/
  `RFLAGS`; `syscall_dispatch` flips bit 0 of `r11` to signal `CF`.
- `dispatch()` is a small, pure, directly unit-tested function separate from
  `syscall_dispatch`'s raw-pointer/frame handling.
- A registered handler's own wire format (`SyscallHandler`) is a plain `i64` (negative = `-errno`)
  — distinct from the public carry-flag ABI, just the module↔kernel boundary's shape.
- `sys_write`/`sys_read` don't validate `[ptr, ptr+len)` before dereferencing — a bad pointer
  page-faults (handled safely: log + reboot for ring-0, real signal delivery for ring-3 — see
  "Real ring-3 fault-to-signal delivery" below), not a soundness hole.
- `sys_read` on stdin is non-blocking by design (returns `Ok(0)` on empty). Any other fd delegates
  to `crate::fd`'s per-process `(Pid, fd)` registry.
- `sys_write`'s `fd == 2` (stderr) is an alias for `fd == 1` — no real second sink exists.

## musl port (`third_party/musl`, `userland/musl-smoke/`, `src/process/user_stack.rs`, `src/cpu/fpu.rs`)

musl is patched (not the kernel made Linux-compatible) to speak this native ABI directly.
`third_party/musl` is a submodule of a personal fork (`ifduyue/musl`), patches on its own
`oxidebsd` branch based on tag `v1.2.6`. Pin/update by committing on that branch, pushing, then
`git add third_party/musl` here. Patch surface is deliberately small, entirely under
`arch/x86_64/`: `syscall_arch.h` (carry-flag→negative-errno conversion after every `syscall`),
`bits/syscall.h.in` (only the `__NR_*` values musl's static-binary startup path actually reaches
are remapped), `__set_thread_area.s` (TLS base via `SYS_SET_FS_BASE`, a bare base-address write).

Key gotchas, each a real bug already hit and fixed — the same *class* of bug can recur for any
future syscall port, so re-check these when adding one:
- musl's stdio write path goes through `writev`, never plain `write` — `SYS_WRITEV` is
  load-bearing (its absence once silently redirected all `printf` output into `getpid()` via a
  numbering collision — no crash, just zero output).
- **Remapping a `__NR_*` macro isn't enough if a 64-bit-suffixed sibling exists.** `src/internal/
  syscall.h` unconditionally prefers `SYS_getdents64` over `SYS_getdents` whenever both are
  defined — found live for `getdents`, both now remapped and kept in sync. Any future syscall with
  a same-shaped 64-bit sibling (`__NR_stat64`, `__NR_fstatat64`, ...) needs the same audit.
- SSE was never enabled at the hardware level; `src/cpu/fpu.rs::init()` enables it once at boot.
  Real per-process `FXSAVE`/`FXRSTOR` across every context switch exists (`Process::fpu_state`) —
  became load-bearing once ring-3 preemption landed (see "Real preemptive scheduling").
- `src/process/user_stack.rs` builds a real System V argc/argv/envp/auxv stack. `AT_PHDR` derived
  from the `PT_LOAD` segment with smallest `p_offset` (linker scripts don't map the ELF header
  into any segment). `AT_RANDOM` is a fixed placeholder.
- **`open`/`execve` argument-convention mismatches are fixed on the musl side**, not by remapping
  alone: length-prefixed `RawArgvEntry{ptr, len}` arrays instead of NUL-terminated `char**`, real
  4th syscall arg (`R10`) for `envp_ptr`. Same length-prefix pattern for
  `unlink`/`rmdir`/`rename`/`readlink`/`symlink`/`chdir`/`mkdir`. **Any future libc call ported
  here needs the same audit** — matching the syscall *number* isn't sufficient if the argument
  shape differs.
- **A hand-written asm stub can bypass the `__NR_*` remap table entirely.** `vfork.s` hardcoded
  the real Linux syscall number directly; fixed by hardcoding OxideBSD's own `SYS_FORK` instead (a
  real `fork()`, not true vfork semantics — POSIX-legal). **Any syscall with its own hand-written
  arch-specific asm stub needs this same direct-patch treatment, not just a header remap** — bit
  again later for `clone.s`/`__unmapself.s` (see "Real threading").
- `utimensat` drops the always-`AT_FDCWD` `fd` arg, passes `(path_ptr, path_len, times_ptr,
  flags)`. Kernel side is existence-check only (oxfs has no per-inode timestamps at the time this
  landed — real mtime/ctime tracking came later, see "SIGCHLD + sched fixes").
- `SYS_MMAP=100` is `(addr_hint, len, prot)` originally, later gained real `flags` (see mmap fixes
  below) — packed into `prot`'s unused high bits. `SYS_BRK=102` grows/shrinks `Process.brk`, no
  reclaim on shrink.

## BusyBox port (`third_party/busybox`, `modules/posix_compat/`)

256 applets run today (24 original + 232 from a second-pass roster), each its own standalone
single-applet static binary. Vendored as a submodule (fork of `mirror/busybox`, tag `1_36_1`,
`oxidebsd` branch — same pin/update procedure as musl). `build.rs`'s `build_busybox_applet` runs
`allnoconfig` → flip one applet's Kconfig symbol → `oldconfig` → build, asserting
`NUM_APPLETS == 1`; `sh` additionally forces on `CONFIG_HUSH_INTERACTIVE`/`HUSH_JOB`/
`FEATURE_EDITING` and hush's control-flow symbols directly (`allnoconfig` writes an explicit
"not set" before `oldconfig` ever sees hush's own `default y`). Applets are embedded into oxfs's
inode table by `modules/oxfs`'s `module_init` (data-driven from `build.rs`'s applet lists; each
new applet needs one manual `seed_file` call). Roster grew 24 → 290 (287 from an exhaustive
per-applet build probe — **"builds" is a much weaker bar than "works"**), then curated down to 232
(256 total) before v0.1 by dropping 58 applets structurally incapable of working under this
kernel's architecture (see `OxideBSD-doc/BUSYBOX_APPLETS.md`'s "Removed before v0.1"; a few later
unblocked — `chroot`/`mknod`/`link` — were fixed forward instead). `OxideBSD-doc/BUSYBOX_APPLETS.md` is the
full roster with per-applet needs (`NEEDS_NETWORK`/`NEEDS_PROC`/`NEEDS_CLOCK`/`NEEDS_UID`/`WORKS`).
`modules/oxfs/src/test_busybox.sh` (seeded at `/test_busybox.sh`) is ~95 real applet/control-flow
checks with a `PASS`/`FAIL` tally — the tool that found several bugs below.

- `build_busybox_applet` is staleness-checked against `third_party/busybox`/`build.rs`/
  `musl_sysroot`'s `lib/libc.a` mtimes, builds in parallel. **Two real staleness bugs found**: (1)
  `libc.a`'s mtime wasn't originally compared, so a musl fix left applets linked against stale
  libc. (2) BusyBox's incremental build never tracks musl's *installed sysroot headers* as a
  dependency — a musl header fix left most object files unrecompiled despite fresh binary mtimes.
  **Only a full `rm -rf` of the stale `O=` out-of-tree build dir reliably fixes this** — trust
  neither BusyBox's incremental tracking nor mtime alone. Expensive (~38 min full rebuild), only
  triggers when something genuinely changed.
- `hush` (pid 1) uses real `execvp()`/`$PATH` (`PATH=/bin` in envp). `modules/oxfs` seeds every
  applet under its bare name in `/bin`.
- New kernel-resident pieces `sh` required: real 4th syscall arg (`R10`, envp), real blocking
  `pipe(2)`/`dup2(2)` (`src/fs/pipe.rs`, `PIPE_CAPACITY=64` KiB, blocks via `BlockReason::
  WaitingForPipeData`/`WaitingForPipeSpace`), and a **per-process** `(Pid, fd)` fd table
  (`src/fs/fd.rs`) — a flat table broke real pipelines when a parent closed its own copy of a pipe
  fd out from under still-using children.
- **Fixed: a producer whose `write()` never blocks used to OOM the kernel heap.** `yes | head -n
  3` reliably panicked — `src/fs/pipe.rs`'s buffer used to be an unbounded `VecDeque<u8>`, and
  with no preemption `head` never got scheduled to stop `yes`. Fixed by bounding the buffer
  (`write_into` now blocks the producer once full, `EPIPE` on read-end close) rather than adding
  preemption.
- **`IA32_FS_BASE` (TLS) is a single global MSR never saved/restored per-process by
  `context_switch::switch_context`** — a resuming musl-linked parent would silently inherit a dead
  child's leftover TLS base and fault its own stack-protector check. Fixed via `Process::fs_base`,
  restored on every switch by `scheduler::activate_and_prepare`.
- `getcwd`/`getppid`/`chdir`/`mkdir` needed the same argument-convention fixes as `open` — only
  surfaced once `hush` was driven interactively.
- musl's stdio calls `write(fd, buf, 0)`/`read(fd, buf, 0)` with a null/garbage `buf`
  (POSIX-legal at length 0) — crashed every fd callback's unconditional `slice::from_raw_parts`;
  fixed centrally in `src/fs/fd.rs`'s `read`/`write` funnel functions.
- New syscalls always go in a dedicated module (`modules/posix_compat/`, `modules/signal/`, ...),
  not `modules/native_abi/` — keeps the core ABI module small.

## Interactive shell (`src/console/stdin.rs`, `userland/stsh/`)

`stsh` ("stupidshell") is the original hand-written interactive userland program — still
buildable, no longer pid 1 (superseded by `hush`). Its design remains the reference for stdin:

- Keyboard IRQ (`src/cpu/interrupts.rs`) decodes scancodes into a fixed 256-byte ring buffer
  (`src/console/stdin.rs`) — non-ASCII dropped, no allocation in the interrupt handler. `sys_read`
  drains it. Auto-echo only when `TERMIOS.ECHO` is set.
- The `spin::Mutex` around the ring buffer can't deadlock between IRQ and syscall context
  specifically because `SFMASK` clears `IF` for a `SYSCALL`'s entire duration on this single core
  — breaks if SMP is ever added.
- `sys_read` is non-blocking; `stsh` busy-polls a byte at a time.
- `src/console/vga.rs`'s `Writer` is a true 2D-addressable console with a minimal ANSI/VT100 CSI
  escape parser so full-screen applets (`vi`, `clear`, `reset`) render correctly.
- Real `SYS_IOCTL=124` (`src/console/stdin.rs`'s `RawTermios`, a single **global**, not
  per-session, `TERMIOS`) implements `TCGETS`/`TCSETS*`/`TIOCGWINSZ` (fixed `24x80`)/`TIOCSWINSZ`;
  else `ENOTTY`. Only succeeds against the real console — load-bearing for `isatty()`.
- No pty/foreground-process-group layer at this file's level — `tcsetpgrp`/`bg`/`fg` are driven
  entirely by the real session/controlling-tty model at the process level (see "Session,
  controlling-tty..." and "Real job control" below); this file's only involvement is the
  Ctrl+C/Ctrl+Z keyboard intercepts in `interrupts::keyboard_interrupt_handler`.

## Process abstraction, scheduler, and fork/exec/wait (`src/process/`)

Dynamically allocated process table, scheduler (cooperative round-robin + real ring-3 preemption,
see "Real preemptive scheduling"), kernel-thread-style context switch between per-process kernel
stacks. No copy-on-write fork (full eager copy), no SMP. **`Process` is no longer strictly one
schedulable entity per real process** — real `clone(2)`/`pthread_create` threads sharing one
address space also exist (`Process::tgid`, `ThreadGroupShared`, a per-thread-group `Arc<Mutex<>>`
bundle covering `cwd`/`root_inode`/`umask`/`uid`/`gid`/`brk`/`mmap_file_regions`) — see "Real
threading" for the full design.

- **Process table is `Mutex<BTreeMap<Pid, Box<Process>>>`, `Box` is load-bearing** — a
  `BTreeMap`'s internal nodes can move on insert/remove, but a `Box`'s heap allocation never does;
  holding the table lock across a context switch would deadlock. Every function touching both the
  table and `scheduler::schedule()` drops the lock first.
- `context_switch::switch_context` only saves System V callee-saved registers + `RSP`. Two
  first-run trampolines: `spawn_trampoline_asm` and `fork_trampoline_asm` (jumps into
  `syscall_entry`'s GPR-pop/`sysretq` tail).
- `fork` resumes the child via a copy of the parent's live `SyscallFrame` with `rax=0` and CF
  explicitly cleared.
- `do_execve` builds everything (new `AddressSpace`, `elf::load`, user stack) *before* mutating
  the live frame/`CR3`/stored `AddressSpace` — a failure at any point must leave the caller
  untouched, matching real `execve(2)`.
- **Real `#!interpreter [arg]` shebang support**: `do_execve` peeks the target's first two bytes;
  if `#!`, parses interpreter + one optional trailing argument, re-targets the load at the
  interpreter, looping up to `MAX_SHEBANG_DEPTH=4` (past which `ELOOP`).
- Per-process state across `fork` (copied)/`execve` (mostly preserved): `cwd` preserved; `brk`
  copied, not reset; `fs_base` copied, reset to 0; `pgid` inherited, untouched; signal state
  (`sigactions` reset to `SIG_DFL` for caught handlers only; `pending`/`blocked` untouched);
  `uid`/`gid` copied, preserved; `sid` inherited, untouched; `rlimits`/`nice`/`sched_policy`/
  `sched_priority`/`umask` copied, preserved (stored, not enforced); `root_inode` copied,
  untouched. Itimer state resets on `fork`, preserved by `execve` (the one exception).
- Kernel stack size floor is `128` KiB — found empirically. No guard page — overflow corrupts
  silently.
- **`do_wait4`'s reported status is real `wait(2)`-encoded — normal exit shifts into bits 8-15**
  (`WEXITSTATUS`). Signal-based termination passes a pre-encoded `128 + sig` directly, must
  **not** be shifted.
- **`kill(pid, 0)`** does a real existence-only check (self or cross-process; a zombie still
  counts until reaped), bypassing the pending-signal bitmask.
- `tests/fork_wait.rs` + `userland/fork-exec-smoke/` covers fork/wait4/exit.
  `modules/oxfs/src/test_busybox.sh` is real, broader, hand-run coverage.

## Dynamic kernel modules (`src/module.rs`, `modules/*`)

Loads independently-compiled, relocatable (`ET_REL`) `#![no_std]` objects into the kernel's
currently-active address space at boot: relocates them, resolves referenced symbols against a
hand-curated kernel API table, calls `module_init`. Distinct from `elf.rs` (loads a
non-relocatable `ET_EXEC` binary with zero relocations) — this is the largest subsystem.

- `build.rs`'s `build_module_crate` runs `cargo rustc --release --lib -- --emit=obj` then a
  mandatory relocatable partial relink (`rust-lld -flavor gnu -r`) against the exact
  `core`/`alloc`/`compiler_builtins` `.rlib`s.
- `--gc-sections -u module_init` on that relink is **required, not optional** — coarse
  archive-member selection during `-r` linking otherwise pulls in entire bundled `core`/`alloc`
  object files (once ballooned a module to 3+ MB/2900 sections, exhausting the boot-time heap).
- `RUSTFLAGS="-C relocation-model=static"` keeps relocations to absolute 32-bit forms — every
  module must map inside the low 2 GiB (`MODULE_VA_BASE=0x10000000`,
  `MODULE_REGION_CEILING=0x80000000`). A few GOT-indirected references survive anyway — handled
  via a minimal, eagerly-populated per-relocation-site GOT.
- **No `core::fmt::Write`/`write!` in module code** — that trait object's vtable emits a GOTPCREL
  reference, the single largest bloat source before `--gc-sections`. Hand-rolled byte formatting
  instead.
- **Modules can't use `alloc`/`Vec`/`BTreeMap`** — avoids depending on `#[global_allocator]`'s
  unstable-ABI internals from relocated code. State lives in fixed-size `static mut` arrays.
- **A `static mut` gotcha distinct from `gdt.rs`'s**: a private `static mut` buffer written but
  never observably read back through an externally-reachable function can have the write deleted
  as an unobservable dead store. Module state needs a syscall-reachable read to survive
  optimization.
- Modules are mapped kernel-only (no `USER_ACCESSIBLE`), every page `WRITABLE` (relocation must
  patch code bytes; no W^X anywhere in this kernel yet).
- A module panic is fatal to that call (no unwinding). `module::CURRENT_MODULE_FATAL` (`static
  mut`) gates a per-module `fatal_on_panic: bool` — `false` for every module except `oxfs`
  (`hlt_loop()`); `oxfs` reboots the whole system (a real disk attached makes a torn
  superblock/inode-table write worse to resume past than an in-memory panic).
- `serial_println!` can't take implicit `{name}`-style captures (its `concat!`-based expansion
  blocks it) — use explicit positional args; `serial_print!` has no such restriction.
- Known limits: no module unload/reload, no versioning, no inter-module direct calls (only
  module→kernel via each module's own resolved symbol table — why `src/fs/fd.rs`'s registry
  exists at all).

## Filesystem: oxfs (live) and FAT32 (superseded)

**`modules/oxfs/`** is the live filesystem — a real Unix-shaped inode/block filesystem. In-memory
by default, with real optional persistence to an attached ATA disk (see "Real disk persistence").
Fixed-size `static mut` pools: `NUM_BLOCKS=16384` × `BLOCK_SIZE=4096` (64 MiB), `MAX_INODES=2048`,
each inode with 12 direct blocks + one single-indirect + one double-indirect block (max
**single-file** size ~4.1 GiB; real pool now 1 GiB, so actual max is pool free space — see "oxfs
max-file-size and streaming write-buffer redesign" below). `NO_BLOCK = u32::MAX` is the "unallocated"
sentinel. Directories are ordinary inodes holding fixed 32-byte records (real names,
`NAME_MAX=26`) that grow additional blocks on demand. `unlink`/`rmdir` only clear a record's
`used` byte (no dealloc). Root is fixed inode `0`, self-referencing `.`/`..`.

- Real multi-component path resolution (`resolve_path`/`resolve_parent`, handling `.`/`..`).
- Real **per-process** cwd: `Process::cwd` (opaque inode number), falls back to `BOOT_CWD` for pid
  `0` (module_init's own self-check).
- Open files stream directly from the block chain on read; writes accumulate in a fixed buffer
  (`MAX_WRITE_BUFFER=131072`) and commit to a real inode at `close`.
- Syscalls: `SYS_OPEN=5`, `SYS_CLOSE=6`, `SYS_CHDIR=12`, `SYS_MKDIR=136`, `SYS_GETCWD=108`,
  `SYS_UNLINK=109`, `SYS_RMDIR=110`, `SYS_RENAME=111`, `SYS_FSTAT=126`/`SYS_STAT=127`/
  `SYS_LSTAT=128` (byte-exact 144-byte musl `struct stat`), `SYS_GETDENTS=129`. `st_uid`/`st_gid`/
  `mode`/timestamps are real (see "Permission model") — `oxfs_lstat` doesn't follow a final
  symlink, `oxfs_stat` does.
- Seed files (BusyBox applet ELFs, the musl/tcc runtime tree, fixtures) are embedded via
  `include_bytes!` in `module_init`, no build-time disk image needed.

**`modules/fat32/`** (superseded, kept for its own build/self-check, not loaded at boot): 8.3
names only, one path component per call, a directory that can never grow past its first cluster,
one kernel-wide cwd, whole-file-buffered reads, no `unlink`/`rmdir`/`rename`.

**`src/fs/fd.rs`** (shared by both, now `tgid`-keyed — see "Real threading"): a per-process
`(Pid, fd)` scoped registry — the only coordination channel between independently-loaded modules.
Bump-allocated fd numbers, never reused.

## Real disk persistence (`src/drivers/ata.rs`, `modules/oxfs`)

Scoped deliberately: real disk I/O and oxfs mount/format persistence, not a general VFS/mount-table
layer.

- **`src/drivers/ata.rs`**: hand-rolled ATA PIO driver, kernel-resident — classic legacy IDE,
  LBA28, **polling only, no IRQ**, fixed legacy ports. Every BSY/DRQ wait is bounded by a real
  `crate::tsc`-based deadline (never `hlt()`, never unbounded) — reachable from inside a real
  syscall handler with interrupts masked.
- **One fixed target: secondary channel, master** (`bootimage` attaches the boot image itself as
  primary master). `run-args` points at `target/oxfs_disk.img` (created only if missing);
  `test-args` at `target/oxfs_test_disk.img` (always freshly zeroed).
- **On-disk layout**: physical block `0` is the superblock (magic `b"OXFS"` + version + layout);
  packed inode table follows; then the block-used bitmap; real data after that. **Never a raw
  transmute/memcpy of `Inode`** — `pack_inode`/`unpack_inode` serialize by hand.
- **Mount-or-format, decided once in `module_init`**: no disk → in-memory only. Disk attached,
  superblock magic **and** stored layout match this build → **mount** (eager-load only used data
  blocks). Magic mismatch, or layout mismatch → **format** (reset the in-memory pool to all-free
  first — a stale bitmap/inode-table load must never leak into a fresh format), reseed, then
  `flush_all_to_disk`.
- **Write-through persistence, centralized at three functions**: `write_block`, `write_inode`,
  `set_block_used` are the *only* functions that ever touch `BLOCKS`/`INODES`/`BLOCK_USED`.
- **`PERSISTENCE_READY`** (`static mut` gate) stays `false` for the entire format/mount duration,
  set `true` right after, before any real syscall becomes reachable.
- **Known, accepted limitation: mount-time load is bitmap-filtered, not true lazy fault-in** — the
  pinned `x86_64` crate has no `rep insw`/`outsw` wrapper, so every 512-byte sector transfer is
  256 individually-trapped port reads under QEMU's TCG.
- **No raw block device is exposed to userland** — the disk is purely internal to oxfs's own
  persistence.
- Verified via `tests/ata_smoke.rs`, `tests/oxfs_persistence_syscall_smoke.rs`. **Not covered**:
  persistence surviving a real QEMU restart — manual only.
- **Operational gotcha**: mounting never re-syncs seeded content against the kernel's current
  embedded bytes — only a fresh *format* does. A fix to seeded content needs
  `target/oxfs_disk.img` deleted (destructive to anything created at the hush prompt — ask the
  user first) and reformatted on the next `cargo run`.

## Mount table (`modules/oxfs/`)

A real, but deliberately scoped, mount table — `mount --bind`/`mount -t tmpfs` only, not a general
pluggable-filesystem-type VFS.

- **A second, purely in-memory inode/block pool for tmpfs**: `BLOCKS`/`BLOCK_USED`/`INODES`
  extended with a tail region (`TMPFS_NUM_BLOCKS=1024`/`TMPFS_MAX_INODES=128`, 4 MiB). Block
  allocation picks the real vs. tmpfs pool via `inode_ensure_block_at`'s `inode_num >= MAX_INODES`
  test; new-inode allocation uses a shared `alloc_inode_in(parent)` chokepoint (found live: three
  call sites used to call plain `alloc_inode()` unconditionally, wrongly persisting tmpfs-created
  files to the real pool). Never reclaimed on unmount.
- **The mount table itself** (`MountEntry`/`MOUNTS`, `MAX_MOUNTS=8`): each entry records the real
  inode a mountpoint shadowed and where lookups redirect instead. `resolve_path_impl` checks
  `active_mount_for` right after each component's `dir_lookup`. Scanned LIFO.
  - Tmpfs mount root's `..` points at the mountpoint's real parent.
  - Bind mount reuses the source directory's own real inode directly — known limitation: `cd ..`
    from inside it follows the source's real parent, not the mountpoint's.
  - `st_dev` is `1` (real fs) or `2` (tmpfs pool) — a bind mount deliberately keeps `st_dev == 1`.
  - **The redirect only fires where `resolve_path_impl`'s per-component loop actually runs** —
    doesn't cover a handler using `resolve_parent` + its own bare `dir_lookup` (correct for
    `mkdir`/`symlink`'s EEXIST check, wrong for `open`'s "existing path" branch — found live,
    fixed for `oxfs_open` specifically).
- **`SYS_MOUNT_BIND=174`/`SYS_MOUNT_TMPFS=175`/`SYS_UMOUNT2=176`** — landed on real Linux's
  long-obsolete `create_module`/`init_module`/`delete_module` slots rather than continuing past
  `SYS_UTIMENSAT=167` (168-170 are real, live `swapoff`/`reboot`/`sethostname` numbers).
  `third_party/musl/src/linux/mount.c` dispatches to one of these two based on `fstype`/`flags`.
- **`/proc/mounts`**: a local formatter produces mtab-shaped lines directly from mount-table state.
- Verified via `tests/mount_syscall_smoke.rs`. **Not covered**: a real block-device-agnostic mount
  table (`pivot_root`/`switch_root`), anything needing a real partition table.

## Permission model (`src/process/`, `modules/oxfs/`, `modules/posix_compat/`)

Real uid/gid, real per-inode `mode`/`uid`/`gid`, real `chmod`/`chown`, real `open()` permission
enforcement. Only one uid existed (root, `0`) until "Session, controlling-tty..." below adds a
real second user.

- `Process` gains `uid`/`gid` — no separate saved/effective pair. `0` at spawn; copied by fork;
  preserved by execve.
- Syscalls: `SYS_GETUID=158`/`SYS_GETEUID=159`/`SYS_GETGID=160`/`SYS_GETEGID=161`/
  `SYS_SETUID=162`/`SYS_SETGID=163`/`SYS_GETGROUPS=164` (`posix_compat`) and `SYS_CHMOD=165`/
  `SYS_CHOWN=166` (`oxfs`).
- **`do_setuid`/`do_setgid`**: real POSIX rule — root may become any uid/gid; anyone else may only
  "become" the uid/gid they already are (no-op success); any other target is `EPERM`.
- **`do_getgroups`** reports a single-element list (caller's own `gid`) — no supplementary-group
  concept.
- **`Inode` gains real `mode`/`uid`/`gid`** (default `FIXED_PERM=0o755`/`0`/`0`). A freshly
  **created** file is owned by its real creator (`OpenFile::Write` gained `owner_uid`).
- **`check_access(inode, uid, gid, want_write)`**: `uid==0` bypasses rwx bits entirely; otherwise
  picks owner/group/other by comparing against the inode's own `uid`/`gid`. Wired into
  `oxfs_open`; `do_execve`'s ELF-loading read goes through this same path (approximate execute
  check).
- **Real write-to-an-existing-file support**: `OpenFile::Write` gained `existing_inode: Option<u32>`
  — `None` is create-new (fresh inode + dir entry at close); `Some(inode)` overwrites in place.
  `O_APPEND` preloads the write buffer with existing content. This filesystem's write primitive
  always replaces a file's complete contents in one shot. Opening a directory with
  `O_WRONLY`/`O_RDWR` is a real `EISDIR`.
- **`oxfs_chmod`**: owner or root only; follows a final symlink. **`oxfs_chown`**: root-only
  unconditionally; supports real POSIX `(uid_t)-1`/`(gid_t)-1` "leave unchanged"; follows a final
  symlink (`lchown` unimplemented).
- **`oxidebsd_current_uid`/`_gid`** (exported to modules) — how oxfs learns the caller's identity.
  `pid == 0` reports root.
- **`/etc/passwd`/`/etc/group`** seeded with a single `root:x:0:0:root:/:/bin/sh` entry (grown
  later — see next section). musl's own `getpwuid`/`getpwnam`/`getgrgid`/`getgrnam` parse these
  directly.
- Verified via `tests/uid_syscall_smoke.rs`. **Not covered**: mutating `/etc/passwd`/`/etc/group`
  (applet-level gap), `lchown`/`fchown` (fchmod later done, see below),
  setuid/setgid/sticky bits.

## Session, controlling-tty, and login authentication (`src/process/`, `src/console/stdin.rs`, `src/cpu/interrupts.rs`, `modules/posix_compat/`, `modules/oxfs/`)

Closes `su`/`login`/`sulogin`/`getty`.

- **A real second user**: `/etc/passwd` gains `user:x:1000:1000:User:/home/user:/bin/sh` (real
  `/home/user`, owned `1000:1000`, mode `0700`). **A real `/etc/shadow`** (mode `0600`, root-owned)
  holds real SHA-512 (`$6$`) `crypt(3)` hashes (password equals username) — musl's stock
  `crypt` code needed zero changes.
- **A real session model**: `Process` gains `sid: Pid`. Two new **single, not per-session**
  globals in `src/console/stdin.rs`: `CONTROLLING_SESSION: Option<Pid>`, `FOREGROUND_PGID:
  Option<Pid>` — this kernel has exactly one real console.
  - **`SYS_SETSID=112`**: `EPERM` if the caller is already a process-group leader; else becomes
    leader of a fresh session+pgroup.
  - **`SYS_GETSID=177`** (invented — real Linux's `124` means `SYS_IOCTL` here).
  - **`SYS_IOCTL` gains `TIOCSCTTY`/`TIOCNOTTY`/`TIOCGPGRP`/`TIOCSPGRP`**, gated to the real
    console fd. `TIOCGPGRP` falls back to the session id when nothing's called `TIOCSPGRP` yet.
  - **Real Ctrl+C → `SIGINT` to the foreground process group**: keyboard IRQ intercepts ASCII ETX
    (`0x03`) before the stdin ring buffer, only when `ISIG` is set **and** `FOREGROUND_PGID` is
    claimed — see "Real job control" below for how pid 1 gets a controlling tty automatically.
  - Verified via `tests/session_syscall_smoke.rs`, run as a forked child of pid 1. Real Ctrl+C
    delivery is manual-QEMU-only.

**Two real bugs found live-testing `su`, both worth remembering for any future syscall number**:
1. **A real syscall-number collision**: this ABI's invented `SYS_KILL` equaled real Linux's inert
   `setgroups` number, which *does* have a live musl caller (`initgroups()` → `setgroups()`,
   called by `su`). Fixed by giving `setgroups` its own number (`SYS_SETGROUPS=178`, root-only
   genuine no-op). Confirms the syscall-ABI rule above.
2. **`ENOSYS` mismatch, concretely breaking real functionality**: BusyBox's `change_identity()`
   treats a failing `initgroups()` as harmless when it's real `ENOSYS` and the target uid already
   equals the caller's — never fired because this kernel's old `ENOSYS` (FreeBSD's `78`) didn't
   match musl's compiled-in `38`. Fixed by correcting the constant.

## Signal handling module (`modules/signal/`, `src/process/signals.rs`, `src/syscall/mod.rs`)

Real `kill(2)`/`sigaction(2)`/`sigprocmask(2)` + delivery, plus
`sigtimedwait(2)`/`sigwaitinfo(2)`/`sigwait(3)`/`sigqueue(2)`. `SYS_KILL=116`/`SYS_SIGACTION=117`/
`SYS_SIGPROCMASK=118`/`SYS_SIGRETURN=119` match real Linux/BSD wire formats (pure number remap).
`SYS_SIGTIMEDWAIT=495`/`SYS_SIGQUEUE=496` are real, unclaimed
`__NR_rt_sigtimedwait`/`__NR_rt_sigqueueinfo` values. Real signal numbers (`SIGHUP=1`...
`SIGSYS=31`), extended later to real-time signals `SIGRTMIN..=SIGRTMAX` (`35..=64`, see "RT signal
queuing" below).

- `Process::sigactions: [SigAction; 65]` (real `SIG_DFL=0`/`SIG_IGN=1`) plus `pending_signals`/
  `blocked_signals` bitmasks, `pending_siginfo: [QueuedSigInfo; 65]` (real per-signal sender
  `pid`/`uid`/`si_code`/`sigqueue` value), and a real `signal_stack: Vec<SignalStackFrame>` (see
  "Real signal-stack chaining" below).
- Delivery happens once, at the tail of `syscall_dispatch` (and now also from `sigreturn` itself —
  see chaining below). `sigreturn` bypasses the normal `Ok`/`Err` carry-flag rewrite entirely.
- `do_kill` cross-process: immediate for the common case (no handler → terminate right there, even
  against a blocked target); deferred until next-scheduled only if the target has a custom
  handler. **Real permission checking** (`has_signal_permission`): sender must be root or share
  the target's uid, else `EPERM` — single-target paths only, not `signal_foreground_group`'s
  broadcast. **Real process-group targeting** (`target_pid == 0`/`< 0`) — see "Real job control".
- **Real `SA_SIGINFO` handler invocation**: `RawSiginfo`/`RawUcontext`/`RawMcontext` built on the
  handler's own stack frame with real GP registers and `uc_sigmask`. **`RawSiginfo`'s
  `si_code`/`si_errno` field order was a real bug, fixed** — see "siginfo field-order bug" below;
  three userland smoke crates hand-duplicate this struct and needed the same fix.
- **`sigtimedwait`/`sigwaitinfo`/`sigwait`**: real POSIX semantics directly *consume* a pending
  signal matching `wait_set`, **bypassing handler invocation** even if one's installed
  (`BlockReason::WaitingForSpecificSignal`). A signal used this way must be blocked via
  `sigprocmask` first, and for cross-process delivery needs a real handler installed too (the
  no-handler immediate-terminate path doesn't consult `blocked_signals`).
- **`sigqueue`**: real `(pid, sig, siginfo_ptr)`, single-target only.

## Real job control: Ctrl+C/Ctrl+Z, colored tty, `kill(-pgrp)` (`src/process/`, `src/cpu/interrupts.rs`, `build.rs`)

**Root cause, no BusyBox patch needed**: `hush.c` has always shipped a complete job-control
startup sequence that activates itself *if* it discovers a controlling tty — it never did, since
pid 1's stdin/stdout were wired directly to the console, never through a real `open()`. **Fix**:
`process::spawn` calls `console::stdin::set_controlling_session(pid)` directly right after
inserting pid 1 — mirrors what a real kernel does. That's what makes `FOREGROUND_PGID` get
claimed (via `hush`'s own `TIOCSPGRP`), unlocking the pre-existing Ctrl+C interception.

- **Colors**: `TERM=linux` + a colored `PS1` added to pid 1's `envp`. Real `ls --color` needed its
  own Kconfig flip in `build.rs`. This BusyBox fork's `grep` has no color feature at all.
- **Real `kill(-pgrp, sig)` process-group broadcast** (`do_kill`'s `target_pid <= 0` branch) —
  `hush`'s own `fg`/`bg` and job-cleanup paths depend on it. Reuses `signal_foreground_group`'s
  exact per-process action resolution.
- **Real `SIGSTOP`/`SIGTSTP`/`SIGCONT`** (genuine Ctrl+Z suspend/`bg`/`fg` resume):
  `ProcState::Stopped(u64)` (payload = stopping signal). `DefaultDisposition::Stop` split from the
  old blanket `Ignore` bucket. `SIGCONT` gets a pre-dispatch step at every cross-process-capable
  call site: an actually-`Stopped` target always resumes regardless of its own disposition, then
  still falls through for a caught handler. `do_wait4` real `WUNTRACED`/`WCONTINUED`/`WNOHANG` —
  `WNOHANG` is load-bearing since `hush.c`'s own `checkjobs(NULL, 0)` polling would otherwise
  block the whole shell (no real `SIGCHLD` existed yet at this point — added later, see "SIGCHLD +
  sched fixes"). New wire status shape: `WIFSTOPPED` writes `0x7f | (stopsig << 8)`;
  `WIFCONTINUED` writes `0xffff`.
  - **A real regression found live**: `process::timers::do_nanosleep` was the one blocking call
    that didn't loop and re-check its wake condition after `scheduler::schedule()` returns. Real
    `SIGCONT` unconditionally wakes a `Stopped` process regardless of what it was blocked on, so
    `bg`-ing a Ctrl+Z-stopped `sleep 100` woke it almost immediately instead of at its real ~100s
    deadline. Fixed by looping and re-checking `ticks() < deadline` — **any future mechanism that
    can force an arbitrary process back to `Ready` cross-process needs the same audit** of every
    non-looping `scheduler::schedule()` call site.
  - Not covered: real `SIGTTIN`/`SIGTTOU`-driven job control (still `Ignore`).

## Real-time clock (`modules/clock/`, `src/cpu/pit.rs`, `src/cpu/rtc.rs`)

`SYS_CLOCK_GETTIME=138` — real `clock_gettime(2)` wire format; `time()`/`gettimeofday()` are
wrappers around it.

- **`src/cpu/pit.rs`** reprograms PIT channel 0 to a fixed `TIMER_HZ=100` at boot.
- **`src/cpu/rtc.rs`** reads the CMOS RTC. `CLOCK_MONOTONIC` converts `ticks()` against
  `TIMER_HZ`. **Real sub-second `CLOCK_REALTIME`** (`unix_epoch_now_precise`) — calibrates a fixed
  `ticks() -> real seconds` offset against the RTC exactly once (lazily), then derives every later
  reading from `ticks()` — needed for `nanosleep/1-1,2-1.c` (see "Three more pilot fixes" below),
  since a fresh whole-second RTC read almost never landed inside a short sleep.
- **`SYS_NANOSLEEP=139`** — converts to an absolute wake-up tick deadline, blocks, woken by the
  timer IRQ scanning the process table. **Real signal-interrupts-sleep**: checks
  `pending_signals & !blocked_signals` before each re-block, returns `EINTR` with real remaining
  time — needed a new `wake_if_sleeping` hook wired into every `Action::SetPending` call site (see
  "Three more pilot fixes").

## Real networking (`src/drivers/pci.rs`, `src/net/*`, `modules/net/`)

Real, phased stack: PCI enumeration, IRQ-driven rtl8139 driver, Ethernet/ARP/IPv4/ICMP, UDP/TCP
sockets, raw ICMP sockets, `poll(2)`, and real hostname resolution via musl's own stub resolver.

- **`src/net/rtl8139.rs`**: brought up unconditionally at boot, absence logged not fatal.
- **`ipv4::next_hop`** is the *only* routing rule (anything outside `GUEST_IP`'s `/24` → gateway).
- **`src/net/udp.rs`/`tcp.rs`**: real sockets behind `SYS_SOCKET=140`/`SYS_BIND=141`/
  `SYS_SENDTO=142`/`SYS_RECVFROM=143`/`SYS_SETSOCKOPT=144` (UDP) and `SYS_CONNECT=145`/
  `SYS_LISTEN=146`/`SYS_ACCEPT=147` (TCP; once `Established`, plain read/write). TCP is
  stop-and-wait (one segment in flight, fixed 536-byte MSS, no window/congestion control).
- **`src/net/icmp.rs`** raw sockets: not port-addressed, every inbound ICMP fans out to every open
  raw socket.
- **`SYS_POLL=148`**: reports `POLLIN` only; an fd not owned by udp/tcp/icmp is always ready.
- **Real DNS resolution**: `/etc/resolv.conf` seeded with SLIRP's DNS relay.
  `recvmsg`/`sendmsg` delegate to `recvfrom`/`sendto` for the single-iovec shape musl's resolver
  actually uses.

**Architectural gotchas, apply to any future syscall-reachable busy-wait**:
1. **QEMU needs `-accel kvm -accel tcg`** (two repeated flags) in both `run-args`/`test-args`, or
   every boot runs pure-software TCG (can stretch boot past a minute under host load).
2. **`hlt()` inside a syscall handler can freeze the CPU permanently.** `SFMASK` clears `IF` for a
   syscall's entire duration — no timer tick can fire to advance `ticks()` either. Any
   syscall-reachable retry loop must use `core::hint::spin_loop()`, never `hlt()`, gated on
   **`src/cpu/tsc.rs`** (`RDTSC`-based, immune to `IF`) — **never `crate::interrupts::ticks()`**,
   frozen for a syscall's whole duration. Current spin-loop-with-tsc-deadline sites:
   `ipv4::resolve_with_retry`, `tcp::oxidebsd_sys_connect`, `net::oxidebsd_sys_poll`. **Invisible
   to any test calling kernel handlers as plain Rust functions instead of through a real
   `SYSCALL`.**
3. **`tcp_read` blocks on spin-loop, deliberately not the `pipe`-style `BlockReason` pattern** —
   incoming-packet processing is pull-based; yielding here would mean nothing services the
   connection once the only interested process stops running. Real EOF (`0`) only once the peer
   has actually FIN'd.

Real-`SYSCALL` smoke tests exist for every scenario (`tests/{udp,poll,ping,socketpair,
tcp}_syscall_smoke.rs`), using test-only syscalls (`SYS_TEST_EXIT=9999`,
`SYS_TEST_INJECT_UDP_FRAME=9998`, `SYS_TEST_TCP_STEP=9997`).

**Other real pieces landed for this stack**: `alarm()`/`setitimer()` (`SYS_SETITIMER=156`/
`SYS_GETITIMER=157`, `modules/clock/`, only `ITIMER_REAL`, expiry only sets `pending_signals`, not
inherited by fork); `socketpair(AF_UNIX, SOCK_STREAM)` (`SYS_SOCKETPAIR=149`, built on
`src/fs/pipe.rs`); getting `wget` HTTPS working needed five further fixes in sequence:
`SYS_SET_TID_ADDRESS=150`, `SYS_FCNTL=151` (`F_GETFL`/`F_SETFL(O_NONBLOCK)`/`F_SETFD`/`F_DUPFD*`),
`SYS_SHUTDOWN=152` (real half-close for a pipe-backed socketpair only), a synthetic
`/dev/{u}random,null,zero` path backed by **`src/random.rs`** (a real
SHA-256-seeded ChaCha20 generator gathering `RDTSC`/PIT/RTC/`RDRAND`/`RDSEED` when available, plus
a persistent `ENTROPY_POOL` folding real IRQ-timing jitter from keyboard/rtl8139 handlers —
`RDRAND`/`RDSEED` are distrusted whenever `running_under_hypervisor()` is true, since a hypervisor
can trap and fake either instruction undetectably; both crates need soft-float-equivalent backend
flags for this SSE-disabled target), and `SYS_READV=153`; plus a real `tcp_read` EOF-vs-empty fix.
No real routing table, no IPv6 anywhere. BusyBox's vendored TLS client doesn't validate certificate
chains (a limitation of that vendored code, not fixable kernel-side).

## Filesystem/process misc syscalls: fsync, ftruncate, fallocate, flock, statfs, prlimit64, nice, chrt, reboot (`modules/oxfs`, `modules/posix_compat`, `src/reboot.rs`)

`link`/`mknod`/SysV IPC/`chroot`/namespaces/`inotify`/ext2 `ioctl`s/`xattr` were a distinct,
deliberately-out-of-scope gap at the time this landed (`link`/`mknod`/`chroot` since done — see
next section); namespaces don't fit this single-address-space kernel at all.

- **All sixteen numbers land at `471`-`486`** — see the syscall-ABI collision rule above.
  `oxfs`'s `SYS_FSYNC=471`...`SYS_FSTATFS=477`, `posix_compat`'s `SYS_PRLIMIT64=478`...
  `SYS_REBOOT=486`.
- **`SYS_FSYNC`/`SYS_SYNC`** are real, not stubs — a shared `commit_write_buffer` (from
  `oxfs_close`) is callable for one fd or swept across every open write fd.
- **`SYS_FTRUNCATE`/`SYS_FALLOCATE`** resize directly at the block level, not via a whole-content
  buffer (the 128 KiB kernel-stack floor can't hold a ~4 MiB file). Growing zero-fills only the
  new region.
- **`SYS_FLOCK`** is a real per-inode `LOCK_SH`/`LOCK_EX`/`LOCK_UN` advisory table (16 entries),
  released on close. A conflicting request fails `EAGAIN` immediately even without `LOCK_NB` — no
  scheduler-yield primitive is reachable from a module syscall handler.
- **`SYS_STATFS`/`SYS_FSTATFS`** report a real musl-layout `struct statfs` (120 bytes) from live
  block/inode-usage counts.
- **`SYS_PRLIMIT64`** backs `getrlimit`/`setrlimit`. `Process::rlimits: [(u64,u64); 16]` — stored,
  never enforced.
- **`SYS_SETPRIORITY`/`SYS_GETPRIORITY`** (`nice`) — `Process::nice: i32`, no real scheduling
  effect. **`SYS_SCHED_SETSCHEDULER`/`_GETSCHEDULER`/`_GETPARAM`/`_GET_PRIORITY_MAX`/`_MIN`**
  (`chrt`) — stored/echoed honestly, no real effect (later gains real `sched_setparam`, see
  "SIGCHLD + sched fixes").
- **`SYS_REBOOT`** (+ `src/reboot.rs`) matches real Linux's `RB_AUTOBOOT`/`RB_HALT_SYSTEM`/
  `RB_POWER_OFF` magic values. No permission check. Every success path halts/resets/powers off the
  VM — manual-QEMU-only.
- **`SYS_UMASK=487`**. `Process::umask: u32` (default `0o022`) — real per-process state, stored
  but not actually consulted anywhere oxfs creates a new inode.
- Verified via `tests/needs_syscall_smoke.rs` (except `reboot`/`umask`, manual-only).

## Real hard links, device nodes, per-process chroot, and getrusage/wait4 rusage (`modules/oxfs`, `modules/posix_compat`, `src/process/`)

- **`SYS_LINK=488`/`SYS_MKNOD=489`/`SYS_CHROOT=490`** (`oxfs`), **`SYS_GETRUSAGE=491`**
  (`posix_compat`).
- **Real hard links**: `Inode` gains `nlink: u16`. `oxfs_link` follows symlinks, rejects
  directories (`EPERM`) and cross-pool links (`EXDEV`). `oxfs_unlink` decrements `nlink` (still
  never actually freed).
- **Real device nodes**: `InodeKind::Device`, `Inode::rdev`/`device_char`. `mknod` creates a real,
  listable inode, but `oxfs_open`'s `Device` dispatch only services major:minor pairs matching the
  same four `/dev/{random,urandom,null,zero}` devices — any other is `ENXIO`. Also supports
  `S_IFREG`; `S_IFIFO`/`S_IFSOCK` are `EINVAL`. Root-only.
- **Real per-process `chroot`**: `Process::root_inode: u64` mirrors `cwd`'s design (`0` = never
  chrooted). `resolve_path_impl` gains a `root_inode` parameter for containment (`..` stays put at
  root). Root-only, doesn't also `chdir`.
- **`SYS_GETRUSAGE` + real `wait4` rusage**: real, correctly-shaped, all-zero `struct rusage` (no
  per-process CPU-time/memory accounting exists).
- **A real regression found by the full test suite**: making `wait4`'s 4th arg (`R10`) meaningful
  broke several hand-written userland `syscall()` helpers that never zeroed `R10`. **Any future
  syscall upgrading 3→4 real arguments needs an audit of every userland crate's own hand-rolled
  `syscall()` helper.**
- Verified via `tests/needs_syscall2_smoke.rs`.

## Two syscalls found live by the expanded `test_busybox.sh` post-v0.1

Both real, unremapped Linux `__NR_*` values used directly (confirmed unclaimed elsewhere in this
ABI's registry).

- **`fchmod`** (`oxfs_fchmod`, real `__NR_fchmod=91`): found via `uudecode`'s real
  `fchmod(fd, mode)` on its still-open output fd — silently `ENOSYS`'d before. Uses
  `resolve_write_fd_inode` + the same owner-or-root check as `oxfs_chmod`.
- **`sched_getaffinity`** (`do_sched_getaffinity`, real `__NR_sched_getaffinity=204`): found via
  `nproc` (which silently fell back to `count=1` on failure, so the gap only showed as a logged
  unrecognized-syscall line). Single-core, mask always bit 0 — writes `min(cpusetsize, 8)` real
  bytes, real raw-syscall return convention.

## TinyCC: a real, on-target C compiler (`third_party/tinycc`, `modules/oxfs`, `build.rs`)

`tcc` is a single monolithic static binary with real upstream musl support (`--config-musl`).
Vendored as a submodule (`Pomsky2011/tinycc-oxidebsd`, `oxidebsd` branch, tag `release_0_9_27`).
`build_tinycc()` cross-builds via `musl-gcc` against the existing musl sysroot; needs explicit
`--crtprefix=/usr/lib --libpaths=/usr/lib --sysincludepaths=/usr/include`. `libtcc1.a` is built via
tcc's `-usegcc=yes` escape hatch (safe — pure freestanding numeric helpers, no syscalls).

**Two real, deep bugs found getting `tcc -static -o hello.elf hello.c && ./hello.elf` working**:
1. This dev machine's host `gcc` defaults to PIE, and musl's own `configure` auto-detected that,
   letting PIE-style GOT-indirect codegen leak into `crt1.o`. Every other consumer links via real
   GNU ld's silent GOTPCRELX relaxation, hiding this — TinyCC's linker doesn't implement that
   relaxation, so the first `tcc`-produced binary faulted on an instruction fetch through a
   never-written GOT slot. Fixed by forcing `-fno-pie -fno-PIC` for the whole musl build (a full
   `make distclean` + fresh sysroot rebuild, transitively relinking every BusyBox applet).
2. **TinyCC generates real PLT/GOT indirection for external calls even under `-static`.**
   PLT/lazy-binding has no meaning with no dynamic loader present. Fixed by patching
   `third_party/tinycc/tccelf.c`'s `build_got_entries` to extend its hidden-visibility no-PLT
   carve-out to also fire whenever `s1->static_link` is true.
3. **A separate crash**: bare `tcc hello.c` (no `-static`) produced a dynamically-linked `a.out`
   that faulted at `VirtAddr(0x0)` (no `PT_INTERP` support existed at the time — since added, see
   "Dynamic linking", but TinyCC's own output was never revisited). Fixed at the root:
   `libtcc.c`'s `tcc_new()` now defaults `s->static_link = 1` unconditionally.

- **`SYS_LSEEK=8`** — tcc's object-file loader needs a real file size upfront (`fseek`/`ftell`)
  before parsing ELF/`ar` headers. Only `{FileRead,DirListing,ProcRead,ProcDir}` variants have a
  real seek position; `Write` and synthetic `/dev/*` report `ESPIPE`.
- **A real, generated on-target runtime tree**: `/usr/include` (musl headers), `/usr/lib`
  (crt/libc.a/musl stub archives), `/usr/lib/tcc` (`libtcc1.a` + tcc's 5 bundled headers).
  Generated by `build.rs`'s `write_tcc_runtime_manifest` into a single `include!`'d generated
  Rust file — literal absolute `include_bytes!` paths, not the per-file `env!()` pattern every
  other embedded ELF uses.
- `modules/oxfs` gained real directory-tree seeding infra: `ensure_dir` (idempotent) and
  `seed_tree` (splits `/`-separated paths, walks/creates intermediates).
- Verified via `tests/tcc_syscall_smoke.rs` — real `fork`+`execve` `tcc -static -o /hello.elf
  /hello.c`, `wait4`, then `fork`+`execve` the produced ELF itself (proving the *output* is a real
  runnable binary), plus the same round trip via bare `tcc -o` (no `-static`, exercising bug 3's
  fix). **Not covered**: `-run` (in-memory JIT execution), self-hosting.

**A real, three-layered disk-persistence bug found on an already-formatted disk** when
`MAX_INODES` changed the on-disk inode-table size: (1) a stale bitmap could leak into a
fallback-to-format path — fixed by always resetting the in-memory pool to all-free before any
format run that might follow a partial mount attempt; (2) `build.rs`'s own hand-duplicated
metadata-block-count constant went stale — fixed by computing it from the real constants; (3)
`mount_from_disk`'s superblock check was magic-only, not layout-aware — fixed by checking stored
`SUPERBLOCK_VERSION`/`NUM_BLOCKS`/`MAX_INODES` too; (4) the persistent dev disk was only ever
created if missing, never grown if undersized — fixed to grow in place (zeros appended, real bytes
untouched).

## Dynamic linking: milestone 1, real `PT_INTERP` (`src/process/elf.rs`, `src/process/lifecycle.rs`, `build.rs`, `modules/oxfs`)

A real, working `fork`+`execve` of a genuinely dynamically-linked ELF, resolved/relocated by
musl's own real `ld.so` running as the interpreter — not this kernel doing the linking itself.

- **A second, fully separate `-fPIC`/shared musl build** produces a real `libc.so`
  (`/lib/ld-musl-x86_64.so.1` is a symlink to it, matching musl's own real convention).
- **`elf.rs` accepts `ET_DYN` alongside `ET_EXEC`** — solely for a `PT_INTERP` interpreter image.
  `elf::load` gained a real, kernel-chosen additive `bias` parameter applied to every segment's
  `p_vaddr`.
- **Found the hard way, why a fixed link-time base doesn't work**: musl's own self-relocation
  bootstrap always computes `real_addr = AT_BASE + stored_value`, expecting `stored_value` already
  zero-based — a fixed-base link double-counts the base. Fixed by linking `libc.so` at its own
  natural near-zero base and applying the real bias in `elf::load` instead.
  `INTERP_LOAD_BASE = 0xc000000` — one fixed VA, nothing here needs more than one interpreter
  resident at once.
- `do_execve` loads the interpreter alongside the main binary when a `PT_INTERP` segment is
  present, both sharing the same fresh address space; the real jump target becomes the
  interpreter's entry point.
- **A permissive `SYS_MPROTECT=492` stub** — `ld.so`'s RELRO step calls real `mprotect`, so it
  needed to stop `ENOSYS`ing, but enforces nothing yet (no W^X anywhere in this kernel).
- Verified end-to-end via `tests/dynlink_syscall_smoke.rs` — real self-relocation, real symbol
  resolution against `libc.so`, a real libc call, all round-trip correctly.
- **Milestone 2, not started**: `dlopen`/`dlsym`/`dlclose`/`dlerror` — blocked on `mmap`/`mprotect`
  actually enforcing real placement/protection (both still permissive no-ops/bump-allocators).

## Real getrandom/sysinfo/sigaltstack/pause/sigsuspend/POSIX timers/POSIX message queues/SysV IPC (`modules/posix_compat`, `modules/signal`, `modules/clock`, `src/fs/{mqueue,sysv_msg,sysv_sem,sysv_shm,sysv_ipc}.rs`)

A 28-syscall batch (`526`-`553`) pre-reserved with permanent invented numbers ahead of having real
handlers (see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s "Pre-reserved" section for why). All 28 now have
real handlers, landed roughly in POSIX/SysV order except SysV IPC landed message queues before
semaphores before shared memory (each needed progressively more novel machinery).

- **`getrandom`** (`526`): thin plumbing to `src/random.rs`'s existing generator. Only reachable
  via `getentropy()` in this port's roster, which caps `len` at 256 and loops — this handler
  always fills the whole request in one shot so that loop exits after one iteration.
- **`sysinfo`** (`527`): `RawSysinfo` (368 bytes, confirmed via a direct C `offsetof`/`sizeof`
  probe). Real `uptime`/`totalram`/`procs`; `freeram == totalram` (no dealloc tracking); rest
  honest zero.
- **`sigaltstack`** (`528`): bookkeeping via `Process::altstack`. No signal was actually delivered
  at this stack's address until later (see `SA_ONSTACK` below).
- **`pause`** (`529`): first item needing a genuine new primitive — `BlockReason::
  WaitingForSignal` + `wake_if_paused`, checked-before-block/looped-after-wake (avoids lost
  wakeup/stale-block, the discipline every blocking primitive here follows).
- **`sigsuspend`** (`530`): reuses `pause`'s primitive plus a temporary `blocked_signals` swap.
- **POSIX timers** `timer_create`/`_settime`/`_gettime`/`_getoverrun`/`_delete` (`531`-`535`,
  `src/process/timers.rs`): `Process::posix_timers`, up to 8, relative/`TIMER_ABSTIME` arming
  against `CLOCK_MONOTONIC`/`CLOCK_REALTIME`, real overrun accounting, delivered from the timer
  IRQ handler. Not inherited by fork; disarmed by execve. Later extended to accept
  `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` too (see "Three UNRESOLVED fixes").
- **POSIX message queues** `mq_open`/`_unlink`/`_timedsend`/`_timedreceive`/`_notify`/`_getsetattr`
  (`536`-`541`, `src/fs/mqueue.rs`): a separate name→queue namespace, real priority-ordered
  delivery, real bounded blocking send/receive, real `mq_notify`/`SIGEV_SIGNAL` via `do_kill`
  directly. `mq_close` isn't its own syscall — an mqd rides the ordinary fd registry.
  `mq_timedsend`/`_timedreceive` needed a musl call-site patch (5 real args packed into one
  register: high 32 bits = len, low 32 = mqd, since nothing here was redundant to drop the usual
  way). Later gained signal-interrupt support (see "POSIX conformance pilot" bug 2 below).
- **SysV message queues** `msgget`/`msgsnd`/`msgrcv`/`msgctl` (`550`-`553`,
  `src/fs/sysv_msg.rs`): integer-`key_t`-addressed, fd-less namespace (no `crate::fs::fd`
  involvement — a queue lives from `msgget` until explicit `IPC_RMID`). Real `ipc_perm` checks,
  real `msgtyp` selection semantics, real timestamps. A real bug found in testing: an early draft
  removed a matched message *before* checking buffer size, destroying it on `E2BIG` — fixed to
  peek length first (real Linux "too-big message stays queued" semantics).
- **SysV semaphores** `semget`/`semop`/`semctl`/`semtimedop` (`546`-`549`,
  `src/fs/sysv_sem.rs`): same `key_t`→id namespace, factored through a shared `sysv_ipc.rs`.
  `semop`/`semtimedop` apply a whole `sembuf` array atomically (simulate-then-commit-or-nothing).
  Real `SEM_UNDO` via `Process::sysv_sem_undo`, applied on process termination. A new
  `BlockReason::WaitingForSemOp` backs real `GETNCNT`/`GETZCNT` — a real bug found live: an early
  draft woke every blocked waiter on *any* successful op, breaking those counts' own accounting.
- **SysV shared memory** `shmget`/`shmat`/`shmctl`/`shmdt` (`542`-`545`,
  `src/fs/sysv_shm.rs`), the one sub-batch needing real memory-management plumbing: `shmget`
  eagerly allocates a fixed `Vec<PhysFrame>`, zero-filled once. **`shmat` is the real proof of
  shared memory** — every attach against the same id maps those exact same frames into the
  caller's own page table (`SHM_REGION_BASE = 0x_4000_0000_0000`). `shmdt` is the one syscall in
  this batch that actually unmaps on the way out (`Process::sysv_shm_attach` list). Real
  `IPC_RMID`-while-attached lifecycle (key unlinked immediately, frames survive until last
  detach). **Not inherited across `fork`** (a forked child's page-table entries already point at
  freshly-copied private frames regardless, since fork here is eager-copy not COW) — starts empty
  in a child, same precedent `sysv_sem_undo` established.

Closes the whole 28-item batch — see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own per-item write-up for
detail this section only summarizes.

## Real preemptive scheduling (`src/process/scheduler.rs`, `src/cpu/interrupts.rs`, `src/cpu/fpu.rs`)

The scheduler is no longer purely cooperative. A process still leaves `Running` voluntarily
(`scheduler::schedule()`, unchanged) — but can now also be preempted:
`interrupts::timer_interrupt_handler` calls `schedule()` directly whenever it catches a process
executing ring-3 code and a quantum (`PREEMPT_QUANTUM_TICKS=4` ticks = 40ms) has elapsed.

- **Deliberately scoped to ring-3 only, not full kernel preemption.** Checked via the interrupted
  frame's CS RPL bits, not a software flag. Kernel/syscall/module code is never preempted
  (`IA32_SFMASK` already clears `IF` for a syscall's entire duration). This is the load-bearing
  scoping decision: user-mode code never holds a kernel `spin::Mutex`, so no existing critical
  section anywhere needed auditing for preemption-safety.
- **The mechanism is unchanged `scheduler::schedule()`, called from a new site** — no raw-asm
  timer entry point needed. Each process's own dormant `iretq`-bound interrupt-return sequence
  sits on its own kernel stack until picked again.
- **EOI is sent before the possible `schedule()` call, not after** — load-bearing: until EOI, the
  PIC won't deliver *any* further timer interrupt to *anyone*, freezing every `ticks()`-gated
  wakeup in the kernel permanently.
- **A real, previously-flagged correctness gap this closed**: `cpu::fpu.rs` never
  saved/restored SSE/x87 state across a context switch — fine only under cooperative-only
  scheduling (a syscall boundary already forces the compiler to spill any XMM state it cares
  about). Real preemption can interrupt at literally any instruction. Fixed via
  `Process::fpu_state` (`FXSAVE`/`FXRSTOR` on **every** switch, not just preemptive ones). A
  freshly spawned/forked process starts from `cpu::fpu::clean_state()` — a real CPU-reset image
  captured once via a genuine `fninit`+`fxsave` at boot, not a hand-guessed all-zero buffer (x87
  control word and `MXCSR` have real nonzero hardware reset defaults).
- **A real regression found by the full test-suite pass**: `sysv-sem-syscall-smoke`'s block/wake
  test assumed the old cooperative guarantee ("the waker stays Ready until its own next blocking
  point") — real preemption breaks that. Fixed in the test itself (bounded polling loops instead
  of one-shot before/after checks) — no other test in the suite carried this same assumption.
- **Verification**: full existing test suite passes under real preemptible execution. Not covered:
  real-world responsiveness/fairness under sustained CPU-bound load — manual-QEMU-only.

## Real-time signal queuing and kill/sigqueue permission checking (`src/process/mod.rs`, `src/process/signals.rs`)

Closes the Open POSIX Test Suite pilot's "Real-time signal queuing" blocker.

- **`SIGRTMIN..=SIGRTMAX` (`35..=64`)**, matching musl's own `sigrtmin.c`/`sigrtmax.c`; `32..=34`
  stay permanently unclaimed (real glibc/musl convention). `Process::sigactions` grew to
  `[SigAction; 65]`.
- **`Process::rt_queue: [Vec<QueuedSigInfo>; RT_SIGNAL_COUNT]`** gives each RT signal its own
  small fixed-capacity (`RT_QUEUE_CAP=16`) FIFO — a second `sigqueue`/`raise` against an
  already-pending RT signal genuinely queues (POSIX requires this; standard signals staying
  bitmask-collapsed is explicitly permitted).
- **`record_pending`** is now RT-aware and fallible: `sig >= SIGRTMIN` pushes/pops `rt_queue`,
  returns `Err(EAGAIN)` once full (the real documented `sigqueue(2)` errno). An RT signal's
  `pending_signals` bit only clears once its own queue is empty.
- **Real `kill(2)`/`sigqueue(2)` permission checking** (`has_signal_permission`): sender must be
  root or share the target's uid — checked by single-target paths, not group broadcast.
- **Verified**: pilot moved 40P/16F/8U/4UT → 52P/9F/3U/4UT across two passes.
- **A real, separate gap surfaced by this work, since fixed** (see "Real signal-stack chaining"
  below): `deliver_pending_signal` used to deliver only **one** signal per completed syscall, so
  code that unblocks several already-queued RT instances in one call only ever saw one delivered.

## Real ring-3 fault-to-signal delivery, and two mmap fixes (`src/cpu/interrupts.rs`, `src/process/fault_trampoline.rs`, `src/process/mm.rs`, `modules/oxfs/`)

Closes a much bigger standing gap the pilot's `mmap/11-2,11-3,12-1.c` FAILs happened to surface:
**`interrupts::page_fault_handler` used to reboot the whole kernel on any page fault, ring-3 or
not.** A wild pointer deref in any userland program took the entire VM down.

- **Real MPR-correct partial mapping**: `mm::do_mmap_file_backed` now only backs/maps
  `covered_pages = real_size.div_ceil(4096).min(page_count)` — the tail past a file's real
  (page-rounded) extent gets **no page-table entry at all**, so a reference there raises `SIGBUS`
  rather than silently succeeding against a zero page.
- **Real fault-to-signal delivery, from scratch**: `page_fault_handler` checks the interrupted
  frame's CS RPL — ring-0 is still an unconditional reboot, but ring-3 now resolves a real signal
  (`SIGBUS` for a reference into a live mapping's own reserved-but-unbacked tail, `SIGSEGV`
  otherwise) via `do_kill`'s self-signal path, then redirects to a real, kernel-authored,
  user-executable trampoline page (`process::fault_trampoline`, fixed VA
  `0x_1FFF_FFFF_F000`, mapped in every fresh address space).
  - **Why not invoke the handler directly from the fault handler**: `extern "x86-interrupt"`'s
    compiler-generated entry/exit exposes no Rust-visible GPR fields to set up a real 3-argument
    handler call. **Fix**: the trampoline is `mov eax, SYS_FAULT_PUMP (554); syscall; ud2` —
    redirecting `instruction_pointer` there forces a real `SYSCALL` through `syscall_entry`'s
    already-correct GPR capture; `syscall_dispatch` special-cases `SYS_FAULT_PUMP` like
    `SYS_SIGRETURN`, calling `deliver_pending_signal` directly. Default disposition (no handler)
    now cleanly terminates just the one offending process instead of rebooting the VM.
- **A real, separate bug found chasing `mmap/12-1.c`, not about mmap at all**: `open(O_CREAT)` on
  a brand-new path defers the real inode/dir-entry until first commit; `unlink()`ing before that
  commit found nothing to remove and silently no-op'd, then the deferred commit resurrected the
  name. Fixed: `OpenFile::Write` gained `unlinked: bool` — `oxfs_unlink` finding no dir entry now
  scans `OPEN_FILES` for a still-uncommitted matching fd and sets this flag instead of `ENOENT`ing;
  `commit_write_buffer` still commits real content but skips `dir_insert` when set.
- Verified via `tests/mmap_syscall_smoke.rs` (4 parts, 3 run in isolated forked children since a
  fault kills whichever process it hits). **Not covered**: `SA_SIGINFO` invocation from a fault;
  dynamic re-check of a grown file's size against an already-mapped region.
- **`invalid_opcode_handler` (`#UD`) had the identical gap, missed at the time this section
  landed** — found later auditing a `v0.1.x` backport of this same fix for an unrelated reason
  (`invalid_opcode_handler` was the one exception handler there that still rebooted the whole VM
  unconditionally on any ring-3 fault), then confirmed `master` had never actually closed it for
  this specific exception either, only `page_fault_handler`/`general_protection_fault_handler`.
  Fixed identically (real `SIGILL`, matching real Linux's `#UD` mapping).

## Three more pilot fixes: signal-interruptible `nanosleep`, real `FD_CLOEXEC`, real per-process CPU-time clocks (`src/cpu/rtc.rs`, `src/process/timers.rs`, `src/process/signals.rs`, `src/fs/fd.rs`, `modules/oxfs/`)

- **Real sub-second `CLOCK_REALTIME`** — see "Real-time clock" above. Closes `nanosleep/1-1,2-1.c`.
- **Real signal-interrupts-sleep** — see "Real-time clock" above (`wake_if_sleeping`). Closes
  `nanosleep/1-3.c`.
- **Real per-`(pid, fd)` `FD_CLOEXEC`** (`src/fs/fd.rs`'s `CLOEXEC` set): `F_GETFD`/`F_SETFD` used
  to be a pure no-op. Scoped per-`(pid, fd)`, not per-`real_fd` (POSIX: property of the descriptor,
  not the open-file description) — `dup`/`dup2` don't copy it, `fork_inherit` does. `do_execve`
  now calls `fs::fd::close_cloexec` — the first real close-on-exec behavior this kernel ever had.
  Closes `shm_open/11-1.c`.
- **Real per-fd access-mode enforcement on write/`ftruncate`/`fallocate`**
  (`OpenFile::Write::readonly`): `oxfs_open`'s create-path branch used to unconditionally produce
  a writable fd regardless of the caller's requested mode. **A real regression found immediately
  by the full test suite**: several existing userland smoke crates and `stsh`'s own `write`
  command called `open(path, O_CREAT)` with no explicit `O_WRONLY`/`O_RDWR` bit, relying on the
  old permissiveness — real, latent bugs in each, fixed by adding the missing explicit access-mode
  bit. Closes `shm_open/13-1.c`.
- **Real per-process CPU-time accounting** (`Process::cpu_ticks`): incremented by 1 on every timer
  tick where that process is the one actually `Running`. `CLOCK_PROCESS_CPUTIME_ID`/
  `CLOCK_THREAD_CPUTIME_ID` both read this (no real threading distinction needed — single
  "thread" per process at the time this landed). Closes `clock_gettime/4-1.c`.
- **Verified**: pilot moved 52P/9F/3U/4UT → 61P/1F/2U/4UT/0TO/0CR.

## Real signal-stack chaining (`src/process/mod.rs`, `src/process/signals.rs`, `src/syscall/mod.rs`)

Closes the pilot's last 2 (`sigqueue/4-1.c` FAIL, `sigqueue/8-1.c` UNRESOLVED) — both `sighold()` +
`sigqueue()` 5 times + `sigrelse()` (one syscall) + immediate check, with **no syscall in
between** the unblock and the check.

- **`Process::signal_stack: Vec<SignalStackFrame>`** replaces the old single-slot saved-frame
  field — `stash_signal_context` pushes an entry per `Handler`-disposition delivery instead of
  overwriting.
- **The chaining mechanism**: `do_sigreturn` now calls `deliver_pending_signal(frame)` itself
  right after popping/restoring an entry, *before* treating that state as final. If another signal
  is deliverable, it redirects `*frame` into that next handler instead of resuming — pushing a
  fresh stack entry, exactly like the first delivery did. Only when a `sigreturn` finds nothing
  else deliverable does execution actually resume. Same fix also closes the general "second signal
  during a *different* handler's execution" gap for free, since both paths call the same
  `deliver_pending_signal`.
- **Verified**: pilot moved 61P/1F/2U/4UT → **64P/0F/0U/4UT/0TO/0CR, 68 total**. Not covered: a
  bound on `signal_stack` depth (real POSIX doesn't bound it either; growth is already bounded by
  `RT_QUEUE_CAP`/bitmask collapse).

## POSIX conformance pilot expanded 68 → 488, plus real frame reclaim and five real bugs it found (`build.rs`, `src/memory/`, `src/process/`, `src/fs/{mqueue,sysv_shm}.rs`, `src/cpu/interrupts.rs`, `modules/oxfs/`, `modules/posix_compat/`)

Grew the pilot corpus from 68 files to 488 (every non-`pthread_*`/non-`aio_*` conformance
directory, deduplicated to one file per assertion-family variant — see `build.rs`'s
`POSIX_TEST_PILOT_FILES` doc comment for the corpus-selection methodology), then fixed five real,
independent kernel bugs the larger corpus's real fork/execve/signal/IPC traffic surfaced.

- **Real per-address-space frame reclaim, closing "no frame dealloc" for the common case** —
  hundreds of real `fork`+`execve`+`exit` cycles in one boot exhausted the heap around file ~140.
  `memory::BootInfoFrameAllocator` gained a real `FrameDeallocator` (an intrusive, singly-linked
  free list stored *in* the freed frames themselves — safe pre-heap-init by construction, unlike a
  `Vec`). **`AddressSpace::teardown`** walks and frees every `USER_ACCESSIBLE` frame beneath a
  discarded address space, safe because every page-table structure frame is always freshly
  allocated per address space, never shared, and fork is eager-copy, never COW.
  **`SHARED_LEAF`** (a repurposed PTE bit) marks the two real exceptions that *do* alias a leaf
  across address spaces — SysV `shmat` and fd-backed `MAP_SHARED` mmap — so `teardown` skips them.
  Wired into `do_execve`'s old-address-space discard and `do_wait4` process reaping. Also bumped:
  heap ceiling 128→1024 MiB, QEMU RAM 1024→8192 MiB, oxfs `NUM_BLOCKS`/`MAX_INODES`
  8192/1024→16384/2048, `test-timeout` 1800→7200.
- **Bug 1 — a ring-3 `#GP` rebooted the whole VM.** `general_protection_fault_handler` never had
  the ring-3 check `page_fault_handler` already had (found via `strftime/2-1.c`'s real
  stack-buffer overflow, correctly caught by musl's stack-protector `hlt`). Fixed with the same
  ring-3 → `SIGSEGV` treatment.
- **Bug 2 — `mq_receive`/`mq_send`'s blocking wait had no signal-interrupt path.** Fixed exactly
  like `pause`/`nanosleep`: check-before-block + a new `wake_if_mq_waiting` hook.
- **Bug 3 — real `futex(2)` doesn't exist, and musl's retry logic turns that into an infinite
  busy-loop, not a clean error.** `sem_timedwait` only treats `EINTR`/`ETIMEDOUT`/`ECANCELED` as
  real failure; anything else (including old `ENOSYS`) silently retried forever with no blocking
  syscall. Fixed with a minimal, honest failure stub: `process::do_futex` (real Linux's unclaimed
  `__NR_futex=202`) — `FUTEX_WAIT` returns real `ETIMEDOUT` instead of a fake `0`. `FUTEX_WAKE`
  just succeeds. (Real futex support landed later — see "Real threading".)
- **Bug 4 — a cross-process signal-default-terminate could panic the kernel via a stale
  scheduler ready-queue entry.** `do_kill`'s cross-process `Action::Terminate` branch, unlike the
  adjacent `Action::Stop` branch, didn't dequeue a `Ready` target from `READY_QUEUE` first — if the
  target was reaped before the scheduler popped that stale entry, `activate_and_prepare` panicked
  ("pid missing from table"). Fixed by adding `scheduler::remove_ready(pid)` into the shared
  `terminate_process` unconditionally.
- **Two pilot-corpus exclusions, not kernel bugs**: `timer_settime/2-1,6-1,9-1.c` block `SIGALRM`
  in-process, which also blocks `t0`'s own rescue alarm (only the three blocking ones excluded,
  not the caught-handler variants); `shm_open/23-1.c` forks 1000 unscaled children with no
  orphan-reaping mechanism on this kernel, permanently exhausting `MAX_OPEN_FILES=8` once its own
  parent dies to the rescue alarm — a structural limitation, not a bug.
- **Verified**: pilot needed 11 full runs to reach clean completion (`target/posix-pilot-logs/`
  holds every run's full serial output). Final baseline: **329P/62F/40U/8US/45UT/3TO/1CR, 488
  total** (the one CRASH is `strftime/2-1.c`'s own real upstream test bug).

## A real timer-signal wake bug, closing a fifth kernel bug the pilot found (`src/cpu/interrupts.rs`, `src/process/signals.rs`)

Found re-running the pilot after `clock_settime(2)` started succeeding for the first time.
`clock_settime/4-1.c` hung permanently past `t0`'s 40s rescue bound.

- **Root cause**: `interrupts::timer_interrupt_handler`'s two signal-expiry sites
  (`real_timer_deadline` and the `posix_timers` loop) only ever set `pending_signals` directly,
  never calling any of the four `wake_if_*` hooks every *other* delivery path already wires in —
  so a process genuinely `Blocked` waiting on a timer-delivered signal was never re-enqueued.
- **Fix**: made all four `wake_if_*` hooks `pub(crate)` and called them from both expiry sites.
- **Verified**: baseline moved 329P/62F/40U/8US/45UT/3TO/1CR → **373P/36F/22U/8US/45UT/3TO/1CR**
  (a broad swath of `sigwait`/`sigtimedwait`/`pause`/`nanosleep`/`mq_receive` tests gated on
  `alarm`/`setitimer`/`timer_create` flipped, not just the one triggering test).

## A real `siginfo_t` field-order bug, plus real `SA_ONSTACK`/`SA_NOCLDWAIT`/`SA_NOCLDSTOP`, plus a real preemption/ready-queue race (`src/process/mod.rs`, `src/process/signals.rs`, `src/process/scheduler.rs`, `src/process/lifecycle.rs`, `src/syscall/mod.rs`)

- **`RawSiginfo`'s `si_code`/`si_errno` fields were swapped relative to real musl x86_64** — a
  real bug present since the struct was first written (x86_64 never uses the MIPS-only swapped
  order). Silent because `SI_USER == 0` too. Found via `sigaction/10-1,11-1.c`'s
  `info->si_code == CLD_STOPPED`/`CLD_CONTINUED` check being permanently unreachable. Fixed by
  reordering the declared fields. **Three userland smoke-test crates hand-duplicate this struct**
  (no shared kernel/userland crate exists) and needed the identical reorder — found by re-running
  the full regression suite, not by inspection. **Any future wire struct duplicated this way needs
  the same audit whenever the kernel-side original changes.**
- **Real `SA_ONSTACK`**: `Process::on_altstack` + `begin_altstack_if_requested` (called by
  `deliver_pending_signal` before `stash_signal_context`); `SignalStackFrame::used_altstack`
  clears it at the right nesting level on `sigreturn`. Real `SS_ONSTACK` readback, real `EPERM`
  when changing the alt stack while genuinely on it.
- **Real `SA_NOCLDWAIT`**: `terminate_process` checks the parent's `SIGCHLD` flags and detaches
  the exiting child immediately instead of leaving an unreapable zombie. Self-exit (still running
  on its own address space) defers pid removal via the existing thread-reap queue instead of
  risking a live-page-table use-after-free — a narrow, intentional gap (one live exerciser).
- **Real `SA_NOCLDSTOP`**: `notify_parent_sigchld` skips `SIGCHLD` generation for the *stop*
  transition specifically when the parent's action has this flag set — a second, independent gap
  the `si_code` fix exposed (this test had always silently "passed" only because the earlier bug
  made its own check permanently false).
- **A real preemption/ready-queue race, found chasing a *flaky* hang**: `scheduler::schedule()`'s
  re-enqueue branch pushed the outgoing pid back onto `READY_QUEUE` without updating its own
  `state` to `Ready` — harmless before real preemption (this branch was only reached via a
  voluntary yield where the caller stayed `Running`-until-resumed), but real preemption now
  reaches it for a merely-interrupted process too, leaving a stale `state == Running` while queued.
  A cross-process `SIGSTOP` targeting that process failed its own `state == Ready` dequeue check,
  so it stayed queued while *also* marked `Stopped` — the scheduler later resumed it anyway,
  silently un-stopping it and stomping the state a subsequent `SIGCONT` depended on. Fixed at the
  actual source of drift: `schedule()` now sets `prev.state = Ready` before enqueueing.
- **`sigaltstack/9-1.c`'s missing `execl()` target**: needed cross-compiling and seeding
  `9-buildonly.c` (a real fixture the pilot's usual `-buildonly.c` exclusion rule wrongly also
  excluded) at its literal upstream-relative path — a pilot-corpus gap, not a kernel change.
- **Verified**: final baseline moved 391P/29F/10U/8US/45UT/4TO/1CR → **398P/25F/9U/8US/45UT/
  2TO/1CR, 488 total** (net seven fixes). Broad signal/scheduling regression suite re-run clean
  given how foundational the `schedule()` fix is.

## Real threading: `clone(2)`, `pthread_create`/`join`, shared address spaces (`src/process/`, `src/memory/address_space.rs`, `src/fs/fd.rs`)

Closes the single biggest foundational architecture blocker this project tracked — motivated by
real POSIX AIO, which both musl and glibc implement as pure userspace logic over a
`pthread_create` worker pool (no distinct kernel AIO syscall family exists on real Unix either).

- **Phase 1**: `clone.s`/`__unmapself.s` hardcoded raw Linux syscall numbers directly (same bug
  class as `vfork.s`, see musl-port section). Fixed: `clone.s` now targets a real reserved
  `SYS_CLONE=555`; `__unmapself.s` calls this ABI's real `SYS_MUNMAP`/`SYS_EXIT` directly.
- **Phase 2**: `Process::tgid: Pid` splits real `getpid()`/`gettid()` apart — set at both
  spawn/fork (never inherited by a forked child, a real process), untouched by execve.
- **Phase 3**: real `FUTEX_WAIT`/`FUTEX_WAKE` (`process::do_futex`, `BlockReason::
  WaitingForFutex(tgid, addr, deadline)`), scoped by `tgid` not raw pid (correct today since no
  ASLR means unrelated processes can share addresses like `USER_STACK_TOP`, and happens to be
  exactly right for `CLONE_THREAD` sharing). Unblocks unnamed POSIX semaphores for real.
- **Phases 4+5, the actual thread-creation prerequisite** — five changes to a kernel with no prior
  notion of two live threads sharing an address space: (1) `AddressSpace` → `Arc<PhysFrame>`-
  refcounted, `teardown` gated on `strong_count == 1`; (2) `ThreadGroupShared`
  (`cwd`/`root_inode`/`umask`/`uid`/`gid`/`brk`/`mmap_file_regions`) `Arc<Mutex<>>`-wrapped, shared
  by every `CLONE_THREAD` sibling; (3) `src/fs/fd.rs` keyed by `tgid`, not raw pid — real
  `CLONE_FILES` sharing falls out for free; (4) real `do_clone`/`SYS_CLONE=555` — `tls` read via
  the same raw-frame-access route `fork`/`execve` already use; (5) per-thread `SYS_EXIT` — a
  non-leader thread's table entry can't be removed inline (the scheduler still needs it mid-
  switch), so it's marked `Zombie` and deferred via `scheduler::queue_thread_reap`, drained at the
  top of every `schedule()` except the one still mid-switch off that exact stack.
  **Two real bugs found landing this**: `do_clone` must *not* call `fs::fd::fork_inherit` (real
  `CLONE_FILES` sharing already falls out from the tgid-keyed table; calling it anyway orphans
  duplicate entries and double-bumps refcounts); `terminate_process`'s whole-group-teardown branch
  must pass `tgid` to `close_all`, not `pid`.
- **Finish line: real `CLONE_CHILD_CLEARTID`** (`Process::clear_child_tid`) — needed for a
  genuinely unmodified `pthread_create()`/`pthread_join()` round trip: real musl's
  `__pthread_exit` routes `__thread_list_lock`'s release through a real kernel clear-and-wake at
  task-exit time, not a plain userspace unlock. Found via live per-syscall dispatch tracing.
  `terminate_process` now does a real write-zero-and-wake of `clear_child_tid` for every exiting
  thread, via a newly factored `process::limits::wake_futex`.

**Two real bugs found writing the raw-`clone(2)` smoke test itself**: a child's own new stack
must be `static mut`, not plain `static` (an all-zero immutable static gets placed read-only by
rustc); a hand-written `asm!` block must `setc` immediately after `syscall`, before any
flag-clobbering instruction.

**Verified**: `tests/clone_syscall_smoke.rs` (raw `clone(2)` proving `CLONE_VM`/`CLONE_THREAD`/
`CLONE_PARENT_SETTID`/futex-based join) and `tests/pthread_syscall_smoke.rs` (a genuinely
unmodified `pthread_create()`/`pthread_join()` C fixture). **What this unlocks**: POSIX AIO with
zero further kernel work; `pthread_mutex_*`/`_cond_*`/`_rwlock_*`/`_barrier_*`/`_spin_*` all
expected to already work (userspace logic over the same real `futex(2)`), not yet covered by a
dedicated smoke test. real `dlopen` stays **not done** (blocked on `mprotect` enforcement,
unrelated to threading).

**Named POSIX semaphores, since fixed** (`process::limits::futex_key`, `src/process/limits.rs`):
`do_futex`'s `FUTEX_WAIT`/`FUTEX_WAKE` used to key every wait/wake pair on `(tgid, addr)` alone —
correct for a *private* futex, but real `sem_open()` semaphores are `pshared` (real, unmodified
musl clears `FUTEX_PRIVATE` for them), meaning `addr` is a virtual address inside a real
`/dev/shm`-backed `MAP_SHARED` mapping that two independent `fork()`ed processes generally map at
their own, *different* virtual addresses (`NEXT_MMAP_PAGE`, `src/process/mm.rs`'s own bump
allocator, is one global counter shared across every process, never reset per caller) — so a
waiter's own `FUTEX_WAIT` and a waker's own `FUTEX_WAKE` almost never agreed on the same key,
permanently hanging `sem_open()`+`fork()` coordination (`build.rs`'s `POSIX_KNOWN_HANGS`'s
`sem_post/8-1.c`/`sem_unlink/{2-2,3-1}.c`/`sem_wait/7-1.c`). Fixed: a *shared* (non-
`FUTEX_PRIVATE`) futex now resolves `addr` through the caller's own address space to the real
physical address backing it instead — identical across every process mapping the same physical
frame, regardless of each one's own virtual address. A private futex is unaffected, still keyed by
`(tgid, addr)` exactly as before (still required on this no-ASLR kernel — see
`BlockReason::WaitingForFutex`'s own doc comment). **Verified**: `tests/sem_open_syscall_smoke.rs`
(a genuinely unmodified `sem_open()`+`fork()`+`sem_post()`/`sem_wait()` C fixture, `userland/
sem-open-smoke/main.c`), plus an isolated canary pilot run (`POSIX_PILOT_CANARY_ONLY=1`, see
`build.rs`'s own doc comment for this validation mechanism) confirming all four previously-excluded
`POSIX_KNOWN_HANGS` files: `sem_unlink/{2-2,3-1}.c`/`sem_wait/7-1.c` now genuinely `PASS`;
`sem_post/8-1.c` cleanly `UNTESTED` (it early-returns on `#ifndef _POSIX_PRIORITY_SCHEDULING`
before ever touching a semaphore or forking — it was swept into the exclusion list by a proactive
pattern match, not an individually confirmed hang, and never actually needed this fix). All four
removed from `POSIX_KNOWN_HANGS`; a full corpus re-run to fold this into the pilot's own official
baseline hasn't been done yet.
Still not done: named POSIX shared memory (`shm_open`, a separate real cross-*process*
coordination path with its own gaps beyond futex keying).

**A real crash found chasing this, from a different angle** (`KernelStack::new`, `src/process/
mod.rs`): canary-testing `pthread_cond_broadcast/1-2.c` (a real `PTHREAD_PROCESS_SHARED` condvar/
mutex stress test creating up to `MAX_THREAD_CHILDREN = 10000` real threads at once) found
`KernelStack::new` hard-`assert!`ed on allocation failure — a single userspace process legitimately
exhausting the kernel-stack pool took the *entire kernel* down, not just that one `pthread_create`/
`fork` call. Fixed: `KernelStack::new` returns `Result<Self, ()>`; `do_fork_from_current`/
`do_clone` (`src/process/lifecycle.rs`) propagate a real `ENOMEM` instead (`do_fork_from_current`
additionally tears down its already-built `child_address_space` on this path — a real deep copy via
`AddressSpace::fork`, would otherwise leak; `do_clone`'s own `child_address_space` is a plain
`Arc::clone` via `AddressSpace::share`, so no teardown needed there). `spawn`'s boot-time call site
still panics — no syscall caller to report `ENOMEM` to that early. Same *class* of bug the "Real
zombie address-space frame reclaim" section above already fixed once, at a sibling allocation site
— `AddressSpace::new`'s own L4-table `.expect()` and the "out of memory mapping a user stack" site
in `lifecycle.rs` were the same shape and unfixed at the time — since closed, see this section's
own follow-up paragraph below. **A second,
unrelated bug this investigation also found**: `interrupts::timer_interrupt_handler`'s own
`[diag-thread]` per-process diagnostic dump (added for the thread-group-signal-delivery
investigation two sections up, explicitly marked temporary) did a full `O(table_len)` scan-and-
`serial_println!` *every 10 real seconds* — with hundreds to thousands of live threads, this alone
dominated a test's real wall-clock runtime badly enough to look like a permanent hang even after
the actual `KernelStack::new` panic was fixed. Removed (the `[diag] tick=table_len=` line itself
stays, `O(1)` per interval, still relevant to `fork/8-1.c`'s own open mystery below).

**The remaining two OOM-panic sites, since closed** (`src/memory/address_space.rs`,
`src/process/lifecycle.rs`, `src/process/fault_trampoline.rs`): `AddressSpace::new`/
`build_from_active` (the shared implementation behind `new_excluding_user`/`fork`) and
`copy_table_level` no longer hard-panic on frame exhaustion, matching `KernelStack::new`'s own
fix just above. `build_from_active`'s frame allocator bound tightened from `FrameAllocator` alone
to `FrameAllocator + FrameDeallocator`: a `copy_table_level` failure partway through a real
`fork()`'s eager deep-copy can leave the new child table holding a genuine, partially-built
subtree that must be freed before returning the error, or it leaks permanently. That cleanup
reuses `free_table_level` (already used by `AddressSpace::teardown`) directly, with no new walk of
its own — safe on a partially-built table because `child` is fully `zero()`'d immediately before
`copy_table_level` starts, so every entry it never reached is still `!PRESENT`, which
`free_table_level` already skips outright. `map_user_stack`/`fault_trampoline::map`
(`lifecycle.rs`) got the identical treatment, including distinguishing `map_to`'s own
`MapToError::FrameAllocationFailed` (real `ENOMEM`) from `ParentEntryHugePage`/`PageAlreadyMapped`
(real logic-invariant violations, still a hard panic — always-fresh VAs in a brand-new address
space, so hitting either means a future change broke that assumption). `do_execve`'s own three
call sites propagate a real `ENOMEM`; `spawn`'s boot-time call sites still panic, same reasoning as
every other boot-time allocation site. **Deliberately not addressed**: `do_execve` still has no
established convention for tearing down its own scratch `new_address_space` on *any* mid-build
failure (an `ENOEXEC` found partway through `elf::load`, for instance, already leaked the same way
before this pass) — the new `ENOMEM` paths in `map_user_stack`/`fault_trampoline::map` match that
existing (imperfect) precedent rather than inventing a new, inconsistent partial-cleanup discipline
for just those two call sites. Verified via `tests/fork_wait.rs`/`clone_syscall_smoke.rs`/
`dynlink_syscall_smoke.rs` (the real `PT_INTERP` path, `new_excluding_user`'s one exerciser)/
`mmap_syscall_smoke.rs` (forks into `fault_trampoline`-driven `SIGBUS`/`SIGSEGV` handlers) in an
isolated git worktree — the happy path is unaffected; the OOM path itself has no dedicated
regression test (would need a real way to force frame exhaustion on demand, not attempted here).

**A much bigger, separate discovery running a fresh full-corpus supervised pilot** (`scripts/
run_posix_pilot_supervised.sh --reset`), since root-caused and fixed: the naive "exclude whatever
file didn't get a classification line, retry" heuristic doesn't converge on this corpus at all. 23
iterations (~90 real minutes) each excluded exactly one file and stalled again almost immediately —
most of those exclusions were **wrong**: `pthread_atfork/3-3.c`/`pthread_attr_destroy/1-1.c`/
`pthread_attr_init/2-1.c` (all independently reconfirmed `PASS` in isolation earlier the same
session) got excluded anyway, because they merely happened to sit immediately after whichever file
actually broke the boot.

The trail: reading `supervised_iter23`'s own log showed `pthread_cancel/5-1.c` (real
`pthread_cancel(3)` isn't implemented) genuinely crashing with `CRASH(139)`, immediately followed
by the boot going silent for good. **First theory, disproven**: that this specific crash somehow
wedged the whole kernel. A dedicated isolated repro (`userland/pthread-cancel-crash/main.c` +
`tests/pthread_cancel_crash_smoke.rs`, reproducing `pthread_cancel/5-1.c`'s own exact scenario —
`pthread_join()`'s real `munmap()` of a joined thread's own stack, then `pthread_cancel()`
unconditionally writing through the now-freed handle) showed the crash recovering *perfectly
cleanly* — a real, unrelated binary ran fine immediately afterward. So the crash was a red herring:
the real manifest showed `pthread_cond_broadcast/1-2.c` sitting just seven files later, already
known from this same session's `KernelStack::new` investigation to stall with a suspiciously flat,
non-growing process table — the actual, silent (no `CRASH` line at all) stuck point, misattributed
to its more dramatic upstream neighbor the same way the wrongly-excluded `pthread_atfork`/
`pthread_attr_*` files were.

**Root cause, confirmed via `userland/pshared-cond-crash/main.c` + `tests/
pshared_cond_crash_smoke.rs`**: a real, previously-undiscovered bug in this project's own musl fork
(`third_party/musl`, commit `665bc49f` on the `oxidebsd` branch) — not a kernel bug. A minimal
repro (real `PTHREAD_PROCESS_SHARED` mutex/cond in a file-backed `MAP_SHARED` region) passed with
one forked child, and even with a concurrently-running second thread alone, but hung as soon as
**both** were combined: two or more real forked children genuinely contending the shared mutex,
forked from a process that already had a second live thread. A one-off `[diag-thread]` dump
(temporarily reintroduced for this one investigation, small process count so the earlier
performance concern didn't apply) showed both stuck children blocked on a real, *private*-scoped
futex at the identical address across both — decoded via `nm` to musl's own internal `ofl_lock`
(the stdio "open file list" lock), not any address of the test's own shared struct.

The actual bug: real, upstream `fork()` (`third_party/musl/src/process/fork.c`) takes a real
`LOCK()` on several internal locks, including `ofl_lock`, in the parent *before* the real fork
syscall, whenever the process is genuinely multi-threaded (`libc.need_locks > 0`) — real, correct,
unmodified musl behavior. But `_Fork.c`'s own `reset_stdio_locks_in_child` — **this project's own
earlier fix for a *different* permanent hang** (`fork/11-1.c`, see "POSIX pilot: full corpus
expansion" above) — unconditionally calls `__ofl_lock()` again to safely walk the open-FILE list.
The child inherits `ofl_lock` in a genuinely *locked* state (copied byte-for-byte from the parent's
own real lock acquisition moments before the fork syscall), so this second `__ofl_lock()` call
self-deadlocks immediately: the child's one surviving thread waits forever on a lock nothing will
ever release. Only reproduces with the exact combination this investigation found by bisection
(2+ real contending children *and* a real second thread already running at fork time) — the
`fork/11-1.c` fix's own original validation never exercised that combination. Fixed the same way
`fork()`'s own child-side atfork cleanup already treats every other lock in this exact situation: a
raw store back to unlocked immediately before ever trying to acquire it, since a freshly forked
child is always, unconditionally, the sole surviving thread — any inherited "locked" state is never
real contention.

**Verified**: the full N=10-children-plus-timer-thread repro, which hung indefinitely before the
fix, now passes cleanly; the existing regression suite (`fork_wait`, `clone_syscall_smoke`,
`pthread_syscall_smoke`, `sysv_sem_syscall_smoke`, `sem_open_syscall_smoke`,
`pthread_cancel_crash_smoke`, `mmap_syscall_smoke`, `dynlink_syscall_smoke`) all still pass after
the musl bump. `fork/8-1.c`'s own separate, still-genuinely-open CPU-timing mystery
(`POSIX_KNOWN_HANGS`) is unrelated to any of this and remains unresolved. A fresh full-corpus
supervised run to fold this fix into an official baseline number hasn't been done yet.

**A real, separate staleness bug found auditing `build.rs`'s own exclusion bookkeeping**:
`pthread_atfork/3-3.c`/`pthread_attr_destroy/1-1.c` were marked "historical markers only, still
excluded in effect by the wholesale `pthread_*`/`aio_*`/`lio_listio*` prefix filter regardless" —
true when written, but that filter's own code was deleted on 2026-09-02 (the "POSIX pilot: full
corpus expansion" section above), and the two array entries were never revisited. Both were quietly
live-excluding two already-fixed, passing files for no real reason since that date. Separately,
`sigwait/4-1.c`/`timer_settime/{2-1,6-1,9-1}.c` turned out to be the same staleness class from a
different cause: all four share one shape (`sigprocmask(SIG_BLOCK, SIGALRM)`, arm a real timer,
`sigwait()` for it) exactly matching the delivery path "A real timer-signal wake bug" (above)
fixed — added to `POSIX_KNOWN_HANGS` before that fix landed, never re-verified after. All six
confirmed `PASS` via isolated canary runs and removed. `POSIX_KNOWN_HANGS` is down to two genuine,
live exclusions: `fork/8-1.c` (confirmed still genuinely stuck, unrelated to the `[diag-thread]`
fix above — needs a live dispatch trace, not more source-reading) and `sched_yield/1-1.c` (needs
real SMP). **Lesson for next time**: an exclusion-list entry justified by "some other mechanism
also catches this" needs that other mechanism re-checked to still exist, not trusted at face
value — the canary mechanism (`POSIX_PILOT_CANARY_ONLY=1`, see `build.rs`'s own doc comment) is now
kept as a standing regression suite covering all ten of these fixes plus the four `sem_*` ones, not
emptied out after use, specifically to make catching this kind of drift cheap going forward.
**Stale as of the next section below**: `POSIX_KNOWN_HANGS` gained a third live exclusion,
`shm_open/23-1.c`, for an unrelated reason (a global-fd-table leak cascade, not a hang) — since
fixed for real, see "oxfs write path..." further below; `POSIX_KNOWN_HANGS` is empty again.

## A global-fd-table exhaustion cascade misclassifying hundreds of unrelated tests as `sigaction/1-N.c` FAILs, `MAX_OPEN_FILES` bumped, `shm_open/23-1.c` excluded (`modules/oxfs/src/lib.rs`, `build.rs`)

A full-corpus supervised pilot run reported 268 FAILs, 210 of them `sigaction/1-N.c` — wildly
disproportionate for a handful of small, previously-passing files. Isolating `sigaction/1-1.c`/
`1-2.c` alone (`POSIX_PILOT_CANARY_ONLY=1`) showed both cleanly `PASS`, proving the bug was
state-dependent on the full sequential run, not in signal delivery itself.

- **Root cause**: `modules/oxfs`'s `OPEN_FILES` table (`MAX_OPEN_FILES`, used for any write-mode or
  newly-created-file open) is a single **global** fixed-size array, not scoped per process. The
  pilot's own `shm_open/23-1.c` (real POSIX atomicity stress test: `NPROCESS=1000` children, each
  looping `NLOOP=1000` times calling `shm_open(name, O_RDONLY|O_CREAT|O_EXCL, ...)`) never calls
  `close(fd)` anywhere in that loop — harmless on a real POSIX system, where fd exhaustion is
  scoped *per-process* (bounded by that one process's own `RLIMIT_NOFILE`), but on this kernel it
  permanently drains a table every other process shares, including **`hush` itself**. Once
  exhausted, `hush` can no longer open its own output-redirect file for the rest of the boot, so
  every later test — regardless of that test's own actual correctness — got misclassified as FAIL
  (`hush: can't open '/posix-tests/run-out.txt': No file descriptors available` on every line).
  Confirmed by rebuilding the canary list to the real manifest slice from `shm_open/1-1.c` through
  `sigaction/1-2.c`: the exact same cascade reproduced in isolation, with `[diag] tick=` showing the
  process table still growing rapidly right as `shm_open/23-1.c` hit its own real `TIMEOUT`.
  `close_all()` (`src/fs/fd.rs`, called from `terminate_process`) is not the bug — verified correct;
  the leaked children are still alive and running, not exited-but-unreaped.
- **`MAX_OPEN_FILES` bumped 8 → 256** (`modules/oxfs/src/lib.rs`) — a genuine, worthwhile increase
  in its own right (each slot costs `MAX_WRITE_BUFFER` = 128 KiB regardless of use, so 256 slots is
  a cheap ~32 MiB), but **not sufficient alone**: `shm_open/23-1.c`'s children keep running and
  leaking new global entries for a real, sustained stretch of wall-clock time (`sleep(1)` plus a
  random 0–20 ms `nanosleep` between each of 1000 iterations, times 1000 children) — confirmed live
  that even with the bump, running the same file far enough ahead of other tests (`timer_settime/
  {2-1,6-1,9-1}.c`, well past `sigaction` in the canary's alphabetical order) still hit the
  identical "No file descriptors available" cascade once enough wall-clock time had passed for the
  orphans to re-exhaust the larger table. A static bump only buys time against an unbounded leak,
  it can't fix one.
- **`shm_open/23-1.c` added to `POSIX_KNOWN_HANGS`** (not a hang — it correctly `TIMEOUT`s at
  `t0`'s own 40s bound, never wedges the boot — but excluded anyway since leaving it in a real
  full-corpus run cascades into misclassifying hundreds of unrelated later files regardless of how
  large `MAX_OPEN_FILES` is). The real fix for this class of test would be a genuine per-process
  (or per-tgid) fd quota — out of scope for this pass; noted as a known architectural gap
  (`OPEN_FILES` being global rather than per-process is otherwise invisible, since almost nothing
  in this corpus leaks fds at this kind of scale). Also dropped from the `POSIX_PILOT_CANARY_ONLY`
  standing regression suite for the same reason — keeping a permanently-excluded, unboundedly
  leaking file in that suite would fail its own downstream neighbors forever regardless of kernel
  correctness, not a useful signal.
- **Verified**: the real manifest slice (all `shm_open`/`shm_unlink` files plus `sigaction/1-{1,2}
  .c`, run in order) now completes cleanly with `sigaction/1-1.c`/`1-2.c` both `PASS` and no
  cascade; the full 64-file standing canary suite (all prior fixes plus this one) also passes
  clean, `table_len` staying flat at 2–3 throughout instead of climbing into the hundreds. Two
  narrow, unrelated, pre-existing FAILs surfaced once the cascade stopped masking them —
  `shm_open/39-2.c`/`shm_unlink/10-2.c`, both `ENAMETOOLONG`-for-`PATH_MAX` enforcement gaps
  neither `shm_open`/`shm_unlink` currently implements — noted as a follow-up, not fixed here. A
  fresh full-corpus supervised run to fold this fix into an official baseline number hasn't been
  done yet.

## Closing a real scheduler race and a real thread-group-leader signal-termination bug (`src/process/{mod,scheduler,lifecycle,signals}.rs`, `src/cpu/interrupts.rs`, `src/syscall/mod.rs`)

A fresh, `--reset` full-corpus supervised pilot run hit the same "naive exclude-the-stalled-file
heuristic doesn't converge" trap the `ofl_lock` investigation hit earlier — 7 iterations, 7
exclusions, every one landing in `pthread_cond_*`/`pthread_cancel`/`pthread_attr_*` territory (new
ground, since the `ofl_lock` fix only just unblocked reaching this far). Investigating the first of
these, `pthread_attr_setdetachstate/2-1.c`, found two real, independent, now-fixed bugs — one
scheduler-level, one signal-delivery-level — behind what looked like one flaky test.

- **Bug 1, the scheduler**: `interrupts::timer_interrupt_handler`'s ring-3 preemption check used to
  be `now.is_multiple_of(PREEMPT_QUANTUM_TICKS)` — a purely **global** tick-counter-phase check, not
  a per-process quantum. A process's actual remaining time before a possible preemption was pure
  luck (1 to `PREEMPT_QUANTUM_TICKS` ticks) depending only on where the global counter's phase
  happened to be when it started running, never on anything about that process itself. Real
  musl's `pthread_join()`/`pthread_detach()` against an already-`PTHREAD_CREATE_DETACHED` thread
  deliberately call `a_crash()` (see Bug 2) after reading that thread's own `detach_state` field —
  a field living inside the very stack mapping the detached thread's own exit path (`__unmapself`)
  unmaps out from under it, with zero synchronization (real POSIX documents this exact case —
  joining/detaching an already-detached thread — as undefined behavior). A real multi-core
  machine's own fast, tiny instruction window between `pthread_create()` returning and that read
  almost never loses this race. Under this kernel's single-core, QEMU/TCG-emulated execution, that
  same handful of instructions can span a whole 10ms tick, making a same-tick preemption to the
  freshly-created (and nearly idle) child land in the middle of that window a real, reproducible
  occurrence.
  - **Fix**: real per-process round-robin quantum. `Process::quantum_ticks_left` is set to a fresh
    `PREEMPT_QUANTUM_TICKS` every time a process is (re)activated to `Running`
    (`scheduler::activate_and_prepare`, and `schedule()`'s own "nothing else ready, same process
    keeps running" fast path, which bypasses that function entirely) and decremented once per tick
    it's found actually running; preempted at `0`. **The actual race-closing move**: `do_clone`
    resets the *caller's own* remaining quantum back to a fresh value right as its new child
    becomes schedulable — giving a thread that just created another thread a real, guaranteed
    window to finish any immediate follow-up work (like this test's own `pthread_join`/
    `pthread_detach` pair) before the brand-new child could possibly preempt it.
- **Bug 2, the real crash-or-hang mechanism**: real, unmodified musl's `a_crash()` (x86_64) is a
  raw ring-3 `hlt` instruction — a privileged opcode, `#GP`-faulting at CPL=3, converted by this
  kernel's own real fault-to-signal delivery (see "Real ring-3 fault-to-signal delivery" above)
  into a genuine self-`SIGSEGV`. That default-disposition termination path
  (`syscall::deliver_pending_signal`'s `SignalDelivery::Terminate` arm) called `do_exit` — a
  **per-thread**-only exit — instead of `do_exit_group`. If the crashing thread happened to be a
  thread-group **leader** with a still-live sibling thread (exactly this test's own shape: the
  main thread crashes inside `pthread_join()` while its own newly-created worker thread might
  still be alive), `terminate_process`'s `other_thread_alive` check saw that live sibling and
  concluded this was "just another disposable `CLONE_THREAD` sibling exiting" — correct for an
  *actual* non-leader thread (never an independent `wait4` target), catastrophically wrong for the
  leader itself, which is the *only* process a real `wait4()` is ever watching. The leader got
  silently marked `Zombie` and queued for full table-entry removal with **no**
  `wake_parent_if_waiting`/`notify_parent_sigchld` call at all — permanently hanging the parent's
  `wait4(-1, ...)`, whether the queued removal finished first (the pid vanishes outright, wait4's
  own children-list scan finds nothing) or not (an unreachable, never-notified zombie sitting
  there, since no second wake is ever coming). This is the **same underlying gap** `do_kill`'s
  cross-process `Action::Terminate` had too (a `kill(pid, SIGKILL)` on a thread-group leader with
  live siblings would hit the identical bug) — both were auditing the wrong function for a signal
  that must, per real POSIX, terminate the *whole* process, not one thread.
  - **Fix**: factored `do_exit_group`'s own "kill every other thread first, then this one" logic
    into `terminate_thread_group` (non-diverging, for a target that isn't necessarily the
    currently-running process — `do_exit_group` itself now just calls this then its own
    `schedule()`/`unreachable!()` epilogue). `deliver_pending_signal`'s `SignalDelivery::Terminate`
    arm now calls `do_exit_group` directly (a strict superset of `do_exit`'s own behavior for a
    genuinely single-threaded caller, safe unconditionally); `do_kill`'s three `Action::Terminate`
    call sites now call `terminate_thread_group` instead of `terminate_process` directly.
- **Debugging note**: found via three rounds of targeted `serial_println!` tracing (queue/drain
  events in the thread-reap queue, then `do_exit`/`do_exit_group`/`wake_parent_if_waiting`/
  `do_wait4`'s own entry points and decisions), not guesswork — the first theory (a pure musl
  detached-thread-exit race, unfixable kernel-side) was **wrong**; mapping a genuine ring-0 page
  fault's own instruction pointer back through the compiled test binary's symbol table (`addr2line`)
  is what actually located the real, fixable bug. All temporary tracing was removed once the real
  fix was confirmed.
- **Verified**: `pthread_attr_setdetachstate/2-1.c` now `CRASH(139)`s **deterministically** (matching
  real musl's own intentional `a_crash()` behavior for this exact undefined-behavior case — not
  something to "fix" further) and the pilot recovers cleanly afterward every time, across 9
  consecutive isolated canary runs (previously flaky: sometimes crashed cleanly, sometimes hung
  forever). Full existing regression suite (`fork_wait`, `clone_syscall_smoke`,
  `pthread_syscall_smoke`, `sysv_sem_syscall_smoke`, `sem_open_syscall_smoke`,
  `pthread_cancel_crash_smoke`, `pshared_cond_crash_smoke`, `mmap_syscall_smoke`,
  `dynlink_syscall_smoke`) still passes, including every fault-to-signal and cross-process-kill
  path this change touches. `pthread_attr_setdetachstate/2-1.c` added to the `POSIX_PILOT_CANARY_ONLY`
  standing regression suite.

## A fresh full-corpus run confirms the fix, plus four newly-found, genuinely distinct pthread hangs (`build.rs`)

A fresh `--reset` full-corpus supervised run, after the fix above, confirmed it working exactly as
intended: `pthread_cond_broadcast/2-3.c`/`4-2.c`, `pthread_cond_destroy/2-1.c`, and
`pthread_cond_init/4-2.c` (all separately flagged stalling in earlier runs, before ever being
individually investigated) now all either `PASS` or cleanly `TIMEOUT` (`t0`-rescued) — the same fix
closed all of them, not just the one file it was built against. All four added to the
`POSIX_PILOT_CANARY_ONLY` standing regression suite.

The run also surfaced a fresh cluster of stalls in `pthread_attr_setstacksize`/`pthread_cancel`/
`pthread_cond_timedwait` territory. Triaged each individually via isolated canary runs (not the
naive supervisor exclude-and-retry loop, which hit the same non-convergence trap as before —
misattributing a stall to whatever file happened to be running when the *build itself*, now over a
minute for this corpus size, ate into the supervisor's 120s stall-detection window before QEMU even
booted; `pthread_cond_timedwait/4-2.c`/`4-3.c`'s own transient exclusions during that run were pure
build-time false positives, not real findings, and were reverted). Verified findings:

- **`pthread_attr_setstacksize/2-1.c`**: a real, genuine, permanent hang — **not** another instance
  of the fix above. The worker thread's own `pthread_getattr_np()` call (a real GNU/NPTL extension)
  should hit a fast, syscall-free path reading its own already-known `stack`/`stack_size` fields;
  the fallback path (calling real musl's own `mremap()`-retry loop) doesn't obviously explain a
  permanent hang either, since `mremap` isn't even registered in this kernel's syscall table (an
  unregistered-syscall `ENOSYS` should make that specific loop exit on its first try, not spin).
  Root cause not yet found — added to `POSIX_KNOWN_HANGS`.
- **`pthread_cancel/5-2.c`**: a real, genuine, permanent hang, also unrelated to the fix above.
  Calls `pthread_cancel()` on a target thread in a tight loop for a full real second while that
  thread only ever spins on `sched_yield()` — never at a real POSIX cancellation point. Real musl's
  own `cancel_handler` (`third_party/musl/src/thread/pthread_cancel.c`) is *designed* to keep
  re-sending `SIGCANCEL` to the target via a raw `tkill` syscall in exactly this situation — a real,
  legitimate (if wasteful) userspace resend loop on any correct system, not itself a bug. Suspected
  but unconfirmed: something about this specific repeated real-time self-directed-signal-storm
  pattern (`pthread_kill`/`tkill` retargeting one specific thread over and over) trips a genuine
  kernel-side issue. Added to `POSIX_KNOWN_HANGS`.
- **`pthread_cond_timedwait/2-5.c`** and **`4-1.c`**: both real, genuine, permanent hangs — `t0`'s
  own 40s rescue alarm never fires for either (unlike every file the fix above actually closed,
  which now cleanly `TIMEOUT`). Structurally quite different from each other (`2-5.c` uses real
  `PTHREAD_PROCESS_SHARED` mutex/cond across multiple threads; `4-1.c` is a plain single
  `pthread_create`) — the one thing they share is calling `pthread_cond_timedwait` itself, the more
  likely common root cause than either file's own surrounding setup. `4-2.c`/`4-3.c` (same
  directory) remain unverified — each attempt to test them got blocked by whichever of these two
  hung first. Both `2-5.c` and `4-1.c` added to `POSIX_KNOWN_HANGS`; `pthread_cond_timedwait` itself
  is the most promising next investigation target, given it's implicated in two independent hangs.

## SIGCHLD delivery, real `sched_setparam(2)`, and four more mmap conformance fixes (`src/process/`, `modules/oxfs/`, `modules/posix_compat/`)

- **Real `SIGCHLD` delivery on child exit/stop/continue**: this kernel never delivered a real
  `SIGCHLD` before this. Found via `sigaction/10-1.c` (a `SIGCHLD` handler busy-waiting for
  `CLD_STOPPED` before ever sending `SIGCONT` — a stopped child became a permanent unreapable
  orphan once the parent died to its own rescue alarm, wedging the rest of the pilot run). Fixed
  with `signals::notify_parent_sigchld` (correct `CLD_EXITED`/`CLD_KILLED`/`CLD_STOPPED`/
  `CLD_CONTINUED` `si_code`+`si_status`, reusing `RawSiginfo`'s existing `si_value` offset), wired
  into every real child-state-transition point. Also fixes `hush`'s own `CONFIG_HUSH_FAST`
  short-circuit, previously dead since its `SIGCHLD` counter could never move. Pilot moved
  373P/36F/22U/8US/45UT/3TO/1CR → 391P/29F/10U/8US/45UT/4TO/1CR (`sigaction/10-1,11-1.c` now
  cleanly `TIMEOUT` instead of hanging forever — still blocked on the unimplemented `select()`).
- **Real `sched_setparam(2)`**: previously permanently stubbed `ENOSYS` in musl itself. Added
  `process::do_sched_setparam` + `SYS_SCHED_SETPARAM=507`. Second bug found the same session:
  `do_sched_scheduler` always returned `Ok(0)` on success, but real POSIX must return the *former*
  policy — fixed.
- **Four more real mmap conformance fixes**, closing `mmap/{3,9,14,18,19,21,28,31}-1.c` and
  `munmap/{3,4}-1.c`: (1) real `MAP_FIXED`/`MAP_PRIVATE` flags riding the wire (packed into
  `prot`'s unused high bits, musl patched accordingly) with real `EBADF`/`EINVAL` validation —
  previously the kernel guessed anonymous-vs-file-backed purely from `fd == -1` and ignored
  `MAP_FIXED` entirely; (2) real `mtime`/`ctime` tracking (`oxidebsd_unix_time` kernel export) plus
  real `mlockall(MCL_FUTURE)`/`RLIMIT_MEMLOCK` enforcement via `ThreadGroupShared`'s new
  `mlockall_future`/`locked_bytes`; (3) real `ENXIO` for an out-of-bounds nonzero-offset mmap
  request; (4) real `EOVERFLOW` when `off + len` exceeds `i64::MAX` (blocked by musl's own
  client-side `len >= PTRDIFF_MAX` guard, removed on the `oxidebsd` branch — **deliberately fixed
  even though real glibc+Linux fails this same test too**, since this project targets literal
  POSIX-spec conformance, not Linux-shaped behavior).
- **Verification**: `userland/mmap-syscall-smoke` extended with 8 further parts. Final:
  398P/25F/9U/8US/45UT/2TO/1CR → **414P/11F/7U/8US/45UT/2TO/1CR, 488 total**.

## Three UNRESOLVED fixes: a stock-musl `sigset` bug, real `timer_create` CPU-time clocks, and a same-process oxfs stat-visibility gap (`third_party/musl`, `src/process/timers.rs`, `src/cpu/interrupts.rs`, `modules/oxfs/`)

- **`sigset(sig, SIG_HOLD)` returned the wrong value on its first call** — a real bug in stock,
  unmodified musl (not anything this fork had patched before): it queried current disposition and
  returned that instead of `SIG_HOLD` whenever `sig` wasn't already blocked. Fixed on the
  `oxidebsd` musl branch (`6d311b99`): `disp == SIG_HOLD` now returns `SIG_HOLD` unconditionally
  once `sigprocmask(SIG_BLOCK)` succeeds. Closes `sigset/6-1,7-1.c`.
- **`timer_create`/`_settime`/`_gettime` rejected CPU-time clockids with a flat `EINVAL`** — musl
  unconditionally claims `sysconf(_SC_CPUTIME)` is supported. Fixed by extending
  `is_cputime_clock` acceptance and arming/reading against `Process::cpu_ticks`. Closes
  `timer_create/10-1,11-1.c`.
- **A same-process `stat()` couldn't see a file its own still-open `O_CREAT` fd had just
  created**: oxfs defers the real inode/dir-entry insert until commit; `force_commit_pending_
  create` (already existed for `oxfs_open`'s own lookup) was never wired into
  `resolve_path_impl` — the shared resolver every *other* path-based syscall uses. Fixed by
  calling it once per path component inside that walk. **Not a plain PASS once fixed** —
  `mmap/13-1.c` then reaches its real assertion and correctly FAILs (`st_atime` is a permanent
  honest-`0` placeholder; real glibc+Linux fails this identical test for the same underlying
  reason per the suite's own `coverage.txt`) — a correctness improvement over the prior false
  `UNRESOLVED`, not a regression.
- **`sched_setparam/9-1,10-1.c` — investigated, not resolved.** Both fork real `SCHED_FIFO`
  children expecting real preemption on `sched_setparam()`, observed via SysV shm. Nothing in
  `do_sched_setparam`/permission checks/`sysconf` looked broken for the single-core root-uid case;
  needs a live dispatch trace to pin down, not more source-reading.
- **Verified**: 414P/11F/7U/8US/45UT/2TO/1CR → **420P/10F/2U/8US/45UT/2TO/1CR, 488 total**.

## POSIX pilot: full corpus expansion, real thread-group signal delivery, `exit_group(2)`, two real musl `fork()` bugs (`build.rs`, `src/process/`, `third_party/musl`)

Grew the pilot from the 488-file curated/deduplicated subset above to the **full Open POSIX Test
Suite corpus** (~1700 files in `conformance/interfaces/`, `pthread_*`/`aio_*`/`lio_listio*` included
now that real threading exists — see "Real threading" above): `discover_posix_test_files` walks the
directory dynamically instead of a hand-curated file list; the build loop is best-effort
(skip+log, not panic) since not every file cross-compiles clean; every pilot binary shares one
fixed load address instead of a unique slot each (the old per-file scheme ran out of VA room past
~700 files); oxfs `NUM_BLOCKS`/`MAX_INODES`/`NAME_MAX` bumped again (65536/8192/40) for the larger,
longer-named corpus; the kernel's own low-VA family shifted `+0x4000000` (third time this exact
"embedded corpus grew past the fixed load-base floor" class of bug has hit — see the userland
load-base note above).

**Reliability fixes needed to get real threading's own test directories past a permanent hang**,
found via a `[diag-thread]` per-process diagnostic dump added to `timer_interrupt_handler`
(pid/tgid/state/pending/blocked/preempted_resume, printed alongside the existing periodic `[diag]
tick=` line) rather than live GDB — each a genuine, independent kernel or musl bug, not one root
cause:

- **Real thread-group-wide signal delivery had two bugs**, both in `process::signals`: (1)
  `resolve_signal_recipient`'s fallback preferred the literal thread-group leader when no sibling
  had reached its own `sigwait()` yet — since the leader itself never sigwaits, a signal aimed at
  the group sat pending-but-blocked on it forever; fixed to prefer any *other* live group member,
  relying on `do_sigtimedwait`'s own check-before-block loop to consume it once that sibling
  arrives. (2) The whole-group reroute fired unconditionally on every `kill`/`sigqueue`, including
  a real `pthread_kill(exact_thread, sig)` (this ABI has no separate `tkill`/`tgkill` — it reaches
  the same code as a process-directed `kill()`, but must target *precisely* the named thread).
  Fixed via `route_signal_target`, gating the reroute to only fire when the literal target names
  its own group's leader. Also fixed in the same pass: `fault_trampoline`'s `mov eax,
  SYS_FAULT_PUMP` (see "Real ring-3 fault-to-signal delivery" above) permanently clobbered the
  interrupted process's real `RAX` before it could be captured — silently corrupting live
  computation on resume for any ring-3 process fielding a signal with no syscall of its own in
  flight. Fixed by stashing real `RAX` to a scratch slot on the trampoline's own page first.
- **A real, distinct `SYS_exit_group` bug**: `exit()`/`_Exit()` shared the exact same syscall
  number as a bare per-thread `SYS_exit` (a leftover predating real threading). A thread-group
  leader calling plain `exit()` only tore down itself — any still-running sibling thread was
  silently orphaned, and later deadlocked in its own `pthread_exit()` cleanup
  (`__tl_lock()`/`__thread_list_lock`) against musl's userspace thread-list bookkeeping, whose
  invariants assume a real `exit_group` already unlinked the leader atomically. Fixed with a
  genuinely distinct `SYS_EXIT_GROUP=556` (`process::do_exit_group`, kills every other tgid member
  first, then the caller) plus a matching `__NR_exit_group` remap on the musl fork.
- **Two real, independent, stock-musl bugs (not kernel bugs) behind `fork/11-1.c`'s permanent
  hang** — found by decoding the exact futex-wait addresses against the compiled test binary's own
  symbol table (`nm` + manual `struct _IO_FILE` offset math), not guesswork: (1) `_Fork()`'s
  `__post_Fork` reset the surviving thread's own `tid`/`__thread_list_lock` in the child but never
  touched any `FILE`'s own `.lock` word — a `flockfile(stdout)` held by the parent before `fork()`
  left `stdout`'s lock word holding a "ghost" tid in the child's eager-copied memory, unrecoverable
  by any thread there (real glibc avoids this via its own `pthread_atfork`-registered
  `_IO_list_resetlock`; stock musl has no equivalent). Fixed by resetting every known `FILE`'s lock
  in `__post_Fork`'s child branch. (2) Once fix (1) let the new thread lock `stdout` successfully, a
  second, fork-independent bug surfaced: that thread exits without ever calling `funlockfile()`
  (legal per POSIX), and musl's own `__do_orphaned_stdio_locks()` marked the lock with a poison bit
  instead of actually releasing it — permanently stuck, since nothing ever wakes it. Fixed to do a
  real release-and-wake, matching `__unlockfile()`'s own pattern. Both fixed on the `oxidebsd` musl
  branch. `pthread_attr_destroy/1-1.c` turned out not to be an independent bug at all: `fork/11-1.c`
  sorts first alphabetically in the sequential pilot boot and permanently wedged the run before this
  file ever got a chance to execute — once `fork/11-1.c` was fixed, it passed with zero further
  changes.
- **`ccache` wired into both the BusyBox applet build and the pilot's own per-file compile loop**
  (`build.rs`'s `compiler_invocation()` helper) — both already did a real rm-rf-and-rebuild-from-
  scratch on any musl core change (correct for staleness, but threw away enormous amounts of
  identical recompilation across BusyBox's ~232 applets). ~79% cache hit rate confirmed live on the
  next build; falls back cleanly when `ccache` isn't installed.

**The wholesale `pthread_*`/`aio_*`/`lio_listio*` prefix exclusion (~600 files) is now lifted** —
the full ~1673-file corpus (all of `conformance/interfaces/`, threading included) has been run to
completion. `sched_yield/1-1.c` stays excluded permanently (assumes real SMP fairness this
single-core kernel can't provide); a handful of `timer_settime`/`sigwait` files stay excluded for
reasons predating this expansion (see `POSIX_KNOWN_HANGS` in `build.rs` for the current, authoritative
list — several entries there are kept only as historical markers of bugs already fixed, not live
exclusions).

## Real zombie address-space frame reclaim at exit, a host-vs-OxideBSD POSIX comparison, and supervised full-corpus tooling (`src/process/`, `scripts/run_posix_pilot_{supervised,host}.sh`, `userland/posix-conformance-driver/`, `build.rs`)

Running the full ~1673-file corpus unattended (`scripts/run_posix_pilot_supervised.sh`, a host-side
supervisor that kills a wedged QEMU boot and retries with the stuck file excluded, since a
kernel-level hang can't be rescued by `t0`'s own userspace `alarm()`) surfaced a real, reproducible
kernel panic partway through — `out of memory mapping a user stack` — confirmed via a supervised
multi-hour run hitting the identical panic site repeatedly regardless of which file happened to be
running when the shared frame pool finally ran dry.

- **Root cause**: this codebase never reparents an orphan to a pid-1 "init" (an accepted
  simplification — see `do_wait4`'s own doc comment), so any process whose real parent already
  exited (or simply never calls `wait4()` on this specific child) leaves a permanent zombie that is
  *never* reaped by anyone. Before this fix, `Process::address_space` was a plain `AddressSpace`
  (not optional) freed only by `wait4`'s own reap path — so an unreaped zombie pinned its *entire*
  address space (every mapped page, not just bookkeeping) for the rest of the boot. Many
  `pthread_*`/`fork` tests in the real POSIX corpus legitimately fork a child and exit without
  joining/waiting it (that's part of what they're testing) — across ~1673 files this compounded
  until physical memory was exhausted.
- **Fix**: `Process::address_space` is now `Option<AddressSpace>` — `None` only for a
  `ProcState::Zombie` whose frames have already been reclaimed; every other state always has
  `Some` (every live read site — `fork`, `clone`, `execve`, `mmap`/`munmap`/`brk`, `shmat`/`shmdt`,
  `activate_and_prepare`'s own context-switch activation — updated to `.expect()` accordingly,
  since a live/`Ready` process always has one). `terminate_process` now tears down the address
  space's physical frames **immediately at exit** (self-exit still has to defer the *teardown call
  itself* until `scheduler::schedule()` confirms `current_pid()` has moved off this exact stack —
  see `scheduler::ReapKind::TeardownOnly`, called via the same `queue_thread_reap` mechanism a
  non-leader thread's table-entry removal already used, now generalized to also do a real teardown
  rather than only a table-entry drop) — not deferred all the way to some future `wait4`. The table
  entry itself still survives in `ProcState::Zombie` either way, so a real future `wait4` can still
  find and report real exit status/rusage; `do_wait4`'s own reap path now correctly finds
  `address_space` already `None` in the common case and skips its own teardown call as a no-op.
- **A real, separate infrastructure gap found alongside this**: `posix-conformance-driver`'s
  harness only checked that `wait4` for `sh` returned the right pid, not that `sh`'s own exit
  *status* was `0` — a shell that silently died partway through the corpus (not a hang, not a
  panic — `wait4` still returned promptly) was reported as a clean "PASS" regardless, hiding the
  failure from every caller trusting that line. Fixed to also check `status == 0` and print the
  real wait-encoded status otherwise (see the syscall-ABI section's own note on `wait4`'s status
  encoding).
- **`scripts/run_posix_pilot_supervised.sh` hardened** to actually find every file standing between
  here and a clean run, not just hang-shaped ones: now excludes+retries on a real crash/panic exit
  (previously only a stall — a detected stall or the run exiting on its own without a clean PASS
  both now feed the same exclude-and-retry path), fixed a `set -e` trap where a bare `wait
  "$test_pid"` on a nonzero exit (a genuine crash, not a stall) used to abort the whole supervisor
  before it could log or exclude anything, added a duplicate-exclusion detector (excluding the same
  file twice in a row means the previous exclusion never actually took effect — most likely a
  `build.rs` `cargo:rerun-if-changed` mtime-granularity race with the very next `cargo test`, now
  padded with a real 2-second sleep — rather than a second genuine hang), and now caches every
  already-classified file's own result line (`target/posix_verified_results.txt`) across
  iterations so a long supervised run never re-executes a file it already has a real answer for
  (still counted in the final tally, just not re-run). `build.rs`'s own `POSIX_EXTRA_EXCLUDE_FILE`
  handling gained an **unconditional** `cargo:rerun-if-changed` (previously only registered when the
  env var was set) — found live: cargo's watch list for a build script is exactly whatever that
  script's *most recent* invocation emitted, so a single plain `cargo build` with the env var unset
  made cargo "forget" to watch the file, silently reusing a stale cached manifest on every later
  supervised invocation regardless of how many new exclusions the script appended.
- **New: `scripts/run_posix_pilot_host.sh`** — builds and runs the exact same vendored corpus
  directly on the host's own real glibc/Linux (same `t0`-wrapped 40s-per-file alarm, same
  PASS/FAIL/UNRESOLVED/UNSUPPORTED/UNTESTED/TIMEOUT/CRASH classification), for a genuine
  apples-to-apples comparison rather than a guess. Must run as root (`sudo`, in a real terminal —
  `sudo` refuses a password prompt with no genuine TTY, so this is manual/user-run only, not
  something to drive via the Bash tool). **Measured result, full ~1673-file corpus, both sides
  including `pthread_*`/`aio_*`**: OxideBSD **82.1%** raw / **85.6%** excluding UNTESTED, vs. the
  user's Artix host (glibc, native) **86.7%** / **89.7%** — a ~4-point gap. Notably, Artix has *more*
  raw FAILs (35 vs 27) and more real self-contained CRASHes (10 vs OxideBSD's genuine 6) than
  OxideBSD does; most of OxideBSD's gap is UNRESOLVED (38 vs 9, likely test-setup/environment gaps,
  not logic bugs) and UNSUPPORTED (131 vs 108, genuinely-unimplemented optional features), not
  correctness failures on paths that do run. The other 28 of OxideBSD's 34 counted CRASHes were the
  kernel-level wedges this section's own frame-reclaim fix targets, not independent bugs each.

## BusyBox gap analysis: what's needed for more applets

Almost everything left needs one of a handful of missing kernel capabilities, each unlocking a
cluster of applets at once. New syscall numbers should continue from the highest currently
assigned. `OxideBSD-doc/BUSYBOX_APPLETS.md` is the authoritative per-applet detail behind this summary
table (counts are out of the 287 applets that built at all; a pre-v0.1 pass cut 58 of those 287
entirely — structurally incapable of working here, not "not started yet" — see that doc's own
"Removed before v0.1" section). 229 remain seeded.

| Gap | Status | Notes |
|---|---|---|
| `argv[0]` passthrough, real signals, process groups, termios/`ioctl`, `stat`/`fstat`/`lstat`, `getdents`/`getdents64` | done | foundational, all landed early |
| Socket syscalls + real DNS, `socketpair`/`fcntl`/`shutdown`/`set_tid_address`/`readv` + `/dev/{u}random,null,zero` + real `tcp_read` EOF fix | done | `wget` HTTPS confirmed live end to end — see "Real networking" |
| `alarm`/`setitimer` | done | unlocks `ping`'s receive-loop timeout |
| `chmod`/`chown`/`chgrp` | done | ext2 `ioctl`/`xattr` (`chattr`/`fatattr`/`lsattr`/`setfattr`) removed from roster before v0.1 instead |
| `fsync`/`sync`/`ftruncate`/`fallocate`/`flock`/`statfs`/`setrlimit`/sched-priority/`reboot`, `link`/`mknod`/`chroot`/`getrusage` | done | see their own sections above |
| SysV IPC, namespaces, `inotify`, ext2 ioctl/xattr | not started, 0 remaining blocked | the applets that needed these were removed from the roster before v0.1 — namespaces don't fit this kernel's single-address-space model at all |
| `/proc` (per-process, system-wide, per-fd) + real symlinks | done | special-cased path prefix in `modules/oxfs`, no VFS layer to plug into |
| Console/VT ioctls, serial/tape/I2C hardware, syslog, real pty | not started, 0 remaining blocked | `cttyhack`/`setsid` already worked and moved to WORKS; rest removed before v0.1 |
| Real block device driver + oxfs persistence, mount table | done | see "Real disk persistence"/"Mount table" — still a fixed, non-mountable backing store; `pivot_root`/`switch_root`/partition tables remain out of scope |
| uid/passwd-db model, real login/session auth | done | `adduser`/`chpasswd`/`passwd` still need real *mutation* of `/etc/passwd`/`/etc/group` (applet-level gap) |
| `clock_gettime`/`gettimeofday`/`time`/`nanosleep` | done | — |
| Init-system/service-supervisor framework | not started, out of scope | 2 applets kept anyway (don't need a real init framework); 4 removed (runit family needs FIFOs oxfs doesn't have) |
| `tcsetpgrp`/real job control | done | see "Real job control" |
| `uname`/`gethostname` | done | `gethostname` is a pure musl wrapper around `uname()`, no new syscall |

**83 more candidate applets didn't even build**: 54 need real Linux kernel uapi headers musl
doesn't vendor, 25 need a companion Kconfig option a single-symbol flip didn't resolve, 3 were
docs/example files mismatched by candidate-extraction, 1 (`lzopcat`) is a genuine link error. See
`OxideBSD-doc/BUSYBOX_APPLETS.md` for the full breakdown.

## Closing two `pthread_cond_timedwait` hangs: a `terminate_thread_group` leader-ordering bug and real `FUTEX_REQUEUE` (`src/process/lifecycle.rs`, `src/process/limits.rs`, `third_party/musl`, `build.rs`)

Both `pthread_cond_timedwait/{2-5,4-1}.c` were real, permanent hangs (`t0`'s own 40s rescue alarm
never fired for either) left open by the previous session's scheduler/signal-termination work.
Traced each to its own actual blocking primitive rather than more source-reading; two independent
bugs, not one.

- **`4-1.c`** (a plain single `pthread_create`, no `PTHREAD_PROCESS_SHARED`): the worker thread
  calls a real `exit()` (== `exit_group`) after its own timed condvar wait, while the main thread
  (the real thread-group *leader*) sits blocked in `pthread_join()`'s own futex wait.
  `terminate_thread_group`'s loop used to kill every "sibling" (everyone but the caller) first,
  then the caller itself last — correct only when the caller happens to *be* the leader. Here the
  caller is the non-leader worker and the leader is one of the "siblings", so the leader got
  processed while the worker (the caller, not yet reached in the loop) was still alive —
  `terminate_process`'s own `other_thread_alive` check saw that and wrongly treated the *leader* as
  a disposable non-leader thread, silently stranding it with no parent notification (the same
  underlying failure mode `pthread_attr_setdetachstate/2-1.c`'s fix closed for the direct-call-site
  version of this bug, just reached via a different ordering inside `terminate_thread_group` itself
  that fix didn't touch). **Fixed**: every non-leader group member is terminated first, the leader
  (`pid == tgid`) always last, regardless of whether it's the original caller or one of its
  "siblings" — by the time the leader's own `terminate_process` call runs, every other real member
  is already `Zombie`, so `other_thread_alive` correctly reads `false`.
- **`2-5.c`** (100 threads, two mutexes, real contended condvar hand-off): musl's own
  `pthread_cond_timedwait.c::unlock_requeue` moves a waiting thread from the condvar's internal
  barrier word onto the mutex's futex word via real `FUTEX_REQUEUE` whenever more than one waiter
  is queued — `do_futex` treated that op (and `FUTEX_CMP_REQUEUE`) as a silent no-op, so a thread
  already blocked in a real kernel `FUTEX_WAIT` on the old address had nothing left to ever wake
  it. Real `FUTEX_REQUEUE` doesn't fit this ABI's plain 4-register `SYS_FUTEX` wire format (real
  `futex(2)` needs 6 args for this op: `uaddr`, `op`, `val`/nr_wake, `val2`/nr_requeue in the
  timeout slot, `uaddr2`, `val3`). **Fixed** with a dedicated `SYS_FUTEX_REQUEUE=557` taking
  exactly the 4 real args the one real call site needs (`uaddr`, `uaddr2`, `nr_wake`,
  `nr_requeue`); `unlock_requeue` patched on the `oxidebsd` musl branch to call it directly instead
  of overloading `SYS_futex`. This kernel has no literal wait-queue data structure to requeue
  between (`WaitingForFutex` is a plain per-process block-reason, not a linked list) — "moving" a
  waiter is just overwriting its own `(scope, key)` fields in place, exactly equivalent in effect.
  Doesn't make `2-5.c` fully `PASS` (it now reaches a real `UNRESOLVED` from something else in its
  own giant pshared/altclock scenario matrix, not a hang), but it's no longer a permanent hang, and
  its previously-unreachable neighbors `4-2.c`/`4-3.c` — blocked from ever running by whichever of
  `2-5.c`/`4-1.c` hung first — both now cleanly `PASS`.
- **Verified**: isolated canary run (`POSIX_PILOT_CANARY_ONLY=1`) — `4-1.c`/`4-2.c`/`4-3.c` `PASS`,
  `2-5.c` `UNRESOLVED` (no longer a hang), full 73-file standing regression suite otherwise
  unchanged (52P/2F/1U/14UT/3TO/1CR). Both files removed from `POSIX_KNOWN_HANGS`, added to the
  `POSIX_PILOT_CANARY_ONLY` standing regression suite. A fresh full-corpus supervised run to fold
  this into an official baseline number hasn't been done yet.

## Real per-process `times(2)`, and closing the last two `POSIX_KNOWN_HANGS` entries from a prior session's pthread investigation (`src/syscall/ffi.rs`, `src/process/mod.rs`, `src/process/lifecycle.rs`, `src/process/signals.rs`, `build.rs`)

Continuing the same hunt as the section above: `fork/8-1.c`, `pthread_attr_setstacksize/2-1.c`, and
`pthread_cancel/5-2.c` were the three remaining entries from a prior session's "four newly-found
pthread hangs" list. All three closed — two were real bugs, one was never actually a hang at all.

- **`fork/8-1.c`**: `sys_times` wrote an unconditionally all-zero `tms` struct — the doc comment
  claimed "this kernel tracks no per-process CPU time at all," but that predated `Process::
  cpu_ticks` (added later, purely for `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`) and was never
  revisited. The test's child thread busy-loops forever on `while ((tms_utime + tms_stime) <= 0)`,
  which an always-zero `tms_utime` can never satisfy — a real, permanent hang, not the parent's own
  `do { ... } while (cur - start < CLK_TCK)` loop a prior session's own notes suspected (that one's
  return value, `ticks()`, was always real). **Fixed**: `sys_times` now reads real `cpu_ticks` into
  `tms_utime` and a new `Process::child_cpu_ticks` accumulator into `tms_cutime` (folded in by
  `do_wait4` at reap time — transitive, since it adds `child.cpu_ticks + child.child_cpu_ticks`, so
  a grandchild's usage flows up automatically). `tms_stime`/`tms_cstime` stay honest zero — no
  separate user/kernel split is tracked, same tier `cpu_ticks`'s own doc comment already
  establishes. `getrusage(2)`'s `ru_utime`/`ru_stime` have the identical latent staleness, noted but
  not fixed (nothing currently depends on it the way this hang did).
- **`pthread_attr_setstacksize/2-1.c` and `pthread_cancel/5-2.c`: neither was ever a real hang.**
  The original full-corpus supervised run's own "exclude whatever file happened to be running when
  a stall was detected" heuristic misattributed some *other* file's real stall to these two — the
  same failure mode `pthread_atfork/3-3.c` suffered before it (see `build.rs`'s own `POSIX_KNOWN_
  HANGS` doc comment). Confirmed by testing each in genuine, complete isolation
  (`POSIX_PILOT_CANARY_ONLY` narrowed to exactly one file) — both run to completion in seconds.
  `pthread_attr_setstacksize/2-1.c` reported a real, narrow `FAIL`: real, unmodified musl's own
  `pthread_create.c` rounds a requested stack size up to a page boundary and folds in TLS/TSD
  overhead before storing `stack_size`, so `pthread_getattr_np()` never round-tripped the *exact*
  raw `PTHREAD_STACK_MIN` this test requested. **Since fixed** on the `oxidebsd` musl branch — but
  only after confirming, live against the host's own real glibc, that this genuinely passes there
  (so it wasn't a bogus/upstream-broken test): `struct pthread` gained a `requested_stack_size`
  field, set once at real thread-creation time to the caller's actual logical request (or the
  implementation default), independent of the real allocator-padded extent `stack_size` still
  tracks for its own (unrelated) purposes. `pthread_getattr_np()` now reports the new field
  instead of deriving a size from `stack - stack_limit` — doesn't touch the actual stack
  allocation/layout algorithm at all, so the one real consumer of `stack_size` itself
  (`map_size`/`map_base` for `munmap` at join/exit) is untouched. Now `PASS`.
- **`pthread_cancel/5-2.c` surfaced two real, since-fixed kernel bugs before settling on a clean,
  bounded `TIMEOUT`**:
  1. **Signals `32..=34` (`SIGTIMER`/`SIGCANCEL`/`SIGSYNCCALL`) were wrongly rejected as `EINVAL`**
     in `do_kill`/`do_sigaction`/`do_sigqueue`. That range is "permanently unclaimed" only as a
     *libc-level* convention (real glibc/musl reserve it for internal NPTL-style machinery so
     application code doesn't collide with it) — not a real POSIX or Linux kernel-level
     restriction. Real, unmodified musl's own `pthread_cancel.c` genuinely calls
     `sigaction(SIGCANCEL=33, ...)` and `pthread_kill(t, SIGCANCEL)` through the exact same raw
     syscalls any other signal uses. Rejecting them broke real `pthread_cancel(3)` for every
     caller, not just this test — `init_cancellation()`'s own `sigaction` call ignores its return
     value, so the first visible symptom was always the `pthread_kill` call surfacing the swallowed
     `EINVAL` as `pthread_cancel`'s own return value (`UNRESOLVED` here). **Fixed**: widened the
     valid range to `0..=34`/`1..=34` at all three call sites. **A second, more serious latent bug
     this exposed before it could ship**: `Process::pending_siginfo` was only a 32-element array
     (`[QueuedSigInfo; 32]`), indexed directly by signal number — accepting signal 33 without
     widening this too would have turned a userspace `EINVAL` into a real out-of-bounds kernel
     panic at `record_pending`'s `proc.pending_siginfo[sig as usize] = info`. Fixed alongside (now
     35 elements, covering `0..=34` — real-time signals `35..=64` use `rt_queue` instead and never
     reach this array).
  2. **`sigaction()` disposition wasn't shared across threads in the same process** — a real,
     pre-existing threading gap, found once the range fix let `SIGCANCEL` actually reach the
     kernel: `Process::sigactions` lived directly on `Process`, not in the `Arc<Mutex<>>`-shared
     `ThreadGroupShared`, so each `CLONE_THREAD` sibling had its own fully independent copy —
     violating real POSIX (`sigaction()` disposition must be process-wide). `init_cancellation()`
     installs `SIGCANCEL`'s handler on whichever thread calls `pthread_cancel()` first, then
     `pthread_kill()`s the *target* thread — which, with a per-thread `sigactions`, still had
     `SIG_DFL`, so the target was unconditionally terminated (`CRASH(161)` = `128 + SIGCANCEL`)
     instead of the handler ever running. **Fixed**: moved `sigactions` into `ThreadGroupShared`.
     `do_fork_from_current` still builds a genuinely fresh `ThreadGroupShared` (copying the
     *value*, real POSIX fork semantics: a forked child is an independent process, never a thread
     sibling); `do_clone`'s own pre-existing `Arc::clone(&caller.shared)` for real `CLONE_THREAD`
     sharing needed no change at all to pick this field up automatically. Every direct
     `proc.sigactions[...]` access site across `signals.rs`/`lifecycle.rs` (9 sites) now goes
     through `proc.shared.lock().sigactions[...]`, respecting the existing "`PROCESS_TABLE` first,
     `ThreadGroupShared` second, never across `schedule()`" lock-ordering rule unchanged.
  3. **Residual, not chased further**: after both fixes, `pthread_cancel/5-2.c` settles at a clean,
     bounded `TIMEOUT` instead of any kind of crash or permanent hang. One thread genuinely
     livelocks in musl's own real `cancel_handler`'s `SIGCANCEL`-resend-via-`tkill` retry loop —
     intentional musl behavior for a target thread that never reaches an actual POSIX cancellation
     point (this test's own target spins on bare `sched_yield()`, which isn't one). Diagnostic
     tracing (`[diag-thread]`, temporarily reinstated for this investigation, removed after) showed
     the same thread `Running` with an identical `pending`/`blocked` signature across four
     consecutive 10-second snapshots — a genuine livelock, not forward progress. On real multi-core
     hardware the target thread's own userspace code still gets real scheduling gaps to notice
     `do_it==0` between resends; whether a resumed thread on this single-core kernel always gets at
     least one real instruction before an immediately-redeliverable signal redirects it again is a
     separate, deep scheduling question, out of scope for this investigation. A bounded `TIMEOUT`
     doesn't cascade into the rest of a full-corpus run the way an actual unbounded hang does, so
     this doesn't block anything.
- **`sched_yield/1-1.c` also turned out to never need SMP at all** — a real, long-standing
  staleness bug in this project's own exclusion reasoning ("assumes real SMP fairness this
  single-core kernel can't provide"), caught by simply re-reading the test's own source instead of
  repeating an old, never-re-verified claim across several sessions. The test forks `ncpu-1`
  CPU-blocking children specifically to *reserve* every core but one before testing
  `sched_yield()`'s effect between two other threads — on a genuinely single-core report (`ncpu ==
  1`, which real `sysconf(_SC_NPROCESSORS_ONLN)` already correctly derives from
  `sched_getaffinity`'s real single-bit mask), that loop forks *zero* children. What's left is two
  equal-priority (`SCHED_FIFO`) threads round-robining via `sched_yield()` against each other — a
  real, single-core-achievable property, not an SMP one. Confirmed via an isolated canary run:
  clean `PASS` (a harmless `unrecognized syscall number 203` — `sched_setaffinity`, which the
  test's own affinity helper only `perror()`s on failure and continues past — doesn't affect the
  outcome). Removed from `POSIX_KNOWN_HANGS` entirely, added to the standing canary suite.
- **`POSIX_KNOWN_HANGS` down to exactly one genuine, permanent, deliberately-out-of-scope
  exclusion**: `shm_open/23-1.c` (an architectural mismatch between oxfs's 128 KiB-per-open-fd
  write-buffer design and this test's own 1000-concurrent-process fd-leak stress shape — a real fix
  means redesigning oxfs's write path to stop costing memory per open fd, scoped as a separate,
  future effort, not attempted here). **Since fixed** — see "oxfs write path..." further below;
  `POSIX_KNOWN_HANGS` is empty again (though `shm_open/23-1.c` itself still doesn't `PASS`, for an
  unrelated, deeper reason that section covers).
- **Verified**: full 77-file standing canary suite (`POSIX_PILOT_CANARY_ONLY=1`, all new entries
  folded in) — `55P/2F/1U/14UT/4TO/1CR`, exactly the prior 76-file baseline (`54P/2F/1U/14UT/4TO/
  1CR`) plus `sched_yield/1-1.c`'s own `PASS` — zero regressions. A fresh full-corpus supervised
  run to fold all of this into an official baseline number hasn't been done yet.

## oxfs write path: `OpenFile::Write`'s buffer moved to a separate pool, closing the last `POSIX_KNOWN_HANGS` entry (`modules/oxfs/src/lib.rs`, `build.rs`)

Closes the architectural gap flagged in the previous section: `shm_open/23-1.c` (see "A global-fd-
table exhaustion cascade..." above) needed up to 1000 real simultaneous `OPEN_FILES` slots (one per
`shm_open`'d name, held open until each holding process's own loop finishes) — far more than any
`MAX_OPEN_FILES` bump could affordably give it, since every slot embedded a full, unconditional
`MAX_WRITE_BUFFER` (128 KiB) regardless of whether that fd was ever actually written to.

- **The real fix**: `OpenFile::Write`'s own `buffer: [u8; MAX_WRITE_BUFFER]` field moved out of the
  enum entirely into a separate, smaller, lazily-claimed `WRITE_BUFFERS`/`WRITE_BUFFER_USED` pool
  (`MAX_WRITE_BUFFERS = 256`, unchanged from the old total capacity) — `OpenFile::Write` now carries
  only `buf_slot: Option<usize>`, an index into that pool, claimed only by the first real `write()`
  call (or, for `O_APPEND`, eagerly at `open()` time, since that path must preserve the file's real
  existing content even if nothing new is ever written — see `buf_slot`'s own doc comment for why
  this one path can't be lazy). A `shm_open(O_RDONLY|O_CREAT, ...)`-shaped fd (this test's own
  entire workload) never touches the pool at all. This dropped `OPEN_FILES`'s own per-slot cost from
  ~128 KiB to ~4 KiB (`DirListing`/`ProcDir`'s `DIR_LISTING_BUFFER` is now the enum's largest
  variant), letting `MAX_OPEN_FILES` scale **256 → 2048** while *lowering* total static cost (~8 MiB
  vs. the old ~32 MiB for 256 slots).
- **`shm_open/23-1.c` removed from `POSIX_KNOWN_HANGS` entirely** — confirmed via an isolated canary
  run with this file restored alongside every other `shm_open`/`shm_unlink` file and
  `sigaction/1-{1,2}.c` (the exact combination that originally exposed the cascade): the cascade is
  gone (`sigaction/1-1.c`/`1-2.c` and every file after `shm_open/23-1.c` again get their own correct,
  individual classification), and the full 78-file tally (`55P/2F/1U/14UT/5TO/1CR`) matches the prior
  77-file baseline exactly plus this file's own legitimate `TIMEOUT`.
- **`shm_open/23-1.c` itself still doesn't `PASS`, and this fix was never going to make it** — a
  genuine, confirmed `TIMEOUT`, not a fd-table symptom: re-run with `t0`'s own alarm manually raised
  from 40s to 180s (4.5x), it *still* timed out. The real remaining bottleneck is raw scheduling
  throughput for 1000 concurrent forked processes under this kernel's single-core, TCG-emulated
  execution — a separate, much deeper problem (likely the scheduler's own per-tick process-table
  scan cost, or eager-copy `fork()`'s per-call cost, multiplied 1000x) than anything the write path
  itself could fix. Not chased further here; `shm_open/23-1.c` is a legitimate, bounded `TIMEOUT` in
  a normal full-corpus run now, same as several other heavy stress tests, rather than a permanent
  exclusion.
- **Verified**: `mmap_syscall_smoke`/`tcc_syscall_smoke` (both exercise the write path heavily —
  fd-backed mmap's own commit-on-demand path, and TinyCC's real multi-file compile+link+run) both
  still pass cleanly; the full canary regression suite (78 files, `shm_open/23-1.c` now included)
  matches the expected baseline with zero regressions.

## Real orphan reparenting, and a real `do_munmap` frame leak found chasing full-corpus physical-frame exhaustion (`src/process/{mod,lifecycle}.rs`, `src/process/mm.rs`)

Running the full, un-curated ~1687-file POSIX pilot corpus (no `POSIX_PILOT_CANARY_ONLY` subset)
for the first time surfaced a real, severe cascade: a fresh `--reset` run reported only 354 `PASS`
against 1196 `UNRESOLVED` (out of 1687) — every file past a point roughly 1/3 through the corpus
(first hit around `pthread_cond_timedwait/1-1.c`) came back `UNRESOLVED`, each one completing
suspiciously fast rather than running its real workload. `run-out.txt`'s own content (temporarily
echoed to serial for diagnosis) showed why: `hush: can't execute 'cat': No memory` — real `ENOMEM`
on `fork()`/`execve()`, not a hang or a crash.

- **First hypothesis, real but not the dominant cause**: this codebase never reparents an orphan
  to a pid-1 "init" (a known, already-documented accepted gap — see `do_wait4`'s own doc comment
  history above). A never-`wait4()`'d child's table entry — including its own `kernel_stack` (a
  real 512 KiB-scaled heap allocation on a RAM-rich boot, not the 128 KiB floor) — survives forever
  once orphaned, unlike its address space (already freed immediately at exit regardless, since the
  "Real zombie address-space frame reclaim" fix). **Fixed for real** (`Process::adopted`,
  `process::lifecycle::reparent_orphans`/`INIT_PID`): any process's still-living children are
  reparented to pid 1 on exit, exactly like real Unix (`getppid()` on an orphan genuinely reads
  back `1`); an *adopted* orphan's own later exit is treated exactly like `SA_NOCLDWAIT` (immediate
  detach-and-reap), since pid 1 here (`hush`) has no generic "reap anything adopted" loop the way a
  real init does. A real, worthwhile fix in its own right — but rerunning the full corpus with only
  this fix landed produced **byte-for-byte identical** results to the run without it, proving it
  wasn't the actual mechanism behind this specific cascade (most of this corpus's tests do properly
  reap their own children or go through real `exit_group()` cleanup; kernel-stack-sized orphan
  leaks are real but comparatively rare).
- **Root cause, found via direct instrumentation, not guesswork**: added temporary counters to
  `BootInfoFrameAllocator` (live frames-in-use) and a read-only mirror of `AddressSpace::teardown`'s
  own walk (counts every frame reachable in a table without freeing anything), then compared
  "frames allocated building this address space" against "frames reachable in its own table" for
  every real `fork()`/`execve()` in the corpus — **zero mismatch, every single time** (295 execve
  samples, 165 fork samples, all `diff=0`). This ruled out both construction (over-allocating
  orphaned, never-linked frames) and destruction (`teardown()`'s own walk, confirmed via a separate
  per-call "frames freed" counter to correctly free everything reachable) as sources of the leak —
  both halves of the address-space lifecycle are individually exact. The actual bug was a third,
  previously unconsidered path: **`do_munmap`'s own unmap loop discarded the frame `Mapper::unmap`
  handed back** (`if let Ok((_, flush)) = mapper.unmap(page)`) instead of ever returning it to the
  frame allocator — a permanent, silent leak of every page any real `munmap()` call ever unmapped.
  Real musl's own `pthread_join()` munmaps a joined thread's stack on every single join, and the
  pilot's own `mmap`/`munmap` directories call this directly too — both leaked one physical frame
  per unmapped page, forever, invisible to both the construction and destruction checks above since
  the frame was already gone from the page table (and thus from `teardown`'s own later view) well
  before either process ever exited. **Fixed**: capture the returned frame and, unless it carries
  `SHARED_LEAF` (a real fd-backed `MAP_SHARED` mapping, whose content is owned by `MMAP_FILE_CACHE`
  and released via `release_mmap_file_ref` instead — same exemption `AddressSpace::teardown`'s own
  walk already makes), return it to the frame allocator via `FrameDeallocator::deallocate_frame`.
  `src/fs/sysv_shm.rs`'s own near-identical-looking `shmdt` unmap loop was checked too and left
  alone — every page there is unconditionally shared (owned by `SEGMENTS`), so discarding the frame
  there is already correct, not the same bug.
- **Verified**: `mmap_syscall_smoke` (real, heavy `munmap` exercise) still passes all 13 parts
  clean; the 78-file standing canary regression suite matches its established baseline exactly
  (`55P/2F/1U/14UT/5TO/1CR`) with the fix in place. **Not yet done**: a fresh full-corpus run to
  measure the real, corrected pass rate — the munmap fix let the corpus run much further than
  before (real workloads instead of instant `ENOMEM` fails) and surfaced a **new**, likely
  pre-existing crash at `pthread_kill/6-1.c` (`EXCEPTION: INVALID OPCODE` at the real
  fault-trampoline's own `ud2` sentinel, `VirtAddr(0x1ffffffff011)`) that was previously masked by
  the frame-exhaustion cascade happening first — a separate, not-yet-investigated bug, most likely
  in cross-thread/cross-process signal delivery given where it landed (this file specifically
  targets an already-joined, no-longer-existent tid via `pthread_kill`, expecting real `ESRCH`),
  next in line for the same "found live, fixed forward" treatment. Excluded in `POSIX_KNOWN_HANGS`
  (see that array's own doc comment) so a real full-corpus run can complete at all.

**A fresh full-corpus supervised run, done the same night**: `scripts/run_posix_pilot_supervised.sh
--reset` converged in 3 iterations, excluding `pthread_kill/6-1.c` (the crash above) and
`shm_open/23-1.c` (not a new finding — the same real single-core scheduling-throughput ceiling for
1000 concurrent processes measured earlier the same session, confirmed again here: it exceeds the
supervisor's own 120s stall-detection window even though it's not a genuine hang, a limitation of
that heuristic for this one already-understood file, not a new bug). Real, measured baseline across
the remaining 1685 files: **1419 PASS / 131 UNSUPPORTED / 68 UNTESTED / 26 UNRESOLVED / 19 FAIL /
12 CRASH / 10 TIMEOUT** — **84.1% raw / 87.8% excluding UNTESTED**, a genuine improvement over the
pre-fix 2026-09-04 baseline (82.1%/85.6%, see "OxideBSD vs Artix POSIX comparison" above) despite
the corpus itself growing slightly larger since then. This is the first time this codebase has ever
measured a real pass rate off a full, uncurated, exhaustion-free run of the whole corpus — every
prior full-corpus number was either pre-`do_munmap`-fix (silently inflated by hundreds of instant,
fake `UNRESOLVED`s never actually being real assertion failures) or measured against a smaller,
curated subset.

## A real fault-to-signal-delivery bug: blocking a synchronously-generated signal, closing `pthread_kill/6-1.c` (`src/process/signals.rs`, `src/cpu/interrupts.rs`)

The `pthread_kill/6-1.c` crash flagged in the previous section, chased the same night: real,
unmodified musl's own `pthread_kill()`/`pthread_cancel()` call `__block_all_sigs()` internally,
masking every signal (including `SIGSEGV`) for a short internal critical section. This file's own
real assertion (`pthread_kill()` on an already-joined, no-longer-existent tid, expecting `ESRCH`)
dereferences that stale `pthread_t` inside musl's own implementation -- a genuine page fault into
memory `pthread_join()`'s own real stack `munmap()` already freed, occurring *while* `SIGSEGV` was
blocked by that exact critical section.

- **Root cause**: `interrupts::page_fault_handler`/`general_protection_fault_handler`'s own ring-3
  fault-to-signal self-`kill` used to record the fault-generated signal exactly like an ordinary
  async `kill()` self-signal -- respecting the target's own blocked-signal mask, correct for
  `kill()` but wrong for a signal that's *synchronously* generated by the process's own faulting
  instruction. Real POSIX documents blocking a signal that's then synchronously generated as
  undefined behavior; real Linux resolves it via `force_sig()`'s own "unblock this one signal, then
  queue it" semantics -- this kernel had no equivalent. With `SIGSEGV` genuinely blocked at fault
  time, `deliver_pending_signal`'s own `take_deliverable_signal` correctly (by the normal rules)
  refused to act on it, leaving `process::fault_trampoline`'s `SYS_FAULT_PUMP` dispatch with
  nothing to deliver -- falling through to the trampoline's own `ud2` safety net, an unbounded,
  whole-VM-halting `EXCEPTION: INVALID OPCODE` instead of the normal per-process `SIGSEGV`
  termination every *other* fault-to-signal path already produced correctly.
- **Fixed**: `process::signals::force_fault_signal(pid, sig)` -- force-clears just the one bit
  being delivered from `blocked_signals` before recording it as pending, matching real Linux's own
  narrow scope (every *other* signal the critical section blocked stays blocked). Both fault
  handlers' identical self-signal call sites now go through this instead of a plain `do_kill`
  self-signal.
- **Confirmed fixed**: this file now cleanly `CRASH(139)`s -- a real, normal, per-process `SIGSEGV`
  termination (accessing already-`munmap()`'d memory via a stale `pthread_t` is genuine real-world
  undefined behavior a real system might also crash on; what mattered was containing it to one
  process instead of halting the whole VM) -- instead of taking the whole boot down. Removed from
  `POSIX_KNOWN_HANGS`, which is empty again; added to the standing canary regression suite.
- **Two real, pre-existing flaky files found re-running the canary suite right after this fix**,
  neither a regression: `pthread_cond_init/4-2.c` (2 of 3 isolated re-runs `PASS`, 1 `CRASH(139)`,
  same build -- unrelated to this fix since it never calls `pthread_kill`/`pthread_cancel`, most
  likely the same *class* of genuine thread-creation-timing race `pthread_attr_setdetachstate/
  2-1.c` had before its own fix made it deterministic) and `timer_settime/2-1.c` (one `FAIL` then
  3/3 clean `PASS` in isolation immediately after -- real-time tests are sensitive to host-load-
  induced QEMU/TCG timing variance, matching this project's own established precedent for this
  test family). Neither excluded or chased further -- noted in `build.rs`'s own doc comment so a
  future canary-tally shift isn't mistaken for a new regression.
- **Verified**: `mmap_syscall_smoke` (all 13 parts, including its own `SIGBUS`/`SIGSEGV` default-
  terminate exercises), `pthread_cancel_crash_smoke`, and `pshared_cond_crash_smoke` (all real
  fault-to-signal/thread-crash exercises) all still pass clean.
- **A fresh full-corpus run, folding this fix in**: `1418 PASS / 131 UNSUPPORTED / 68 UNTESTED /
  26 UNRESOLVED / 19 FAIL / 13 CRASH / 12 TIMEOUT` across all 1687 files, `POSIX_KNOWN_HANGS` empty
  -- **84.1% raw / 87.6% excluding UNTESTED**, essentially flat against the prior 84.1%/87.8%
  figure (expected: `pthread_kill/6-1.c` was already being excluded from that count, so including
  it as a real, contained `CRASH` instead doesn't move the aggregate -- the real win is qualitative,
  a full run no longer needs any exclusion at all to complete). The small remaining shifts
  (`PASS` 1419→1418, `TIMEOUT` 10→12) are ordinary run-to-run variance, not new regressions --
  matches the `pthread_cond_init/4-2.c`/`timer_settime/2-1.c` flakiness already documented above.

## A real (if narrowly-scoped) `ENAMETOOLONG` gap closed, and why two tests that originally flagged it still can't pass (`modules/oxfs/src/lib.rs`)

`shm_open/39-2.c`/`shm_unlink/10-2.c` (noted as a known, unfixed gap in the "global-fd-table
exhaustion cascade" section above) check that a real, whole path exceeding `{PATH_MAX}` gets
`ENAMETOOLONG` -- oxfs had no such check at all, only `NAME_MAX`'s own per-*component* limit.

- **Fixed for real**: `OXFS_PATH_MAX = 4096` (musl's own real compiled `PATH_MAX`), checked against
  the real, whole, original path in `resolve_parent` (covers `open`/`unlink`/`mkdir`/`rmdir`/
  `rename`/`symlink`) and in `resolve_path_impl` guarded to `depth == 0` (covers `stat`/`lstat`/
  `chdir`/`readlink`, but not a symlink target's own recursive re-resolution, already bounded well
  under this by `MAX_CWD_PATH`'s own 256-byte buffer regardless) -- real `ENAMETOOLONG` for an
  ordinary, non-shm path that's genuinely too long, where none existed before.
- **Does not close the two tests that flagged the gap, and never can without a real musl bug**:
  both construct a name with *embedded* `/` characters to build a genuinely `PATH_MAX`-length
  string -- but real, upstream musl's own `__shm_mapname()` (`third_party/musl/src/mman/
  shm_open.c`) rejects any embedded `/` as `EINVAL` *before* ever checking length. Real POSIX
  explicitly leaves embedded-slash interpretation in a `shm_open()` name implementation-defined, so
  this is legitimate, spec-legal musl behavior (confirmed via a live diagnostic: both tests report
  `EINVAL`/`ENOENT`, never reaching the kernel's own new check at all), not a bug to route around --
  an existing comment in `shm_unlink.c` itself, from an earlier session, already reached the same
  conclusion for `shm_unlink`'s own half of this. Both files remain the same accepted, understood
  `FAIL` they already were; the new check is still real and correct for the case it actually covers.
- **Verified**: `mmap_syscall_smoke`, `fork_wait`, `tcc_syscall_smoke` (real heavy path/file usage
  through the exact resolvers this touches), and the 79-file standing canary suite (matching its
  established baseline exactly, `shm_open/39-2.c`/`shm_unlink/10-2.c` still `FAIL` as expected, no
  new regressions) all pass clean.

## oxfs max-file-size and streaming write-buffer redesign, plus a musl `PTHREAD_STACK_MIN` fix

`Inode` gained a `double_indirect` block pointer (~4 MiB/file → ~4.1 GiB addressable; real ceiling
is pool free space, now 1 GiB not 256 MiB). `OpenFile::Write` no longer buffers a whole file and
replaces it at `close()` — it streams to real blocks once `MAX_WRITE_BUFFER` (now 16 MiB) fills.
Found and fixed along the way: the on-disk bitmap was hardcoded to one block (broken past
`NUM_BLOCKS=32768`), and the block allocator was an O(n²) rescan. `SUPERBLOCK_VERSION` bumped.

Also bumped musl's `PTHREAD_STACK_MIN` 2048 → 65536 (a real page-size multiple, for future
16K/64K-page ports) plus a companion `sysconf.c` widening (`short`→`int` table) it needed to
actually take effect — closed 15 real `pthread_*` conformance files that were bailing `UNTESTED`.
Surfaced two new `CRASH` bugs in `pthread_detach`, root-caused as two *different* real musl issues,
not OxideBSD bugs. `1-2.c`: joins an already-exited self-detached thread — a real, genuinely
undetectable UAF in `__pthread_timedjoin_np` reading a freed TCB, same documented-UB class as
`pthread_attr_setdetachstate/2-1.c` — left as an accepted `CRASH(139)`, not fixable without a much
bigger design change. `4-3.c`: `pthread_detach()` on a thread already created
`PTHREAD_CREATE_DETACHED` — real, unmodified musl's own `pthread_detach()` had the information (its
own `a_cas()` result) to detect this and return `EINVAL`, but instead unconditionally fell back to
`__pthread_join()`, hitting that function's own internal `a_crash()`. Unlike `1-2.c`, this case is
memory-safe to detect directly (target is always `pthread_self()`) — **fixed** on the `oxidebsd`
musl branch: `pthread_detach()` now returns `EINVAL` here instead of ever reaching
`__pthread_join()`. `4-3.c` now cleanly `TIMEOUT`s (a real, heavy workload hitting `t0`'s bound, same
class as `shm_open/23-1.c`) instead of crashing. Full corpus: 87.5%→88.4%.

## USB input: xHCI + HID boot-protocol keyboard (`src/drivers/usb/`, `src/drivers/pci.rs`, `src/cpu/interrupts.rs`)

This kernel's first real-hardware (not just QEMU) boot target is a Surface Pro, which has no PS/2
controller at all — this closes that gap. `src/drivers/usb/xhci.rs` is the xHCI host-controller
driver (register access, command/event rings, device-slot enable/address/configure); `hid_keyboard.rs`
is a HID **Boot Protocol** keyboard on top of it (no general HID Report Descriptor parsing); `mod.rs`
ties both together and exposes `init`/`poll`.

- **Polling, not IRQ-driven, deliberately** — matches `drivers::ata`'s own established
  polling-only precedent. This kernel has no IOAPIC/MSI support, and legacy PCI `INTx` routing on
  a modern UEFI-only chipset is a real, unquantified risk not worth taking for a few ms of
  keystroke latency a human typist won't notice. `usb::poll()` runs once per timer tick, draining
  the shared Event Ring — `IMAN.IE`/`USBCMD.INTE` are deliberately left clear.
- **32-byte device contexts only** (`HCCPARAMS1.CSZ == 0`) — what QEMU's `qemu-xhci` and the
  overwhelming majority of real platforms use. `CSZ == 1` is logged and treated as unsupported
  hardware.
- **A real bug found live, not by spec-reading**: an early version trusted Limine's HHDM to cover
  the xHCI BAR's physical range unconditionally (same reasoning `console::framebuffer` uses for
  Limine's framebuffer). **Wrong for a 64-bit BAR** — a real boot under OVMF (UEFI) placed
  `qemu-xhci`'s BAR0 at physical `0x800000000` (32 GiB; the same boot under SeaBIOS placed it at a
  conventional `0xfebd0000`, which would have worked fine and masked the bug). Real firmware parks
  large/64-bit BARs in a high MMIO window specifically to avoid the low 32-bit PCI hole; Limine's
  HHDM only guarantees "at least 4 GiB, plus whatever the memory map itself reports" — nowhere
  near a firmware-placed hole that far up. The very first capability-register read through the
  unmapped HHDM address page-faulted immediately. Fixed with a real, explicit two-phase mapping in
  `Xhci::init` (`map_bar_pages`, `NO_CACHE`, via the same `Mapper::map_to` primitive
  `module::map_region` already uses): map one page first (enough to read the Capability registers
  and learn `DBOFF`/`RTSOFF`/port count), then map however many pages the real needed extent
  turns out to be. **Confirmed on both BIOS and UEFI boots** (`OXIDEBSD_QEMU_USB=1 cargo run`,
  both `OXIDEBSD_FIRMWARE` values) before landing.
- **Real BIOS/SMM-to-OS ownership handoff** (USB Legacy Support Capability, walked via
  `HCCPARAMS1.xECP` inside xHCI's own MMIO space — a real *xHCI extended capability*, entirely
  separate from the PCI config-space capability list) — real Intel platforms (this project's own
  real-hardware target's chipset included) can leave the controller SMM-owned by default. QEMU
  doesn't implement this capability at all, so every QEMU boot logs "no USB Legacy Support
  capability" and moves on — this path is untested by QEMU and only actually exercised on real
  hardware.
- **`drivers::pci::PciDevice::mem_bar` gained real 64-bit BAR-pair merging** (bits `2:1 == 0b10`,
  BAR `n+1` holds the high 32 bits) — xHCI controllers commonly use a 64-bit BAR0; the old
  32-bit-only version silently truncated it.
- **Reuses `cpu::interrupts`'s existing PS/2 decode pipeline wholesale, not a second implementation.**
  `keyboard_interrupt_handler`'s post-decode logic (echo/Ctrl+C→`SIGINT`/Ctrl+Z→`SIGTSTP`/`push_byte`)
  is factored into `handle_decoded_key`, called by both the real PS/2 IRQ handler and a new
  `feed_synthetic_scancode` entry point `hid_keyboard` calls once per synthesized PS/2 Scan Code
  Set 1 byte (diffed from each HID boot report against the previous one, including the `0xE0`
  extended-key prefix). Shift state, Caps Lock, signal interception, and echo all come along for
  free. **`feed_synthetic_scancode` never touches the PIC** — only `keyboard_interrupt_handler`
  (the one actually inside a real hardware IRQ) sends its own EOI, unconditionally, after calling
  `handle_decoded_key` regardless of whether it returned early.
- One keyboard device for v1 (first HID boot-keyboard endpoint found during `usb::init`'s one-time
  port scan wins), no hot-plug, US 104-key layout only (a handful of ISO/PrintScreen/Pause keys
  unmapped — real, narrow, deliberate gaps). Mouse/pointer input out of scope entirely — no GUI or
  pointer concept exists anywhere in this kernel to consume it yet.
- **Real key auto-repeat** (`hid_keyboard::KeyboardDevice::repeat_usage`/`repeat_next_tick`,
  checked every `poll()` tick) — a real USB HID boot-keyboard device reports a key exactly once per
  state change and never again while it's held (unlike a PS/2 keyboard, whose own firmware
  autonomously resends the make code — real hardware autorepeat, entirely transparent to this
  kernel's decode pipeline, no kernel code needed). Typematic repeat is universally an OS-side
  responsibility on real desktop systems, so it's synthesized here instead, driven by
  `cpu::interrupts::ticks()` rather than by report arrival (a held key generates no further xHCI
  Transfer Events at all). Only the single most-recently-pressed still-held key repeats, matching
  real desktop-OS convention; modifiers never repeat.
- QEMU test devices (`-device qemu-xhci -device usb-kbd`) are opt-in via `OXIDEBSD_QEMU_USB=1` in
  `scripts/qemu_runner.sh`, not default — QEMU's default i440fx machine already wires up a PS/2
  keyboard at the hardware-model level, so an always-on USB keyboard would double-push every
  keystroke typed into the QEMU window into stdin.
- **Real hardware (Surface Pro) itself is genuinely manual-only** — but live interactive-keystroke
  verification (Ctrl+C/history/shift through the shared decode pipeline) turned out **not** to need
  a human at a real display after all: QEMU's own monitor `sendkey <combo> [hold-ms]` genuinely
  synthesizes guest keystrokes (including held-key duration, for auto-repeat testing) over a plain
  TCP socket (`scripts/qemu_runner.sh`'s opt-in `OXIDEBSD_QEMU_MONITOR=<port>`) — this is how the
  real Ctrl+C/Ctrl+D bug in the next section was actually found and confirmed fixed, headlessly.
  Revise CLAUDE.md's test-architecture section's "can't be scripted, manual-QEMU-only" framing
  accordingly for anything keyboard-shaped specifically (still true for anything needing a real
  human decision mid-session, e.g. `sulogin` credential entry).

## A real, pre-existing (PS/2 *and* USB) bug found via scripted keystroke testing: Ctrl+C/Ctrl+D silently did nothing once BusyBox's line editor took over (`src/console/stdin.rs`)

Found and fixed while validating the USB keyboard work above (via the new `OXIDEBSD_QEMU_MONITOR`
`sendkey` capability, not a real keyboard) — but the bug itself predates USB entirely and affects
plain PS/2 too, confirmed via the identical byte-level trace.

- **Root cause**: `DEFAULT_TERMIOS.c_cc` (the fallback/initial `struct termios` `TCGETS` returns
  before anything ever calls `TCSETS`) was all-zero. Real, unmodified BusyBox `libbb/lineedit.c`
  deliberately clears `ISIG` when it takes over line editing (so it can implement Ctrl+C/Ctrl+D
  itself on raw bytes, real upstream behavior, not an OxideBSD-side choice) — and recognizes them
  by comparing each incoming byte against `initial_settings.c_cc[VINTR]`/`c_cc[VEOF]` (the
  *original* termios it read via `TCGETS` right before switching to raw mode), each check
  explicitly guarded by `!= 0` ("this control character is disabled"). An all-zero default silently
  satisfied that guard as "disabled" — so Ctrl+C/Ctrl+D never did anything once `hush`'s own line
  editor was driving the prompt (which is effectively always, interactively), regardless of the
  real, independently-working `ISIG`-gated `SIGINT`/`SIGTSTP` interception path (`cpu::interrupts`)
  or the real `TIOCSCTTY`/`TIOCSPGRP` session wiring (`console::stdin::foreground_pgid`) — both of
  which traced out correctly and were never the actual problem, confirmed via the same live trace
  before landing on the real cause.
- **Fixed**: `DEFAULT_TERMIOS.c_cc` now holds the real POSIX/Linux default control-character values
  (`VINTR=^C`/`VQUIT=^\`/`VERASE=DEL`/`VKILL=^U`/`VEOF=^D`/`VSTART=^Q`/`VSTOP=^S`/`VSUSP=^Z`/
  `VREPRINT=^R`/`VDISCARD=^O`/`VWERASE=^W`/`VLNEXT=^V`, matching `third_party/musl`'s own
  `arch/generic/bits/termios.h` index layout — the one every non-MIPS/PowerPC arch, x86_64
  included, uses) instead of a comment claiming "nothing depends on exact default `c_cc` values" —
  which was simply wrong, BusyBox's own line editor is exactly such a dependent, and a very common
  one for any future port to hit again.
- **Confirmed fixed live, headlessly**, via `OXIDEBSD_QEMU_MONITOR`'s `sendkey`: typed `sleep 100`,
  waited for it to actually start, sent `ctrl-c` — real `^C` printed and a fresh prompt returned
  immediately (not a 100-second wait), proving a real `SIGINT` reached the real foreground process
  group. `ctrl-d` at an empty prompt cleanly ended the boot's own serial output (`hush`, pid 1,
  exiting on real EOF, matching real Unix behavior — nothing left to schedule after that).
- **Worth a v0.1.x backport**: this is a genuine, narrow, low-risk correctness bugfix (wrong
  default constant values, nothing structural) in code that predates and is unrelated to the
  Limine/USB work landing alongside it — real Ctrl+C/Ctrl+D affects every interactive session,
  PS/2 included, on that branch too.

## A real `sys_pwritev2` gap closed the post-Limine full-corpus POSIX regression (`src/syscall/ffi.rs`)

`sys_pwritev2` was missing the negative-offset check `sys_pwrite` already has. Real musl's own
`pwrite()` issues `SYS_pwritev2`, not `SYS_pwrite` — so that existing check never ran for an
ordinary `pwrite()` call. `aio_write/9-1.c`'s real worker thread calls `pwrite(fd, buf, len, -1)`;
musl maps `-1`→`-2` (avoiding pwritev2's own "`-1` = current position" sentinel) and the resulting
huge, unvalidated offset drained oxfs's *entire* free-block pool in one `resize_inode_data` call
(bounded, not memory-unsafe — `alloc_block` just returns `None` once exhausted) before failing
`EIO` instead of the `EINVAL` POSIX requires — starving every later test in the same boot that
needed to write a file. Explains the ~86%→~2026-09-10 full-corpus UNRESOLVED spike blamed on
Limine timing at the time: real trigger was corpus content/order exercising this path for the
first time, not a timing-sensitive scheduler race. Fixed: reject any `ofs` other than exactly
`u64::MAX` (the real "current position" sentinel) that's negative. Closes the whole cascade —
53-file minimal repro moved 15P/8F/28U/1CRASH → 49P/0F/3U(pre-existing, unrelated)/0CRASH. A fresh
full ~1687-file supervised run confirms it: clean on the first iteration, zero exclusions needed
(previously required excluding wedged files to complete at all) — **1515P/26F/18U/29US/77UT/8TO/
14CRASH, 89.8% raw / 94.1% excl-untested**, a new high (prior best: 88.4%/92.5%, before this
regression dropped it to 86.6% excl-untested). Every remaining FAIL/CRASH/TIMEOUT matches an
already-documented, accepted gap elsewhere in this file (musl's stale-tid UAF class, `strftime/
2-1.c`'s known upstream bug, `shm_open/39-2.c`'s `ENAMETOOLONG` gap, etc.) — nothing new.

## Dependency notes

- `x86_64` crate: `default-features = false, features = ["instructions", "abi_x86_interrupt"]` —
  the default feature set pulls in `step_trait`, an unstable-API moving target that has broken
  this crate against newer nightlies before.
- `bootloader` pinned to `0.9` (not `0.11+`'s artifact-dependency API) — keeps setup in one crate;
  `map_physical_memory` feature is required for `BootInfo::physical_memory_offset` to exist.
- `linked_list_allocator`: `default-features = false` — its default `LockedHeap` depends on
  `spinning_top`, a second spinlock crate alongside `spin` (used everywhere else here).
- `pc-keyboard` 0.9's type is `PS2Keyboard<L, S>`, not `Keyboard<L, S>` (older tutorials reference
  the pre-0.9 name). Decoding is two calls through the *same* locked guard: `add_byte` →
  `KeyEvent`, then `process_keyevent` → `DecodedKey`.
- `pic8259`/`uart_16550` are deliberately **not** dependencies — both wrap a handful of
  `outb`/`inb` calls against a stable protocol, small enough that owning the code (`src/cpu/
  pic.rs`, `src/console/serial.rs`) outweighs the dependency. `pc-keyboard` (hundreds of lines of
  scancode tables) and `linked_list_allocator` (safety-critical free-list logic) stay external.
- `sha2`/`chacha20` (`src/random.rs`): `default-features = false`, `sha2` additionally needs
  `features = ["force-soft"]` and `chacha20` needs `--cfg chacha20_backend="soft"` via
  `.cargo/config.toml`'s rustflags — both otherwise try to compile a SIMD backend this target's
  disabled SSE/MMX can't lower. Crypto primitives are the one place this codebase deliberately
  prefers a vetted dependency over hand-rolling — the opposite call from `pic8259`/`uart_16550`
  above.
