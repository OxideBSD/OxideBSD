# CLAUDE.md

Guidance for Claude Code in this repository.

## Policy for this file

**NO COVERAGE OF EVERY SINGLE BUG AND HOW IT WAS FIXED.** This file loads every session; every
line costs tokens forever. It holds only:

- invariants and rules that still constrain new code,
- gotchas that will bite again (one or two lines each: the rule, not the war story),
- commands, layout, and pointers to where the real detail lives.

Bug narratives belong in the commit message. Design detail belongs in the code's doc comments or
in `OxideBSD-doc` (separate repo, `~/Documents/Code/OxideBSD-doc`). The pre-2026-09-29 long-form
version of this file, with the full per-subsystem bug history, is archived at
`OxideBSD-doc/HISTORY.md`. When adding an entry here, ask "would a future session break something
without this?" If not, leave it out.

## Project

OxideBSD: a Rust BSD-like OS, x86_64 only, single core. Roadmap: `OxideBSD-doc/ROADMAP.md`.

**Minimum requirements, permanent (never increase):** a 64-bit, little-endian x64, ARM64, PPC64,
MIPS64 or RISCV64 machine with 64 MB of RAM. The ISA baseline is the first generation (x86-64-v1:
SSE2 and NX, nothing newer): a newer CPU feature may be used when present (PCID, SMEP, SMAP), never
required -- probe it and keep a fallback.

- Boots via Limine (hybrid BIOS+UEFI ISO, `sys/boot/mod.rs`), or via Multiboot2 (`multiboot2`
  feature, `sys/boot/multiboot2.rs`). Higher-half kernel.
- Per-process address spaces, ELF64 loading (static `ET_EXEC`, PIE with ASLR, `PT_INTERP` dynamic
  via musl's `ld.so`), ring 3, a native BSD-style syscall ABI over `SYSCALL`/`SYSRETQ`.
- Syscalls are registered at runtime by dynamically loaded kernel modules (`sys/module.rs`,
  `sys/modules/*`): `native_abi`, `posix_compat`, `signal`, `oxfs`, `socket`, `clock`, `sysctl`.
- oxfs (`sys/modules/oxfs`): in-memory Unix inode/block filesystem, persisted to a virtio-blk or
  IDE disk; scoped bind/tmpfs mount table; `/proc`.
- Process table, round-robin scheduler with ring-3 preemption, fork/execve/wait4, real threads
  (`clone`/futex), signals, job control, ttys (`sys/tty`), SysV + POSIX IPC.
- Networking: rtl8139, Ethernet/ARP/IPv4/ICMP/UDP/TCP, `AF_UNIX`, poll/select, DNS via musl.
- Userland: pid 1 is `/sbin/init` (`init(8)`: `/etc/rc`, then getty/login on the `/etc/ttys`
  terminals; the console is `insecure`: log in as `user`, then `sudo`/`su`, sudo-rs at
  `external/mit/sudo-rs`, `user` in `wheel`); OxideBSD's own `/bin/sh`
  from `lib/libsh`; 128 standalone BusyBox applets;
  native PIE utilities over `lib/oxlibc`; on-target Clang/LLVM, bmake, ninja, ncurses, nano, nvi;
  a real `x86_64-unknown-oxidebsd` Rust `std` target. Layout: `hier(7)` (`share/man/man7/hier.7`).

**Known deliberate gaps**: no pointer validation in `sys_read`/`sys_write`, no module unload, no
kernel-mode preemption, no general VFS, no IPv6, static interfaces (no ifconfig/route), no SMP,
no IOAPIC/MSI. Architecture decisions for unbuilt subsystems haven't been made: discuss with the
user before large structural commitments.

## Git workflow

- Work directly on `master`; no feature branches. `v0.2.x` still gets fixes; `v0.1.x` is EOL.
- Commit before a risky change. Never `git stash`; read old versions with `git show <rev>:<path>`.

## Toolchain

- Nightly Rust pinned in `rust-toolchain.toml`. Load-bearing unstable features: `-Z build-std`,
  `-Z json-target-spec`, `-Z panic-abort-tests`.
- **`external/mit/rust` must sit on that nightly's exact commit** (`git_commit_hash` in
  `static.rust-lang.org/dist/<date>/channel-rust-nightly.toml`). Bump both together, plus the libc
  fork if std's required `libc` version moved.
- Needs `qemu-system-x86_64` and OVMF (UEFI is the default firmware).
- `.cargo/config.toml`: default target `x86_64-oxidebsd.json`, `runner = scripts/qemu_runner.sh`.
- **Cross compilers live in `toolchain/`** (gitignored, built by `build.rs`, `toolchain_dir`): the
  musl sysroot `toolchain/x86_64-unknown-oxidebsd`, `toolchain/bin/x86_64-unknown-oxidebsd-{cc,
  clang,clang++,ld.lld}` and `oxidebsd-rustc-wrapper`, the Rust sysroot, and `build/` (host LLVM,
  compiler-rt, libgcc_s). `cargo clean` leaves it; `scripts/wipe.sh` removes `target/` and
  `toolchain/`. Things built *for* OxideBSD stay in `target/`.

## Commands

- `cargo bv` / `cargo tv` / `cargo rv`: build / test / run with `-vv` so `build.rs` output
  streams live. Prefer these.
- The dev profile is `opt-level = 2` (with debug info): set it to 0 to step through the kernel in
  gdb. `sysctl -n debug.syscall.stats` shows per-system-call cost (`debug.syscall.reset=1`).
- `cargo run`: stages the ISO and boots QEMU, serial on stdio. `cargo run -- -s` (or
  `OXIDEBSD_KERNEL_CMDLINE=-s`) passes kernel boot flags.
- `cargo test --test <name>`: each test boots its own QEMU (slow; no fast path). Tests run with
  `-no-reboot` (a fault or panic fails at once) and a stall guard: no serial output for
  `OXIDEBSD_TEST_STALL_SECS` (default 600, 0 off) kills the run as HUNG.
- `cargo fmt -p oxidebsd`: **bare `cargo fmt` reformats the whole workspace.**
- Root commands target only the `oxidebsd` package. `regress/*`, `usr.bin/*`, `bin/*`,
  `sys/modules/*` are workspace members that `build.rs` cross-builds. To build one directly:
  `--manifest-path <dir>/Cargo.toml --target-dir target/userland` (or `target/modules`) to avoid a
  nested cargo lock deadlock.
- **Editing `build.rs` forces a large rebuild; editing `build_busybox.rs` forces the ~20-40 min
  BusyBox rebuild.** Never `touch build.rs` to force rebuilds.
- Useful env: `OXIDEBSD_FIRMWARE=bios`, `OXIDEBSD_QEMU_DISK=ide|virtio`, `OXIDEBSD_DISK_IMAGE`,
  `OXIDEBSD_QEMU_USB=1`, `OXIDEBSD_QEMU_DISPLAY=none`, `OXIDEBSD_QEMU_MONITOR=<port>`,
  `OXIDEBSD_QEMU_MEM=<MiB>` (default 8192; the floor is 64),
  `OXIDEBSD_QEMU_CPU=max` (QEMU's default CPU has no SMEP/SMAP; set this to exercise them),
  `OXIDEBSD_QEMU_ACCEL=tcg` (pure emulation: with `OXIDEBSD_QEMU_CPU=Opteron_G1` it checks the
  x86-64-v1 baseline, since under KVM `-cpu` only masks CPUID and newer instructions still run),
  `OXIDEBSD_REAL_HARDWARE=1` (adds `no-ata`).

## Test architecture

No libtest. Tests boot in QEMU and report through `isa-debug-exit` (`sys/qemu.rs`;
`test-success-exit-code` in `Cargo.toml` must match `QemuExitCode::Success`) and serial.

- `tests/*.rs` are `harness = false`, each with its own entry point, calling `exit_qemu()`.
- Test binaries/module objects live under `build/<crate>/<hash>/out/`, not `deps/`.
  `qemu_runner.sh` identifies a test by its `-<16 hex>` suffix.
- **Syscall-reachable code is tested by spawning a real ELF that executes `SYSCALL`**
  (`tests/*_syscall_smoke.rs` + `regress/*-syscall-smoke/`), never by calling handlers as Rust
  functions (interrupts stay on and `ticks()` advances, hiding real bugs). Test-only syscalls:
  `9999` exit, `9998` inject UDP frame, `9997` TCP step.
- **Interactive input can be scripted headlessly**: a test's `tests/<name>.serial` is typed on
  COM1 (`ttyv0`'s input under `-D`) once the guest prints `serial input: ready`; or QEMU monitor
  `sendkey`/`screendump` over `OXIDEBSD_QEMU_MONITOR`, or `scripts/qemu_sendkeys.py`. Only credential prompts and
  restart/reboot/poweroff persistence stay manual; hand those to the user.
- **POSIX pilot** (`tests/posix_conformance_smoke.rs`, full Open POSIX Test Suite) is the main
  regression and bug-finding check; its pass rate is not a conformance measure. Run with `scripts/run_posix_pilot_supervised.sh [--reset]`.
  `POSIX_PILOT_CANARY_ONLY=1` runs the curated regression subset. When the supervisor excludes a
  file for a stall, verify it in isolation: it often blames an innocent neighbour. Current numbers
  live in `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`, never in this file.
- `lib/libsh` is a host workspace: `cargo test` there diffs `tests/diff/*.sh` against `dash`.
  `tests/sh_syscall_smoke.rs` runs the same corpus on target against checked-in `*.expected`
  (regenerate with dash when a script changes).
- When a slow-I/O stretch looks like a hang, sample `RIP` several times over gdbserver before
  calling it stuck, and check whether a "corrupt" address is a named constant (`HEAP_START =
  0xffff_c100_0000_0000`).

## Target spec (`x86_64-oxidebsd.json`)

- `target-pointer-width`/`target-c-int-width` are numbers, not strings.
- Soft float needs both `+soft-float` in `features` and `"rustc-abi": "softfloat"`.
- `panic-strategy: abort` only (hence `-Z panic-abort-tests`). SSE/MMX off, red zone off.

## build.rs rules

- **Nested cargo invocations must `.env_remove("CARGO_ENCODED_RUSTFLAGS")`**, or the kernel's
  rustflags (linker script) leak into them and override their own `RUSTFLAGS`. Check any new
  top-level rustflag against this leak.
- Never `rerun-if-changed` a path that may not exist, or a file something writes every run: both
  make every build dirty. `cargo build -v` names the dirty path.
- cargo doesn't track `libc.a` (it's behind `-C linker=musl-gcc`) or musl's installed headers.
  Staleness checks compare against `musl_sysroot/lib/libc.a`; a musl header change needs a
  BusyBox `O=` dir wipe.
- `ccache` is used for BusyBox and the POSIX pilot when installed.

## Boot

- `sys/boot/mod.rs`: Limine request statics, `BootInfo` shim (`physical_memory_offset`,
  `memory_map`), `limine_entry_point!`. No direct `0xb8000` access: the console is the
  framebuffer (`sys/console/framebuffer.rs`), fed by `boot::FbInfo`.
- Kernel cmdline (`boot::parse_cmdline`): `no-ata`/`no-disk`, `console.underline=color`, `-s`
  single user, `-D` dual console, `-h` serial console, `init=`/`init_path=` (programs the kernel
  tries as pid 1, read from disk; `process::init`). Tests and headless runs get `-D`.
- **Multiboot2** is a deliberately maintained second boot path (it eases bootloader
  development); don't remove it. Works under Limine's multiboot2 loader and GRUB on BIOS. The full kernel needs
  `OXIDEBSD_FIRMWARE=bios` (UEFI has no contiguous hole for the ~266 MiB image; GRUB 2.14 under
  UEFI has an upstream relocator bug). `regress/multiboot2-boot-smoke/` is trampoline-only;
  `regress/multiboot2-kernel/` boots the real system via `scripts/run_multiboot2_kernel.sh`. The
  smoke crate depends on the `oxidebsd` lib, so its build is guarded by
  `OXIDEBSD_BUILDING_MULTIBOOT2_SMOKE`.
- `scripts/mkbootimg.sh <bootdir> <out.img>`: a self-booting GPT disk (BIOS boot partition via
  `mkimg -b`, FAT32 ESP via `makefs -t msdos`, the root image), from `target/iso_root/boot`;
  tests `disk_boot`/`disk_boot_bios` boot it with no ISO.
- `global_asm!` that switches sections must `.pushsection`/`.popsection`.

## Memory

- `memory::init` walks `CR3` + HHDM offset; call once.
- `BootInfoFrameAllocator` is built **before the heap exists**: no heap allocation inside it. Its
  free list is intrusive (stored in the freed frames). Code that can run inside a `module_init`
  (frames freed or mapped at boot) uses `module::phys_mem_offset`, not `memory::phys_mem_offset`.
- Fresh mappings use `.ignore()` not `.flush()`.
- Heap at fixed `allocator::HEAP_START` (L4 slot 386), size scales with RAM (clamped). **Nothing
  kernel-only may be mapped in the user range** `[VM_MINUSER, VM_MAXUSER)` (`memory/usercopy.rs`,
  checked at boot): copyin relies on it. Kernel stacks live in
  `memory::kstack`'s window (L4 slot 385) with guard gaps; overflow logs `KERNEL STACK OVERFLOW`.
  The buffer cache's window (`kern::vfs_bio`) is L4 slot 387.
- **Ring-0 stacks in `gdt.rs` (and any stack like them) must be `static mut`**, or they land in
  `.rodata`.
- **The kernel image must end below `module::MODULE_VA_BASE` (`0xffff_ffff_a000_0000`).** Module
  data pools live at `MODULE_DATA_BASE` (L4 384).
- **New C programs and fixtures are static PIE** (`build_c_pie`, `musl-gcc -static-pie`; musl is
  built `-fPIE`). Fixed-address binaries (BusyBox, bmake, vi, nano, ninja, doom, the POSIX corpus)
  need a load base above the kernel's low reservations and below `0x2000_0000` (the module
  region); the floor moves as the image grows and fails as `MappingFailed`/`PageAlreadyMapped` at
  exec: `readelf -l target/x86_64-oxidebsd/debug/oxidebsd`.
- **One musl build makes `libc.a` and `libc.so`**: `musl-gcc` without `-static`/`-static-pie`
  links dynamically (`PT_INTERP` `/lib/ld-musl-x86_64.so.1`). Every `ET_DYN` main binary gets an
  ASLR bias, `PT_INTERP` or not, from `execve` and the kernel's own `spawn` (which refuses a
  `PT_INTERP` image: it loads no dynamic linker).
- **`/bin` and `/sbin` are static** (OpenBSD-style; `build_static_std_crate`, `StdLink::StaticPie`),
  including `/sbin/init`, `/bin/sh` and `/sbin/emergency`, which the kernel reads from the root
  file system and spawns as pid 1 (nothing userland is embedded in it). **Everything else is a dynamic PIE** on `/lib/libc.so` and `/lib/libgcc_s.so.1` (LLVM
  libunwind, `build_libgcc_s`).
- **`/sbin/init` has no controlling terminal** (`InitProgram::console`); each child it starts is
  its own session and takes the console with `TIOCSCTTY`. The kernel never lets a session leader
  drop its terminal, so pid 1 must not be given one.
- User stacks grow on demand inside an 8 MiB reserve (`mm::try_grow_user_stack`, both rings).
- `AddressSpace` is `Arc`-refcounted; frames are reclaimed at exit. `SHARED_LEAF` PTEs (SysV shm,
  `MAP_SHARED`) are never freed by teardown.
- **Fork is copy-on-write** (`OxideBSD-doc/COW.md`): private frames are shared, counted in
  `memory::refs`. **Drop a private frame only via `refs::release`** (free it when that returns
  true). **Never write a user page through the HHDM** unless it's freshly allocated or
  `SHARED_LEAF`: write through the user address (copyout), so the COW fault (`mm::try_resolve_cow`,
  both rings) copies it first. The frame allocator lock is never held across a sleep.
- **W^X** (`THREAT_MODEL.md` §3.3): every new mapping is `NO_EXECUTE` (`cpu::nx::no_execute()`)
  unless it holds code; nothing is writable and executable. `memory::wx` audits the kernel at boot
  and after the modules load (`[wx]` lines must say none). User `PROT_WRITE|PROT_EXEC` is
  `ENOTSUP` unless `wxneeded` (`PT_OXIDEBSD_WXNEEDED`, `ld.lld -z wxneeded`) on a `wxallowed` mount.
- User leaves carry software bits: `SHARED_LEAF`, `CACHED_LEAF`, `PROT_NONE_LEAF` (non-present,
  keeps its frame), `MAY_WRITE_LEAF`, `COW_LEAF`, `FILE_LEAF` (non-present, **no** frame: a page
  cache page not filled yet, entry id + file page in its address bits).
- **File mappings are demand-paged** (`OxideBSD-doc/DEMANDPAGE.md`): exec and `mmap` write
  `FILE_LEAF` entries; the fault fills them from the disk through the entry's block map, never
  through oxfs. A new page table walk must handle `FILE_LEAF` (fork copies it, munmap forgets it,
  mprotect/mlock fill it first). **A fault in a copy routine must never sleep or wait**: the
  interrupted code may hold any spin lock (syscalls do copy in under the process table's lock). **A page-table walk must not treat a non-`USER_ACCESSIBLE`
  user-range entry as kernel-owned**; a non-present leaf may still own a frame.

## Syscall ABI (`sys/syscall/`)

Native, BSD-flavoured, not Linux-compatible. Number in `RAX`, args in `RDI`/`RSI`/`RDX`/`R10`.
**Carry flag** signals failure (`CF=1`, positive errno in `RAX`). Handlers registered with
`oxidebsd_register_syscall`; a handler returns `i64` (negative = `-errno`). Unregistered numbers
log `unrecognized syscall number N` and return `ENOSYS`.

- **Picking a new number**: check `sys/syscall/` and module sources for the current highest.
  Invented numbers go at `471`+ (permanently collision-free with this frozen musl `v1.2.6`), or
  above the highest assigned. **Also check the `__NR_*` macro name** against
  `external/mit/musl/arch/x86_64/bits/syscall.h.in`: a duplicate name silently wins by textual
  order. Never write a literal `__NR_` in a comment in that file.
- **errno values must match musl's `bits/errno.h`**, not FreeBSD's.
- New syscalls go in a dedicated module, not `native_abi`. OxideBSD invents its own numbers and
  semantics rather than copying FreeBSD's.
- Matching a number isn't enough: argument shapes differ (length-prefixed paths/argv, `RawAtPath`
  for `*at()`, packed mmap flags). Audit the musl call site.
- Hand-written musl asm stubs (`vfork.s`, `clone.s`, `__unmapself.s`, ...) bypass both the number
  remap and the carry-flag conversion: patch them directly.
- If a remapped syscall has a `*64` sibling (`getdents64`, `stat64`, ...), remap both.
- GDT order is forced by `SYSRETQ`: kernel code, kernel data, placeholder, user data, user code,
  TSS. `Star::write` panics if it regresses.
- No automatic stack switch on `SYSCALL`: `gdt::CURRENT_RSP0` names the current kernel stack.
- **`SYSRETQ` takes `RIP` from `RCX` at execution time**: any async redirect of a ring-3 frame
  must restore `RCX`/`R11` through the two-stage trampoline, not clobber them.
- **Interrupts are masked for a whole syscall (`SFMASK`).** Inside a syscall: never `hlt()`,
  never gate on `ticks()` (frozen); bound busy-waits with `sys/cpu/tsc.rs` and `spin_loop()`.
  Anything waiting on an interrupt-driven event (tty input, IRQ-woken devices) must block via the
  scheduler, which re-enables interrupts; spinning makes the event impossible.
- IDT gates reachable from ring 3 via `int n` need `DPL = Ring3`.
- **The entry area** (`cpu::entry`): anything a ring-3 trap or `syscall` touches before reaching
  Rust, or after leaving it, goes in `.text.entry*`/`.data.entry*` (KPTI maps only those);
  `entry::check` panics at boot otherwise. Ring-3 traps land on `ENTRY_STACK` (fixed `TSS.RSP0`).
- The NMI handler takes no locks (it only counts): an NMI can interrupt any lock holder.
- **KPTI** (`cpu::pti`, `THREAT_MODEL.md` §3.4): on for Intel without RDCL_NO, off otherwise;
  `pti=`/`kpti=`/`meltdown=` on|off override, `vm.pmap.pti`/`machdep.kpti`/`hw.meltdown` report it.
  Each `AddressSpace` gets a second (user) L4 mapping only the entry area plus its user half
  (mirrored lazily on fault, `mirror_user_l4`); the trap/syscall entry+exit asm switches CR3 when
  `PTI_ON`. NMI/#DF/#MC use `trap_common_paranoid` (save/restore CR3). With PCID (CPUID.1:ECX[17])
  the kernel table runs on PCID 1 kept across a syscall (entry sets CR3's no-flush bit) and the
  user table on PCID 2 flushed on every ring-3 return -- so no `.flush()` site needs PCID
  awareness; without PCID each switch flushes the whole TLB (fallback).
- Wire structs duplicated in `regress/*` crates (siginfo, ucontext, ...) must be updated together
  with the kernel copy.

## Kernel modules (`sys/module.rs`)

- Built with `cargo rustc --emit=obj` then `rust-lld -r --gc-sections -u module_init` (the gc is
  mandatory). `RUSTFLAGS="-C relocation-model=static -C code-model=kernel"`.
- Module code may use `alloc` and `core::fmt` by depending on `lib/libkern-mod` (`use kern_mod as
  _;`): a global allocator over the kernel heap (1/8 of RAM, 8 MiB at 64 MB), charged per module
  (`kern.module.<name>.alloc`). An infallible allocation that fails is a module panic: use
  `try_reserve` and return `ENOMEM` where a call can fail. **Never hand out `&'static mut` into a
  growable `Vec`** (it moves): grow in boxed chunks. Large boot-time pools still come from
  `oxidebsd_module_alloc_zeroed` inside `module_init`.
- A `static mut` written but never read through a syscall-reachable path can be optimised away.
- `serial_println!` can't take implicit `{name}` captures.
- A module panic is fatal to the call; oxfs's panic reboots.
- **File systems are VFS types** (`OxideBSD-doc/VFS.md`): a module registers a static `VfsConf`
  with `oxidebsd_vfs_register` and calls `oxidebsd_module_serialize` (the giant lock); the
  interface types live in `lib/libvfs` (crate `vfs_if`), shared with the kernel: never duplicate
  them. The root mounts when its type (`/boot/fsconf`, else `oxfs`) registers.
- Modules talk only to the kernel, never to each other. `sys/fs/fd.rs` is the shared fd registry:
  `(tgid, fd) -> real_fd -> Description` (a `struct file`: static `FileOps` table, data, `f_flag`,
  offset). A new kind of file is one `#[repr(C)] static FileOps` (null entry = kernel default),
  made with `finstall`/`oxidebsd_finstall(real_fd, &OPS, data, oflags)`, which returns the user fd.
  The kernel checks the access mode and keeps a `DFLAG_SEEKABLE` file's offset (`FOF_NEXTOFF` vs
  `pread`'s `FOF_OFFSET`); close/lseek/fstat/ioctl/ftruncate/fsync go through the table. An open
  the kernel makes for itself goes inside `fd::kernel_open` (no fd; `release` the handle).

## Processes, scheduling, threads (`sys/process/`)

- Process table is `Mutex<BTreeMap<Pid, Box<Process>>>`; the `Box` is load-bearing. **Drop the
  table lock before `scheduler::schedule()`.**
- **Every blocking `schedule()` call site must loop and re-check its wake condition**: `SIGCONT`
  and other cross-process wakes can make a process `Ready` early. New force-wake mechanisms need an
  audit of all call sites.
- Blocking follows check-before-block / re-check-after-wake. EINTR decisions use
  `signals::has_interrupting_signal` (ignored signals don't interrupt).
- Ring-3 preemption only (checked via interrupted CS RPL); 4-tick quantum. **Timer EOI before
  `schedule()`.** An IRQ handler may only call `schedule()` when it interrupted ring 3.
- Per-process `FXSAVE`/`FXRSTOR` and `fs_base` are restored on every switch.
- `do_execve` builds everything before touching the caller, so failure leaves it intact.
- `wait4` status is `wait(2)`-encoded (exit status shifted into bits 8-15; signal deaths not).
- Threads: `Process::tgid`, `ThreadGroupShared` (`Arc<Mutex<>>`: cwd, root, umask, ids, brk,
  sigactions, ...). fd table is keyed by `tgid`; `do_clone` must not call `fork_inherit`.
  Group-killing signals go through `terminate_thread_group` (leader last). `exit` is
  `SYS_EXIT_GROUP`.
- Private futexes key on `(tgid, addr)`; shared ones on physical address only for `SHARED_LEAF`
  pages (a private page's frame changes at its COW copy).
- Orphans reparent to pid 1.
- Kernel stack floor 128 KiB.

## Signals, ttys, time

- Signals `1..=64`; `32..=34` are valid kernel-side. Delivery at syscall exit and from
  `sigreturn` (chaining). Faults deliver via `force_fault_signal` (ignores the blocked mask) and
  the trampoline at `0x1FFF_FFFF_F000` + `SYS_FAULT_PUMP`. Ring-0 faults reboot.
- `sys/tty`: each terminal is a `Tty` with its own termios and line discipline; `ttyv0` is the
  console. Spec and status: `OxideBSD-doc/TTY.md` §10. The keyboard sends CR for Enter
  (`normalize_enter_key`; Ctrl+J stays LF), DEL for Backspace, Linux-console escape sequences.
- `sys/console/vga.rs`'s CSI parser silently drops unknown sequences; a garbled curses screen
  usually means a missing CSI final byte.
- A console `write` costs ~1 ms: utilities that print a lot must batch (`oxlibc::io::BufWriter`).
- PIT at 100 Hz is the tick. HPET is a counter-only overlay (no interrupts). `CLOCK_REALTIME` is
  RTC-calibrated once, then tick-derived; use it (not raw CMOS reads) for timestamps.
- sysctl: `OxideBSD-doc/SYSCTL.md`. Kernel prints also go to the msgbuf.

## oxfs and disks (`sys/modules/oxfs`, `sys/drivers/`)

- Fixed block pool (`NUM_BLOCKS`, `NAME_MAX=255`, ...); inodes live in a growable inode file
  (`InodeTable`), freed by `maybe_release` once no name, oxfs descriptor or kernel reference
  (`oxidebsd_inode_in_use`) remains. **A new kernel structure that keeps an oxfs inode number must
  be added to `oxidebsd_inode_in_use`**, or the inode can be freed and reused under it. Changing
  anything in the on-disk layout **must bump `SUPERBLOCK_VERSION`** (mount checks, else reformats).
- Only `write_block`, `write_inode`, `set_block_used` touch the backing pools (write-through
  persistence). Inodes are serialized by `pack_inode`/`unpack_inode`, never transmuted.
- **A new path that changes a file's contents or frees an inode must call `content_changed`**, or
  the kernel's page cache (`sys/memory/pagecache.rs`, `OxideBSD-doc/PAGECACHE.md`) keeps mapping
  the old pages into new execs. Cached pages are `SHARED_LEAF | CACHED_LEAF`, read-only.
- **RAM rule: never require more than 64 MB**, boot and console install, forever (user, 2026-10-14);
  UEFI is exempt only if OVMF itself needs more. `ram_floor_boot` boots at 64 MB and fails on any
  `[fault]` or failed rc service, not just panics. Under UEFI that takes our Limine fork's
  `LIMINE_FIRMWARE_RESERVE_MIB` (set in `build.rs`) and `memory::reclaim_bootloader_memory`; boot
  responses read after boot are cached first (`boot::snapshot`).
- **The kernel never formats or seeds** (RAM_FLOOR.md §4): the system is `target/images/disk.img`,
  built by `build_install.rs` (makefs/mkimg, fsck'd at build). Tests boot a fresh copy; the dev
  disk `target/oxfs_disk.img` is replaced when the sets' contents change (`OXIDEBSD_KEEP_DISK=1`
  keeps it), and may be deleted to get a fresh one.
- New mount options go through `oxfs_nmount` and `MountEntry` (`nosuid`, `wxallowed`), checked
  at exec through the `ContentSetId` accessor.
- `/dev` is devfs (`OxideBSD-doc/DEVFS.md`): built every boot from the kernel's device registry
  (`sys/fs/devfs.rs`). **A new device registers with `make_dev`/`oxidebsd_make_dev`**, never by
  seeding a node; every device node opens through `oxidebsd_dev_open` by number.
- A new installed file goes in `distrib/install.mtree`, and its set in `distrib/sets/lists/*`
  (the build fails on an unlisted path). Modes: `0755` only for ELFs and `#!` scripts (the
  default).
- The mount redirect only fires inside `resolve_path_impl`'s component loop.
- Disk: virtio-blk, else IDE secondary master (DMA, else PIO). The boot ISO is on virtio-scsi.
  `no-ata` protects real hardware from being formatted.
- rtl8139 DMA is 32-bit: `rtl8139::init` must run before big allocations.

## Porting (musl, BusyBox, std, C/C++)

- **musl** (`external/mit/musl`, fork branch `oxidebsd` on tag `v1.2.6`): patched to speak this
  ABI. Update by committing on that branch, pushing, then `git add external/mit/musl`. Known,
  accepted stock-musl bugs (stale-tid UAF in pthread_*, async-cancel deadlock) are not ours.
- **BusyBox** (`external/gpl2/busybox`, `1_38_0`, no patches): one static binary per applet,
  `build_busybox_applet` asserts `NUM_APPLETS == 1`. Roster: `OxideBSD-doc/BUSYBOX_APPLETS.md`.
  `/bin/sh` runs autoconf `configure` (bmake's on target, nano/ncurses on the host match dash).
- **std target** (`external/mit/rust` + libc fork): reuses `sys::pal::unix`. A mysterious
  `ENOTTY`/`ENOSYS` from a std program is usually a hardcoded `target_os` allowlist in std missing
  `oxidebsd` (`ioctl` only handles tty requests on tty fds).
- **Rust crates using OpenSSL** (`openssl`/`openssl-sys`, unpatched): build with `OPENSSL_DIR` =
  `target/openssl/root/usr` and `CC_x86_64_unknown_oxidebsd` = `toolchain/bin/x86_64-unknown-
  oxidebsd-cc` (`openssl-rs-smoke`).
- **PIE binaries** (`lib/oxlibc`, `bin/*`, `build_pie_crate_at`) must have zero relocations
  (checked at build): `panic=immediate-abort`, `location-detail=none`, symbol addresses via
  `asm!("lea ...")`, no `core::fmt`, no tables of slices, no `-T` linker script.
- **Clang/LLVM** (`external/apache2/llvm`, `llvmorg-23.1.2`, see its `VENDOR_NOTES.md`):
  `Triple::OxideBSD` toolchain driver; lld's `-m elf_x86_64_oxidebsd` emulation (OxideBSD's
  program header types, `0x6f78xxxx`). `build.rs` rebuilds on `clang/lib/Driver` and `lld/ELF`. The on-target toolchain's configure-args stamp and musl
  `libc.a` mtime decide relinks.
- ncurses (`lib/ncurses`), bmake (`usr.bin/make`) are committed trees; nano, OpenVi, ninja are
  forks on `oxidebsd` branches. Make variable precedence matters: see `build_nvi`/`build_nano`.
- Placement: `/bin` vs `/usr/bin` per `hier(7)`; per-binary inventory in `OxideBSD-doc/HIER.md`.
  Root `PATH` includes `/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/...`.

## Networking (`sys/net`, `sys/netinet`, `sys/kern/uipc_*.rs`)

- BSD layout; spec `OxideBSD-doc/UNIX.md`. Protocols never block: they return `EAGAIN` and the
  socket layer waits via `net::wait_for_change`.
- Interfaces `lo0` (127.0.0.1/8) and `rl0` (10.0.2.15/24) are static (`sys/net/ifnet.rs`);
  `ifnet::route` picks interface, next hop and source. Loopback output is queued (`if_loop`) and
  drained by `net::poll`, never delivered inside the send (protocol locks would re-enter).
- QEMU needs `-accel kvm -accel tcg` or everything runs under TCG.
- A test using sockets, `poll`, or `socketpair` must load the `socket` module.
- Every test that loads `native_abi` also loads `vfs` (close, lseek, fstat, ioctl, ...).
- TCP is stop-and-wait, fixed MSS.

## USB (`sys/drivers/usb/`)

Polling xHCI + HID boot keyboard (Surface target has no PS/2). BARs are mapped explicitly
`NO_CACHE` (`xhci.rs`); don't assume HHDM covers MMIO (firmware parks 64-bit BARs above 4 GiB). Feeds the PS/2 decode path via
`feed_synthetic_scancode`. QEMU devices opt-in with `OXIDEBSD_QEMU_USB=1`.

## Dependencies

- `x86_64`: `default-features = false, features = ["instructions"]`. No `extern "x86-interrupt"`:
  every IDT vector enters through `cpu::trap`'s asm stubs and gets a `&mut TrapFrame`.
- `linked_list_allocator`: `default-features = false`, wrapped in local `Locked<T>` over `spin`.
- `pc-keyboard` 0.9: `PS2Keyboard<L, S>`; `add_byte` then `process_keyevent` on one guard.
- `pic8259`/`uart_16550` are deliberately not dependencies.
- `sha2` (`force-soft`) and `chacha20` (`chacha20_backend="soft"`) must avoid SIMD backends.
