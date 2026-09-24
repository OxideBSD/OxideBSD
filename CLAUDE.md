# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project

OxideBSD is a 100% Rust-based BSD-like OS, x86_64 only (see `OxideBSD-doc/ROADMAP.md` for phase history).
Current state:

- Boots via the Limine protocol (`limine` crate + `scripts/qemu_runner.sh` staging a hybrid
  BIOS+UEFI ISO, `sys/boot.rs`) — not the old `bootloader` crate, retired in the Limine migration
  (see "Boot: Limine" below). GDT/TSS/IDT with a dedicated double-fault stack, PIC-driven
  interrupts (timer + PS/2 keyboard, plus a real xHCI/HID USB keyboard path — see "USB input"),
  a VGA console mirroring serial plus a real framebuffer console, a heap allocator over
  Limine-provided paging info (HHDM offset + memory map).
- Separate per-process address spaces, ELF64 loading, ring-3 execution, and a native BSD-style
  syscall ABI over `SYSCALL`/`SYSRETQ` (`sys/syscall/mod.rs`) with carry-flag error signaling.
- A dynamic kernel module loader (`sys/module.rs`) relocates `#![no_std]` code into the kernel at
  boot and resolves symbol references against a hand-curated kernel API. Syscall handlers are
  registered by modules, not hardcoded: `sys/modules/native_abi/` (core syscalls), `modules/
  posix_compat/` (pipe/dup2/ioctl/setpgid/...), `sys/modules/signal/` (kill/sigaction/...),
  `sys/modules/oxfs/` (the live filesystem).
- `sys/modules/oxfs/` is a real in-memory Unix-shaped inode/block filesystem (real names,
  multi-component paths, per-process cwd, no fixed file-size cap) — replaced an earlier FAT32
  module (8.3 names, one path component per call, fixed file cap), since removed entirely (v0.2.0
  cleanup — no longer built or loaded).
- A real process table + scheduler (`sys/process/`) with `fork`/`execve`/`wait4`/`getpid`, real
  `argv`/`envp` passthrough, blocking pipes, per-process signal delivery, real ring-3 preemption
  (see "Real preemptive scheduling"), and real threading (`clone(2)`/`pthread_create`, see "Real
  threading").
- pid 1 is OxideBSD's own `/bin/sh` (`lib/libsh`, see "Shell"), an interactive login shell;
  BusyBox's `hush` (built against a patched musl fork) is still at `/bin/hush`. 195 BusyBox applets run as standalone static
  binaries, `execve`'d individually (not a multi-call `busybox` binary), placed per HIER.md (see
  "Filesystem layout"). 12 utilities (`echo true false pwd cat ls mkdir rm cp mv ln touch`) are
  native `bin/<name>` PIE binaries over `lib/oxlibc` — see "Real PIE/ASLR loading" below.
- A real networking stack (`sys/drivers/pci.rs`, `sys/net/*`, `sys/modules/net/`): PCI + an rtl8139
  driver, Ethernet/ARP/IPv4/ICMP, UDP/TCP/raw-ICMP sockets, `poll(2)`, and real hostname
  resolution over musl's own DNS stub resolver (no DNS protocol code of its own) — see "Real
  networking" below.
- A real, on-target Clang/LLVM C/C++ toolchain (`external/apache2/llvm`, see "Clang/LLVM port"
  below) — a real, statically-linked, self-hosted `clang`+`ld.lld`, cross-compiled by itself, runs
  as ordinary seeded `/bin` binaries and can genuinely compile+link+run a real C file against a
  real, seeded `/usr/include`/`/usr/lib` musl tree. Real `futex(2)`, real threading, and milestone 1
  of real dynamic linking (`PT_INTERP`) exist. An earlier, simpler on-target compiler (TinyCC)
  served as this project's first proof that a real on-target compile+link was even possible, and
  was removed once Clang/LLVM superseded it.
- Real USB input (xHCI + HID boot-protocol keyboard, see "USB input" below) — this kernel's first
  real-hardware boot target.

Known, deliberate gaps: no pointer validation in `sys_read`/`sys_write`, no module unload/reload,
no *kernel-mode* preemption (real ring-3/user-mode preemption exists), no copy-on-write fork
(real per-address-space frame reclaim exists at exit, see "Real threading"/memory-reclaim notes
below), no general
block-device-agnostic VFS/mount-table layer (a real ATA disk driver + oxfs mount/format
persistence + a scoped bind/tmpfs mount table exist now — see "Real disk persistence"/"Mount
table" — but only for oxfs's own fixed backing store), no IPv6, no real routing table (one
default-gateway rule only), no SMP. See "BusyBox gap analysis" below for what's needed to go
further. Architecture decisions for remaining subsystems haven't been made — discuss with the
user before large structural commitments.

## Toolchain

- Nightly Rust, pinned via `rust-toolchain.toml`. Load-bearing unstable features: `-Z build-std`
  (no prebuilt std for the custom target), `-Z json-target-spec`, `-Z panic-abort-tests`.
- Requires `qemu-system-x86_64` on `PATH`, plus OVMF firmware for UEFI boot (the default — see
  "Boot: Limine" below); no separate `bootimage` install needed any more.
- `.cargo/config.toml` sets the default target to `x86_64-oxidebsd.json` and
  `runner = "scripts/qemu_runner.sh"` — replaces the retired `bootimage runner`.

## Commands

- `cargo build` — kernel ELF only
- `cargo run` — stages a hybrid BIOS+UEFI ISO (`scripts/qemu_runner.sh`, via `build.rs`'s
  `build_limine_deploy_tool`) and boots it in QEMU, serial to stdio
- `cargo test` / `cargo test --test basic_boot` — each target boots its own QEMU instance (slow;
  no fast check path exists)
- `cargo clippy` / `cargo fmt` — **`cargo fmt` with no package selector reformats the entire
  workspace**, including every separate `regress/*`/`usr.bin/*`/`sys/modules/*` crate — scope it
  with `cargo fmt -p oxidebsd` to touch only the root package, matching how build/test commands are
  already scoped below.

These commands at the repo root only target the `oxidebsd` package. `regress/*`, `usr.bin/*`, and
`sys/modules/*` are separate workspace members that the root `build.rs` cross-builds as a side
effect of building `oxidebsd`. To build one directly: `--manifest-path <dir>/<name>/Cargo.toml --target-dir
target/userland` (or `target/modules`) — a separate target dir avoids a nested-cargo lock deadlock
against the outer build. **Editing `build.rs` or an `include!`'d
sibling (`build_busybox.rs`) invalidates the build-script cache and forces a full rebuild**,
including the ~20-30 min BusyBox roster rebuild and the multi-minute POSIX pilot cross-compile —
expect a single-line comment tweak in either file to cost real wall-clock time on the next build.

## Test architecture

No libtest — `no_std`, tests boot in QEMU and self-report via `sys/qemu.rs` (writes to the
`isa-debug-exit` port; `test-success-exit-code` in `Cargo.toml` must stay in sync with
`QemuExitCode::Success`) and `sys/console/serial.rs` (hand-rolled 16550 UART, read via `-serial
stdio`).

- `sys/lib.rs` defines `no_std` test scaffolding (`custom_test_frameworks`, `#[test_case]`) and
  boots itself under `#[cfg(test)]`.
- `tests/*.rs` integration tests use `harness = false` — each defines its own `fn main()` via
  `entry_point!` and calls `exit_qemu()` directly.
- `tests/fork_wait.rs` + `regress/fork-exec-smoke/`: since `scheduler::start`/`process::do_exit`
  never return to a test's own `main`, it registers a syscall number (`9999`) directly via
  `oxidebsd::syscall::oxidebsd_register_syscall` (kept `pub` for this) whose handler calls
  `exit_qemu`.
- **Any test claiming to verify syscall-reachable code should spawn a real ELF and go through an
  actual `SYSCALL` instruction**, not call kernel handlers as plain Rust functions from a test's
  own `main()` — interrupts stay enabled and `ticks()` keeps advancing in the latter, hiding real
  bugs (see "Real networking" gotcha 2 below). Established pattern (`tests/*_syscall_smoke.rs` +
  `regress/*-syscall-smoke/`) for anything syscall-shaped added from here on.
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
- **The full ~1687-file Open POSIX Test Suite pilot** (`tests/posix_conformance_smoke.rs`) is the
  primary correctness signal for POSIX conformance work — see "POSIX conformance pilot" below for
  its own history/tooling. `scripts/run_posix_pilot_supervised.sh [--reset]` is the standard way
  to run it unattended (a host-side supervisor that kills and retries around a genuine kernel-level
  wedge, since `t0`'s own userspace `alarm(40)` can't rescue one). A curated, fast-running subset
  (`POSIX_PILOT_CANARY_ONLY=1`, `build.rs`) accumulates every file a real regression was ever found
  through, as a standing smoke suite — currently ~173 files.

## Custom target spec (`x86_64-oxidebsd.json`)

- `target-pointer-width`/`target-c-int-width` must be numbers, not strings.
- Float returns need both `"features": "...,+soft-float"` and `"rustc-abi": "softfloat"`, or
  `core`/`compiler_builtins` fail to build.
- `panic-strategy: "abort"` is the only supported strategy — hence `-Z panic-abort-tests` in
  `.cargo/config.toml` (otherwise Cargo builds an unwind-based test harness and produces a second,
  ABI-incompatible `core`).
- SSE/MMX disabled, `disable-redzone: true` (interrupt handlers can't safely use either).

## Boot: Limine (`sys/boot/mod.rs`, `x86_64-oxidebsd.ld`, `scripts/qemu_runner.sh`, `external/bsd/limine`)

Migrated off the `bootloader` v0.9 crate (BIOS-only, unmaintained) to the Limine boot protocol
2026-09-09/10 — real UEFI boot capability, needed for the eventual real-hardware (Surface) target
(see "USB input" below).

- `sys/boot/mod.rs` (renamed from `sys/boot.rs` when the Multiboot2 boot path below was added)
  declares the Limine request statics (`HhdmRequest`/`MemmapRequest`/
  `FramebufferRequest`/`RsdpRequest`/`ExecutableCmdlineRequest`) Limine scans for at load time,
  plus a `BootInfo` shim (`physical_memory_offset`/`memory_map` — same field names as the old
  `bootloader::BootInfo`, so every existing call site across `sys/main.rs`/`sys/lib.rs`/
  `tests/*.rs` keeps working unchanged; Limine's HHDM offset and memory map are direct analogs of
  the old crate's two fields) and a `limine_entry_point!` macro replacing `entry_point!`.
- **Higher-half kernel placement**: `x86_64-oxidebsd.ld` links the kernel into the top of the
  address space now, not identity-mapped low memory — this is *why* `module::MODULE_VA_BASE`
  moved into the top 2 GiB (see "Dynamic kernel modules" below) and needed a matching
  `-C code-model=kernel` rustflag.
- **No more direct `0xb8000` VGA text-mode access** — Limine doesn't guarantee that mapping.
  `sys/console/framebuffer.rs` is a from-scratch real framebuffer console (dynamic grid sizing off
  Limine's own reported resolution, a hand-rolled 16x8 glyph font) replacing it; `sys/console/
  vga.rs`'s VT100/ANSI layer now writes through the framebuffer console instead.
- **PIC/LAPIC interrupt routing needed real fixes** — Limine's own interrupt setup differs from
  `bootloader` v0.9's: LAPIC disable + IMCR + explicit IRQ unmask, done explicitly at boot rather
  than relying on firmware/bootloader state left over from `bootloader` v0.9.
- **`scripts/qemu_runner.sh`** replaces `bootimage runner` as `.cargo/config.toml`'s `runner`:
  stages a hybrid BIOS+UEFI ISO from `target/limine-stage/` (populated by `build.rs`'s
  `build_limine_deploy_tool`) plus the just-built kernel/test ELF, boots it under QEMU (UEFI/OVMF
  by default, `OXIDEBSD_FIRMWARE=bios` for the legacy path), and for a test binary translates the
  real `isa-debug-exit` code into this script's own pass/fail exit status. See "Real disk
  persistence" below for how the real ATA disk and the boot ISO share IDE channels without
  colliding.
- **Real-hardware safety gate**: a `no-ata` kernel cmdline token (`oxidebsd::boot::ata_disabled()`)
  skips the real ATA disk probe entirely — oxfs's mount-or-format logic will genuinely *format*
  whatever disk it finds on the legacy IDE ports, so this is off by default (QEMU dev/test workflow
  relies on the real ATA-backed disk) and on whenever `OXIDEBSD_REAL_HARDWARE=1 cargo run` is used.
- **Two real regressions found the same migration session, both from one root gap** in `build.rs`:
  cargo silently inherits a build script's own `CARGO_ENCODED_RUSTFLAGS` (higher-priority than a
  plain `.env("RUSTFLAGS", ...)` override) into any `Command` it spawns — the kernel's own new
  `-T x86_64-oxidebsd.ld` linker flag was leaking into every nested userland/module `cargo`
  invocation, silently overriding their own linker scripts. Broke every userland crate's entry
  point (`ENTRY(_start)`, produced ELFs with entry `0x0`/zero program headers) until fixed with
  `.env_remove("CARGO_ENCODED_RUSTFLAGS")` in both `build_userland_crate` and
  `build_module_crate` — which in turn let `-C relocation-model=static` start genuinely applying
  to module builds for the first time, surfacing the `code-model=kernel` gap noted under "Dynamic
  kernel modules" below. **Any future rustflags addition to the top-level target should be
  checked against this same leak path** before assuming a nested `cargo` invocation's own
  `.env("RUSTFLAGS", ...)` override actually took effect.
- Verified via all 51 `tests/*.rs` files migrated and passing, confirmed on both `OXIDEBSD_FIRMWARE`
  values.

## Boot: Multiboot2 (`sys/boot/multiboot2.rs`, `x86_64-oxidebsd-multiboot2.ld`, `regress/multiboot2-boot-smoke/`, `regress/multiboot2-kernel/`, `scripts/qemu_common.sh`, `scripts/run_multiboot2_smoke.sh`, `scripts/run_multiboot2_kernel.sh`)

A second, independent boot path alongside Limine — real GRUB or Limine's own `protocol:
multiboot2` can load this kernel directly. Gated behind a `multiboot2` Cargo feature; one
dedicated smoke test (`tests/multiboot2_boot_smoke.rs`, structurally identical to `basic_boot.rs`
via a `multiboot2_entry_point!` macro mirroring `limine_entry_point!`) lives in its own workspace
member (`regress/multiboot2-boot-smoke/`) purely so it can get its own linker script under an
otherwise-shared-rustflags workspace.

- A real, hand-written 32-bit-protected-mode → 64-bit-long-mode trampoline (`global_asm!`, Intel
  syntax): builds temporary page tables (a fixed 64 MiB low-identity window + a kernel-higher-half
  window sized *dynamically* from linker-provided `_kernel_phys_start`/`_kernel_phys_end` — this
  kernel's own embedded content already makes `.rodata` alone >100 MiB, so a hardcoded page count
  would go stale exactly like the userland-load-base floor already has), enables PAE/LME/paging,
  hands off to Rust (`init_from_mbi`: parses the real Multiboot2 memory map into the same
  `limine::memmap::Entry` shape the frame allocator consumes, builds final page tables including a
  fresh 8 GiB HHDM window at `MULTIBOOT2_HHDM_OFFSET`, returns a `&'static BootInfo`).
- **Real bug**: the smoke crate depends on the `oxidebsd` lib itself (unlike every other
  `build_*_crate` helper in `build.rs`), so an unconditional call to build it from `oxidebsd`'s own
  build script recurses forever. `CARGO_PRIMARY_PACKAGE` looks like the fix but isn't — Cargo sets
  it only while *compiling* a package, not while running its already-built build-script binary.
  Fixed with an explicit `OXIDEBSD_BUILDING_MULTIBOOT2_SMOKE` reentrancy-guard env var instead.
- **Two real bugs found on the first real boot, both silent triple faults** (no IDT exists this
  early in boot): (1) the final page tables dropped Stage A's own low-identity window, exactly
  where the still-active call stack (`boot32_stack`) lives — `Cr3::write` unmapped the stack out
  from under itself; fixed by keeping that window mapped permanently instead. (2) entering Rust via
  `jmp` instead of `call` left `RSP` at the wrong System V ABI parity (`%16==0`, not `8`) —
  harmless until the first alignment-sensitive instruction, `cpu::fpu::init`'s `fxsave`; fixed with
  a `sub rsp, 8`.
- `scripts/qemu_common.sh`: the loader-agnostic parts of driving QEMU (firmware/OVMF selection, the
  fixed IDE topology, isa-debug-exit wedge-guard/exit-code translation), shared by `qemu_runner.sh`
  and `scripts/run_multiboot2_smoke.sh` (`OXIDEBSD_MULTIBOOT2_LOADER=limine|grub`, default limine).
- Verified booting clean via both Limine's own multiboot2 protocol and real GRUB (BIOS). **GRUB
  under UEFI/OVMF crashes inside GRUB/firmware itself, before ever reaching this kernel's own
  code** — root-caused by disassembling GRUB's own compiled `multiboot2.mod`/`relocator.mod`
  (real evidence, not a guess): GRUB's classic-entry boot dispatch always uses its own
  `grub_relocator32_boot`, which has a genuine internal bug downgrading itself from UEFI's 64-bit
  long mode back to 32-bit protected mode (confirmed via a fully isolated repro — a trivial,
  unrelated hand-assembled kernel crashes identically through the same GRUB+OVMF+QEMU pipeline).
  Two more header tags fixed the *dispatch*, confirmed by the crash address changing: a bare
  `MULTIBOOT_HEADER_TAG_EFI_BS` (type 7, optional) tells GRUB not to call `ExitBootServices()`
  first, which is what its dispatch checks (`grub_efi_is_finished`) to choose the native
  `grub_relocator64_efi_boot` over the buggy downgrade. Past that, a **third, deeper issue
  remains, outside this kernel's reach**: `grub_relocator64_efi_boot` itself page-faults writing
  to one of its own global variables (confirmed via QEMU's gdbstub — a correctly-relocated
  address, but the page is mapped read-only). **Confirmed via web search to be a known, already-
  diagnosed upstream GRUB 2.14 regression** (our exact installed version, released 2026-01-14),
  not an OVMF quirk: commit `d72208423dca` ("kern/dl: Use correct segment in
  `grub_dl_set_mem_attrs()`") made GRUB correctly mark loaded modules' `.text` read-only per real
  ELF section flags, but the x86 relocator's own stubs are patched *in place at runtime* and GNU
  `as` always emits plain `.text` as `"ax"` (no write flag) — so the runtime patch now faults. A
  fix (moves those stubs into a new `.text.relocator` section flagged `"awx"`) was submitted
  upstream 2026-05-13 ("relocator/x86: fix multiboot2 Xen boot failure on GRUB 2.14"); merge
  status into a release build unconfirmed as of this writing. `OXIDEBSD_FIRMWARE=bios` with the
  grub loader remains the reliable path until a fixed GRUB lands.
- **`regress/multiboot2-kernel/`**: a second, separate entry crate booting the *real* kernel (module
  loading, `hush` spawn, scheduler handoff — `oxidebsd::kernel_main::run_real_system`, shared
  verbatim with `sys/main.rs`'s own Limine path) via Multiboot2, not just the trampoline-only smoke
  test above. Needs its own crate rather than reusing `sys/main.rs` directly (the smoke test's own
  trick): every embedded module/`hush` ELF's `include_bytes!(env!("..._PATH"))` needs a
  `rustc-env` var only visible while compiling the package that set it, never a downstream
  dependent — confirmed directly, not assumed. `scripts/run_multiboot2_kernel.sh` builds and boots
  it interactively; needs `RUSTFLAGS` to fully override (not merely append to) the plain kernel's
  own config-resolved `-Tx86_64-oxidebsd.ld`, same reasoning as `build_multiboot2_boot_smoke_crate`.
- **A real, previously-latent frame-allocator bug, only surfaced by a kernel this large**: a
  Multiboot2 memory map (unlike Limine's own) has no concept of "where the loader put the kernel" —
  left unfixed, `BootInfoFrameAllocator` treated this kernel's own ~266 MiB debug image as free
  memory and started handing out frames that alias its own live code/page-tables, hanging silently
  right after the heap-mapping log line (no panic — consistent with corrupting currently-executing
  state, not a caught fault). The tiny `multiboot2-boot-smoke` test never allocates enough to hit
  it. Fixed: `exclude_kernel_range` carves `[0x100000, _kernel_phys_end)` out of any `MEMMAP_USABLE`
  entry before it reaches the frame allocator, splitting an entry if the exclusion falls strictly
  inside it.
- **Real UEFI can't load this real kernel via Multiboot2 at all, separately from the GRUB/UEFI bug
  above**: Multiboot2's fixed-physical-address placement (no relocation, unlike Limine's native
  protocol) needs one contiguous free hole the image's full size — confirmed live, Limine's own
  multiboot2 loader panics `"Could not find viable load address for executable"` under OVMF for
  this real ~266 MiB image (the small smoke-test image never hit this either). Real BIOS/SeaBIOS's
  much simpler, unfragmented memory map has no such hole shortage. `scripts/run_multiboot2_kernel.sh`
  therefore defaults to `OXIDEBSD_FIRMWARE=bios` itself (unlike every other script here, which
  defaults to `uefi`) — this is now the *only* known-working firmware choice for either loader with
  the real, full-size kernel.
- **`exclude_kernel_range`'s own alignment bug, found chasing a real, reproducible page fault**:
  `_kernel_phys_end` isn't page-aligned, but the exclusion used it as-is — `BootInfoFrameAllocator`'s
  `region.base / 4096` truncates *down*, so the first frame handed out after exclusion still
  overlapped the kernel's own `.bss` (specifically `MMAP_PTRS` itself, right at the tail of the
  image) by however many bytes `_kernel_phys_end` overshot its own page boundary. The first
  consumer to receive that frame corrupted a `&'static Entry` pointer read back later, producing a
  fault at a garbage address inside `BootInfoFrameAllocator::allocate_frame` — root-caused via
  `addr2line` against the real faulting `RIP`, not guessed. Fixed: round the exclusion's own end up
  to the next page boundary.
- **`boot32_stack` (the Stage A trampoline's own stack, never replaced by a real per-process kernel
  stack this early in boot) was only 64 KiB, sized for `multiboot2-boot-smoke`'s tiny workload,
  never revisited once `multiboot2-kernel` (module loading + oxfs's real mount-or-format pass)
  started using the same trampoline**. Silently overflowed (no guard page) into the corrupted-frame
  bug above with no evidence beyond a shifted stack pointer. Bumped to 1 MiB.
- **Real Multiboot2 framebuffer support**: added the header's own framebuffer *request* tag (type
  5) plus parsing of the loader's *info* tag (type 8) it produces in response — without either,
  `console::framebuffer` has nothing to find and the screen stays black, confirmed live (a real
  boot reached a working `hush` prompt, serial-log-confirmed, with a genuinely blank display).
  `boot::FbInfo` is a new boot-path-agnostic descriptor `console::framebuffer`/`drivers::fbdev` now
  consume instead of `limine::framebuffer::Framebuffer` directly, so the same rasterizer/`/dev/fb0`
  code serves either boot path. **A real off-by-one-byte bug in the info tag's own layout**: its
  `reserved` field (right after `framebuffer_type`) is a `u16`, not a `u8` — every color-info field
  read one byte too early, producing plausible-looking but wrong red/green/blue mask values (e.g.
  `red_size=16`, an impossible width for one channel) that rendered the whole text console in the
  wrong color (blue instead of white) while doom's own direct pixel writes — a separate path,
  bypassing this tag entirely — stayed correct throughout, which is what made it look
  doom-specific at first. Root-caused by printing the parsed values and back-solving what a
  one-byte shift would produce (a clean, standard XRGB8888 layout), not by guessing at the fix.
  Also required exposing a `boot::set_hhdm_offset` setter: `boot::hhdm_offset()` (used by
  `drivers::fbdev` to recover the framebuffer's real physical address) was populated only by
  Limine's own `read_boot_info`, panicking the instant anything called it under multiboot2.
  Confirmed end to end: a real, playable doom frame captured via QEMU's own `screendump`.

## Memory management (`sys/memory/mod.rs`, `sys/memory/allocator.rs`)

- `memory::init` walks `CR3` and adds `BootInfo::physical_memory_offset` to get a virtual pointer
  to the level-4 table. Call at most once — hands out a `&'static mut`.
- `memory::BootInfoFrameAllocator` bump-allocates from `BootInfo::memory_map`'s `Usable` regions.
  Holds plain `(region_index, frame_number)` cursor state, not a rebuilt-each-call iterator (the
  old approach was O(n²)). **A boxed-iterator "fix" is wrong, not just suboptimal**: this
  allocator is constructed *before* `allocator::init_heap` (which needs it to map the heap's own
  pages), so any heap allocation inside its own constructor panics with no heap yet to satisfy it.
  Gained a real `FrameDeallocator` impl later (an intrusive, singly-linked free list stored *in*
  the freed frames themselves — safe pre-heap-init by construction, unlike a `Vec`) — see "Real
  threading"'s memory-reclaim notes below.
- `allocator::init_heap` and `module::map_region` map freshly allocated pages with `.ignore()`,
  not `.flush()` — a never-before-mapped page has no stale TLB entry, and `invlpg` is individually
  trapped under QEMU's software TCG.
- The heap lives at a fixed VA (`allocator::HEAP_START`); size scales with detected RAM
  (`memory::usable_ram_bytes()`), clamped floor/ceiling (currently `1024` MiB ceiling, QEMU RAM
  `8192` MiB). Same RAM-scaling pattern for `process::kernel_stack_size()`/`user_stack_pages()`.
  NOT scaled: `module::MODULE_VA_BASE`/`MODULE_REGION_CEILING` (a VA-range limit from the
  relocation model, not RAM).
- Global allocator is `linked_list_allocator`'s `Heap` wrapped in a local `Locked<T>`
  (`spin::Mutex`), not the crate's own `LockedHeap` — avoids a second spinlock crate in the graph.

## User-mode execution (`sys/memory/address_space.rs`, `sys/process/elf.rs`, `sys/process/usermode.rs`)

`process::spawn` builds the first process this way at boot; `process::do_execve` builds every
later one the same way, mid-syscall.

- Regression-test crates (`regress/*`) are separate workspace members; `build.rs`'s
  `build_userland_crate` (kept its name -- see that function's own doc comment) cross-builds each
  into `target/userland/` and exposes `<NAME>_ELF_PATH`
  via `cargo:rustc-env` for `include_bytes!`. Each crate's `linker.ld` forces a distinct load base
  clear of the kernel image, heap, phys-mem-offset window, and identity-mapped low-memory region.
  **This floor moves as the kernel image grows** — surfaces as `Elf(MappingFailed)`/
  `PageAlreadyMapped` at `execve`/spawn time, not build time. **Before adding a new binary or
  trusting the current floor**, re-derive it: `readelf -l target/x86_64-oxidebsd/debug/oxidebsd |
  grep -A1 LOAD`, take highest `VirtAddr + MemSiz`, round up with real headroom — this exact class
  of bug ("embedded corpus/kernel image grew past the fixed load-base floor") has hit multiple
  times as the kernel and the POSIX test corpus grew. `regress/musl-smoke/` isn't a Rust crate —
  built with `musl-gcc`, load base via `-Wl,-Ttext-segment=`.
- `AddressSpace::new` shallow-copies all 512 L4 entries from the currently active table — safe
  only when the active table's user-space content is empty (true only for boot spawn).
  `AddressSpace::fork`/`new_excluding_user` (live process) instead recursively walk the table
  using `USER_ACCESSIBLE` as the sole kernel-vs-user signal at any level. `AddressSpace` is now
  `Arc`-refcounted (`teardown` gated on `strong_count == 1`) — see "Real threading" below.
- **`gdt.rs`'s ring-0 stacks must be `static mut`, not `static`.** A plain `static`, never written
  via a Rust `&mut`, gets interned into `.rodata` by the optimizer — causes a double/triple fault
  the instant an exception uses it. Any future stack added the same way needs the same treatment.
- **Every IDT gate a software interrupt (`int n`, `int3`, ...) can trigger from ring 3 needs
  `DPL = Ring3` explicitly** — gates default to `Ring0`. Wrong DPL manifests as a `#GP` on the IDT
  entry itself.
- **`elf::load` tracks already-mapped pages in a `BTreeMap<Page, PhysFrame>` for one call** —
  `PT_LOAD` segments align to `p_align`, not to each other, so small binaries routinely share a
  page across segments. Flags aren't unioned across segments sharing a page — found live via a
  small RW segment sharing a page with an RX segment, keeping only the RX flags (first static
  write page-faulted). Worked around at the linker-script level for that one crate, not fixed in
  `elf.rs` generally — a real flag-union fix would help every future small binary with writable
  globals.
- Known simplification: no `NO_EXECUTE` on any ELF segment (would also need `EFER.NXE`).

## Syscall ABI (`sys/syscall/`)

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
`SYS_MKNOD=489`, `SYS_CHROOT=490`, `SYS_GETRUSAGE=491`, `SYS_MPROTECT=492`, `SYS_SIGTIMEDWAIT=495`,
`SYS_SIGQUEUE=496`, `SYS_SCHED_SETPARAM=507`, the pre-reserved `526`-`553` POSIX/SysV batch (see
that section), `SYS_FAULT_PUMP=554`, `SYS_CLONE=555`, `SYS_EXIT_GROUP=556`,
`SYS_FUTEX_REQUEUE=557`; plus real Linux numbers reused directly where confirmed dead in this musl
fork (`fchmod=91`, `sched_getaffinity=204`, `futex=202`). **Check `sys/syscall/` and module
sources for the current highest number before assigning a new one.**

**Before picking a new syscall number**: grep every still-inert real-Linux value in
`external/mit/musl/arch/x86_64/bits/syscall.h.in` for a live musl caller before reusing it — bit
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
deliberately deferred — discuss scope before a sweeping renumbering): `sys/net/udp.rs`'s
`ENOTSOCK=38` (musl: `88`), `EDESTADDRREQ=39` (musl: `89`), `EADDRINUSE=48` (musl: `98`),
`EHOSTUNREACH=65` (musl: `113`); `sys/net/tcp.rs`'s
`EISCONN`/`ENOTCONN`/`ECONNREFUSED`/`ETIMEDOUT`/`EOPNOTSUPP`/`EADDRINUSE`/`EHOSTUNREACH`.

The number→handler mapping is a runtime registry (`SYSCALL_TABLE`, `Mutex<BTreeMap>`) populated by
`oxidebsd_register_syscall` from each module's `module_init` — not a hardcoded `match`. An
unregistered number logs `[boot] unrecognized syscall number N` and returns `ENOSYS`, the main
tool for discovering what a ported program's startup still needs.

- **`SYSRETQ`'s selector scheme forces GDT order.** `SYSRETQ` derives `SS`/`CS` from
  `IA32_STAR[63:48]` as `+8`/`+16` — user data must sit immediately before user code. `sys/cpu/
  gdt.rs` order: kernel code, kernel data, unused placeholder, user data, user code, TSS. Don't
  reorder without redoing the `STAR` arithmetic; `Star::write` panics loudly if the GDT regresses.
- **No automatic stack switch on `SYSCALL` entry.** Control arrives at `syscall_entry` still on
  the user's own stack. `gdt::CURRENT_RSP0` (`static mut`, kept in sync by
  `gdt::set_kernel_stack` on every context switch) always names the current process's own kernel
  stack — required since two processes can be mid-syscall at once. No per-CPU `swapgs` —
  single-core only.
- `SyscallFrame`: the stub's pushed GPRs plus `user_rsp`. `rcx`/`r11` double as saved `RIP`/
  `RFLAGS`; `syscall_dispatch` flips bit 0 of `r11` to signal `CF`. **`SYSRETQ` couples `RIP` to
  the value in `RCX` at the instant it executes** — any code path that redirects execution
  asynchronously (the fault/timer trampoline redirect, see "Real ring-3 fault-to-signal delivery"
  below) must restore real `RCX`/`R11` through a dedicated two-stage restore-stub trampoline, not
  a plain register clobber, or it silently corrupts the interrupted process's own live computation
  on resume.
- `dispatch()` is a small, pure, directly unit-tested function separate from
  `syscall_dispatch`'s raw-pointer/frame handling.
- A registered handler's own wire format (`SyscallHandler`) is a plain `i64` (negative = `-errno`)
  — distinct from the public carry-flag ABI, just the module↔kernel boundary's shape.
- `sys_write`/`sys_read` don't validate `[ptr, ptr+len)` before dereferencing — a bad pointer
  page-faults (handled safely: log + reboot for ring-0, real signal delivery for ring-3 — see
  "Real ring-3 fault-to-signal delivery" below), not a soundness hole.
- `sys_read` delegates every fd, including 0/stdin, to `crate::fd`'s per-process `(Pid, fd)`
  registry — stdin's own registered callback is a **real, genuine blocking read** (`console::
  stdin::read`, see "Interactive shell" below), not a return-`0`-immediately one; corrected here
  2026-09-22 after a real, previously-undiscovered input-hang investigation (see the ncurses/nano/
  nvi section) found this file's own earlier claim to the contrary was stale.
- `sys_write`'s `fd == 2` (stderr) is an alias for `fd == 1` — no real second sink exists.

## musl port (`external/mit/musl`, `regress/musl-smoke/`, `sys/process/user_stack.rs`, `sys/cpu/fpu.rs`)

musl is patched (not the kernel made Linux-compatible) to speak this native ABI directly.
`external/mit/musl` is a submodule of a personal fork (`ifduyue/musl`), patches on its own
`oxidebsd` branch based on tag `v1.2.6`. Pin/update by committing on that branch, pushing, then
`git add external/mit/musl` here. Patch surface is deliberately small, entirely under
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
- SSE was never enabled at the hardware level; `sys/cpu/fpu.rs::init()` enables it once at boot.
  Real per-process `FXSAVE`/`FXRSTOR` across every context switch exists (`Process::fpu_state`) —
  became load-bearing once ring-3 preemption landed (see "Real preemptive scheduling").
- `sys/process/user_stack.rs` builds a real System V argc/argv/envp/auxv stack. `AT_PHDR` derived
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
  flags)`. Kernel side gained real mtime/ctime tracking (`oxidebsd_unix_time`) later, and
  `oxfs_utimensat` now genuinely sets atime/mtime (null `times` = now; `UTIME_NOW`/`UTIME_OMIT`;
  `EINVAL` on bad `tv_nsec`; explicit times need owner-or-root, "now" also allows write access).
- `SYS_MMAP=100` is `(addr_hint, len, prot)` originally, later gained real `flags` (packed into
  `prot`'s unused high bits) and real `MAP_FIXED`/`MAP_PRIVATE` handling. `SYS_BRK=102`
  grows/shrinks `Process.brk`, no reclaim on shrink.
- **A real, previously-undiscovered bug in this project's own musl fork**: real, unmodified
  `fork()` takes a `LOCK()` on internal locks (including stdio's `ofl_lock`) in the parent
  whenever the process is genuinely multi-threaded — but `_Fork.c`'s own `reset_stdio_locks_in_child`
  (an earlier fix for a *different* hang, `fork/11-1.c`) unconditionally re-locks `ofl_lock` to
  walk the open-`FILE` list, self-deadlocking since the child inherits it already locked. Only
  reproduces with 2+ real contending forked children *and* a live second thread at fork time.
  Fixed on the `oxidebsd` musl branch: reset the lock to unlocked in the child unconditionally,
  matching how every other atfork lock is already treated (a freshly forked child is always the
  sole surviving thread, so any inherited "locked" state is never real contention).
- **Two more real, independent stock-musl bugs behind `fork/11-1.c`'s original hang**: (1)
  `__post_Fork` never reset any `FILE`'s own `.lock` word in the child, so a `flockfile(stdout)`
  held by the parent left a "ghost" tid the child could never clear (real glibc avoids this via
  `pthread_atfork`; stock musl has none) — fixed by resetting every known `FILE`'s lock in the
  child branch. (2) Once that let the child lock `stdout`, a thread exiting without
  `funlockfile()` (legal per POSIX) hit `__do_orphaned_stdio_locks()`, which marked the lock with
  a poison bit instead of releasing it — fixed to do a real release-and-wake.
- **`sigset(sig, SIG_HOLD)`** had a real stock-musl bug (returned current disposition instead of
  `SIG_HOLD` on first call) — fixed on the `oxidebsd` branch.
- **`PTHREAD_STACK_MIN`** was `2048`, too small for a real page-size multiple — bumped to `65536`
  (plus a `sysconf.c` `short`→`int` table widening it needed to take effect).
- **`pthread_detach()` on an already-`PTHREAD_CREATE_DETACHED` thread** used to unconditionally
  fall back to `__pthread_join()`'s own `a_crash()` instead of returning `EINVAL` — fixed on the
  `oxidebsd` branch (this specific case is memory-safe to detect directly, target is always
  `pthread_self()`).
- **A real, permanent, accepted class of musl 1.2.6 bug, not OxideBSD's**: several real conformance
  files (`pthread_join`/`_detach`/`_cancel`/`_kill`/`_create`/`_key_create`/`_getcpuclockid` on a
  stale tid) crash on a real use-after-free reading a freed TCB — confirmed via direct
  reproduction against the host's own unmodified musl 1.2.6, not an OxideBSD bug, not fixable
  without a much bigger design change. Left as accepted `CRASH` results.

## BusyBox port (`external/gpl2/busybox`, `sys/modules/posix_compat/`)

256 applets run today (24 original + 232 from a second-pass roster), each its own standalone
single-applet static binary. Vendored as a submodule (fork of `mirror/busybox`, tag `1_36_1`,
`oxidebsd` branch — same pin/update procedure as musl). `build.rs`'s `build_busybox_applet` runs
`allnoconfig` → flip one applet's Kconfig symbol → `oldconfig` → build, asserting
`NUM_APPLETS == 1`; `sh` additionally forces on `CONFIG_HUSH_INTERACTIVE`/`HUSH_JOB`/
`FEATURE_EDITING` and hush's control-flow symbols directly (`allnoconfig` writes an explicit
"not set" before `oldconfig` ever sees hush's own `default y`). Applets are embedded into oxfs's
inode table by `sys/modules/oxfs`'s `module_init` (data-driven from `build.rs`'s applet lists; each
new applet needs one manual `seed_file` call). Roster grew 24 → 290 (287 from an exhaustive
per-applet build probe — **"builds" is a much weaker bar than "works"**), then curated down to 232
(256 total) before v0.1 by dropping 58 applets structurally incapable of working under this
kernel's architecture (see `OxideBSD-doc/BUSYBOX_APPLETS.md`'s "Removed before v0.1"; a few later
unblocked — `chroot`/`mknod`/`link` — were fixed forward instead). `OxideBSD-doc/BUSYBOX_APPLETS.md` is the
full roster with per-applet needs (`NEEDS_NETWORK`/`NEEDS_PROC`/`NEEDS_CLOCK`/`NEEDS_UID`/`WORKS`).
`sys/modules/oxfs/src/test_busybox.sh` (seeded at `/test_busybox.sh`) is ~95 real applet/control-flow
checks with a `PASS`/`FAIL` tally — the tool that found several bugs below.

- `build_busybox_applet` is staleness-checked against `external/gpl2/busybox`/`build.rs`/
  `musl_sysroot`'s `lib/libc.a` mtimes, builds in parallel. **Two real staleness bugs found**: (1)
  `libc.a`'s mtime wasn't originally compared, so a musl fix left applets linked against stale
  libc. (2) BusyBox's incremental build never tracks musl's *installed sysroot headers* as a
  dependency — a musl header fix left most object files unrecompiled despite fresh binary mtimes.
  **Only a full `rm -rf` of the stale `O=` out-of-tree build dir reliably fixes this** — trust
  neither BusyBox's incremental tracking nor mtime alone. Expensive (~38 min full rebuild), only
  triggers when something genuinely changed. **`ccache` is wired into both this build and the
  POSIX pilot's own per-file compile loop** (~79% hit rate confirmed live) — falls back cleanly
  when not installed.
- `hush` (pid 1) uses real `execvp()`/`$PATH` (`PATH=/bin` in envp). `sys/modules/oxfs` seeds every
  applet under its bare name in `/bin`.
- New kernel-resident pieces `sh` required: real 4th syscall arg (`R10`, envp), real blocking
  `pipe(2)`/`dup2(2)` (`sys/fs/pipe.rs`, `PIPE_CAPACITY=64` KiB, blocks via `BlockReason::
  WaitingForPipeData`/`WaitingForPipeSpace`), and a **per-process** `(Pid, fd)` fd table
  (`sys/fs/fd.rs`) — a flat table broke real pipelines when a parent closed its own copy of a pipe
  fd out from under still-using children.
- **Fixed: a producer whose `write()` never blocks used to OOM the kernel heap.** `yes | head -n
  3` reliably panicked — `sys/fs/pipe.rs`'s buffer used to be an unbounded `VecDeque<u8>`, and
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
  fixed centrally in `sys/fs/fd.rs`'s `read`/`write` funnel functions.
- New syscalls always go in a dedicated module (`sys/modules/posix_compat/`, `sys/modules/signal/`, ...),
  not `sys/modules/native_abi/` — keeps the core ABI module small.
- **83 more candidate applets didn't even build**: 54 need real Linux kernel uapi headers musl
  doesn't vendor, 25 need a companion Kconfig option a single-symbol flip didn't resolve, 3 were
  docs/example files mismatched by candidate-extraction, 1 (`lzopcat`) is a genuine link error.

## Interactive shell (`sys/console/stdin.rs`)

`stsh` ("stupidshell"), the original hand-written interactive userland program, was pid 1 before
BusyBox's `hush` superseded it, and has since been removed entirely (v0.2.0 cleanup — see git
history for its design if ever needed again). Its influence remains in how stdin works:

- Keyboard IRQ (`sys/cpu/interrupts.rs`) decodes scancodes into a fixed 256-byte ring buffer
  (`sys/console/stdin.rs`) — non-ASCII dropped, no allocation in the interrupt handler. `sys_read`
  drains it. Auto-echo only when `TERMIOS.ECHO` is set.
- The `spin::Mutex` around the ring buffer can't deadlock between IRQ and syscall context
  specifically because `SFMASK` clears `IF` for a `SYSCALL`'s entire duration on this single core
  — breaks if SMP is ever added.
- `sys_read` on stdin is a real, genuine blocking read (`console::stdin::read` — `ProcState::
  Blocked(BlockReason::WaitingForStdin)` + `scheduler::schedule()`, woken by the keyboard IRQ
  handler's own `push_byte`/`wake_blocked_readers`); `hush` reads one byte at a time in its own
  line-editing loop, same shape `stsh` used, but each individual read genuinely blocks rather than
  busy-polling. (This file used to claim `sys_read` was non-blocking — stale, corrected
  2026-09-22, see the ncurses/nano/nvi section's own real input-hang writeup for how that surfaced.)
- `sys/console/vga.rs`'s `Writer` is a true 2D-addressable console with a minimal ANSI/VT100 CSI
  escape parser so full-screen applets (`vi`, `clear`, `reset`) render correctly.
- Real `SYS_IOCTL=124` (`sys/console/stdin.rs`'s `RawTermios`, a single **global**, not
  per-session, `TERMIOS`) implements `TCGETS`/`TCSETS*`/`TIOCGWINSZ` (the console's real grid)/`TIOCSWINSZ`;
  else `ENOTTY`. Only succeeds against the real console — load-bearing for `isatty()`.
- No pty/foreground-process-group layer at this file's level — `tcsetpgrp`/`bg`/`fg` are driven
  entirely by the real session/controlling-tty model at the process level (see "Session,
  controlling-tty..." and "Real job control" below); this file's only involvement is the
  Ctrl+C/Ctrl+Z keyboard intercepts in `interrupts::keyboard_interrupt_handler`.
- **`DEFAULT_TERMIOS.c_cc` (the fallback `TCGETS` returns before any `TCSETS`) must hold real
  POSIX/Linux default control-character values, not all-zero.** Real BusyBox `libbb/lineedit.c`
  clears `ISIG` when it takes over line editing and implements Ctrl+C/Ctrl+D itself by comparing
  each byte against `initial_settings.c_cc[VINTR]`/`c_cc[VEOF]`, guarded by `!= 0`. An all-zero
  default silently read as "disabled," so Ctrl+C/Ctrl+D did nothing once `hush`'s line editor took
  over (effectively always, interactively) — a real, pre-existing bug affecting plain PS/2 too,
  not USB-specific, found via scripted `OXIDEBSD_QEMU_MONITOR` keystroke testing. Fixed:
  `DEFAULT_TERMIOS.c_cc` now holds real values (`VINTR=^C`/`VEOF=^D`/etc., matching musl's
  `arch/generic/bits/termios.h` index layout). Confirmed live: Ctrl+C during a `sleep 100` now
  returns immediately with a fresh prompt; Ctrl+D at an empty prompt cleanly ends the session.

## Process abstraction, scheduler, and fork/exec/wait (`sys/process/`)

Dynamically allocated process table, scheduler (cooperative round-robin + real ring-3 preemption,
see "Real preemptive scheduling"), kernel-thread-style context switch between per-process kernel
stacks. No copy-on-write fork (full eager copy), no SMP. **`Process` is no longer strictly one
schedulable entity per real process** — real `clone(2)`/`pthread_create` threads sharing one
address space also exist (`Process::tgid`, `ThreadGroupShared`, a per-thread-group `Arc<Mutex<>>`
bundle covering `cwd`/`root_inode`/`umask`/`uid`/`gid`/`brk`/`mmap_file_regions`/`sigactions`) —
see "Real threading" for the full design.

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
  `sched_priority`/`umask` copied, preserved; `root_inode` copied, untouched. Itimer state resets
  on `fork`, preserved by `execve` (the one exception).
- Kernel stack size floor is `128` KiB — found empirically. No guard page — overflow corrupts
  silently.
- **`do_wait4`'s reported status is real `wait(2)`-encoded — normal exit shifts into bits 8-15**
  (`WEXITSTATUS`). Signal-based termination passes a pre-encoded `128 + sig` directly, must
  **not** be shifted. Real `WUNTRACED`/`WCONTINUED`/`WNOHANG`; `WIFSTOPPED` writes
  `0x7f | (stopsig << 8)`, `WIFCONTINUED` writes `0xffff`.
- **`kill(pid, 0)`** does a real existence-only check (self or cross-process; a zombie still
  counts until reaped), bypassing the pending-signal bitmask.
- **Real orphan reparenting**: a process's still-living children are reparented to pid 1
  (`Process::adopted`, `process::lifecycle::reparent_orphans`/`INIT_PID`) on exit, matching real
  Unix; an adopted orphan's own later exit is treated like `SA_NOCLDWAIT` (immediate detach, since
  pid 1 here has no generic "reap anything adopted" loop).
- **Real per-process `times(2)`** (`Process::cpu_ticks`/`child_cpu_ticks`, folded in transitively
  by `do_wait4` at reap time) — `tms_utime`/`tms_cutime` real, `tms_stime`/`tms_cstime` honest
  zero (no user/kernel CPU-time split tracked). `getrusage(2)`'s `ru_utime`/`ru_stime` have the
  same latent staleness, not yet fixed.
- `tests/fork_wait.rs` + `regress/fork-exec-smoke/` covers fork/wait4/exit.
  `sys/modules/oxfs/src/test_busybox.sh` is real, broader, hand-run coverage.

## Dynamic kernel modules (`sys/module.rs`, `sys/modules/*`)

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
- `RUSTFLAGS="-C relocation-model=static -C code-model=kernel"` keeps relocations to absolute
  32-bit forms — every module maps inside the top-2GiB kernel region (`MODULE_VA_BASE=
  0xffff_ffff_a000_0000`, `MODULE_REGION_CEILING=0xffff_ffff_ff00_0000` — moved here from the low
  2 GiB during the Limine migration's higher-half kernel placement, see "Boot: Limine" below).
  **The kernel image must end below `MODULE_VA_BASE`** (512 MiB from `0xffff_ffff_8000_0000`) —
  the debug image crossing the old `0x9000_0000` base surfaced as `MappingFailed` on the first
  module load; check `readelf -lW` when embedding more. `oxidebsd_module_alloc_zeroed` pools
  (oxfs's ~1.25 GiB) live in a separate window, `MODULE_DATA_BASE=0xffff_c000_0000_0000` (64 GiB,
  L4 slot 384) — pointer-reached, so no `±2 GiB` constraint.
  `code-model=kernel` is required alongside `relocation-model=static` at this placement — LLVM's
  default `small` code model emits unsigned `R_X86_64_32` for function-pointer references,
  unrepresentable this high up; `kernel` emits sign-extending `R_X86_64_32S` instead. Found live:
  `build.rs` was silently leaking the kernel's own `-T x86_64-oxidebsd.ld` rustflags into nested
  module/userland `cargo` invocations via inherited `CARGO_ENCODED_RUSTFLAGS` (higher-priority
  than a plain `.env("RUSTFLAGS", ...)` override) — fixed with an explicit
  `.env_remove("CARGO_ENCODED_RUSTFLAGS")`, which is what let `relocation-model=static` actually
  start applying to module builds for the first time and surfaced the `code-model=kernel` gap.
  A few GOT-indirected references survive anyway — handled via a minimal, eagerly-populated
  per-relocation-site GOT.
- **No `core::fmt::Write`/`write!` in module code** — that trait object's vtable emits a GOTPCREL
  reference, the single largest bloat source before `--gc-sections`. Hand-rolled byte formatting
  instead.
- **Modules can't use `alloc`/`Vec`/`BTreeMap`** — avoids depending on `#[global_allocator]`'s
  unstable-ABI internals from relocated code. State lives in fixed-size `static mut` arrays, or,
  for a genuinely large pool (see oxfs's own `BLOCKS`/`WRITE_BUFFERS`), real kernel-allocated
  memory via `oxidebsd_module_alloc_zeroed` — a module calling this from *inside* its own
  `module_init` reaches the exact `allocate_region`/`map_region` machinery `module::load` already
  used for that module's own code, rather than baking the pool into its own object file's `.bss`.
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
  module→kernel via each module's own resolved symbol table — why `sys/fs/fd.rs`'s registry
  exists at all).

## Filesystem: oxfs

**`sys/modules/oxfs/`** is the live filesystem — a real Unix-shaped inode/block filesystem. In-memory
by default, with real optional persistence to an attached ATA disk (see "Real disk persistence").
Fixed-size `static mut` pools: `NUM_BLOCKS=65536` × `BLOCK_SIZE=4096`, `MAX_INODES=8192`,
`NAME_MAX=40`, `OXFS_PATH_MAX=4096` (real, whole-path `ENAMETOOLONG` enforcement, matching musl's
`PATH_MAX` — doesn't cover a name with embedded `/` characters, since real POSIX leaves
interpretation of those implementation-defined and musl's own `shm_open` client code already
rejects them before the kernel ever sees them). Each inode has 12 direct blocks + one
single-indirect + one **double-indirect** block (~4.1 GiB addressable per file; real ceiling is
pool free space, ~1 GiB pool). `OpenFile::Write` streams to real blocks once its buffer
(`MAX_WRITE_BUFFER=16` MiB) fills, rather than buffering a whole file and replacing it at `close`.
The buffer itself lives in a separate, lazily-claimed pool (`WRITE_BUFFERS`/`WRITE_BUFFER_USED`,
`MAX_WRITE_BUFFERS=256`) rather than embedded in every `OpenFile::Write` — a read-only or
never-written fd never claims a slot, which is what let `MAX_OPEN_FILES` scale `256 → 2048`
cheaply (found necessary chasing a real POSIX stress test that opened up to 1000 fds
simultaneously with no `close()`). `NO_BLOCK = u32::MAX` is the "unallocated" sentinel.
Directories are ordinary inodes holding fixed 32-byte records that grow additional blocks on
demand. `unlink`/`rmdir` only clear a record's `used` byte (no dealloc). Root is fixed inode `0`,
self-referencing `.`/`..`.

- Real multi-component path resolution (`resolve_path`/`resolve_parent`, handling `.`/`..`).
- Real **per-process** cwd: `Process::cwd` (opaque inode number), falls back to `BOOT_CWD` for pid
  `0` (module_init's own self-check).
- Syscalls: `SYS_OPEN=5`, `SYS_CLOSE=6`, `SYS_CHDIR=12`, `SYS_MKDIR=136`, `SYS_GETCWD=108`,
  `SYS_UNLINK=109`, `SYS_RMDIR=110`, `SYS_RENAME=111`, `SYS_FSTAT=126`/`SYS_STAT=127`/
  `SYS_LSTAT=128` (byte-exact 144-byte musl `struct stat`), `SYS_GETDENTS=129`. `st_uid`/`st_gid`/
  `mode`/timestamps are real (see "Permission model") — `oxfs_lstat` doesn't follow a final
  symlink, `oxfs_stat` does.
- Seed files (BusyBox applet ELFs, the musl runtime tree, fixtures) are embedded via
  `include_bytes!` in `module_init`, no build-time disk image needed.
- **The on-disk bitmap was once hardcoded to one block** (broken past `NUM_BLOCKS=32768`) and the
  block allocator was once an O(n²) rescan — both fixed as part of the max-file-size redesign.
  `SUPERBLOCK_VERSION` bumped alongside.
- **`BLOCKS`/`WRITE_BUFFERS` are real, kernel-allocated memory (`oxidebsd_module_alloc_zeroed`,
  `sys/module.rs`), not `static mut` arrays baked into this module's own object file** — found live
  investigating a boot-path memory failure: those two pools alone made this module's own mapped
  region ~1.5 GiB (the block pool's real ~1 GiB capacity plus the write-buffer pool, versus ~230 MiB
  of actual code/embedded seed content). `init_pools()` (top of `module_init`) requests both from
  the kernel via a new symbol modules can call *from inside* `module_init`, reusing the exact
  `allocate_region`/`map_region` machinery `module::load` already uses for a module's own code —
  bridged via raw pointers `load` stashes for the duration of one `module_init` call
  (`CURRENT_LOAD_MAPPER`/`_FRAME_ALLOCATOR`, `sys/module.rs`), since `module_init`'s own fixed,
  parameterless calling convention can't carry them directly.

An earlier FAT32 module (8.3 names only, one path component per call, a directory that could never
grow past its first cluster, one kernel-wide cwd, whole-file-buffered reads, no `unlink`/`rmdir`/
`rename`) has since been removed entirely (v0.2.0 cleanup) — oxfs replaced it as the live
filesystem well before that, this was just retiring dead weight.

**`sys/fs/fd.rs`** (now `tgid`-keyed — see "Real threading"): a per-process
`(Pid, fd)` scoped registry — the only coordination channel between independently-loaded modules.
Bump-allocated fd numbers, never reused. **Real per-`(pid, fd)` `FD_CLOEXEC`**: scoped per
descriptor not per open-file description (`dup`/`dup2` don't copy it, `fork_inherit` does);
`do_execve` calls `fs::fd::close_cloexec`. **Real per-fd access-mode enforcement**
(`OpenFile::Write::readonly`) on write/`ftruncate`/`fallocate` — `open(path, O_CREAT)` with no
explicit `O_WRONLY`/`O_RDWR` now genuinely produces a read-only fd rather than silently writable.

## Real disk persistence (`sys/drivers/ata.rs`, `sys/modules/oxfs`)

Scoped deliberately: real disk I/O and oxfs mount/format persistence, not a general VFS/mount-table
layer.

- **`sys/drivers/ata.rs`**: hand-rolled ATA PIO driver, kernel-resident — classic legacy IDE,
  LBA28, **polling only, no IRQ**, fixed legacy ports. Every BSY/DRQ wait is bounded by a real
  `crate::tsc`-based deadline (never `hlt()`, never unbounded) — reachable from inside a real
  syscall handler with interrupts masked.
- **One fixed target: secondary channel, master** — `scripts/qemu_runner.sh` attaches the real
  ATA data disk at the primary channel's master instead (`ide.0`, unit 0), since QEMU's own
  `-cdrom` convenience default for the Limine boot ISO already claims the secondary master's
  usual slot (`ide.1`, unit 0) and collides if both target it. Disk image at
  `target/oxfs_disk.img` (created only if missing) for `cargo run`, `target/oxfs_test_disk.img`
  (always freshly zeroed) for `cargo test`.
- **On-disk layout**: physical block `0` is the superblock (magic `b"OXFS"` + version + layout);
  packed inode table follows; then the block-used bitmap; real data after that. **Never a raw
  transmute/memcpy of `Inode`** — `pack_inode`/`unpack_inode` serialize by hand.
- **Mount-or-format, decided once in `module_init`**: no disk → in-memory only. Disk attached,
  superblock magic **and** stored layout match this build → **mount** (eager-load only used data
  blocks). Magic mismatch, or layout mismatch → **format** (reset the in-memory pool to all-free
  first — a stale bitmap/inode-table load must never leak into a fresh format), reseed, then
  `flush_all_to_disk`. **A real, three-layered bug found when `MAX_INODES` changed the on-disk
  table size**: a stale bitmap could leak into a fallback-to-format path, `build.rs`'s own
  hand-duplicated metadata-block-count constant went stale, `mount_from_disk`'s superblock check
  was magic-only (not layout-aware), and the persistent dev disk was never grown if undersized —
  all four fixed (always reset-then-format; compute the constant; check
  `SUPERBLOCK_VERSION`/`NUM_BLOCKS`/`MAX_INODES` too; grow the disk in place).
- **Write-through persistence, centralized at three functions**: `write_block`, `write_inode`,
  `set_block_used` are the *only* functions that ever touch `BLOCKS`/`INODES`/`BLOCK_USED`.
- **`PERSISTENCE_READY`** (`static mut` gate) stays `false` for the entire format/mount duration,
  set `true` right after, before any real syscall becomes reachable.
- **Known, accepted limitation: mount-time load is bitmap-filtered, not true lazy fault-in.**
  Sector transfers themselves are NOT the bottleneck this once implied — `insw`/`outsw` (hand-rolled
  `rep insw`/`outsw` via inline `asm!`, not the pinned `x86_64` crate's own `Port` abstraction,
  which has no such wrapper) already move a whole 512-byte sector in one trapped instruction under
  QEMU's TCG. The real per-command cost is fixed overhead (drive select, `BSY`/`DRQ` polling)
  independent of transfer size — `oxidebsd_block_{read,write}_batch` (`sys/drivers/ata.rs`) cut
  this by issuing one real command (and, for writes, one `CACHE FLUSH`) per *contiguous* run of
  oxfs blocks instead of one per individual 4 KiB block; `mount_from_disk`/`flush_all_to_disk` use
  these instead of the single-block API for their own data-block loops. A full fresh-format-and-
  flush of this kernel's real seed content is still genuinely slow in absolute terms (tens of
  thousands of real blocks) — confirmed via direct baseline comparison to be pre-existing behavior,
  not a regression from either this change or oxfs's own kernel-allocated-pool refactor above.
- **The same batching extended to live per-syscall writes, not just the bulk mount/format pass**
  (`write_inode_at`'s own `persist_data_run_if_ready`, `sys/modules/oxfs`) — found live chasing
  real disk-I/O slowness while self-hosting bmake (see the bmake section above): every real
  `write()`/`close()` on a growing file used to persist (and real-`CACHE-FLUSH`) one block at a
  time even when the underlying physical blocks were genuinely contiguous, which a forward-only
  bump allocator (`NEXT_FREE_BLOCK`) makes the common case for a freshly-written file. Now tracks
  a pending contiguous run across the write loop and flushes it in one real batched command,
  falling back correctly (one run of length 1) whenever blocks genuinely aren't contiguous.
  Verified via `tests/mmap_syscall_smoke.rs` (all 15 parts, including real mtime/ctime and
  `MAP_SHARED` writeback) and `tests/oxfs_persistence_syscall_smoke.rs`.
- **Every internal mtime/ctime/atime stamp used to do a fresh raw CMOS hardware read** (real
  `sys/cpu/rtc.rs` `cmos_read`, 7+ separate trapped `out`/`in` port pairs) via
  `oxidebsd_unix_time()`, called on *every* oxfs write/touch — found the same session, real,
  avoidable overhead on a call this hot under QEMU's TCG. Fixed: uses `unix_epoch_now_precise()`
  (the same calibrated-once, `ticks()`-derived clock `sys_clock_gettime`'s own `CLOCK_REALTIME`
  already reads) instead — a real correctness fix too, not just speed, since a file's `st_mtime`
  and `time(NULL)` could previously disagree by however much the two independently-read clocks
  drifted apart. SysV IPC's own `stime`/`rtime`/`ctime`/`otime`/`dtime`/`atime` fields (`sys/fs/
  sysv_{msg,sem,shm}.rs`, called directly, not through `oxidebsd_unix_time()`) had the identical
  bug and got the identical fix, for the same reason `process::timers::abstime_to_ticks` already
  needed it (see that function's own doc comment — same bug class, found once before).
- **No raw block device is exposed to userland** — the disk is purely internal to oxfs's own
  persistence.
- Verified via `tests/ata_smoke.rs`, `tests/oxfs_persistence_syscall_smoke.rs`. **Not covered**:
  persistence surviving a real QEMU restart — manual only.
- **Operational gotcha**: mounting never re-syncs seeded content against the kernel's current
  embedded bytes — only a fresh *format* does. A fix to seeded content needs
  `target/oxfs_disk.img` deleted (destructive to anything created at the hush prompt — ask the
  user first) and reformatted on the next `cargo run`.

## Mount table (`sys/modules/oxfs/`)

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
  `external/mit/musl/src/linux/mount.c` dispatches to one of these two based on `fstype`/`flags`.
- **`/proc/mounts`**: a local formatter produces mtab-shaped lines directly from mount-table state.
- Verified via `tests/mount_syscall_smoke.rs`. **Not covered**: a real block-device-agnostic mount
  table (`pivot_root`/`switch_root`), anything needing a real partition table.

## Permission model (`sys/process/`, `sys/modules/oxfs/`, `sys/modules/posix_compat/`)

Real uid/gid, real per-inode `mode`/`uid`/`gid`, real `chmod`/`chown`, real `open()` permission
enforcement.

- `Process` gains `uid`/`gid` — no separate saved/effective pair. `0` at spawn; copied by fork;
  preserved by execve.
- Syscalls: `SYS_GETUID=158`/`SYS_GETEUID=159`/`SYS_GETGID=160`/`SYS_GETEGID=161`/
  `SYS_SETUID=162`/`SYS_SETGID=163`/`SYS_GETGROUPS=164` (`posix_compat`) and `SYS_CHMOD=165`/
  `SYS_CHOWN=166` (`oxfs`), plus real `fchmod` (`__NR_fchmod=91`, found via `uudecode`).
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
- **`/etc/passwd`/`/etc/group`** seeded with `root:x:0:0:root:/:/bin/sh` and (see "Session..."
  below) a real second user. musl's own `getpwuid`/`getpwnam`/`getgrgid`/`getgrnam` parse these
  directly.
- **Real hard links**: `Inode::nlink`. `oxfs_link` follows symlinks, rejects directories (`EPERM`)
  and cross-pool links (`EXDEV`). `oxfs_unlink` decrements `nlink` (still never actually freed).
- **Real device nodes**: `InodeKind::Device`, `Inode::rdev`/`device_char`. `mknod` creates a real,
  listable inode; `oxfs_open`'s `Device` dispatch only services major:minor pairs matching the
  four `/dev/{random,urandom,null,zero}` devices — any other is `ENXIO`. Root-only.
- **Real per-process `chroot`**: `Process::root_inode: u64` mirrors `cwd`'s design (`0` = never
  chrooted). `resolve_path_impl` gains a `root_inode` parameter for containment. Root-only.
- Verified via `tests/uid_syscall_smoke.rs`, `tests/needs_syscall2_smoke.rs`. **Not covered**:
  mutating `/etc/passwd`/`/etc/group` (applet-level gap), `lchown`/setuid/setgid/sticky bits.

## The `*at()` family (`sys/modules/oxfs`, `sys/process/lifecycle.rs`, `external/mit/musl`)

Every `*at()` call musl can issue: `openat`/`mkdirat`/`mknodat`/`fchownat`/`newfstatat`/`unlinkat`/
`renameat`/`linkat`/`symlinkat`/`readlinkat`/`fchmodat`/`faccessat`/`utimensat`/`renameat2` =
`560`-`573` (oxfs), `execveat` = `574` (`native_abi`). Not done: `statx` (musl falls back to
`fstatat`), `name_to_handle_at`/`open_by_handle_at`, `RENAME_EXCHANGE`/`RENAME_WHITEOUT` (`EINVAL`).

- **Wire format**: each `(dirfd, path)` is a pointer to `{dirfd: i64, ptr, len}` in caller memory
  (`RawAtPath` / musl `src/internal/oxidebsd_at.h`) -- `linkat`/`renameat2` can't fit 2 dirfds + 2
  length-prefixed paths + flags in 4 registers. `ptr == 0` is a real NULL path (`futimens`).
- **Kernel design**: single-base calls set `AtBaseGuard` (a static override of `current_cwd()`) and
  delegate to the plain handler, so `/proc`, mounts and chroot behave identically; relies on
  syscalls being uninterruptible on one core (SMP breaks it, like the stdin ring lock). `link`/
  `rename` take both bases explicitly (`link_impl`/`rename_impl`).
- `execveat` pre-reads the image via `SYS_OPENAT`, or `pread` on the fd (`fexecve`). A `#!` script
  reached through a dirfd/fd is `ENOENT` -- no `/dev/fd/N` to hand the interpreter.
- `SYS_UTIMENSAT=167` (path-only) stays for `lib/oxlibc`'s `touch`; musl's `utimensat` name now
  maps to `572`.
- **Real bugs found/fixed alongside**: `open()` ignored `O_DIRECTORY`/`O_NOFOLLOW`; `rename(a, a)`
  lost the entry (`EIO`); musl's `fstatat`/`remove`/`tmpfile`/`tmpnam`/`tempnam` passed upstream
  arg shapes to this ABI's length-prefixed handlers; `lchown`/`fchown`/`futimens`/`utimensat(dirfd)`
  were always `ENOSYS`; `execve` with a garbage argv length **panicked the kernel** (unbounded
  allocation) -- now a 2 MiB total `E2BIG` cap (`MAX_EXEC_ARG_BYTES`); `sys/boot/multiboot2.rs`'s
  `global_asm!` never restored its section, so a CGU reshuffle put the syscall entry stub in
  `.boot32.text` (`multiboot2-boot-smoke` link failure) -- now `.pushsection`/`.popsection`.
- Known, not fixed: moving a directory to a new parent doesn't rewrite its `..`; oxfs `ENOTEMPTY`
  is FreeBSD's `66`, not musl's `39` (same deferred errno class as the net stack's).
- Verified: `tests/at_syscall_smoke.rs` (`regress/at-smoke/main.c`, real musl API, PASS/FAIL per
  check) and `std::filesystem::remove_all` in `tests/clangxx_syscall_smoke.rs`.

## Session, controlling-tty, and login authentication (`sys/process/`, `sys/console/stdin.rs`, `sys/cpu/interrupts.rs`, `sys/modules/posix_compat/`, `sys/modules/oxfs/`)

Closes `su`/`login`/`sulogin`/`getty`.

- **A real second user**: `/etc/passwd` gains `user:x:1000:1000:User:/home/user:/bin/sh` (real
  `/home/user`, owned `1000:1000`, mode `0700`). **A real `/etc/shadow`** (mode `0600`, root-owned)
  holds real SHA-512 (`$6$`) `crypt(3)` hashes (password equals username) — musl's stock
  `crypt` code needed zero changes.
- **A real session model**: `Process` gains `sid: Pid`. Two new **single, not per-session**
  globals in `sys/console/stdin.rs`: `CONTROLLING_SESSION: Option<Pid>`, `FOREGROUND_PGID:
  Option<Pid>` — this kernel has exactly one real console.
  - **`SYS_SETSID=112`**: `EPERM` if the caller is already a process-group leader; else becomes
    leader of a fresh session+pgroup.
  - **`SYS_GETSID=177`** (invented — real Linux's `124` means `SYS_IOCTL` here).
  - **`SYS_IOCTL` gains `TIOCSCTTY`/`TIOCNOTTY`/`TIOCGPGRP`/`TIOCSPGRP`**, gated to the real
    console fd. `TIOCGPGRP` falls back to the session id when nothing's called `TIOCSPGRP` yet.
  - **Real Ctrl+C → `SIGINT` to the foreground process group**: keyboard IRQ intercepts ASCII ETX
    (`0x03`) before the stdin ring buffer, only when `ISIG` is set **and** `FOREGROUND_PGID` is
    claimed — see "Real job control" below for how pid 1 gets a controlling tty automatically.
  - Verified via `tests/session_syscall_smoke.rs`, run as a forked child of pid 1.

**Two real bugs found live-testing `su`**: a real syscall-number collision (this ABI's invented
`SYS_KILL` equaled real Linux's inert `setgroups`, which *did* have a live musl caller via
`initgroups()`, silently misrouting `setgroups()` into `kill(2)` — fixed with a dedicated
`SYS_SETGROUPS=178`); and a real `ENOSYS` mismatch (this kernel's `ENOSYS` was FreeBSD's `78`
instead of musl's compiled-in `38`, so BusyBox's `initgroups()`-failure-is-harmless fallback never
fired — fixed by correcting the constant). Both confirm the syscall-ABI collision rule above.

## Signal handling module (`sys/modules/signal/`, `sys/process/signals.rs`, `sys/syscall/mod.rs`)

Real `kill(2)`/`sigaction(2)`/`sigprocmask(2)` + delivery, plus
`sigtimedwait(2)`/`sigwaitinfo(2)`/`sigwait(3)`/`sigqueue(2)`. `SYS_KILL=116`/`SYS_SIGACTION=117`/
`SYS_SIGPROCMASK=118`/`SYS_SIGRETURN=119` match real Linux/BSD wire formats (pure number remap).
`SYS_SIGTIMEDWAIT=495`/`SYS_SIGQUEUE=496` are real, unclaimed
`__NR_rt_sigtimedwait`/`__NR_rt_sigqueueinfo` values. Real signal numbers (`SIGHUP=1`...
`SIGSYS=31`), extended to real-time signals `SIGRTMIN..=SIGRTMAX` (`35..=64`, matching musl's own
`sigrtmin.c`/`sigrtmax.c`). Signals `32..=34` (`SIGTIMER`/`SIGCANCEL`/`SIGSYNCCALL`) are valid,
kernel-side, real signal numbers too — real musl uses `SIGCANCEL=33` for `pthread_cancel(3)` over
the same raw `kill`/`sigaction` path as any other signal; the "permanently unclaimed" framing is a
libc-level convention only, not a kernel restriction.

- `Process::sigactions` moved from `Process` into the `Arc<Mutex<>>`-shared `ThreadGroupShared` —
  real POSIX requires signal disposition to be process-wide, not per-thread (found live: a
  per-thread copy meant `pthread_cancel()`'s installed `SIGCANCEL` handler was invisible to the
  actual target thread). `[SigAction; 65]` (real `SIG_DFL=0`/`SIG_IGN=1`); `Process` itself still
  holds `pending_signals`/`blocked_signals` bitmasks, `pending_siginfo: [QueuedSigInfo; 65]` (real
  per-signal sender `pid`/`uid`/`si_code`/`sigqueue` value — **sized to cover the full `0..=64`
  range**, found live: accepting the `32..=34` range without widening this array first would have
  turned a userspace `EINVAL` into a real kernel out-of-bounds panic), and a real
  `signal_stack: Vec<SignalStackFrame>`.
- **Real RT signal queuing**: `Process::rt_queue: [Vec<QueuedSigInfo>; RT_SIGNAL_COUNT]` gives
  each RT signal its own small fixed-capacity (`RT_QUEUE_CAP=16`) FIFO — a second
  `sigqueue`/`raise` against an already-pending RT signal genuinely queues (standard signals stay
  bitmask-collapsed, which POSIX permits). `record_pending` is RT-aware and fallible: returns
  `Err(EAGAIN)` once a queue is full.
- Delivery happens once, at the tail of `syscall_dispatch` (and from `sigreturn` itself — see
  chaining below). `sigreturn` bypasses the normal `Ok`/`Err` carry-flag rewrite entirely.
- `do_kill` cross-process: immediate for the common case (no handler → terminate right there, even
  against a blocked target); deferred until next-scheduled only if the target has a custom
  handler. **Real permission checking** (`has_signal_permission`): sender must be root or share
  the target's uid, else `EPERM` — single-target paths only, not `signal_foreground_group`'s
  broadcast. **Real process-group targeting** (`target_pid == 0`/`< 0`) — see "Real job control".
  **A signal that must terminate the whole thread group** (default-disposition delivery via
  `deliver_pending_signal`, and every `do_kill` `Action::Terminate` site) routes through
  `terminate_thread_group`, not a single-thread `terminate_process` — killing every non-leader
  member first, the leader always last (found live: a signal hitting the leader while a sibling
  was still alive used to wrongly treat the leader as disposable and skip parent notification,
  permanently hanging `wait4`).
- **Real `SA_SIGINFO` handler invocation**: `RawSiginfo`/`RawUcontext`/`RawMcontext` built on the
  handler's own stack frame with real GP registers and `uc_sigmask`. **`RawSiginfo`'s
  `si_code`/`si_errno` field order was a real bug** (swapped relative to real musl x86_64, silent
  because `SI_USER == 0` too) — fixed by reordering. **Three userland smoke crates hand-duplicate
  this struct** and needed the identical fix — any future wire struct duplicated this way needs
  the same audit whenever the kernel-side original changes.
- **`sigtimedwait`/`sigwaitinfo`/`sigwait`**: real POSIX semantics directly *consume* a pending
  signal matching `wait_set`, **bypassing handler invocation** even if one's installed. A signal
  used this way must be blocked via `sigprocmask` first.
- **`sigqueue`**: real `(pid, sig, siginfo_ptr)`, single-target only.
- **Real signal-stack chaining**: `do_sigreturn` calls `deliver_pending_signal(frame)` itself
  right after popping/restoring a `signal_stack` entry — if another signal is deliverable, it
  redirects into that next handler instead of resuming. Closes the general "second signal during
  a different handler's execution" gap, since any sequence of deliverable signals now plays out as
  N real handler invocations before the originally-interrupted code resumes.
- **Real `SA_ONSTACK`**/**`SA_NOCLDWAIT`**/**`SA_NOCLDSTOP`**: `Process::on_altstack` +
  `begin_altstack_if_requested`; `terminate_process` detaches an exiting child immediately when
  the parent's `SIGCHLD` flags request it; `notify_parent_sigchld` skips generation for the *stop*
  transition when requested.
- **Real `SIGCHLD` delivery** on child exit/stop/continue (`signals::notify_parent_sigchld`, real
  `CLD_EXITED`/`CLD_KILLED`/`CLD_STOPPED`/`CLD_CONTINUED`) — this kernel never delivered a real
  `SIGCHLD` before a dedicated pass added it, also fixing `hush`'s own `CONFIG_HUSH_FAST`
  short-circuit (previously dead since its `SIGCHLD` counter could never move).
- **A real fault-to-signal-delivery bug: blocking a synchronously-generated signal.** Real musl's
  `pthread_kill()`/`pthread_cancel()` call `__block_all_sigs()` internally — a real page fault
  occurring inside that critical section used to respect the target's blocked-signal mask (correct
  for an async `kill()`-delivered signal, wrong for one synchronously generated by the faulting
  instruction itself), leaving nothing for the fault trampoline to deliver and falling through to
  its `ud2` safety net — an unbounded, whole-VM-halting crash instead of a normal per-process
  `SIGSEGV`. Fixed: `process::signals::force_fault_signal(pid, sig)` force-clears just the one bit
  being delivered before recording it pending, matching real Linux's `force_sig()` semantics
  (every other blocked signal stays blocked). Both fault handlers' self-signal call sites use it.
- **`SYS_FUTEX_REQUEUE=557`**: real `pthread_cond_timedwait`'s `unlock_requeue` needs to move a
  waiter from a condvar's futex word to a mutex's — doesn't fit this ABI's plain 4-register
  `SYS_FUTEX` wire format (real `futex(2)` needs 6 args for this op), so it's a dedicated syscall
  taking exactly `(uaddr, uaddr2, nr_wake, nr_requeue)`. This kernel has no literal wait-queue
  structure to requeue between — "moving" a waiter is just overwriting its own `(scope, key)`
  fields in place.

## Real job control: Ctrl+C/Ctrl+Z, colored tty, `kill(-pgrp)` (`sys/process/`, `sys/cpu/interrupts.rs`, `build.rs`)

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
  call site: an actually-`Stopped` target always resumes regardless of its own disposition.
  - **A real regression found live**: `process::timers::do_nanosleep` was the one blocking call
    that didn't loop and re-check its wake condition after `scheduler::schedule()` returns. Real
    `SIGCONT` unconditionally wakes a `Stopped` process, so `bg`-ing a Ctrl+Z-stopped `sleep 100`
    woke it almost immediately instead of at its real ~100s deadline. Fixed by looping and
    re-checking the deadline — **any future mechanism that can force an arbitrary process back to
    `Ready` cross-process needs the same audit** of every non-looping `scheduler::schedule()` call
    site.
  - Not covered: real `SIGTTIN`/`SIGTTOU`-driven job control (still `Ignore`).

## Real-time clock (`sys/modules/clock/`, `sys/cpu/pit.rs`, `sys/cpu/rtc.rs`, `sys/cpu/hpet.rs`)

`SYS_CLOCK_GETTIME=138` — real `clock_gettime(2)` wire format; `time()`/`gettimeofday()` are
wrappers around it.

- **`sys/cpu/pit.rs`** reprograms PIT channel 0 to a fixed `TIMER_HZ=100` at boot — the
  scheduler's own tick, untouched by anything below.
- **`sys/cpu/rtc.rs`** reads the CMOS RTC. `CLOCK_MONOTONIC` converts `ticks()` against
  `TIMER_HZ`. **Real sub-second `CLOCK_REALTIME`** (`unix_epoch_now_precise`) calibrates a fixed
  `ticks() -> real seconds` offset against the RTC once, then derives every later reading from
  `ticks()`.
- **`SYS_NANOSLEEP=139`** — converts to an absolute wake-up tick deadline, blocks, woken by the
  timer IRQ. **Real signal-interrupts-sleep**: checks `pending_signals & !blocked_signals` before
  each re-block, returns `EINTR` with real remaining time. **Only counts a signal that will
  actually invoke a handler or terminate** (`process::signals::has_interrupting_signal`) — a
  default-`Ignore` signal like `SIGCONT`/`SIGCHLD` must not spuriously interrupt a blocking call;
  the same bug shape (claiming to filter by disposition but not actually doing it) existed at 9
  call sites total (`do_pause`, `do_sigsuspend`, `do_clock_nanosleep`, `do_mq_timedsend`/
  `_timedreceive`, two `FUTEX_WAIT` check sites, `oxidebsd_sys_select`, this one) — fixed
  uniformly. Deliberately doesn't apply to `sigwait`/`sigtimedwait` (bypass disposition by design)
  or the preemption-redirect-to-trampoline check (not a userspace `EINTR` decision).
- **`sys/cpu/hpet.rs` — a real ACPI HPET, but a counter-only sub-tick *overlay*, never an interrupt
  source and never a PIT replacement.** This kernel has no IOAPIC/MSI support, so a real
  interrupt-driven comparator would mean stealing IRQ0 from the PIT — rejected. Instead, a POSIX
  timer's overrun count is computed as exact `elapsed_ns / interval_ns` "catch-up" arithmetic
  (same technique real Linux's `hrtimer_forward()` uses), read at whatever cadence already polls
  (the 100Hz tick) — needed since `TIMER_HZ=100`'s 10ms tick can't represent a 5ms interval.
  Discovered via Limine's real RSDP → XSDT/RSDT → `"HPET"` table walk (`boot::rsdp_address`,
  checksummed, `NO_CACHE`-mapped). Absence at any step is logged, never fatal — every caller has
  an honest tick-based fallback. `sys_clock_getres` reports HPET resolution for
  `CLOCK_REALTIME`/`CLOCK_MONOTONIC` when present; cputime clocks always stay tick-quantized.
  `do_nanosleep` gained a real HPET top-off after the tick deadline passes (bounded, capped at 50
  ticks/500ms) since PIT `ticks()` can measurably lag a directly-read HPET counter by a few ms
  under KVM. **Known, accepted drift**: PIT and HPET are independently clocked with no
  cross-calibration, and their relative *rates* measurably diverge over several minutes of
  sustained guest uptime — a real-time overrun test that passes in isolation can fail deep into a
  long continuous boot; not chased further (would need periodic recalibration).

## Real networking (`sys/drivers/pci.rs`, `sys/net/*`, `sys/modules/net/`)

Real, phased stack: PCI enumeration, IRQ-driven rtl8139 driver, Ethernet/ARP/IPv4/ICMP, UDP/TCP
sockets, raw ICMP sockets, `poll(2)`, and real hostname resolution via musl's own stub resolver.

- **`sys/net/rtl8139.rs`**: brought up unconditionally at boot, absence logged not fatal.
- **`ipv4::next_hop`** is the *only* routing rule (anything outside `GUEST_IP`'s `/24` → gateway).
- **`sys/net/udp.rs`/`tcp.rs`**: real sockets behind `SYS_SOCKET=140`/`SYS_BIND=141`/
  `SYS_SENDTO=142`/`SYS_RECVFROM=143`/`SYS_SETSOCKOPT=144` (UDP) and `SYS_CONNECT=145`/
  `SYS_LISTEN=146`/`SYS_ACCEPT=147` (TCP; once `Established`, plain read/write). TCP is
  stop-and-wait (one segment in flight, fixed 536-byte MSS, no window/congestion control).
- **`sys/net/icmp.rs`** raw sockets: not port-addressed, every inbound ICMP fans out to every open
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
   **`sys/cpu/tsc.rs`** (`RDTSC`-based, immune to `IF`) — **never `crate::interrupts::ticks()`**,
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
`SYS_GETITIMER=157`, `sys/modules/clock/`, only `ITIMER_REAL`, expiry only sets `pending_signals`, not
inherited by fork); `socketpair(AF_UNIX, SOCK_STREAM)` (`SYS_SOCKETPAIR=149`, built on
`sys/fs/pipe.rs`); getting `wget` HTTPS working needed five further fixes in sequence:
`SYS_SET_TID_ADDRESS=150`, `SYS_FCNTL=151` (`F_GETFL`/`F_SETFL(O_NONBLOCK)`/`F_SETFD`/`F_DUPFD*`),
`SYS_SHUTDOWN=152` (real half-close for a pipe-backed socketpair only), a synthetic
`/dev/{u}random,null,zero` path backed by **`sys/random.rs`** (a real
SHA-256-seeded ChaCha20 generator gathering `RDTSC`/PIT/RTC/`RDRAND`/`RDSEED` when available, plus
a persistent `ENTROPY_POOL` folding real IRQ-timing jitter from keyboard/rtl8139 handlers —
`RDRAND`/`RDSEED` are distrusted whenever `running_under_hypervisor()` is true, since a hypervisor
can trap and fake either instruction undetectably; both crates need soft-float-equivalent backend
flags for this SSE-disabled target), and `SYS_READV=153`; plus a real `tcp_read` EOF-vs-empty fix.
No real routing table, no IPv6 anywhere. BusyBox's vendored TLS client doesn't validate certificate
chains (a limitation of that vendored code, not fixable kernel-side).

## Filesystem/process misc syscalls: fsync, ftruncate, fallocate, flock, statfs, prlimit64, nice, chrt, reboot (`sys/modules/oxfs`, `sys/modules/posix_compat`, `sys/reboot.rs`)

`link`/`mknod`/SysV IPC/`chroot`/namespaces/`inotify`/ext2 `ioctl`s/`xattr` were a distinct,
deliberately-out-of-scope gap at the time this landed (`link`/`mknod`/`chroot` since done);
namespaces don't fit this single-address-space kernel at all.

- **All sixteen numbers land at `471`-`486`** — see the syscall-ABI collision rule above.
  `oxfs`'s `SYS_FSYNC=471`...`SYS_FSTATFS=477`, `posix_compat`'s `SYS_PRLIMIT64=478`...
  `SYS_REBOOT=486`.
- **`SYS_FSYNC`/`SYS_SYNC`** are real, not stubs — a shared `commit_write_buffer` (from
  `oxfs_close`) is callable for one fd or swept across every open write fd.
- **`SYS_FTRUNCATE`/`SYS_FALLOCATE`** resize directly at the block level, not via a whole-content
  buffer (the 128 KiB kernel-stack floor can't hold a large file). Growing zero-fills only the
  new region.
- **`SYS_FLOCK`** is a real per-inode `LOCK_SH`/`LOCK_EX`/`LOCK_UN` advisory table (16 entries),
  released on close. A conflicting request fails `EAGAIN` immediately even without `LOCK_NB` — no
  scheduler-yield primitive is reachable from a module syscall handler.
- **`SYS_STATFS`/`SYS_FSTATFS`** report a real musl-layout `struct statfs` (120 bytes) from live
  block/inode-usage counts.
- **`SYS_PRLIMIT64`** backs `getrlimit`/`setrlimit`. `Process::rlimits: [(u64,u64); 16]` — stored,
  never enforced.
- **`SYS_SETPRIORITY`/`SYS_GETPRIORITY`** (`nice`) — `Process::nice: i32`, no real scheduling
  effect. **`SYS_SCHED_SETSCHEDULER`/`_GETSCHEDULER`/`_GETPARAM`/`_GET_PRIORITY_MAX`/`_MIN`/
  `SYS_SCHED_SETPARAM=507`** (`chrt`) — **real `SCHED_FIFO`/`SCHED_RR` priority semantics are
  genuinely enforced**, including a real `EPERM` on a non-root priority raise; `sched_setscheduler`
  returns `0` on success (not the former policy — a real bug where an earlier draft returned the
  former policy broke `pthread_setschedparam()` whenever the caller's policy wasn't already
  `SCHED_OTHER`, since fixed).
- **`SYS_REBOOT`** (+ `sys/reboot.rs`) matches real Linux's `RB_AUTOBOOT`/`RB_HALT_SYSTEM`/
  `RB_POWER_OFF` magic values. No permission check. Every success path halts/resets/powers off the
  VM — manual-QEMU-only.
- **`SYS_UMASK=487`**. `Process::umask: u32` (default `0o022`) — real per-process state, stored
  but not actually consulted anywhere oxfs creates a new inode.
- **`sched_getaffinity`** (real `__NR_sched_getaffinity=204`, found via `nproc`): single-core, mask
  always bit 0.
- Verified via `tests/needs_syscall_smoke.rs`/`needs_syscall2_smoke.rs` (except `reboot`/`umask`,
  manual-only).

An earlier TinyCC port (`third_party/tinycc`) was this project's first real, on-target C compiler
— proved a real `tcc -static -o hello.elf hello.c && ./hello.elf` round trip, contributed
`SYS_LSEEK`/the `ensure_dir`/`seed_tree` directory-seeding infra oxfs still uses, and found two
real GOT/PLT-relocation bugs (one in musl's own PIE-defaulting `configure` probe, one in TinyCC's
own static-link codegen). Removed entirely (2026-09-20 cleanup) once Clang/LLVM (below) superseded
it as this project's real on-target C/C++ toolchain — see git history for TinyCC's own design if
ever needed again.

## Clang/LLVM port: Milestone 7 done, real compile+link+run round trip (`external/apache2/llvm`, `sys/modules/oxfs`, `build.rs`)

A real on-target C/C++ toolchain — genuinely self-hosted (a host-built cross-compiler builds a
target-executable `clang`+`ld.lld`), not vendored binaries. Vendored as a submodule
(`OxideBSD/llvm-project-oxidebsd`, `oxidebsd` branch, sparse checkout trimmed of tests/docs/
unittests, tag `llvmorg-23.1.1`). `build.rs`: `build_llvm_host_toolchain` (host cross-compiler) →
`build_llvm_target_runtimes` (libc++/libc++abi/libunwind + compiler-rt, statically self-contained)
→ `build_llvm_target_toolchain` (the real, on-target-executable `clang`+`ld.lld`, built using the
host cross-compiler). A real `Triple::OxideBSD` + `clang::driver::toolchains::OxideBSD`
(`clang/lib/Driver/ToolChains/OxideBSD.{h,cpp}`) picks `gnutools::{Assembler,Linker,StaticLibTool}`
and defaults to LLD by literal name (`ld.lld`), not a triple-prefixed name. `sys/modules/oxfs` seeds
`clang`/`ld.lld` under `/bin`, plus a generated `/lib/clang/23` resource-dir tree
(`write_clang_runtime_manifest`, mirroring `write_musl_runtime_manifest`'s pattern).

**This is the real subprocess-pipeline milestone CLAUDE.md's own intro names as the reason GCC/
Clang were historically unstarted**: `clang`'s driver forks real, separate `cc1`/`ld.lld` child
processes — not something built here, just something that had to start working. Getting from
`ld.lld --version` running at all to a real `clang -static -o out.elf in.c` round trip took three
real, independent bugs, each found live via `tests/clang_syscall_smoke.rs` +
`regress/clang-syscall-smoke/`:

- **A real musl bug, `__init_tls.c`**: its raw `mmap` syscall for large-`PT_TLS` binaries never got
  the packed-args ABI patch the public `mmap()` wrapper already has — `ld.lld` (the first on-target
  binary with a `PT_TLS` big enough to cross musl's `builtin_tls` fast-path threshold) crashed with
  a page fault into `-EFAULT`. Fixed on the musl `oxidebsd` branch.
- **`oxfs_fstat` returned a flat `EBADF` for the console's stdin/stdout/stderr** (`real_fd` `0`/`1`/
  `2` — no backing oxfs inode exists for them). `llvm::sys::Process::FixupStandardFileDescriptors()`
  genuinely `fstat()`s its own fd `0`/`1`/`2` at Clang startup; the `EBADF` made it conclude all
  three were invalid and `dup2` every one onto a freshly opened `/dev/null` — silently discarding
  every one of Clang's own later diagnostic/output writes, no visible error anywhere. Fixed:
  `oxfs_fstat` synthesizes a real character-device `stat` for `real_fd <= 2` instead.
- **`do_clone` flatly rejected `CLONE_VM|CLONE_VFORK|SIGCHLD`** (real vfork-via-`clone()`) — exactly
  what musl's own `posix_spawn()` issues to launch `ld.lld` (`external/mit/musl/src/process/
  posix_spawn.c`). Fixed: `do_clone` accepts this second flag combination too, degrading to a real
  `fork()` (`do_vfork_clone`, sharing `do_fork_from_current`'s body via a common `fork_impl`) — the
  same "vfork degrades to fork" simplification `vfork.s` already uses, POSIX-legal. Uncovered a
  **paired real musl ABI bug**: `clone.s`'s hand-written asm stub bypasses `syscall_arch.h`'s normal
  carry-flag→negative-errno conversion (same bug class as `vfork.s`/`__unmapself.s` before it, the
  ABI-convention half rather than the number-remap half) — on failure it returned this kernel's raw
  *positive* errno as-is, which `posix_spawn` read as a small, valid-looking child pid instead of an
  error, then `waitpid()`'d on a pid that was never created (`ECHILD`, ABI-wire evidence, not the
  real failure). Fixed on the musl `oxidebsd` branch.
- **A real, deferred gap in the `OxideBSD` toolchain's own constructor, closed once a real on-target
  invocation finally exercised it**: `OxideBSD::OxideBSD()` only ever registered `SysRoot + "/lib"`
  as a `crt1.o`/`crti.o`/`crtn.o` search path (correct for the *host-side* cross-compile sysroot
  layout, `target/musl-sysroot`) — but on-target, `D.SysRoot` is empty (nothing to point
  `--sysroot=` at) and the real oxfs seed layout puts those files under `/usr/lib` instead.
  `ToolChain::GetFilePath` silently falls back to an unresolved bare filename on a
  miss, which is exactly what left `ld.lld` invoked with a plain `"crt1.o"` it could never open.
  Fixed: the constructor now registers both directories.
- **The smoke test's own invocation needed fixing too**: `argv[0]` must be the resolvable
  `/bin/clang`, not the bare `"clang"` (Clang's own `InstalledDir` self-location came up empty
  otherwise), and `--target=x86_64-unknown-oxidebsd-musl` must be passed explicitly (the on-target
  binary's own baked-in default triple is still `x86_64-unknown-linux-gnu`).

**Two more real bugs closed the whole milestone, both root-caused by hexdumping the actual
committed object bytes (not more syscall tracing) once a real link kept failing with `ld.lld:
error: <obj>: section header string table index 1 does not exist`:**

- **Real bug 1, in oxfs itself**: `llvm::raw_fd_ostream::pwrite_impl` (LLVM's ELF object writer,
  on every platform — never a real `pwrite64` syscall) backpatches a freshly-written object's
  header (`e_shoff`/`e_shnum`, computed only after every section is already written) via
  `lseek(SEEK_SET)` + `write()` + `lseek(SEEK_SET)` on its own plain `O_WRONLY` output fd. oxfs's
  `Write`-mode fds reported `ESPIPE` for *any* `lseek()`, silently ignored by LLVM's own
  error-handling (no crash) — so both backpatch `write()`s landed at the file's real tail instead
  of overwriting the header in place, leaving `e_shoff`/`e_shnum` at their initial zero
  placeholders (confirmed byte-for-byte: the object's last 10 bytes were exactly the two patch
  values that belonged at offsets 40/60). Fixed: every `Write` fd (`O_WRONLY` included, not just
  `O_RDWR`) now gets a real seekable `position`, and `oxfs_write` compares it against the
  streaming path's own natural next-append offset (`write_pos + len`) to decide whether a
  `write()` call should take the existing fast buffered-append path or instead overwrite at that
  exact seeked position via the same `write_inode_at` primitive `pwrite(2)` already uses
  (`oxfs_lseek`/`oxfs_write` in `sys/modules/oxfs/sys/lib.rs`).
- **Real bug 2, in musl**: `execve.c`'s own `MAX_EXECVE_ENTRIES` (a fixed-size stack array
  converting a real NUL-terminated `argv[]` into this ABI's length-prefixed wire format) was
  hardcoded to `32`, stale against `sys/process/lifecycle.rs`'s own `MAX_PTR_LEN_ENTRIES` (raised
  to `256` earlier in this same port) — silently truncating a real `clang` driver → `cc1`
  subprocess exec's argv mid-flag whenever enough preceding flags (`-dumpdir`/`-static-define`,
  present only on the full compile+link path, never a bare `-c`, which clang runs `cc1` in-process
  and never execs at all) pushed a later flag's own *value* past index 31 — surfaced as a bogus
  `error: argument to '-internal-isystem' is missing`. Fixed on the musl `oxidebsd` branch.
  **A third, real build-caching gap found applying this fix**: `build_llvm_target_toolchain`'s own
  staleness check only ever compared `clang`/`ld.lld`'s mtimes against the *host* build's
  `libc++.a`, never `musl_sysroot`'s — so a musl-only fix left the on-target `clang`/`ld.lld`
  binaries looking "fresh" and silently kept linked against the *old* musl (this build-caching
  bug class already burned the regress/std/`sys/modules/oxfs` build path once, see the std-target
  section below — same shape, different consumer). Fixed: the staleness floor now includes
  `musl_sysroot`'s own `libc.a` mtime, and going stale that way now deletes just the two output
  binaries (not the whole build dir) to force a real `ninja` relink from already-compiled objects,
  since ninja itself has no dependency edge from an external sysroot lib to its own link steps.

Verified end to end via `tests/clang_syscall_smoke.rs`: a real `clang -static -o /hello.elf
/hello.c` (real `cc1` compile, real `ld.lld` link against `crt1.o`/`crti.o`/`crtn.o`/
`libclang_rt.builtins.a`/`libc.a`/`crtn.o`) followed by actually running the produced `/hello.elf`,
which printed its own output and exited `0`. Closes this port's own headline subprocess-pipeline
milestone.

**C++ stage (self-hosting clang, step 2)**: libc++/abi/unwind seeded FreeBSD-style
(`/usr/include/c++/v1`, per-triple `__config_site` under `/usr/include/<triple>/c++/v1`, archives in
`/usr/lib`; `write_libcxx_runtime_manifest`), `/bin/clang++ -> clang`, the LLVM fork's
`OxideBSD::addLibCxxIncludePaths`, and `LLVM_DEFAULT_TARGET_TRIPLE` (no `--target=` needed any
more). `tests/clangxx_syscall_smoke.rs` does a bare `clang++ -static -o /hello-cpp.elf /hello.cpp`
and runs it (`sys/modules/oxfs/src/hello.cpp`: STL, exceptions across frames, RTTI, 4x
`std::thread`+mutex, `std::filesystem`). Real bugs found:
- **`-DCLANG_DEFAULT_SYSROOT` was never a real cmake variable** (it's `DEFAULT_SYSROOT`) -- the
  on-target sysroot was silently empty for the whole port. C hid it (cc1's own `InitHeaderSearch`
  falls back to `/usr/include` for driver-unclaimed triples; `/usr/lib` was registered explicitly).
- `build_llvm_target_toolchain` only configured once and never tracked the patched driver sources
  -- fixed with a configure-args stamp (`oxidebsd-configure-args.stamp`) plus a direct
  `clang/lib/Driver` mtime floor. `build_llvm_target_runtimes` now bumps `libc++.a`'s mtime after a
  no-op ninja run (was permanently "stale" vs. a relinked host clang).
- `std::filesystem::remove_all` needed the whole `*at()` family (libc++ uses `openat`/`unlinkat`/
  `fdopendir`) -- see "The `*at()` family" below.

## bmake (`usr.bin/make`, `build.rs`'s `build_bmake`) — self-hosting stage 1: **done**

Upstream portable bmake 20260912, vendored as a plain committed tree (tarball from crufty.net; no
git mirror exists, no fork). Cross-built by `configure --host=…` (skips run-tests) +
`make-bootstrap.sh` into a static `ET_EXEC` at `0x18000000`; `/bin/bmake` (+ `/bin/make` symlink),
`*.mk` seeded at `/usr/share/mk` (`BMAKE_MK_FILES`). Verified live (headless `sendkey`): bmake
drives on-target `clang -c` + link + run, incremental rebuilds/`touch` dependency tracking correct.
Editing `build.rs` does *not* stale BusyBox (only `build_busybox.rs` does). Known: `gettid` (186)
is unrecognized — clang logs it once per compile, harmless so far. **Genuinely self-hosts on
target now, not just pre-built**: bmake's own `configure` + `make-bootstrap.sh`, run on-target
under `/bin/ash` driving on-target `clang`, both exit `0` and produce a real, working `bmake`
binary built entirely from its own source (see the `NAME_MAX` bug below for what blocked this).
Staged plan for the rest of self-hosting: C → C++ (seed libc++) → ninja/cmake → rebuild clang;
**nano (+ vendored ncurses) is next, planned for a separate session.**

- **`hush` can't parse `>&$var`** (redirect to a variable file descriptor, e.g. `>&$4`) — real
  BusyBox `shell/hush.c` parser limitation (`redirect_opt_num`'s own `//TODO: this is the place to
  catch ">&file" bashism` comment, "ambiguous redirect"), hit immediately by autoconf-generated
  `configure` scripts (`as_fn_error`'s `>&$4`). Not a bug to patch in BusyBox — routed around by
  running `configure`/`make-bootstrap.sh` under `/bin/ash` instead (`CONFIG_SHELL=/bin/ash ... ash
  configure ...`), already in the seeded roster.
- **The real bug: `NAME_MAX=40` was too short, and the over-length check returned the wrong
  errno**, found self-hosting bmake's own build on-target. Symptom chain, each link confirmed
  directly rather than assumed: BusyBox `tar` extracting bmake's own real source tree silently
  dropped exactly 3 files (`util.c`/`var.c`/`wait.h` — the archive's *last* 3 members, out of 985)
  even on a freshly-formatted disk with hundreds of MiB and thousands of free inodes to spare
  (`statfs()` confirmed real headroom on both counts, ruling out `ENOSPC`); a **host-native build
  of the identical vendored BusyBox source** (`make O=... allnoconfig` + flip `CONFIG_TAR`, run
  directly on the host, no OxideBSD involved at all) extracted all 985 members correctly, ruling
  out a BusyBox-source bug; capturing `tar`'s own stderr on-target (every earlier attempt had
  discarded it) surfaced the real error directly: `tar: can't remove old file
  bmake/unit-tests/varname-dot-make-meta-ignore_patterns.exp: Invalid argument` — a 41-byte
  filename, one byte past oxfs's `NAME_MAX = 40`. `dir_insert`'s own length check returned
  `OxfsError::InvalidPath` (`EINVAL`) for an over-length name instead of the semantically-correct,
  already-defined `OxfsError::NameTooLong` (`ENAMETOOLONG`) — `EINVAL` is what BusyBox `tar`
  doesn't tolerate, aborting the whole archive instead of continuing past one bad name.
  **Fixed**: `NAME_MAX` raised `40 → 255` (matching musl's own compiled-in `NAME_MAX`,
  `external/mit/musl/include/limits.h` — closes the mismatch for real, not just this one filename),
  both wrong-errno call sites (`dir_insert`, `resolve_parent`) now return `NameTooLong` correctly,
  `SUPERBLOCK_VERSION` bumped `2 → 3` (`DIR_RECORD_SIZE` changed, `6 + NAME_MAX`: 46 → 261 bytes —
  a real on-disk layout change, needs the same automatic-reformat treatment every prior
  `SUPERBLOCK_VERSION` bump got). Verified end-to-end: a full, genuine self-hosted build —
  `configure` (under `ash`, see above) + `make-bootstrap.sh`, both `rc=0`, real on-target `clang`
  compiling `var.c`/`util.c`/the `wait.h`-dependent code that used to be missing, linking a real,
  working `bmake` binary that reports its own correct version string. **Accepted tradeoff**:
  `RECORDS_PER_BLOCK` drops `89 → 15` (more real directory blocks needed for the same content), a
  real, meaningfully slower format/flush and heavier ongoing directory-write I/O — see the
  freeze-that-wasn't below for why this matters.
- **A real, documented misdiagnosis along the way, corrected rather than left standing**: the
  above investigation's early attempts (before stderr was captured) looked like a genuine
  full-kernel freeze — QEMU pinned near 100% CPU, zero new serial output, and the QEMU monitor's
  own `sendkey` confirmed a keystroke was sent successfully yet the guest never echoed it
  (console-IRQ-level echo happens independent of scheduling, which is why this looked like more
  than "just a busy foreground process"). `gdbserver`-attached (QEMU monitor `gdbserver
  tcp::<port>`, then `gdb -ex "target remote localhost:<port>"`) at freeze time: caught inside
  `cpu::rtc::cmos_read`'s raw `in al, dx`, with **`RSP` reading `0x44444472a1d4`** — read at the
  time as a corrupted/poisoned stack pointer (a suspicious repeating-nibble pattern), which is what
  motivated a `process::KERNEL_STACK_SIZE_CEILING` bump (`512 KiB → 4 MiB`) as a stack-overflow
  mitigation, briefly landed and even backported to `v0.2.x`. **That reading was wrong**:
  `allocator::HEAP_START = 0x_4444_4444_0000` — `0x444444...` is this kernel's own real heap base
  address, not corruption; an ordinary `KernelStack::new` (`alloc_zeroed`) stack legitimately lands
  there. Confirmed directly: re-running the identical repro (stack ceiling still raised) hit the
  identical symptom again — and this time, instead of assuming it was dead, it was left running far
  longer. It completed cleanly on its own (`configure`'s real `exit 0`, then a real bootstrap
  compile+link). Repeated `gdbserver` sampling a few seconds apart during the "freeze" showed `RIP`
  genuinely moving between real functions (`cpu::rtc::cmos_read`, `drivers::ata::outsw`), not
  stuck at one instruction — consistent with real, if slow, ongoing work, not a hang. **What
  actually explains the symptom**: a real, syscall-scoped stretch of heavy disk I/O (many real ATA
  block writes, each preceded by a real RTC read for mtime-stamping — see "Filesystem: oxfs"
  above), run with interrupts masked for that syscall's duration (`SFMASK` clears `IF`, see the
  syscall-ABI section), made meaningfully worse by this same investigation's own `NAME_MAX` fix
  (more, smaller directory records → more real per-block ATA writes for the same directory
  content) — long enough, with interrupts genuinely off, to look indistinguishable from a hang.
  **The stack-ceiling bump has been reverted** (`sys/process/mod.rs`, back to 512 KiB — see its own
  doc comment) on master and via a follow-up revert commit on `v0.2.x`, since there was never real
  evidence it needed to move. Kept in this file specifically so a future investigation hitting the
  same "everything just stopped" symptom on a real slow-I/O stretch doesn't retread the same false
  trail: verify `RIP` is genuinely stuck (not just sampled once) and check whether the address in
  question is a real, named constant (like `HEAP_START`) before concluding "corruption."

## ncurses, nano, nvi: a real BSD-shaped curses/editor stack (`lib/ncurses`, `bin/vi`, `usr.bin/nano`, `build.rs`, `sys/console/vga.rs`, `sys/process/lifecycle.rs`)

The self-hosting plan's next stage after bmake (see that section above) -- a real curses library
plus two real editors, matching how the actual BSDs split the role: `/bin/vi` (OpenVi, a portable
extraction of OpenBSD's own vi/ex, BSD-3-Clause) is the essential, single-user-mode-capable editor;
`/usr/bin/nano` (GNU nano, GPLv3+) is everything-else. ncurses itself mirrors FreeBSD's own choice
to vendor it directly into base (`lib/ncurses`, not `external/`) -- permissively (X11/MIT-style)
licensed despite the "GNU" association, and its portable autotools build is exactly the kind of
`./configure && make` self-hosting story this stage is chasing.

- **Vendoring**: ncurses is a plain committed tree (6.6, no submodule -- same reasoning as bmake,
  no single canonical upstream git to fork, just versioned tarballs). `nano`/`vi` are submodules of
  personal forks (`OxideBSD/nano-oxidebsd` from `ahjragaas/nano`, a fast-syncing unofficial mirror
  of the real `git.sv.gnu.org/nano.git`; `OxideBSD/OpenVi-oxidebsd` from `johnsonjh/OpenVi`), each
  pinned to an `oxidebsd` branch -- same convention as musl/busybox.
- **`build_ncurses`**: cross-builds a real, wide-char (`ncursesw`, genuine UTF-8 support) static
  `libncursesw.a`/`libpanelw.a`/`libmenuw.a`/`libformw.a` + headers against `musl_sysroot`,
  installed to its own `target/ncurses-sysroot`. Library + headers only -- `tic`/`tset`/`tput`/...
  are deliberately out of scope for now (each would need its own fixed load address like every
  other `ET_EXEC` here); the one terminfo-compile step this build needs uses the *host's* own
  `tic` instead (confirmed byte-version-identical to this vendored release), producing a
  deliberately minimal compiled terminfo database (`linux`/`vt100`/`vt100-am`/`dumb` -- the only
  `TERM` values this kernel's own console will ever report) seeded at `/usr/share/terminfo`.
- **Two real musl gaps closed for OpenVi's own `cl/*.c`/`common/*.c`**: `<sys/queue.h>` and
  `<bitstring.h>` (both real BSD-isms, not POSIX, so musl ships neither) -- vendored from real
  FreeBSD (BSD-3-Clause, kept verbatim) into this project's own musl fork. `<sys/queue.h>` needed a
  companion `<sys/cdefs.h>` shim too (`__containerof`/`__predict_false`/...) -- FreeBSD's own real
  version isn't a clean standalone drop-in (cascades into further FreeBSD-internal headers), so
  this one is a small, purpose-built reimplementation of just those macros, still tagged
  BSD-3-Clause (its shape is FreeBSD's, not independently invented, even though the file itself
  is). `<bitstring.h>` needed light patching too (`<stdlib.h>`/`<strings.h>` includes FreeBSD's own
  build environment provides transitively but musl doesn't, `__builtin_popcountl` in place of
  glibc's own internal `__bitcountl` alias). **A real location bug found live**: `bitstring.h`
  belongs directly under `/usr/include`, not `/usr/include/sys/` -- confirmed via OpenVi's own
  `#include <bitstring.h>` (no `sys/` prefix), matching real BSD's own `bitstring(3)` convention.
- **`build_nvi`**: OpenVi's own plain `GNUmakefile` (no autotools) directly -- already portable,
  ships its own BSD-compat shims (`openbsd/strlcpy.c`/`getopt_long.c`/`reallocarray.c`/...) for
  exactly this kind of non-glibc/non-BSD target. **Two real GNU Make variable-precedence gotchas,
  opposite directions, neither a bug in the Makefile itself**: `CURSESLIB`/`OS` are passed as
  `make` command-line args (highest precedence) so the Makefile's own `ifndef CURSESLIB`
  pkg-config-autodetect and `ifeq ($(OS), ...)` platform branches reliably short-circuit;
  `CFLAGS`/`LDFLAGS` are passed as **environment** variables instead, since a command-line-origin
  value would silently block the Makefile's own `CFLAGS += $(CSTD) $(INCLDS)` entirely (GNU Make
  blocks *any* makefile-side assignment to a command-line-overridden variable, `+=` included) --
  found live via every `cl/*.c` file failing `fatal error: bsd_stdlib.h: No such file or
  directory` despite that header genuinely existing in `include/`, simply because `-Iinclude` had
  been silently dropped.
- **`build_nano`**: the bare git checkout deliberately ships no `configure` (upstream's own
  `autogen.sh` clones a separate `gnulib` repo at `--depth=2222` and runs `gnulib-tool`+
  `autoreconf` to produce one fresh) -- rather than replicate that heavy chain, the `oxidebsd`
  branch overlays the exact generated output (`configure`/`config.h.in`/`m4/*`/the gnulib-derived
  `lib/` shim) the official v9.2 release tarball already ships. Real, full-featured wide-char
  build (`ncursesw`, not `--enable-tiny` -- this project's own ncurses has no narrow fallback, and
  a stripped-down editor isn't the point). **A third real Make gotcha, the opposite precedence
  choice from OpenVi's for a genuinely different reason**: automake substitutes `@LDFLAGS@` into
  the generated `src/Makefile` *at configure time* as a hardcoded plain `=` assignment, which
  always overrides an environment-origin value (unlike a command-line-origin one) -- an
  environment `LDFLAGS` at `make` time was silently ignored entirely, producing a `nano` linked at
  the linker's own default base (`0x402554`) squarely inside this kernel's reserved low-memory
  region instead of a real, chosen `-Wl,-Ttext-segment=`. Fixed by passing `LDFLAGS` as a `make`
  command-line argument at the final build step specifically (the one point after `configure` that
  still has a chance to override it).
- **A real BusyBox-applet env-var collision, found live via a real boot, not by inspection**:
  BusyBox already ships its own compact `vi` applet, and `oxfs_env_var_name` derives an env var
  name purely from the seeded filename with no notion of "already taken" -- both BusyBox's own `vi`
  and this real OpenVi replacement produced an env var literally named `OXFS_VI_ELF_PATH`.
  `Command::env`'s last-write-wins semantics meant OpenVi's real build was silently never actually
  reaching the seeded filesystem at all; `ls -la /bin/vi` inside a real boot reported BusyBox's
  much smaller size instead. Fixed the same way `NATIVE_BIN_UTILITIES` handles this class of
  collision for the native `/bin` utilities -- a small, separate `REPLACED_BUSYBOX_APPLETS` list
  (kept separate since `NATIVE_BIN_UTILITIES` also drives building each entry as a `bin/<name>`
  oxlibc crate, which doesn't fit a real cross-compiled C program) filters BusyBox's own `vi` out
  of the roster entirely.
- **A real, previously-unhit gap in this kernel's own VT100/ANSI console parser, found live**:
  `sys/console/vga.rs`'s `execute_csi` had no case for VPA (`ESC[Nd`, vertical position absolute)
  -- nothing in the prior userland roster ever emitted it, so the pre-existing `_ => {}` catch-all
  silently swallowed it instead of moving the cursor. OpenVi's own curses backend uses VPA for
  nearly every row-only cursor move (its status-line/tilde-fill redraw is almost entirely `ESC[Nd`
  sequences), so every subsequent write landed at whatever position the cursor was last left at
  instead of where the program intended -- visually collapsing a full-screen redraw down to just
  its own last line (confirmed via a real screendump showing only the status line, everything else
  black, before the fix; a full, correct redraw -- real file content, tilde fills down the whole
  screen, status line correctly on the last row -- after it). Fixed alongside its sibling gap, CHA
  (`ESC[NG`)/HPA (`` ESC[N` ``), the same class even though not yet confirmed hit.
- **A real `$PATH` gap, found live once something was actually seeded at `/usr/bin`**: pid 1's own
  `envp` only ever set `PATH=/bin` (see "Real job control" above) -- nothing had ever needed
  `/usr/bin` to exist until `nano` did. A bare `nano` invocation failed `ENOENT` via `execvp()`'s
  real `$PATH` search despite the file genuinely existing at `/usr/bin/nano`. Fixed:
  `PATH=/bin:/usr/bin`.
- **A real, severe, three-layered keyboard-input hang, found live *after* the section above's own
  original "verified" claim** (real rendering was genuinely confirmed; real interactive typing
  wasn't tested until a live session tried it and reported "nano freezes the entire machine,
  albeit it's still running") -- root-caused via `gdb`/`gdbserver` (the same live-debugging
  approach used for bmake's own investigations), not guessed:
  1. **`SYS_POLL`/`SYS_SELECT`'s generic "not a socket fd -> always ready" fallback (`sys/net/
     mod.rs`) was wrong for the console specifically.** Correct for a regular oxfs file or a pipe
     (this stack doesn't model real blocking for either), but stdin is genuinely, legitimately
     empty whenever nobody's typing -- and a real curses program's own `nodelay()`-mode "drain any
     further already-buffered keys without blocking" idiom (`nano`'s own `read_keys_from`,
     `usr.bin/nano/src/winio.c`) depends on a zero-timeout `poll`/`select` honestly reporting
     "nothing here yet" to know when to stop and hand a complete keystroke back to its own caller.
     Fixed: a real `console::stdin::has_bytes_available()` check, special-cased for `real_fd == 0`
     (a fixed, global mapping -- see `sys/fs/fd.rs`'s `init`) in both syscalls, instead of the
     blind fallback.
  2. **A real, separate, pre-existing bug that fix #1 newly exposed rather than caused**: `sys/net/
     rtl8139.rs`'s `poll_recv` had no genuine iteration bound, unlike every other syscall-reachable
     retry loop in this kernel (this section's own networking "architectural gotchas" already
     establish `spin_loop()` not `hlt()`, always `tsc`-bounded). Before fix #1, `oxidebsd_sys_poll`
     always returned "ready" on its own very first pass (stdin was unconditionally "ready"), so its
     own NIC-drain call (`net::poll()`, already unconditionally reachable every loop pass) never
     got a chance to iterate *internally* more than once either. A real `poll(stdin, timeout=-1)`
     genuinely needing to retry (exactly what fix #1 correctly enables) is what finally exercised a
     real, confirmed hang -- `gdb`'s own `RIP` sampling caught it stuck solid, several seconds
     apart, inside `poll_recv`'s own `CR_BUFFER_EMPTY` port read, cycling through "not empty" +
     "bad frame" forever. Root cause of *why* the ring gets stuck this way is still open; fixed the
     blast radius instead (bounded to 64 frames per call, then gives up and returns `None`,
     matching "ring empty," with a diagnostic log line if it ever fires) rather than claim to have
     found that deeper cause too.
  3. **The real, deepest root cause, found once #1 and #2 together still didn't fix a plain `echo`
     at the `hush` prompt**: both `oxidebsd_sys_poll`/`_select`'s own retry loops used
     `core::hint::spin_loop()` while genuinely waiting -- but this whole syscall runs with
     interrupts masked for its *entire* duration (`SFMASK`, same fact this section's own
     networking gotchas already document). Stdin's own readiness is **interrupt-driven** -- only
     `keyboard_interrupt_handler`'s own `push_byte` call ever adds a byte -- unlike NIC readiness,
     which the same loop's own `poll()` call discovers by directly reading hardware registers, no
     interrupt required. A bare `spin_loop()` while waiting on stdin therefore doesn't just waste
     cycles the way it might for a network fd -- it makes the one event being waited for
     *structurally impossible*, since the interrupt that would ever deliver it can't fire while
     this loop keeps spinning. Confirmed live end to end: real keystrokes genuinely reached the
     kernel's own ring buffer the whole time (`gdb` memory dumps showed `head` correctly advancing
     with every byte sent), so "blocked forever," not "lost," was always the right diagnosis --
     `read_keys_from`/`get_kbinput` never returned because the syscall it was stuck in could
     structurally never see its own wakeup condition become true. Fixed: when stdin is one of the
     awaited fds, block via the exact same `WaitingForStdin` primitive `console::stdin::read`
     itself already uses (a real context switch, which is what actually re-enables interrupts) --
     scoped to "stdin is among the awaited fds" rather than every poll, since a poll that only
     awaits network fds still needs the original spin-and-repoll behavior to keep actively pumping
     a connection nothing else services, and no real caller in this kernel currently mixes stdin
     with a socket fd in one call.
- **This CLAUDE.md's own earlier "sys_read on stdin is non-blocking" claim (see the syscall-ABI
  section above) is stale**, found live investigating this same bug: `console::stdin::read` is a
  real, genuine blocking implementation (`ProcState::Blocked(BlockReason::WaitingForStdin)` +
  `scheduler::schedule()`, woken by `push_byte`'s own `wake_blocked_readers`), not a
  return-`0`-immediately one. Not yet corrected at that section -- flagged here so a future pass
  doesn't trust it without checking the real source first.
- Verified end to end via a real boot, driven headlessly through the QEMU monitor's own
  `sendkey`/`screendump` (`OXIDEBSD_QEMU_DISPLAY=none`, no window needed): a bare `vi /etc/passwd`
  and a bare `nano /etc/passwd` each produce a real, correct, full curses render *and* now
  genuinely accept real keystrokes -- confirmed via `screendump` showing real inserted text
  (`nano`'s own "Modified" indicator lighting up, `vi`'s own insert-mode text landing at the
  cursor), not just rendering. Both exit cleanly back to a plain `hush` prompt through their real
  save-prompt/`:q!` flows, and a plain `echo` at the `hush` prompt itself -- unaffected by any of
  this section's own changes on its face, but genuinely exercising the identical `poll`/`select`
  code path -- was retested and confirmed still correct.
- **Two more real, user-reported bugs, found the same way**: "nano freezes" turned out to be three
  kernel-level input bugs (above); once those were fixed, real interactive use surfaced two more,
  narrower ones -- "can't save documents" and "kinda corrupted due to some unsupported tty
  features."
  1. **The real corruption**: `sys/console/vga.rs`'s `execute_csi` had no case for `X` (ECH,
     "erase character", `ESC[NX]`) -- the same silently-swallowed-by-`_ => {}` shape as the earlier
     VPA/CHA/HPA gaps. `nano`'s own status-bar/shortcut-list redraw (`usr.bin/nano/src/winio.c`)
     uses `ECH` to blank stale menu-item text before writing shorter replacement text over the same
     cells (e.g. switching between the main-menu footer and the write-prompt's own shorter one) --
     without it, old text was never actually cleared, so new text landed *on top of* it. Confirmed
     live via a real screendump showing garbled, overlapping footer fragments exactly where a
     shorter label replaced a longer one; fixed and reconfirmed clean.
  2. **The real save failure, root-caused precisely, not patched around**: pressing Enter to
     confirm `nano`'s "Write to File" prompt did nothing -- the dialog just sat there forever, even
     though the exact same physical Enter keystroke worked fine for inserting a newline in the main
     editor. Traced to `pc-keyboard`'s own `Us104Key` layout (`lib.rs`'s `KeyCode::Return =>
     DecodedKey::Unicode('\u{000A}')`, i.e. LF) -- every real terminal and every curses/readline
     program's own shortcut table is built around a physical Enter key sending **CR** (`\r`,
     `0x0D`) raw (ICRNL-style LF translation is a later, optional *tty-driver*-only step); `nano`'s
     own prompt-confirmation logic (`acquire_an_answer`, `usr.bin/nano/src/prompt.c`) checks only
     its shortcut table (`^M`/`\r` -> `do_enter`, `global.c`), which a raw LF byte never matches --
     while the *main editor's* own newline handling happens to also accept `\n` as a permissive
     fallback (`nano.c`'s own `input == '\r' || input == '\n'` check), which is exactly what masked
     this in every earlier test in this same section. Fixed at the actual translation point
     (`sys/cpu/interrupts.rs`'s new `normalize_enter_key`, called right after `process_keyevent` in
     both the real PS/2 IRQ handler and the USB HID synthetic-scancode path): rewrites LF back to
     CR specifically for the `Return`/`NumpadEnter` key, using the still-available raw `KeyCode`
     rather than the already-collapsed `DecodedKey`. **Deliberately not a blanket `\n` -> `\r`
     rewrite** -- Ctrl+J legitimately decodes to the same Unicode LF via `pc-keyboard`'s own
     `HandleControl` mapping and is a real, distinct keystroke (`nano`'s own `^J` -> `do_justify`)
     that must stay LF; a blanket rewrite would have made the two indistinguishable. Verified live
     end to end: `nano`'s own "[ Wrote 1 line ]" confirmation, the "Modified" indicator correctly
     clearing, and the real saved content confirmed via `cat` afterward.
- **Known, disclosed gaps, not yet chased**: `nano` probes `ioctl(TIOCLINUX)` at startup (`0x5603`,
  a real Linux-console-specific request this kernel doesn't implement) -- logged as unrecognized,
  harmless, nano works fine without it. ncurses' own utility programs (`tic`/`tset`/`tput`/`clear`/
  `infocmp`) aren't built or seeded yet -- a real on-target self-hosting attempt (building ncurses/
  nano from source under `ash`+on-target `clang`+`bmake`, the way bmake's own self-hosting was
  proven, see that section above) is a natural next step, not yet attempted this session. The real
  root cause of `rtl8139::poll_recv`'s own `CR_BUFFER_EMPTY`-never-resolves hang (item 2 above)
  is still open -- the bound prevents a permanent freeze but doesn't explain *why* the ring gets
  into that state, and could still degrade a real poll's latency by up to 64 wasted iterations
  every retry pass until it's actually chased down.

## Shell: `lib/libsh`, `/bin/sh`, `/sbin/init_sh`

From-scratch Rust POSIX shell core (spec: OxideBSD-doc `INIT_SH.md`); `bin/sh` and `sbin/init_sh`
are std binaries over it (`init_sh` adds the `init-dialect` feature, still empty). `/bin/sh` is
libsh now — bmake/ninja/`system()`/the POSIX pilot's driver all go through it — and it's pid 1
(`sys/kernel_main.rs`, `spawn_with(..., &[b"-sh"], ...)`: a login shell with `HOME=/`). Interactive
mode (`src/interactive.rs`, `lineedit.rs`, `jobs.rs`, `prompt.rs`): its own raw-mode line editor
(the console has no line discipline), history in `$HISTFILE` (`~/.sh_history`), Tab completion,
Ctrl+R, `PS2` continuation via `ParseError::incomplete`, job control (`set -m`, `jobs`/`fg`/`bg`,
`%n` specs), FreeBSD-sh `PS1` escapes. Shell errors are `Flow::Fatal` (ends a script, not an
interactive shell); only `exit`/`set -e` are `Flow::Exit`. **The console's fds are one-way** (fd 0
read-only, 1/2 write-only), so the editor reads fd 0 and draws on fd 2 — writing to a dup of fd 0
fails silently. `init_sh` refuses interactive mode. BusyBox hush remains at `/bin/hush`.
- The keyboard driver now sends Linux-console sequences for arrows/Home/End/Insert/Delete/PgUp/PgDn
  (`dispatch_key`, `sys/cpu/interrupts.rs`) — they used to be dropped entirely — and DEL (0x7f)
  for Backspace, matching `TERM=linux`.
- Host-testing the interactive shell: drive `target/x86_64-unknown-linux-gnu/debug/libsh` through
  a pty (Python `pty.fork()`); the diff corpus only covers non-interactive behavior.
- `lib/libsh` is its own workspace targeting the host: `cargo test` there runs
  `tests/differential.rs` (`tests/diff/*.sh` vs `dash`: stdout + status exact). Its
  `.cargo/config.toml` adds `std` to `build-std`, since cargo merges that array with the root's.
- `tests/sh_syscall_smoke.rs` runs the same corpus on target (`/sh-smoke/`) against the
  checked-in `*.expected` (dash's host output) — regenerate those with dash when a script changes.
- `build_std_oxidebsd_userland_crate` takes a crate path now (not just `regress/std/<name>`).

## Filesystem layout (OxideBSD-doc `HIER.md`)

oxfs seeds the BSD hierarchy HIER.md defines, not a flat `/bin`: `/bin` (44, single-user
essentials) / `/sbin` / `/usr/bin` (clang, ld.lld, bmake, nano, ninja, most applets) / `/usr/sbin`
/ `/usr/libexec/getty` / `/usr/games/doom` / `/usr/tests` (regress fixtures: `musl`, `smoke`,
`std-*`). Clang's resource dir follows the binary: `/usr/lib/clang/23`. Root PATH (pid 1, POSIX
driver) is `/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/games` (the POSIX driver omits `/usr/games`). 48 BusyBox applets were
cut outright (2026-09-23); `build_busybox.rs` no longer carries the native-utility/`vi` tuples, so
there's no roster filter any more. Older sections below still say `/bin/clang` etc.

## ninja (`usr.bin/ninja`), `ppoll(2)`, and demand-grown user stacks

- **ninja**: submodule of `OxideBSD/ninja-oxidebsd` (`oxidebsd` branch, v1.13.2). Built with the
  fork's own `Makefile.oxidebsd` -- plain POSIX make, no Python (`configure.py`) or CMake -- by both
  `build.rs`'s `build_ninja` (host cross-build, static `ET_EXEC` at `0x1e000000`, seeded
  `/usr/bin/ninja`) and on-target bmake + `clang++` from the seeded `/usr/src/ninja` -- **self-hosts**:
  `cd /usr/src/ninja && bmake -f Makefile.oxidebsd && ./ninja --version` builds all 32 files and
  prints `1.13.2` (verified headless; needs `src/third_party/` seeded, header-only deps).
  `tests/ninja_syscall_smoke.rs`: on-target `ninja -C /ninja-demo` (2 `clang -c` jobs + link via
  `/bin/sh`), then runs the result.
- **`SYS_PPOLL=575`** (`sys/net/mod.rs`, net module): `poll` + atomic sigmask swap, reusing
  `do_sigsuspend`'s deferred restore (`begin/end_temporary_sigmask`). Limit inherited from `poll`:
  a signal arriving mid-wait isn't noticed until the wait ends. Fixed alongside: `poll(NULL, 0, t)`
  panicked the kernel (slice from a null pointer). `tests/ppoll_syscall_smoke.rs`.
- **User stacks grow on demand**: `USER_STACK_RESERVE` (8 MiB) below `USER_STACK_TOP`; only the top
  `user_stack_pages()` -- or enough for the argv/envp image -- are mapped at exec.
  `mm::try_grow_user_stack` maps a zeroed page for a not-present fault in the reserve, called first
  in `page_fault_handler` for **both rings** (the kernel writes user stacks too: `read()` into
  on-stack buffers, signal frames); lock-light (mapper from `CR3`, `try_lock` frame allocator).
  Found via ninja (`BuildLog::Load`'s 256 KiB on-stack buffer vs. the old fixed 256 KiB stack).
  Also fixed: an `execve` whose args outgrew the eager stack panicked the kernel
  (`user_stack::write_image`). SysV shm's region now stops at the reserve's bottom.
- Ring-3 page faults and `#GP` now log `[fault] pid N ... ip ...` (Linux's "segfault at" line).

## Dynamic linking: milestone 1, real `PT_INTERP` (`sys/process/elf.rs`, `sys/process/lifecycle.rs`, `build.rs`, `sys/modules/oxfs`)

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
- **`SYS_MPROTECT=492`** — `ld.so`'s RELRO step calls real `mprotect`, now gained real, scoped
  enforcement (see "Real anonymous `PROT_NONE` + scoped real `mprotect(2)`" below) — RELRO's own
  call target (a `PT_LOAD` ELF segment) falls outside that scope and stays the original permissive
  no-op, confirmed unaffected.
- Verified end-to-end via `tests/dynlink_syscall_smoke.rs`.
- **Milestone 2, not started**: `dlopen`/`dlsym`/`dlclose`/`dlerror` — blocked on `mmap`/`mprotect`
  actually enforcing real placement/protection outside the narrow anonymous-mmap-window scope that
  now exists (real file-backed segment protection and `MAP_FIXED` placement guarantees a real
  dynamic loader would need are still permissive no-ops/bump-allocators).

## Real PIE/ASLR loading + native `/bin` utilities (`sys/process/aslr.rs`, `lib/oxlibc`, `bin/*`, `build.rs`)

- A no-`PT_INTERP` `ET_DYN` main binary is a real PIE: `do_execve` loads it at a fresh random,
  page-aligned bias from `aslr::pick_bias()` (~32 bits, window starts at `0x3000_0000_0000`, an
  empty gap above the mmap region). `fork` never re-picks (it never calls `elf::load`). Every
  fixed-`ET_EXEC` (`regress/*`, BusyBox) is unchanged. `user_stack::build` adds `main_bias` to
  `AT_PHDR`/`AT_ENTRY` (silently correct before only because that bias was always 0).
- **No in-kernel relocation processor**: a PIE-model binary must have *zero* relocations, enforced
  at build time by `build_pie_crate_at`'s `assert_zero_relocations` (fails the build). Traps found
  live: (1) ordinary disciplined Rust still gets relocations, because `#[track_caller]` bounds-check
  `Location` metadata embeds a real address — a fixed-address link hides this entirely (same source:
  0 relocs as `ET_EXEC`, 4 as `ET_DYN`); `build_pie_crate_at` bakes in `-C panic=immediate-abort -Z
  location-detail=none` to fix it (so `#[panic_handler]` is mostly dead code). (2) `_start as usize
  as u64` compiles to a stored, GOT-style address — take symbol addresses with `asm!("lea …",
  sym _start)`. (3) no `core::fmt`, no tables of slices (use `if` chains).
- PIE crates use **no `-T<linker.ld>`**: rust-lld's default script is what maps the ELF header/phdrs
  into the first `PT_LOAD` (so `AT_PHDR` is dereferenceable; note the first phdr is `PT_PHDR`, not
  `PT_LOAD`). Their `build.rs` is just `-pie` + `--no-dynamic-linker`.
- `lib/oxlibc` (`#![no_std]`, deliberately the seed of the eventual libc): syscall stubs,
  `entry_point!` (`global_asm!` `_start` capturing `RSP`), `exit`, the crate graph's one
  `#[panic_handler]`, `fs`/`io`/`path`/`args`. `bin/{echo,true,false,pwd,cat,ls,mkdir,rm,cp,mv,ln,
  touch}` bind to the same `OXFS_<NAME>_ELF_PATH` names their BusyBox predecessors used, so
  `sys/modules/oxfs`'s `seed_file` calls are unchanged. `NATIVE_BIN_UTILITIES` in `build.rs` filters
  them out of the roster — deliberately *not* by deleting their tuples from `build_busybox.rs`,
  which would force a ~1h full BusyBox rebuild (the inert tuples can go with the next unrelated
  edit there). `sbin/lsoxmod` is PIE too.
- Behavior notes: flags are `-n` echo, `-a -l -1 -C --color=…` ls (sorted; on a tty a plain `ls`
  is column-major and colored — dirs bold blue, symlinks cyan, executables green; off a tty, i.e.
  redirected/piped, it's one-per-line and plain, since `tty_size()`/`TIOCGWINSZ` only succeeds on
  the console; `-l` has aligned columns, a `total` line, owner/group names from `/etc/passwd`+
  `/etc/group`, UTC mtime, ` -> target`), `-p` mkdir, `-r -f` rm, `-r` cp, `-s` ln, `-c` touch
  (really updates mtime); short-flag clusters (`-rf`) work. `lib/oxlibc` has `time`
  (`clock_gettime` + epoch→UTC civil date) and `io::BufWriter`.
- **A console `write` costs ~1 ms** (framebuffer render + serial mirror): `ls /bin` took 770 ms to
  the console but 30 ms to `/dev/null`, `ls -l /bin` 3.25 s vs 70 ms. Any utility that prints many
  small pieces must batch through `BufWriter`, not `print`. `TIOCGWINSZ` reports the console's
  real grid (`console::vga::width()/height()`, framebuffer ÷ 8x16, e.g. 160x50 at 1280x800) — it
  used to be a fixed 24x80, which left `ls` columns and `hush` wrapping on half the screen. `cat`
  with no file args reads fd 0 (fine from a pipe). **Corrected 2026-09-22** (this entry previously
  claimed the console's stdin was non-blocking, so bare interactive `cat` "just exits" — stale,
  see the ncurses/nano/nvi section's own real input-hang writeup for why): stdin is a real,
  genuine blocking read, so a bare interactive `cat` now genuinely **blocks** waiting for input,
  confirmed live — double-echoing each typed character (the kernel's own auto-echo plus `cat`'s
  own read-then-write-to-stdout loop, both independently echoing the same bytes, a real and
  expected effect against a program with no line-editing of its own). **Real, disclosed gap found
  the same way**: this kernel has no canonical-mode (`ICANON`) EOF-character handling at all (see
  the syscall-ABI section's own `ICANON` doc comment) — Ctrl+D lands as a plain byte `0x04`, not a
  real end-of-file, so a bare interactive `cat` with no controlling-tty session established (the
  common case; nothing here has called `setsid`/`TIOCSCTTY`) currently has no keyboard-reachable
  way to end it at all. `rm -r` re-opens the directory after each batch: oxfs's `getdents` cursor
  counts *used* records, so deleting under a live cursor skips entries.
- Seeded file modes (`oxfs`'s `seed_mode`): `0755` only for what the kernel could execute — a
  `#!` script or an `ET_EXEC`/`ET_DYN` ELF (static binaries, PIEs, `libc.so`) — else `0644` (data,
  headers, `.a`, relocatable `.o`); `/etc/shadow` stays `0600`. It used to be `0755` for everything.
- **Gotcha**: a persistent `target/oxfs_disk.img` keeps its old seeded binaries — the native
  utilities only appear after a fresh format (delete the image; formatting takes ~10 min).
- Verified by `tests/pie_aslr_smoke.rs` (real per-exec randomization, fork inherits),
  `tests/native_bin_syscall_smoke.rs` (all 12, flags + error paths), and `sh /test_busybox.sh`
  through real hush (104/104), driven headlessly via `OXIDEBSD_QEMU_MONITOR` `sendkey`.

## Real getrandom/sysinfo/sigaltstack/pause/sigsuspend/POSIX timers/POSIX message queues/SysV IPC (`sys/modules/posix_compat`, `sys/modules/signal`, `sys/modules/clock`, `sys/fs/{mqueue,sysv_msg,sysv_sem,sysv_shm,sysv_ipc}.rs`)

A 28-syscall batch (`526`-`553`) pre-reserved with permanent invented numbers ahead of having real
handlers (see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s "Pre-reserved" section for why). All 28 now have
real handlers, landed roughly in POSIX/SysV order except SysV IPC landed message queues before
semaphores before shared memory (each needed progressively more novel machinery).

- **`getrandom`** (`526`): thin plumbing to `sys/random.rs`'s existing generator. Only reachable
  via `getentropy()` in this port's roster, which caps `len` at 256 and loops — this handler
  always fills the whole request in one shot so that loop exits after one iteration.
- **`sysinfo`** (`527`): `RawSysinfo` (368 bytes, confirmed via a direct C `offsetof`/`sizeof`
  probe). Real `uptime`/`totalram`/`procs`; `freeram == totalram` (no dealloc tracking); rest
  honest zero.
- **`sigaltstack`** (`528`): bookkeeping via `Process::altstack`, real `SA_ONSTACK` delivery (see
  Signal handling module above).
- **`pause`** (`529`): first item needing a genuine new primitive — `BlockReason::
  WaitingForSignal` + `wake_if_paused`, checked-before-block/looped-after-wake (avoids lost
  wakeup/stale-block, the discipline every blocking primitive here follows).
- **`sigsuspend`** (`530`): reuses `pause`'s primitive plus a temporary `blocked_signals` swap.
- **POSIX timers** `timer_create`/`_settime`/`_gettime`/`_getoverrun`/`_delete` (`531`-`535`,
  `sys/process/timers.rs`): `Process::posix_timers`, up to 8, relative/`TIMER_ABSTIME` arming
  against `CLOCK_MONOTONIC`/`CLOCK_REALTIME`, real overrun accounting (HPET-precision when
  present, see "Real-time clock" above), delivered from the timer IRQ handler. Not inherited by
  fork; disarmed by execve. Also accepts `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID`
  (real musl unconditionally claims `_SC_CPUTIME` support; rejecting these was a real bug, fixed).
- **POSIX message queues** `mq_open`/`_unlink`/`_timedsend`/`_timedreceive`/`_notify`/`_getsetattr`
  (`536`-`541`, `sys/fs/mqueue.rs`): a separate name→queue namespace, real priority-ordered
  delivery, real bounded blocking send/receive with real signal-interrupt support, real
  `mq_notify`/`SIGEV_SIGNAL` via `do_kill` directly. `mq_close` isn't its own syscall — an mqd
  rides the ordinary fd registry. `mq_timedsend`/`_timedreceive` needed a musl call-site patch (5
  real args packed into one register: high 32 bits = len, low 32 = mqd).
- **SysV message queues** `msgget`/`msgsnd`/`msgrcv`/`msgctl` (`550`-`553`,
  `sys/fs/sysv_msg.rs`): integer-`key_t`-addressed, fd-less namespace (a queue lives from `msgget`
  until explicit `IPC_RMID`). Real `ipc_perm` checks, real `msgtyp` selection semantics, real
  timestamps. A real bug found in testing: an early draft removed a matched message *before*
  checking buffer size, destroying it on `E2BIG` — fixed to peek length first (real Linux
  "too-big message stays queued" semantics).
- **SysV semaphores** `semget`/`semop`/`semctl`/`semtimedop` (`546`-`549`,
  `sys/fs/sysv_sem.rs`): same `key_t`→id namespace, factored through a shared `sysv_ipc.rs`.
  `semop`/`semtimedop` apply a whole `sembuf` array atomically (simulate-then-commit-or-nothing).
  Real `SEM_UNDO` via `Process::sysv_sem_undo`, applied on process termination. A new
  `BlockReason::WaitingForSemOp` backs real `GETNCNT`/`GETZCNT`.
- **SysV shared memory** `shmget`/`shmat`/`shmctl`/`shmdt` (`542`-`545`,
  `sys/fs/sysv_shm.rs`), the one sub-batch needing real memory-management plumbing: `shmget`
  eagerly allocates a fixed `Vec<PhysFrame>`, zero-filled once. **`shmat` is the real proof of
  shared memory** — every attach against the same id maps those exact same frames into the
  caller's own page table (`SHM_REGION_BASE = 0x_4000_0000_0000`). `shmdt` is the one syscall in
  this batch that actually unmaps on the way out. Real `IPC_RMID`-while-attached lifecycle. **Not
  inherited across `fork`** (fork here is eager-copy, never COW) — starts empty in a child, same
  precedent `sysv_sem_undo` established.

Closes the whole 28-item batch — see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own per-item write-up for
detail this section only summarizes.

## Real preemptive scheduling (`sys/process/scheduler.rs`, `sys/cpu/interrupts.rs`, `sys/cpu/fpu.rs`)

The scheduler is no longer purely cooperative. A process still leaves `Running` voluntarily
(`scheduler::schedule()`, unchanged) — but can now also be preempted:
`interrupts::timer_interrupt_handler` calls `schedule()` directly whenever it catches a process
executing ring-3 code and a quantum has elapsed. **`Process::quantum_ticks_left`** is set to a
fresh `PREEMPT_QUANTUM_TICKS=4` (40ms) every time a process is (re)activated to `Running`, and
decremented once per tick it's found running — a real per-process round-robin quantum, not a
purely global tick-phase check (an early version used `now.is_multiple_of(PREEMPT_QUANTUM_TICKS)`,
which gave a freshly-created thread anywhere from 1 to 4 ticks of guaranteed runtime purely by
luck of the global counter's phase — real, reproducible races under this kernel's single-core
QEMU/TCG timing, since a real multi-core machine's own fast instruction window almost never loses
the same race. `do_clone` resets the *caller's* own remaining quantum on creating a new thread,
giving it a guaranteed window to finish any immediate follow-up work before the new child could
preempt it).

- **Deliberately scoped to ring-3 only, not full kernel preemption.** Checked via the interrupted
  frame's CS RPL bits, not a software flag. Kernel/syscall/module code is never preempted
  (`IA32_SFMASK` already clears `IF` for a syscall's entire duration). This is the load-bearing
  scoping decision: user-mode code never holds a kernel `spin::Mutex`, so no existing critical
  section anywhere needed auditing for preemption-safety.
- **EOI is sent before the possible `schedule()` call, not after** — load-bearing: until EOI, the
  PIC won't deliver *any* further timer interrupt to *anyone*, freezing every `ticks()`-gated
  wakeup in the kernel permanently.
- **Real per-process `FXSAVE`/`FXRSTOR` across every context switch** (`Process::fpu_state`) —
  became load-bearing once preemption could interrupt at literally any instruction, not just a
  syscall boundary. A freshly spawned/forked process starts from `cpu::fpu::clean_state()` (a real
  CPU-reset image captured once via `fninit`+`fxsave` at boot).
- **A real scheduler bug found chasing a flaky hang**: `schedule()`'s re-enqueue branch used to
  push the outgoing pid back onto `READY_QUEUE` without updating its own `state` to `Ready` —
  harmless before real preemption, but a cross-process `SIGSTOP` targeting a merely-interrupted
  (not genuinely re-blocked) process failed its own `state == Ready` dequeue check, leaving it
  queued *and* marked `Stopped` — the scheduler later resumed it anyway, silently un-stopping it.
  Fixed at the source: `schedule()` now sets `prev.state = Ready` before enqueueing.

## Real threading: `clone(2)`, `pthread_create`/`join`, shared address spaces (`sys/process/`, `sys/memory/address_space.rs`, `sys/fs/fd.rs`)

Closes the single biggest foundational architecture blocker this project tracked — motivated by
real POSIX AIO, which both musl and glibc implement as pure userspace logic over a
`pthread_create` worker pool (no distinct kernel AIO syscall family exists on real Unix either).

- **Phase 1**: `clone.s`/`__unmapself.s` hardcoded raw Linux syscall numbers directly (same bug
  class as `vfork.s`). Fixed: `clone.s` targets a real reserved `SYS_CLONE=555`;
  `__unmapself.s` calls this ABI's real `SYS_MUNMAP`/`SYS_EXIT` directly.
- **Phase 2**: `Process::tgid: Pid` splits real `getpid()`/`gettid()` apart — set at both
  spawn/fork (never inherited by a forked child, a real process), untouched by execve.
- **Phase 3**: real `FUTEX_WAIT`/`FUTEX_WAKE` (`process::do_futex`, `BlockReason::
  WaitingForFutex(tgid, addr, deadline)`), scoped by `tgid` not raw pid (correct today since no
  ASLR means unrelated processes can share addresses like `USER_STACK_TOP`, and happens to be
  exactly right for `CLONE_THREAD` sharing).
- **Phases 4+5, the actual thread-creation prerequisite** — five changes to a kernel with no prior
  notion of two live threads sharing an address space: (1) `AddressSpace` → `Arc<PhysFrame>`-
  refcounted, `teardown` gated on `strong_count == 1`; (2) `ThreadGroupShared`
  (`cwd`/`root_inode`/`umask`/`uid`/`gid`/`brk`/`mmap_file_regions`/`sigactions`) `Arc<Mutex<>>`-
  wrapped, shared by every `CLONE_THREAD` sibling; (3) `sys/fs/fd.rs` keyed by `tgid`, not raw pid
  — real `CLONE_FILES` sharing falls out for free (`do_clone` must *not* also call
  `fs::fd::fork_inherit`, or it orphans duplicate entries); (4) real `do_clone`/`SYS_CLONE=555`;
  (5) per-thread `SYS_EXIT` — a non-leader thread's table entry is marked `Zombie` and deferred
  via `scheduler::queue_thread_reap`, drained at the top of every `schedule()`.
- **Real `CLONE_CHILD_CLEARTID`** (`Process::clear_child_tid`) — needed for a genuinely unmodified
  `pthread_create()`/`pthread_join()` round trip: real musl's `__pthread_exit` routes
  `__thread_list_lock`'s release through a real kernel clear-and-wake at task-exit time.
- **Real per-address-space frame reclaim**: `memory::BootInfoFrameAllocator` gained a real
  `FrameDeallocator`; `AddressSpace::teardown` walks and frees every `USER_ACCESSIBLE` frame
  beneath a discarded address space (safe since every page-table structure frame is always
  freshly allocated per address space, fork is eager-copy never COW). `SHARED_LEAF` (a repurposed
  PTE bit) marks the two real exceptions that *do* alias a leaf across address spaces — SysV
  `shmat` and fd-backed `MAP_SHARED` mmap — `teardown` skips those. `Process::address_space` is
  `Option<AddressSpace>` (`None` only for a `Zombie` whose frames are already reclaimed) —
  `terminate_process` tears down frames **immediately at exit**, not deferred to a future
  `wait4`, closing a real physical-frame-exhaustion cascade the full POSIX corpus otherwise hit
  (many `pthread_*`/`fork` tests fork-and-exit without ever `wait4`ing). Every OOM path along this
  chain (`KernelStack::new`, `AddressSpace::new`/`copy_table_level`, `map_user_stack`,
  `fault_trampoline::map`) returns a real `Result` instead of hard-panicking, since a single
  userspace process exhausting a shared pool must not take the whole kernel down —
  `do_fork_from_current`/`do_clone` propagate a real `ENOMEM`; boot-time call sites still panic
  (no syscall caller to report to that early).
- **A real, separate `do_munmap` frame leak**, found chasing renewed physical-frame exhaustion
  after the fix above: the unmap loop discarded the frame `Mapper::unmap` handed back instead of
  ever returning it to the frame allocator — every real `munmap()` (including `pthread_join()`'s
  own stack unmap on every join) leaked one physical frame per page, permanently. Fixed: capture
  the frame and return it via `FrameDeallocator::deallocate_frame` unless it carries `SHARED_LEAF`
  (owned by `MMAP_FILE_CACHE` instead, released via `release_mmap_file_ref`). `sysv_shm.rs`'s
  near-identical-looking `shmdt` unmap loop was checked and is correctly unaffected (every page
  there is unconditionally shared, owned by `SEGMENTS`).
- **Named POSIX semaphores** (`process::limits::futex_key`): a *shared* (non-`FUTEX_PRIVATE`)
  futex now resolves `addr` through the caller's address space to the real physical address
  backing it, rather than keying purely on `(tgid, addr)` — real `sem_open()` semaphores are
  `pshared`, and two independently `fork()`ed processes generally map the same `/dev/shm`-backed
  region at *different* virtual addresses (this kernel's `NEXT_MMAP_PAGE` bump allocator is
  global, not reset per caller), so a waiter's `FUTEX_WAIT` and a waker's `FUTEX_WAKE` almost
  never agreed on the same key before this fix. A private futex is unaffected, still keyed by
  `(tgid, addr)` (still required on this no-ASLR kernel). Named POSIX shared memory (`shm_open`)
  still needs its own separate cross-process coordination work beyond this.

**Verified**: `tests/clone_syscall_smoke.rs` (raw `clone(2)`), `tests/pthread_syscall_smoke.rs` (a
genuinely unmodified `pthread_create()`/`pthread_join()` C fixture),
`tests/sem_open_syscall_smoke.rs` (unmodified `sem_open()`+`fork()`+`sem_post()`/`sem_wait()`).
**Unlocks**: POSIX AIO with zero further kernel work; `pthread_mutex_*`/`_cond_*`/`_rwlock_*`/
`_barrier_*`/`_spin_*` all expected to already work (userspace logic over the same real
`futex(2)`). Real `dlopen` stays not done (blocked on `mprotect` enforcement, unrelated to
threading).

**Two real bugs found writing the raw-`clone(2)` smoke test itself**: a child's own new stack must
be `static mut`, not plain `static` (an all-zero immutable static gets placed read-only by
rustc); a hand-written `asm!` block must `setc` immediately after `syscall`, before any
flag-clobbering instruction.

## Real ring-3 fault-to-signal delivery, and real mmap fixes (`sys/cpu/interrupts.rs`, `sys/process/fault_trampoline.rs`, `sys/process/mm.rs`, `sys/modules/oxfs/`, `sys/syscall/ffi.rs`)

**`interrupts::page_fault_handler` used to reboot the whole kernel on any page fault, ring-3 or
not** — a wild pointer deref in any userland program took the entire VM down. Fixed: on ring-3
(checked via the interrupted frame's CS RPL; ring-0 stays a hard reboot), resolves a real signal
(`SIGBUS` for a reference into a live mapping's own reserved-but-unbacked tail, `SIGSEGV`
otherwise) via `do_kill`'s self-signal path, then redirects to a real, kernel-authored,
user-executable trampoline page (`process::fault_trampoline`, fixed VA `0x_1FFF_FFFF_F000`).
`general_protection_fault_handler` and `invalid_opcode_handler` (`#UD`, real `SIGILL`) needed and
got the identical ring-3 treatment, each found missing it independently later.

- **Why not invoke the handler directly from the fault handler**: `extern "x86-interrupt"`'s
  compiler-generated entry/exit exposes no Rust-visible GPR fields. Fix: the trampoline is
  `mov eax, SYS_FAULT_PUMP (554); syscall; ud2` — redirecting `instruction_pointer` there forces a
  real `SYSCALL` through `syscall_entry`'s already-correct GPR capture; `syscall_dispatch`
  special-cases `SYS_FAULT_PUMP` like `SYS_SIGRETURN`. **Redirecting execution this way
  permanently clobbered the interrupted process's real `RAX` before it could be captured** until
  fixed by stashing it to a scratch slot on the trampoline's own page first — and separately, see
  the syscall-ABI section's `SYSRETQ`/`RCX` note for the deeper version of this same class of bug.
- **Real MPR-correct partial mapping**: `mm::do_mmap_file_backed` only backs/maps pages covered by
  a file's real (page-rounded) extent — the tail past it gets no page-table entry at all, so a
  reference there raises `SIGBUS` rather than silently succeeding against a zero page.
- **A real, separate bug found chasing this, not about mmap at all**: `open(O_CREAT)` on a
  brand-new path defers the real inode/dir-entry until first commit; `unlink()`ing before that
  commit found nothing to remove and silently no-op'd, then the deferred commit resurrected the
  name. Fixed: `OpenFile::Write` gained `unlinked: bool`.
- **Real `MAP_FIXED`/`MAP_PRIVATE` flags** riding the wire (packed into `prot`'s unused high bits,
  musl patched accordingly) with real `EBADF`/`EINVAL` validation — previously the kernel guessed
  anonymous-vs-file-backed purely from `fd == -1` and ignored `MAP_FIXED` entirely. Real
  `mtime`/`ctime` tracking (`oxidebsd_unix_time`). Real `mlockall(MCL_FUTURE)`/`RLIMIT_MEMLOCK`
  enforcement via `ThreadGroupShared`'s `mlockall_future`/`locked_bytes` — no longer a no-op.
  Real `ENXIO` for an out-of-bounds nonzero-offset mmap; real `EOVERFLOW` when `off + len` exceeds
  `i64::MAX` (musl's own client-side guard against this was removed on the `oxidebsd` branch —
  deliberately fixed even though real glibc+Linux fails this same test too, since this project
  targets literal POSIX-spec conformance).
- **Real anonymous `PROT_NONE` + scoped real `mprotect(2)`**: `SYS_MPROTECT` had been a total
  no-op; real musl's `pthread_create()` builds a guard page via `mmap(PROT_NONE)` then
  `mprotect()`s the usable tail — with both stubbed, no pthread stack ever had a real guard.
  `PROT_NONE` anonymous mmap now leaves the region genuinely unmapped (load-bearing:
  `AddressSpace::teardown` treats a clear `USER_ACCESSIBLE` bit as an absolute "nothing here"
  signal and would otherwise leak a frame per guard page). `mprotect(2)` enforcement is
  deliberately scoped to only the mmap-managed VA window (`MMAP_REGION_BASE..CEILING`) — outside
  it (a `PT_LOAD` segment, the heap, `ld.so`'s own RELRO target) stays the original permissive
  no-op, since the module/kernel region's page tables are shared physical frames across every
  process. A not-yet-backed page inside the window demand-allocates on `mprotect` instead of
  `ENOMEM`ing, matching musl's guard-then-widen sequence — uses
  `map_to_with_table_flags` with intermediate P2/P3/P4 flags always pinned fully open (the
  convenience `map_to` derives parent flags from the leaf, which would leave a widened region's
  own intermediate tables permanently inaccessible).
- **A real `sys_pwritev2` gap**: missing the negative-offset check `sys_pwrite` already had —
  real musl's `pwrite()` issues `SYS_pwritev2`, not `SYS_pwrite`, so that check never ran. A test
  calling `pwrite(fd, buf, len, -1)` (musl maps to `-2` internally) drained oxfs's entire
  free-block pool in one `resize_inode_data` call before failing `EIO` instead of the `EINVAL`
  POSIX requires, starving every later test in the same boot that needed to write a file. Fixed:
  reject any `ofs` other than exactly `u64::MAX` (the real "current position" sentinel) that's
  negative.
- `pthread_create/1-5.c`/`3-2.c` (real pthread guard-page/stack-size-immutability checks) still
  `FAIL` even with a real, verified-working guard mechanism — confirmed not the same bug: this
  musl port's own TLS/TSD carve-out leaves more slack before the guard boundary than
  `_SC_THREAD_STACK_MIN` accounts for, so the tests' bounded recursion never actually touches the
  guard on this build. `pthread_create/1-6.c` is a real, permanent, accepted `TIMEOUT` — the test
  hardcodes `NCPU=4` real-parallel busy-loop threads, which serialize on this single-core kernel;
  a real-SMP prerequisite (ROADMAP.md v0.5.0), not a bug.
- `mlockall/3-7.c` — not a kernel bug: the only file in the whole corpus that `open()`s its own
  source by a relative path; fixed by seeding that literal fixture path (`POSIX_TEST_EXTRA_FILES`
  in `build.rs`, same convention `sigaltstack/9-1.c`'s fixture already established).
- Verified via `tests/mmap_syscall_smoke.rs` (14 parts, several run in isolated forked children
  since a fault kills whichever process it hits) and `tests/dynlink_syscall_smoke.rs` (RELRO's
  `mprotect` call untouched by the new enforcement scope).

## POSIX conformance pilot: growth, tooling, and accumulated fixes (`build.rs`, `sys/process/`, `sys/fs/`, `scripts/run_posix_pilot_{supervised,host}.sh`, `regress/posix-conformance-driver/`)

The Open POSIX Test Suite pilot (`tests/posix_conformance_smoke.rs`) grew from a hand-picked 68
files to a curated/deduplicated 488, then to the **full ~1687-file corpus** (`pthread_*`/`aio_*`/
`lio_listio*` included once real threading landed — `discover_posix_test_files` walks the
directory dynamically). Each growth pass needed the kernel's low-VA userland-load-base floor
shifted forward (the same "embedded corpus grew past the fixed floor" class of bug hit multiple
times — see "User-mode execution" above) and oxfs's block/inode/name-length pools bumped.

- **`scripts/run_posix_pilot_supervised.sh [--reset]`** is a host-side supervisor: kills a wedged
  QEMU boot (a genuine kernel-level hang can't be rescued by the suite's own in-guest 40s
  `alarm()`), excludes the stuck file, retries — now also excludes+retries on a real crash/panic
  exit, not just a stall, and caches every already-classified file's result across iterations so a
  long run never re-executes a file it already has an answer for. **The naive "exclude whatever
  file was running when a stall was detected" heuristic does not reliably converge** — several
  real investigations found it misattributing a stall to an innocent neighbor file that merely
  happened to be running next; when a supervised run needs many iterations to converge, verify
  each exclusion by testing that exact file in complete isolation before trusting it.
  **`scripts/run_posix_pilot_host.sh`** runs the identical corpus on the host's own real
  glibc/Linux for an apples-to-apples baseline (manual/root-run only, needs a real TTY for `sudo`).
- **A real, severe frame-exhaustion cascade** once the full corpus first ran uncurated (most files
  past ~1/3 through came back instant `UNRESOLVED`, real `ENOMEM` on `fork`/`execve`) — root
  causes and fixes are covered in "Real threading"'s memory-reclaim notes above (zombie
  address-space frames, `do_munmap`'s leak, orphan reparenting). Any full-corpus pass-rate number
  measured before those fixes landed is not comparable to one after.
- **A real global-fd-table exhaustion cascade**, unrelated to memory: `sys/modules/oxfs`'s
  `OPEN_FILES` table is process-*global*, not scoped per process — one real POSIX stress test
  (`shm_open/23-1.c`, 1000 children each opening a new fd with no `close()`) permanently drained
  it, breaking `hush`'s own output redirection for the rest of the boot and misclassifying
  hundreds of unrelated later files as `sigaction`-family FAILs. `MAX_OPEN_FILES` bumped `8 → 256`
  wasn't sufficient alone (the leak is unbounded over wall-clock time); the real fix moved
  `OpenFile::Write`'s buffer out of the enum into a separate, lazily-claimed pool (see "Filesystem:
  oxfs" above), letting `MAX_OPEN_FILES` scale to `2048` while *lowering* total static cost. That
  one file still doesn't `PASS` — a real, accepted single-core scheduling-throughput ceiling for
  1000 concurrent forked processes, not a fd-table symptom (confirmed by raising the rescue
  timeout 4.5x and still timing out).
- **`sched_yield/1-1.c`, once excluded as "needs real SMP," never actually did** — re-reading the
  test's own source (not re-trusting an old, unverified claim) showed it only forks CPU-reserving
  children when `ncpu > 1`; on a genuinely single-core report it correctly exercises two
  equal-priority threads round-robining via `sched_yield()`, a real single-core-achievable
  property. A stale exclusion-list reason needs the same live re-verification as any other claim.
- **A real, distinct `exit_group(2)` bug**: plain `exit()`/`_Exit()` shared a syscall number with
  a bare per-thread exit — a thread-group leader calling `exit()` only tore down itself, silently
  orphaning any live sibling into a deadlocked `pthread_exit()` cleanup. Fixed with a genuinely
  distinct `SYS_EXIT_GROUP=556` (kills every other tgid member first, leader-ordering fixed the
  same way `terminate_thread_group` was — see Signal handling module above) plus a matching musl
  `__NR_exit_group` remap.
- **Real thread-group-wide signal delivery had a routing bug**: the whole-group reroute used to
  fire on every `kill`/`sigqueue`, including a real `pthread_kill(exact_thread, sig)` (this ABI
  has no separate `tkill`/`tgkill`) — fixed via `route_signal_target`, gating the reroute to only
  fire when the literal target names the group's own leader.
- **The last three open scheduler-shaped hangs** (`fork/18-1.c`, `pthread_mutex_init/{1,3}-2.c`)
  were all confirmed **real, pre-existing musl 1.2.6 bugs, not OxideBSD bugs**, via direct
  byte-for-byte reproduction against the host's own unmodified musl: a `PTHREAD_CANCEL_ASYNCHRONOUS`
  cancel landing inside musl's own `canceldisable`-protected mutex-timedlock wait self-deadlocks
  (real musl behavior); a failing `SIGEV_THREAD_ID timer_create()` reports the wrong errno
  (`EAGAIN` instead of `EINVAL`). No kernel code changed for either — left as accepted non-PASS
  results, same bucket as the stale-tid UAF class (see musl-port section above).
- `OxideBSD-doc/BUSYBOX_APPLETS.md`/`MISSING_POSIX_SYSCALLS.md`/`POSIX_COMPLIANCE_CHECKLIST.md` (in
  the separate `OxideBSD-doc` repo) track applet/syscall/conformance detail this section
  summarizes; check there (and `build.rs`'s `POSIX_KNOWN_HANGS` doc comment, currently empty of
  live exclusions) for the current numbers rather than any pass-rate figure in this file, which
  goes stale quickly.

## BusyBox gap analysis: what's needed for more applets

Almost everything left needs one of a handful of missing kernel capabilities, each unlocking a
cluster of applets at once. New syscall numbers should continue from the highest currently
assigned. `OxideBSD-doc/BUSYBOX_APPLETS.md` is the authoritative per-applet detail behind this summary
table (counts are out of the 287 applets that built at all; a pre-v0.1 pass cut 58 of those 287
entirely — structurally incapable of working here, not "not started yet"). 229 remain seeded.

| Gap | Status | Notes |
|---|---|---|
| `argv[0]` passthrough, real signals, process groups, termios/`ioctl`, `stat`/`fstat`/`lstat`, `getdents`/`getdents64` | done | foundational, all landed early |
| Socket syscalls + real DNS, `socketpair`/`fcntl`/`shutdown`/`set_tid_address`/`readv` + `/dev/{u}random,null,zero` + real `tcp_read` EOF fix | done | `wget` HTTPS confirmed live end to end — see "Real networking" |
| `alarm`/`setitimer` | done | unlocks `ping`'s receive-loop timeout |
| `chmod`/`chown`/`chgrp` | done | ext2 `ioctl`/`xattr` (`chattr`/`fatattr`/`lsattr`/`setfattr`) removed from roster before v0.1 instead |
| `fsync`/`sync`/`ftruncate`/`fallocate`/`flock`/`statfs`/`setrlimit`/sched-priority/`reboot`, `link`/`mknod`/`chroot`/`getrusage` | done | see their own sections above |
| SysV IPC, namespaces, `inotify`, ext2 ioctl/xattr | not started, 0 remaining blocked | the applets that needed these were removed from the roster before v0.1 — namespaces don't fit this kernel's single-address-space model at all |
| `/proc` (per-process, system-wide, per-fd) + real symlinks | done | special-cased path prefix in `sys/modules/oxfs`, no VFS layer to plug into |
| Console/VT ioctls, serial/tape/I2C hardware, syslog, real pty | not started, 0 remaining blocked | `cttyhack`/`setsid` already worked and moved to WORKS; rest removed before v0.1 |
| Real block device driver + oxfs persistence, mount table | done | see "Real disk persistence"/"Mount table" — still a fixed, non-mountable backing store; `pivot_root`/`switch_root`/partition tables remain out of scope |
| uid/passwd-db model, real login/session auth | done | `adduser`/`chpasswd`/`passwd` still need real *mutation* of `/etc/passwd`/`/etc/group` (applet-level gap) |
| `clock_gettime`/`gettimeofday`/`time`/`nanosleep` | done | — |
| Init-system/service-supervisor framework | not started, out of scope | 2 applets kept anyway (don't need a real init framework); 4 removed (runit family needs FIFOs oxfs doesn't have) |
| `tcsetpgrp`/real job control | done | see "Real job control" |
| `uname`/`gethostname` | done | `gethostname` is a pure musl wrapper around `uname()`, no new syscall |

**83 more candidate applets didn't even build** — see the BusyBox port section above for the
breakdown; full detail in `OxideBSD-doc/BUSYBOX_APPLETS.md`.

## USB input: xHCI + HID boot-protocol keyboard (`sys/drivers/usb/`, `sys/drivers/pci.rs`, `sys/cpu/interrupts.rs`)

This kernel's first real-hardware (not just QEMU) boot target is a Surface Pro, which has no PS/2
controller at all — this closes that gap. `sys/drivers/usb/xhci.rs` is the xHCI host-controller
driver (register access, command/event rings, device-slot enable/address/configure); `hid_keyboard.rs`
is a HID **Boot Protocol** keyboard on top of it (no general HID Report Descriptor parsing); `mod.rs`
ties both together and exposes `init`/`poll`.

- **Polling, not IRQ-driven, deliberately** — matches `drivers::ata`'s own established
  polling-only precedent. This kernel has no IOAPIC/MSI support, and legacy PCI `INTx` routing on
  a modern UEFI-only chipset is a real, unquantified risk not worth taking for a few ms of
  keystroke latency. `usb::poll()` runs once per timer tick, draining the shared Event Ring.
- **32-byte device contexts only** (`HCCPARAMS1.CSZ == 0`) — what QEMU's `qemu-xhci` and the
  overwhelming majority of real platforms use. `CSZ == 1` is logged and treated as unsupported.
- **A real bug found live, not by spec-reading**: an early version trusted the boot loader's HHDM
  to cover the xHCI BAR's physical range unconditionally. **Wrong for a 64-bit BAR** — a real boot
  under OVMF (UEFI) placed `qemu-xhci`'s BAR0 at physical `0x800000000` (32 GiB) — real firmware
  parks large/64-bit BARs in a high MMIO window the HHDM's own "at least 4 GiB" guarantee doesn't
  reach. Fixed with a real, explicit two-phase mapping (`map_bar_pages`, `NO_CACHE`): map one page
  first (enough to read Capability registers and learn the real needed extent), then map however
  many pages that turns out to be. Confirmed on both BIOS and UEFI boots before landing.
- **Real BIOS/SMM-to-OS ownership handoff** (USB Legacy Support Capability, walked via
  `HCCPARAMS1.xECP`) — real Intel platforms (this project's own hardware target's chipset
  included) can leave the controller SMM-owned by default; QEMU doesn't implement this capability
  at all, so this path is untested by QEMU, only exercised on real hardware.
- **`drivers::pci::PciDevice::mem_bar` gained real 64-bit BAR-pair merging** (bits `2:1 == 0b10`,
  BAR `n+1` holds the high 32 bits) — the old 32-bit-only version silently truncated it.
- **Reuses `cpu::interrupts`'s existing PS/2 decode pipeline wholesale, not a second
  implementation.** `keyboard_interrupt_handler`'s post-decode logic is factored into
  `handle_decoded_key`, called by both the real PS/2 IRQ handler and a new
  `feed_synthetic_scancode` entry point `hid_keyboard` calls per synthesized PS/2 Scan Code Set 1
  byte. Shift state, Caps Lock, signal interception, and echo all come along for free.
  `feed_synthetic_scancode` never touches the PIC — only the real IRQ handler sends EOI.
- One keyboard device for v1, no hot-plug, US 104-key layout only. Mouse/pointer input entirely
  out of scope — no GUI or pointer concept exists anywhere in this kernel yet.
- **Real key auto-repeat** synthesized kernel-side (`KeyboardDevice::repeat_usage`/
  `repeat_next_tick`, driven by `ticks()`) — unlike PS/2, a USB HID boot-keyboard device reports a
  key exactly once per state change and never resends while held. Only the single
  most-recently-pressed still-held key repeats; modifiers never repeat.
- QEMU test devices (`-device qemu-xhci -device usb-kbd`) are opt-in via `OXIDEBSD_QEMU_USB=1` in
  `scripts/qemu_runner.sh`, not default — QEMU's default i440fx machine already wires up its own
  PS/2 keyboard, so an always-on USB one would double-push every keystroke.
- **Real hardware (Surface Pro) itself is genuinely manual-only** — but live interactive-keystroke
  verification turned out **not** to need a human at a real display after all: QEMU's own monitor
  `sendkey <combo> [hold-ms]` genuinely synthesizes guest keystrokes (including held-key duration)
  over a plain TCP socket (`OXIDEBSD_QEMU_MONITOR=<port>`) — this is how a real, pre-existing
  Ctrl+C/Ctrl+D bug (see "Interactive shell" above) was found and confirmed fixed headlessly.
  Revise the "manual-QEMU-only" framing in Test architecture accordingly for anything
  keyboard-shaped specifically (still true for anything needing a real human *decision* mid-session,
  e.g. `sulogin` credential entry).

## Real Rust `std` target: `x86_64-unknown-oxidebsd` (`external/mit/rust`, `regress/std/`, `build.rs`)

v0.3.0 work (see `OxideBSD-doc/ROADMAP.md`) — a private `rust-lang/rust` fork (`OxideBSD/
rust-oxidebsd`, `oxidebsd` branch) plus a private `libc` crate fork (`OxideBSD/
libc-crate-oxidebsd`, `oxidebsd` branch, patched in via `library/Cargo.toml`'s
`[patch.crates-io]`) add real `target_os = "oxidebsd"` support throughout `std`'s *existing*
`linux`/musl-shaped cfg gates, reusing `sys::pal::unix` wholesale rather than writing a new
backend — this kernel's own patched musl fork's public C ABI is unchanged from stock musl.
`library/std/build.rs`'s supported-platform allowlist lists `oxidebsd` too, so consumer binaries
need no `#![feature(restricted_std)]` — a real, fully-supported target, not one std merely
tolerates. `build_std_oxidebsd_userland_crate` in `build.rs` does a genuine `-Z
build-std=std,core,alloc,panic_abort` recompile every build (~20-40s, no prebuilt `std` exists for
a brand-new custom target), linked via a `musl-gcc` `RUSTC_WRAPPER` against the same
`target/musl-sysroot` every other userland ELF uses.

- **A real, repeatedly-hit build-caching gotcha, distinct from the BusyBox one above**: neither
  the outer `cargo test`/`cargo build` nor the nested `-Z build-std` cargo invocation tracks
  `target/musl-sysroot`'s `libc.a` as a dependency — it's referenced only via a raw `-C
  linker=.../musl-gcc` flag, invisible to cargo's fingerprinting. Editing `external/mit/musl` and
  rebuilding it does **not** force a relink of an already-built `regress/std/*` crate, even
  though `build.rs` itself correctly reruns and rebuilds musl fresh — the *nested* cargo build for
  that one regress/std crate silently reuses its own stale cached executable. Confirmed via
  direct `objdump` inspection: `target/musl-sysroot/lib/libc.a` had the fix, the linked
  `regress/std` ELF didn't, until `target/userland-std-oxidebsd/<crate>` was deleted by hand.
  **A second, compounding layer of the same bug**: `sys/modules/oxfs`'s own `build_module_crate`
  invocation (a fresh `cargo rustc` subprocess every time `build.rs` runs at all) can *also* skip
  re-embedding a regress/std ELF via its own `include_bytes!(env!(...))` if its own nested
  cargo's fingerprint doesn't notice the referenced file's content changed — even right after a
  genuinely fresh relink of that ELF. **The only fix found reliable**: delete both
  `target/userland-std-oxidebsd` and `target/modules` outright, or (cheaper) `touch
  sys/modules/oxfs/sys/lib.rs` to force *that* crate's own next `cargo rustc` invocation to actually
  recompile (a real, cargo-tracked source-file change) rather than trusting either layer's
  incremental cache after a musl/`external/mit/rust` edit. **Do not `touch build.rs` itself** to
  force this — its own `rerun-if-changed` self-watch would also trip BusyBox's mtime-based
  staleness check (see "BusyBox port" above), triggering an unwanted ~30min rebuild.
- **Real consumer proofs, each a `#![no_std]` fork+execve+wait4 wrapper spawning a real `std`
  binary embedded at `/bin/<name>`** (same pattern as `clang-syscall-smoke`/`std-hello-syscall-
  smoke`): `std-hello-oxidebsd` (target identity only — `println!`/`process::exit`);
  `std-process-fs-oxidebsd` (real `std::fs` write/read_to_string/remove_file +
  `std::process::Command` spawning `/bin/true`/`/bin/echo`); `std-thread-net-signal-oxidebsd`
  (real `std::thread` spawn/join + `Arc<Mutex<_>>` over real `futex(2)`; real
  SIGPIPE-ignored-at-startup broken-pipe handling + real `SIGKILL`/`ExitStatusExt::signal()`
  `wait(2)`-status decoding; real UDP/TCP `socket()`/`bind()`/`local_addr()`/`listen()`/nonblocking
  `accept()`).
- **Two real `std` platform-allowlist gaps found and fixed the same way as `restricted_std`**
  (`external/mit/rust`, each a hardcoded `target_os` list `std` uses to pick a fallback code path):
  `sys/pipe/unix.rs`'s `pipe2` list (without `oxidebsd`, `pipe()` fell back to plain `pipe()` +
  `ioctl(FIONBIO)`-based `set_cloexec`, both broken here) and `sys/net/connection/socket/
  unix.rs`'s `Socket::set_nonblocking` (same `ioctl(FIONBIO)` default fallback). **OxideBSD's real
  `ioctl(2)` only ever handles `TCGETS`/`TCSETS*`/`TIOCGWINSZ`/`TIOCSWINSZ` against the real
  console fd — any other request or fd returns `ENOTTY`** (see "Interactive shell" above), so any
  future `std` gap surfacing as a mysterious `ENOTTY`/`ENOSYS`-shaped `io::Error` from a
  first-real-consumer program is probably this same allowlist-gap class, not a kernel bug.
- **A real, previously-missing kernel syscall found this way, not just a std/libc gap**:
  `getsockname(2)` had never been implemented at all (`sys/net/tcp.rs`'s `getsockname`/
  `sys/net/udp.rs`'s `oxidebsd_sys_getsockname`, `SYS_GETSOCKNAME=559`) — real Linux's own stock
  `__NR_getsockname=51` had simply never been remapped, since nothing needed it before a real
  `std::net` consumer called `local_addr()`. `getpeername` remains a deliberately narrower,
  disclosed, still-open gap.
- **No loopback interface exists on this kernel** (single real NIC, see "Real networking" above)
  — the `std::net` consumer proof is real socket/bind/listen/nonblocking-accept plumbing, not a
  full external round trip.
- Not yet exercised through real `std`: anything beyond fs/process/thread/signal-basics/net-
  plumbing above (no real `TcpStream`/`UdpSocket` data transfer, no `std::net` DNS resolution, no
  `panic=unwind`).

## Dependency notes

- `x86_64` crate: `default-features = false, features = ["instructions", "abi_x86_interrupt"]` —
  the default feature set pulls in `step_trait`, an unstable-API moving target that has broken
  this crate against newer nightlies before.
- `limine` crate (`"0.6"`) — the request-statics/response-parsing glue for the Limine boot
  protocol; see "Boot: Limine" below. Replaced the old `bootloader` v0.9 crate (BIOS-only,
  unmaintained) in the 2026-09-09/10 migration.
- `linked_list_allocator`: `default-features = false` — its default `LockedHeap` depends on
  `spinning_top`, a second spinlock crate alongside `spin` (used everywhere else here).
- `pc-keyboard` 0.9's type is `PS2Keyboard<L, S>`, not `Keyboard<L, S>` (older tutorials reference
  the pre-0.9 name). Decoding is two calls through the *same* locked guard: `add_byte` →
  `KeyEvent`, then `process_keyevent` → `DecodedKey`.
- `pic8259`/`uart_16550` are deliberately **not** dependencies — both wrap a handful of
  `outb`/`inb` calls against a stable protocol, small enough that owning the code (`sys/cpu/
  pic.rs`, `sys/console/serial.rs`) outweighs the dependency. `pc-keyboard` (hundreds of lines of
  scancode tables) and `linked_list_allocator` (safety-critical free-list logic) stay external.
- `sha2`/`chacha20` (`sys/random.rs`): `default-features = false`, `sha2` additionally needs
  `features = ["force-soft"]` and `chacha20` needs `--cfg chacha20_backend="soft"` via
  `.cargo/config.toml`'s rustflags — both otherwise try to compile a SIMD backend this target's
  disabled SSE/MMX can't lower. Crypto primitives are the one place this codebase deliberately
  prefers a vetted dependency over hand-rolling — the opposite call from `pic8259`/`uart_16550`
  above.
