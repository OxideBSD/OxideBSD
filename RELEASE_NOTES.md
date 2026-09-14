# OxideBSD 0.1.0

First tagged snapshot of OxideBSD, a 100% Rust, x86_64-only, BSD-like operating system built from
scratch (bootloader, kernel, syscall ABI, filesystem, and a real ported libc/userland). This is a
`0.x` release: a real, usable snapshot of current progress, not a promise of API/ABI stability
between minors. See `OxideBSD-doc/ROADMAP.md`/`CLAUDE.md` for the full three-phase plan this project is working
toward; `1.0.0` is reserved for the day OxideBSD can rebuild itself from source with no host OS
involved (see "Not in this release," below).

## What works

- **Boots and stays up.** `bootloader` v0.9 + QEMU, GDT/TSS/IDT with a dedicated double-fault
  stack, PIC-driven interrupts, a heap allocator, a VGA console mirroring serial.
- **Real process model.** Separate per-process address spaces, ELF64 loading, ring-3 execution, a
  native BSD-style syscall ABI over `SYSCALL`/`SYSRETQ`, a process table with a cooperative
  round-robin scheduler, `fork`/`execve`/`wait4`, blocking pipes, per-process signal delivery.
- **A real, ported libc.** musl, patched to speak this kernel's own native syscall ABI directly
  (not a Linux-compatibility shim) — real `malloc`, stdio, TLS, DNS resolution, `crypt(3)`, and
  more, all musl's own real code running against this kernel's real syscalls.
- **A real shell and userland.** BusyBox's `hush` as pid 1, real shell control flow (`if`/`for`/
  `while`/`case`/functions), 256 BusyBox applets built and running as standalone binaries
  (curated down from an original 314-applet build probe — see `OxideBSD-doc/BUSYBOX_APPLETS.md`'s
  "Removed before v0.1" section for what was cut and why).
- **A real filesystem.** `oxfs`, an in-memory-by-default Unix-shaped inode/block filesystem with
  real multi-component paths, per-process cwd, hard links, symlinks, device nodes, permissions —
  plus real, optional persistence to an attached ATA disk (ports a session survives a reboot on),
  and a real `mount --bind`/`mount -t tmpfs` mount table.
- **A real permission and session model.** uid/gid, `chmod`/`chown`, real `open()` enforcement,
  `/etc/passwd`+`/etc/shadow` with SHA-512 password hashes, real `su`/`login` authentication, and a
  real session/controlling-tty/foreground-process-group model (`setsid`, `SIGINT` delivery to the
  foreground group).
- **Real networking.** PCI enumeration, an rtl8139 driver, Ethernet/ARP/IPv4/ICMP, UDP/TCP/raw-ICMP
  sockets, `poll(2)`, and real hostname resolution over musl's own DNS stub resolver — `ping`,
  `wget` (including HTTPS), and `nslookup` all confirmed working against real remote hosts.
- **A real, on-target C compiler.** `tcc` (vendored TinyCC) runs as an ordinary `/bin` binary and
  can genuinely compile and link a real C program against a real, seeded musl `/usr/include`/
  `/usr/lib` tree, producing a real, runnable ELF — entirely on-target, no host toolchain involved
  at runtime.

## Not in this release

- **No package manager, no ports system.** Every binary in this image is baked in at build time by
  the host-side `build.rs`; there is no on-target mechanism yet to fetch, build, or install
  software after boot.
- **No self-hosting.** `rustc`/`cargo` do not run under OxideBSD yet, and TinyCC hasn't been used
  to compile itself on-target yet either — the toolchain that built this image is still entirely
  host-side.
- Known kernel-level gaps: no SMP, no preemption, no copy-on-write fork, no frame deallocation
  anywhere, no IPv6, no real routing table, GCC/Clang unstarted. See `CLAUDE.md`'s "Known,
  deliberate gaps" and per-subsystem sections for the complete, current list.

## Building and running

Requires nightly Rust (pinned via `rust-toolchain.toml`), `bootimage` (`cargo install bootimage`),
`qemu-system-x86_64`, and a host C toolchain (musl-gcc is built from source as part of the build;
GNU `make` and a host C compiler are required to cross-build musl/BusyBox/TinyCC at build time).

```sh
cargo run          # boot in QEMU, serial to stdio
cargo build         # kernel ELF only
cargo bootimage      # bootable disk image
cargo test           # integration tests (each boots its own QEMU instance)
```

Linux is the primary supported host; macOS/Windows are untested.
