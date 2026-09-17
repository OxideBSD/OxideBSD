# OxideBSD 0.1.3

A bugfix-only release on top of 0.1.2 — no new capabilities, same `v0.1.x` policy as always. This
is planned as the final `v0.1.x` release: all three fixes below were found on `master`'s own
ongoing pre-`0.2.0` bug-hunting pass, then confirmed to affect this branch too, and backported
here rather than left to bit-rot in an unmaintained tag.

## Fixed since 0.1.2

- **A real OOB-read/memory-disclosure bug in the rtl8139 NIC driver**: `poll_recv` sized a heap
  allocation and a raw memory copy directly off the hardware-reported RX frame length (a `u16`,
  trusted up to its full range) — since this kernel's HHDM maps all of physical memory, an
  oversized value from a corrupted or adversarial inbound frame wouldn't fault, it would silently
  read unrelated physical memory into a packet handed up to the network stack. The existing
  malformed-packet check was also decorative: it logged a warning but still processed and returned
  the untrusted payload regardless. Fixed: a bad status or an out-of-range length now gets the
  frame dropped outright, with the ring's own read cursor advanced by a bounded amount instead of
  the same untrusted length, so a single corrupted header can't desync it from the card's real
  write pointer either.
- **`rmdir` on an active mount silently orphaned it**: the mount-table (`mount --bind`/
  `mount -t tmpfs`) redirect only ever applied automatically to an *intermediate* path component,
  not the final one being removed — the exact same bypass already fixed once for `open()` on a
  mountpoint path, recurring here in a second handler. `rmdir` on a non-empty mount used to see
  straight through to the real, always-empty attachment-point directory underneath it, delete that
  directory's name, and leave the mount's actual content permanently unreachable (not even
  `umount2`-able afterward). Now a real `EBUSY`, matching real Unix's own refusal to `rmdir` a busy
  mountpoint.
- **A real ATA write-persistence bug**: the post-write `CACHE FLUSH` command's own completion check
  only ever waited for the drive to stop being busy — it never checked whether the drive's status
  register actually reported an error once it did. A real flush failure was silently treated as a
  success all the way up through `oxfs`'s own write-through persistence path, meaning the kernel
  could believe a block had reached stable storage when the hardware had actually reported
  otherwise. Fixed: the status byte the busy-wait already had in hand is now checked for a real
  error before reporting success.
- Also applied a defensive PIC IRQ2-cascade fix to `unmask_irq()` (any IRQ8-15 line, including the
  rtl8139's, physically cascades into the CPU through PIC1's own IRQ2 input, which this function
  never touched). Live and load-bearing on `master`'s Limine-based boot path; likely inert here,
  since this branch's BIOS/`bootloader`-crate boot path appears to inherit IRQ2 already unmasked
  from firmware — included anyway so the function is correct on its own merits.

- **Ctrl+C/Ctrl+D silently did nothing once BusyBox's own line editor was driving the interactive
  prompt** (which is effectively always) — found first on `master` while validating unrelated
  work, then confirmed to affect this branch too. Root cause: the default `struct termios`
  `TCGETS` reports before anything ever calls `TCSETS` had an all-zero `c_cc[]` control-character
  array. BusyBox's own `libbb/lineedit.c` deliberately disables the kernel's `ISIG`-based signal
  generation while it's editing a line (real upstream behavior) and instead recognizes Ctrl+C/
  Ctrl+D itself by comparing raw bytes against the *original* termios' `c_cc[VINTR]`/`c_cc[VEOF]`
  — each check guarded by "is this control character even enabled (nonzero)?". An all-zero default
  silently satisfied that guard as "disabled." Fixed: real POSIX/Linux default `c_cc` values.
  Confirmed live: `sleep 100` + Ctrl+C now returns to a fresh prompt immediately (a real `SIGINT`
  reaching the real foreground process group) instead of waiting out the full sleep; Ctrl+D at an
  empty prompt now ends the shell on real EOF.
- **A real page fault, `#GP`, or invalid-opcode fault from *any* ring-3 program rebooted the entire
  kernel** — a wild pointer dereference, invalid access, or illegal instruction (a real `ud2`, or a
  genuinely corrupted jump) in any userland program (a bug in a BusyBox applet, a bug in a program
  compiled with the on-target `tcc`, ...) took the whole VM down instead of just that one process.
  Fixed with a real, minimal fix for this one safety property specifically (not the larger real
  fault-to-signal-delivery mechanism `master`/`0.2.0` eventually grew): a ring-3 fault now
  terminates just the offending process with the matching signal (`SIGSEGV`/`SIGILL`), reusing the
  same self-termination path a normal `exit()` already goes through. Ring-0 faults (a genuine
  kernel bug) still reboot, as before. Confirmed live: a `tcc`-compiled program dereferencing a
  null pointer now cleanly prints "Segmentation fault," and one executing a bare `ud2` prints
  "Illegal instruction" — both return to a live, responsive prompt instead of taking the VM down.
- **`fork()`/`execve()` could panic the entire kernel on real, ordinary memory exhaustion** — the
  kernel stack allocation every `fork()` needs, the deep address-space copy `fork()` makes, and the
  fresh user-stack mapping every `execve()` makes all hard-panicked on the frame/heap allocator
  running out, rather than failing that one syscall. None of this needed anything malicious: an
  ordinary, unprivileged fork bomb, or simply enough real memory pressure during a routine command,
  could already take the whole system down before this fix. Fixed: all three now return a real
  `ENOMEM` to the syscall that hit the limit instead of panicking (the one exception, matching
  existing precedent for every other boot-time allocation in this codebase, is `pid 1`'s own
  original `spawn()` at boot, which still panics — there's no syscall caller to report `ENOMEM` to
  that early). Confirmed live: ordinary fork/exec (every shell command) still works identically.
- **Killing a process that's waiting its turn (not the one currently running — an entirely
  ordinary case, e.g. `kill` on a backgrounded job) resurrected it instead of actually terminating
  it.** The scheduler's ready queue never had the killed process's entry removed, so it would later
  get popped and resumed from wherever it last yielded — while its own process-table entry was
  simultaneously marked exited and eligible for a real `wait4()` reap out from under it. Fixed by
  dequeuing on termination. Confirmed live: backgrounding a long `sleep`, then killing it, now
  leaves no trace in the shell's own job list — no resurrection, no crash.

---

# OxideBSD 0.1.1

A bugfix-only release on top of 0.1.0 — no new capabilities. `v0.1.x` is this project's
maintenance branch: it only ever backports real, independently-verified fixes (most found first on
`master`'s own ongoing POSIX-conformance work, then confirmed to affect this branch too), never new
feature work — that all happens on `master` toward `0.2.0`.

## Fixed since 0.1.0

- **A real permission/security gap**: `open(path, O_CREAT, mode)` silently discarded the caller's
  requested creation mode — every new file got a fixed `0o755` regardless of what was actually
  asked for (e.g. `open(path, O_CREAT|O_WRONLY, 0600)` didn't get a private file). Needed a musl
  submodule patch (threading `mode` through as a real 4th syscall argument) plus an oxfs-side fix.
- **`su`'s real privilege-drop path was broken**: `socket(AF_UNIX, ...)` returned the wrong errno
  (`EPROTONOSUPPORT` instead of `EAFNOSUPPORT`), which broke musl's own `initgroups()` fallback —
  any real `su` to a non-root uid would fail with "can't set groups: Function not implemented."
- **A real POSIX filesystem-semantics bug**: `unlink()`ing a file before its first `write()`/
  `close()` ever committed a real inode used to silently no-op, then resurrect the file on the next
  commit — breaking the classic "open, unlink, keep writing" temp-file idiom.
- **`sched_setscheduler(2)` returned the wrong value** on success (always `0` instead of the real
  POSIX-mandated former scheduling policy).
- **Real Ctrl+C job control and colored `ls`/prompt** — a session/controlling-tty fix that lets
  `hush`'s own real job-control startup activate for the first time; `kill(-pgrp, sig)`
  process-group broadcast also now works. (Real Ctrl+Z stop/resume stays `master`/`0.2.0`-only.)
- **A real `poll()` livelock**: `nfds == 0` with an infinite timeout used to spin forever with no
  possible escape, starving the whole (single-core) system.
- **33 real syscall-number collisions** between this ABI's own invented numbers and still-live real
  Linux syscall numbers musl's own compiled-in headers reference — found via a full header sweep,
  fixed by moving every colliding invented number to a verified-unclaimed one.
- **A real kernel-heap OOM panic**: `yes | head -n 3` (or any pipeline where a non-blocking
  producer outpaces a consumer that stops reading early) could exhaust the kernel heap. Fixed by
  bounding the pipe buffer with a real blocking writer.

Building/running instructions are unchanged from 0.1.0 — see below.

---

# OxideBSD 0.1.0

First tagged snapshot of OxideBSD, a 100% Rust, x86_64-only, BSD-like operating system built from
scratch (bootloader, kernel, syscall ABI, filesystem, and a real ported libc/userland). This is a
`0.x` release: a real, usable snapshot of current progress, not a promise of API/ABI stability
between minors. See `ROADMAP.md`/`CLAUDE.md` for the full three-phase plan this project is working
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
  (curated down from an original 314-applet build probe — see `docs/BUSYBOX_APPLETS.md`'s
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
