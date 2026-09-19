//! Cross-builds the userland demo binaries under `userland/` and the kernel modules under
//! `modules/` so `src/main.rs` can embed them via `include_bytes!(env!(...))`. This keeps
//! `cargo build`/`cargo run`/`cargo test` working with no manual pre-step.
//!
//! Builds into target-dirs of their own (`target/userland`, `target/modules`), not the shared
//! workspace `target/` directory: cargo takes a lock on the target directory for the whole outer
//! build, including while this build script runs, so a nested `cargo build` sharing that same
//! target directory can deadlock waiting for a lock the outer, still-running build already holds.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Prefixes a compiler invocation with `ccache` when it's available on the host, letting
/// BusyBox's own ~232-applet fanout (and the POSIX pilot's own up-to-~1700-file fanout) reuse
/// identical object code across build directories instead of recompiling shared BusyBox-core/
/// musl-static-lib content from scratch every time. Both already do a real rm-rf-and-rebuild on
/// any musl core change (see `build_busybox_applet`'s own doc comment) -- correct for staleness,
/// but it throws away an enormous amount of otherwise-identical recompilation across applets/test
/// files that share the vast majority of their own object code. Detected once via `OnceLock`, not
/// per call site (`Command::new("ccache")` spawning a process per applet/test file at this fanout
/// would itself add real overhead) -- safe to call from the parallel worker pools both `main()`
/// and `build_busybox_applet` already use, since `OnceLock::get_or_init` serializes concurrent
/// first callers. Falls back to the plain compiler, unprefixed, when `ccache` isn't on `PATH` --
/// this is a pure speed optimization, never load-bearing for correctness. Returns the argv prefix
/// (`["ccache", "<compiler>"]` or just `["<compiler>"]`) rather than a single string so callers
/// building a real `Command` don't need to re-split a shell-quoted string; a `make CC=` caller
/// instead wants `.join(" ")` (`make` treats a multi-word `$(CC)` as a shell command prefix
/// inside its own recipe lines, so this is safe to hand it directly).
fn compiler_invocation(compiler: &Path) -> Vec<String> {
    static CCACHE_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let available = *CCACHE_AVAILABLE.get_or_init(|| {
        Command::new("ccache")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    if available {
        vec!["ccache".to_string(), compiler.display().to_string()]
    } else {
        vec![compiler.display().to_string()]
    }
}

/// Real host parallelism to use for every C-side build fanout (musl's own `make -j`, BusyBox's
/// per-applet worker pool, the POSIX pilot's per-file worker pool). Reads cargo's own `NUM_JOBS`
/// env var -- set by cargo for every build script invocation to whatever job count *this specific
/// build* is actually using (`cargo build -j N`, or a `[build] jobs = N` in `.cargo/config.toml`/
/// `CARGO_BUILD_JOBS`, or the real host core count if the caller never configured one) -- rather
/// than hardcoding a number here: this file is shared/committed, so a fixed cap picked for one
/// contributor's own machine would wrongly under- or over-subscribe everyone else's. A contributor
/// who wants these C-side builds to leave real headroom for other work should set their own `jobs`
/// via one of those normal cargo mechanisms; this just relays whatever that resolves to. Falls back
/// to real host parallelism only if `NUM_JOBS` is somehow absent (a raw `rustc`/non-cargo build).
fn build_jobs() -> usize {
    std::env::var("NUM_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

// `BUSYBOX_APPLETS`/`BUSYBOX_APPLETS_PASS2`/`build_busybox_applet`/`configure_busybox_single_applet`/
// `resolve_busybox_new_config_options` -- split into their own file specifically so unrelated
// edits to *this* file don't invalidate every cached BusyBox applet binary. See
// `build_busybox.rs`'s own module doc comment for the full story (a real ~20-30 minute rebuild
// cascade, found live).
include!("build_busybox.rs");

/// Builds Limine's small C deploy/install tool (`limine.c` -> `limine`) from the vendored
/// `-binary`-branch submodule (`third_party/limine`, a personal fork pinned the same way as
/// musl/busybox/tinycc), then stages it plus every prebuilt bootloader-stage blob this project
/// needs into a fixed location, `target/limine-stage/`, that `scripts/qemu_runner.sh` reads from
/// directly -- the runner never reaches into `third_party/limine` itself, mirroring how nothing
/// else in this file hands another tool a path into `third_party/*` directly either (env-var/
/// fixed-path handoff instead). The `-binary` branch ships every actual bootloader stage
/// (`limine-bios.sys`, `limine-bios-cd.bin`, `limine-uefi-cd.bin`, `BOOTX64.EFI`, `BOOTIA32.EFI`)
/// as pre-built, committed blobs -- `make` here only compiles the deploy tool itself (`limine.c`,
/// a plain host-native C program with a trivial `.POSIX` Makefile that already does its own real
/// incremental-rebuild tracking, unlike tinycc's own more elaborate out-of-tree build -- no
/// separate staleness bookkeeping needed here, `make` is cheap to just always invoke).
fn build_limine_deploy_tool() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let limine_dir = Path::new(manifest_dir).join("third_party/limine");
    let stage_dir = Path::new(manifest_dir).join("target/limine-stage");

    println!(
        "cargo:rerun-if-changed={}",
        limine_dir.join("limine.c").display()
    );

    let status = Command::new("make")
        .current_dir(&limine_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to run make for third_party/limine: {e}"));
    if !status.success() {
        panic!("building limine's deploy tool failed: {status}");
    }

    std::fs::create_dir_all(&stage_dir)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", stage_dir.display()));

    // Everything scripts/qemu_runner.sh needs to stage a bootable hybrid BIOS+UEFI ISO: the
    // deploy tool itself (for `limine bios-install`), both CD boot images, `limine-bios.sys`
    // (BIOS boot from a raw/hybrid image), and the two EFI executables the ISO's `EFI/BOOT/`
    // directory needs for UEFI (x86_64 32- and 64-bit).
    const STAGE_FILES: &[&str] = &[
        "limine",
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
        "BOOTX64.EFI",
        "BOOTIA32.EFI",
    ];
    for name in STAGE_FILES {
        let src = limine_dir.join(name);
        let dst = stage_dir.join(name);
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!(
                "failed to stage {} -> {}: {e}",
                src.display(),
                dst.display()
            )
        });
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build_busybox.rs");
    build_limine_deploy_tool();
    let ring3_smoke_elf_path = build_userland_crate("ring3-smoke", "RING3_SMOKE_ELF_PATH");
    build_userland_crate("fork-exec-smoke", "FORK_EXEC_SMOKE_ELF_PATH");
    // Real-SYSCALL counterparts to the direct-call network smoke tests -- see CLAUDE.md's "Real
    // networking" section for the blind spot these close (every prior network test called kernel
    // handlers as plain Rust functions, never through a genuine SYSCALL with interrupts actually
    // masked).
    build_userland_crate(
        "socketpair-syscall-smoke",
        "SOCKETPAIR_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("ping-syscall-smoke", "PING_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("udp-syscall-smoke", "UDP_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("poll-syscall-smoke", "POLL_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("tcp-syscall-smoke", "TCP_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("proc-smoke", "PROC_SMOKE_ELF_PATH");
    build_userland_crate("itimer-syscall-smoke", "ITIMER_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("uid-syscall-smoke", "UID_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("mmap-syscall-smoke", "MMAP_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "oxfs-persistence-syscall-smoke",
        "OXFS_PERSISTENCE_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("mount-syscall-smoke", "MOUNT_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("session-syscall-smoke", "SESSION_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("needs-syscall-smoke", "NEEDS_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("needs-syscall2-smoke", "NEEDS_SYSCALL2_SMOKE_ELF_PATH");
    build_userland_crate("tcc-syscall-smoke", "TCC_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("clang-syscall-smoke", "CLANG_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "std-hello-syscall-smoke",
        "STD_HELLO_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "std-hello-oxidebsd-syscall-smoke",
        "STD_HELLO_OXIDEBSD_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "std-process-fs-oxidebsd-syscall-smoke",
        "STD_PROCESS_FS_OXIDEBSD_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "std-thread-net-signal-oxidebsd-syscall-smoke",
        "STD_THREAD_NET_SIGNAL_OXIDEBSD_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("access-syscall-smoke", "ACCESS_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "pipe-backpressure-syscall-smoke",
        "PIPE_BACKPRESSURE_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("dynlink-syscall-smoke", "DYNLINK_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "sa-siginfo-syscall-smoke",
        "SA_SIGINFO_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "getrandom-syscall-smoke",
        "GETRANDOM_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("sysinfo-syscall-smoke", "SYSINFO_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "sigaltstack-syscall-smoke",
        "SIGALTSTACK_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("pause-syscall-smoke", "PAUSE_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "sigsuspend-syscall-smoke",
        "SIGSUSPEND_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "posix-timer-syscall-smoke",
        "POSIX_TIMER_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate("mq-syscall-smoke", "MQ_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sysv-msg-syscall-smoke", "SYSV_MSG_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sysv-sem-syscall-smoke", "SYSV_SEM_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sysv-shm-syscall-smoke", "SYSV_SHM_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sig-syscall-smoke", "SIG_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "rt-signal-syscall-smoke",
        "RT_SIGNAL_SYSCALL_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "posix-conformance-driver",
        "POSIX_CONFORMANCE_DRIVER_ELF_PATH",
    );
    build_userland_crate("clock-syscall-smoke", "CLOCK_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sched-syscall-smoke", "SCHED_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("clone-syscall-smoke", "CLONE_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("pthread-syscall-smoke", "PTHREAD_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("sem-open-syscall-smoke", "SEM_OPEN_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate(
        "pthread-cancel-crash-smoke",
        "PTHREAD_CANCEL_CRASH_SMOKE_ELF_PATH",
    );
    build_userland_crate(
        "pshared-cond-crash-smoke",
        "PSHARED_COND_CRASH_SMOKE_ELF_PATH",
    );
    // Phase 1 verification for the fbdoom/doomgeneric port's own new kernel primitives -- see
    // these two crates' own module doc comments.
    build_userland_crate("fb-mmap-syscall-smoke", "FB_MMAP_SYSCALL_SMOKE_ELF_PATH");
    build_userland_crate("keyevent-syscall-smoke", "KEYEVENT_SYSCALL_SMOKE_ELF_PATH");
    // A real standalone userland utility (embedded into oxfs's own /bin below, not a test) --
    // same category as ring3-smoke/musl-smoke above, not a BusyBox applet. Lists OxideBSD's own
    // loaded kernel modules by reading the real /proc/modules this pass added to modules/oxfs.
    let lsoxmod_elf_path = build_userland_crate("lsoxmod", "LSOXMOD_ELF_PATH");

    build_module_crate("hello", "HELLO", &[]);
    build_module_crate("native_abi", "NATIVE_ABI", &[]);
    build_module_crate("posix_compat", "POSIX_COMPAT", &[]);
    build_module_crate("signal", "SIGNAL", &[]);
    build_module_crate("clock", "CLOCK", &[]);
    build_module_crate("net", "NET", &[]);

    // ring3-smoke is a real, already-working fork+execve+wait target -- see CLAUDE.md's
    // process/scheduler section. Also embedded into oxfs below.
    let musl_sysroot = build_musl_sysroot();

    // musl-smoke is a first real (patched) musl static binary -- see CLAUDE.md's musl section.
    // Also embedded into oxfs below.
    let musl_smoke_elf_path = build_musl_smoke(&musl_sysroot);

    // Real Rust `std` target proof of concept -- see `userland-std/std-hello/src/main.rs`'s own
    // doc comment. Also embedded into oxfs below.
    let std_hello_elf_path = build_std_hello_spike(&musl_sysroot);

    // The real thing: OxideBSD's own x86_64-unknown-oxidebsd target (genuinely reports
    // target_os = "oxidebsd", not borrowed Linux identity) -- see `userland-std/
    // std-hello-oxidebsd/src/main.rs`'s own doc comment and `build_std_oxidebsd_userland_crate`'s
    // for the real, disclosed ~40s-per-build cost (a genuine std/core/alloc recompile every time,
    // no prebuilt std exists for a brand-new custom target). Also embedded into oxfs below.
    let std_hello_oxidebsd_elf_path = build_std_oxidebsd_userland_crate(
        "std-hello-oxidebsd",
        "OXFS_STD_HELLO_OXIDEBSD_ELF_PATH",
        &musl_sysroot,
    );

    // v0.3.0's "first real std consumer" proof -- std::fs + std::process::Command actually
    // driving their own internal fork+execve+waitpid, not just runtime startup/shutdown. See
    // userland-std/std-process-fs-oxidebsd/src/main.rs's own doc comment.
    let std_process_fs_oxidebsd_elf_path = build_std_oxidebsd_userland_crate(
        "std-process-fs-oxidebsd",
        "OXFS_STD_PROCESS_FS_OXIDEBSD_ELF_PATH",
        &musl_sysroot,
    );

    // Extends the real std consumer proof into std::thread, signals, and std::net -- see
    // userland-std/std-thread-net-signal-oxidebsd/src/main.rs's own doc comment.
    let std_thread_net_signal_oxidebsd_elf_path = build_std_oxidebsd_userland_crate(
        "std-thread-net-signal-oxidebsd",
        "OXFS_STD_THREAD_NET_SIGNAL_OXIDEBSD_ELF_PATH",
        &musl_sysroot,
    );

    // Derisk check for the fbdoom/doomgeneric port -- see userland/float-smoke/main.c's own doc
    // comment.
    let float_smoke_elf_path = build_float_smoke(&musl_sysroot);

    // "Real threading" phases 1-5's own finish line -- see userland/pthread-smoke/main.c's own
    // doc comment.
    let pthread_smoke_elf_path = build_pthread_smoke(&musl_sysroot);

    // Real cross-process named-semaphore coordination -- see userland/sem-open-smoke/main.c's own
    // doc comment.
    let sem_open_smoke_elf_path = build_sem_open_smoke(&musl_sysroot);

    // Isolated pthread_cancel/5-1.c crash-then-wedge repro -- see userland/pthread-cancel-crash/
    // main.c's own doc comment.
    let pthread_cancel_crash_elf_path = build_pthread_cancel_crash(&musl_sysroot);

    // Isolated pthread_cond_broadcast/1-2.c real-cross-process-stall repro -- see
    // userland/pshared-cond-crash/main.c's own doc comment.
    let pshared_cond_crash_elf_path = build_pshared_cond_crash(&musl_sysroot);

    // TinyCC: OxideBSD's first on-target C compiler -- see CLAUDE.md's TinyCC section and
    // `build_tinycc`'s own doc comment. The `tcc` binary itself is embedded into oxfs's `/bin`
    // alongside every BusyBox applet; `write_tcc_runtime_manifest` separately produces the
    // generated `/usr/include`+`/usr/lib`+`/usr/lib/tcc` manifest tcc needs to actually compile and
    // link a user's C file once running on target (not needed just to launch).
    let tinycc_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("third_party/tinycc");
    let tcc_elf_path = build_tinycc(&musl_sysroot);
    let tcc_runtime_manifest_path = write_tcc_runtime_manifest(&musl_sysroot, &tinycc_dir);

    // Clang/LLVM: OxideBSD's second real on-target C/C++ compiler (see CLAUDE.md's Clang/LLVM
    // port section). A two-stage cross-compile: a host-executable cross compiler
    // (`build_llvm_host_toolchain`) builds the target's own C++ runtime
    // (`build_llvm_target_runtimes`) and then the real, on-target-executable clang+lld
    // (`build_llvm_target_toolchain`) using that same cross compiler. Genuinely slow on a clean
    // checkout (multi-hour) -- staleness-gated the same way `build_tinycc` is.
    vendor_linux_uapi_headers(&musl_sysroot);
    let llvm_host_build = build_llvm_host_toolchain();
    build_llvm_target_runtimes(&llvm_host_build, &musl_sysroot);
    let llvm_target_build = build_llvm_target_toolchain(&llvm_host_build, &musl_sysroot);
    let clang_elf_path = llvm_target_build.join("bin/clang-23");
    let lld_elf_path = llvm_target_build.join("bin/lld");
    let clang_runtime_manifest_path = write_clang_runtime_manifest(&llvm_target_build);

    // A real, playable port of Doom (via doomgeneric) -- see `build_doomgeneric`'s own doc
    // comment for the source list, and `third_party/doomgeneric/doomgeneric/doomgeneric_oxidebsd.c`
    // for the backend. `doom1.wad` (the freely-redistributable shareware IWAD) is vendored
    // directly, not built.
    let doom_elf_path = build_doomgeneric(&musl_sysroot);
    let doom1_wad_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("third_party/doom1.wad");

    // A real POSIX conformance baseline: see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`'s own
    // "Verification" section and `modules/oxfs/src/posix_conformance.sh`'s doc comment. Source-only
    // (compiled on-target by `tcc`, not cross-compiled here) -- see `write_posix_test_manifest`'s
    // own doc comment for why.
    let posixtestsuite_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("third_party/posixtestsuite");
    let posix_test_manifest_path = write_posix_test_manifest(&musl_sysroot, &posixtestsuite_dir);

    // Real PT_INTERP / dynamic-linking milestone 1: a real, separate shared musl build (see
    // `build_musl_sysroot_shared`'s own doc comment for why it can't reuse the static sysroot
    // above, and why it's linked at its own natural base rather than a fixed one) producing
    // `libc.so` (which doubles as `ld-musl-x86_64.so.1`, musl's own convention) -- the kernel
    // itself picks its real runtime placement (`src/process/lifecycle.rs`'s `INTERP_LOAD_BASE`, `0x10000000`)
    // at `execve` time, not this build. The fixture binary
    // (`userland/dynlink-smoke/main.c`) is fixed at `0x8d00000` -- an ordinary `ET_EXEC` main
    // binary, same fixed-link-time-base treatment every other userland crate here gets, distinct
    // from `INTERP_LOAD_BASE` since the two must be *co-resident* in the same address space for a
    // real `PT_INTERP` exec to work at all. (Both moved `+0x4000000` alongside every other fixed
    // userland/BusyBox/module address -- see `module::MODULE_VA_BASE`'s own doc comment.)
    let dynlink_fixture_base: u64 = 0x8d00000;
    let dynlink_musl_sysroot = build_musl_sysroot_shared();
    let dynlink_libc_so_path = dynlink_musl_sysroot.join("lib/libc.so");
    let dynlink_smoke_elf_path = build_dynlink_smoke(&dynlink_musl_sysroot, dynlink_fixture_base);

    let busybox_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("third_party/busybox");
    println!("cargo:rerun-if-changed={}", busybox_dir.display());
    let busybox_source_mtime = latest_mtime(&busybox_dir);

    // Parallel across applets, `-j1` within each one (see `build_busybox_applet`'s own doc
    // comment) -- a plain work-stealing pool over a shared atomic index, not a thread per applet
    // (~300 of those would vastly oversubscribe an 8-core host) and not a chunked static split
    // (uneven applet build times would leave some workers idle while others queue up).
    let all_applets: Vec<(&str, &str, u64)> = BUSYBOX_APPLETS
        .iter()
        .copied()
        .chain(BUSYBOX_APPLETS_PASS2.iter().copied())
        .collect();
    let jobs = build_jobs();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(&(applet_symbol, out_name, load_addr)) = all_applets.get(i) else {
                        break;
                    };
                    build_busybox_applet(
                        applet_symbol,
                        out_name,
                        load_addr,
                        &musl_sysroot,
                        busybox_source_mtime,
                    );
                }
            });
        }
    });

    // oxfs: the real, live filesystem (see CLAUDE.md's oxfs section). There's no
    // on-disk image format to generate -- oxfs's own module_init populates its inode table directly
    // via ordinary function calls, using each already-built ELF's path passed straight through as
    // its own env var (see `build_module_crate`'s own doc comment for the `extra_env` mechanism). Built
    // from BUSYBOX_APPLETS itself (not one hand-written `let ..._elf_path = ...` line per applet)
    // so the next applet added there doesn't need a matching edit here too -- `oxfs_env_var_name`
    // derives each one's `OXFS_<NAME>_ELF_PATH` env var straight from its own `out_name`, with one
    // explicit exception ("sh" -> "HUSH", matching `modules/oxfs/src/lib.rs`'s existing
    // `OXFS_HUSH_ELF_PATH`/`seed_file(root, b"sh.elf", ...)` naming, itself inherited from this
    // applet's own Kconfig symbol `HUSH`, not its embedded filename).
    let hush_elf_path_for_main = target_dir_busybox_elf("sh");
    println!("cargo:rustc-env=HUSH_ELF_PATH={hush_elf_path_for_main}");
    let oxfs_applet_paths: Vec<(String, String)> = all_applets
        .iter()
        .map(|&(_, out_name, _)| {
            (
                oxfs_env_var_name(out_name),
                target_dir_busybox_elf(out_name),
            )
        })
        .collect();
    let mut oxfs_extra_env: Vec<(&str, &str)> = vec![
        (
            "OXFS_SMOKE_ELF_PATH",
            ring3_smoke_elf_path.to_str().unwrap(),
        ),
        ("OXFS_MUSL_ELF_PATH", musl_smoke_elf_path.to_str().unwrap()),
        (
            "OXFS_STD_HELLO_ELF_PATH",
            std_hello_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_STD_HELLO_OXIDEBSD_ELF_PATH",
            std_hello_oxidebsd_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_STD_PROCESS_FS_OXIDEBSD_ELF_PATH",
            std_process_fs_oxidebsd_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_STD_THREAD_NET_SIGNAL_OXIDEBSD_ELF_PATH",
            std_thread_net_signal_oxidebsd_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_FLOAT_SMOKE_ELF_PATH",
            float_smoke_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_PTHREAD_SMOKE_ELF_PATH",
            pthread_smoke_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_SEM_OPEN_SMOKE_ELF_PATH",
            sem_open_smoke_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_PTHREAD_CANCEL_CRASH_ELF_PATH",
            pthread_cancel_crash_elf_path.to_str().unwrap(),
        ),
        (
            "OXFS_PSHARED_COND_CRASH_ELF_PATH",
            pshared_cond_crash_elf_path.to_str().unwrap(),
        ),
        ("OXFS_LSOXMOD_ELF_PATH", lsoxmod_elf_path.to_str().unwrap()),
        ("OXFS_TCC_ELF_PATH", tcc_elf_path.to_str().unwrap()),
        ("OXFS_CLANG_ELF_PATH", clang_elf_path.to_str().unwrap()),
        ("OXFS_LLD_ELF_PATH", lld_elf_path.to_str().unwrap()),
        ("OXFS_DOOM_ELF_PATH", doom_elf_path.to_str().unwrap()),
        ("OXFS_DOOM1_WAD_PATH", doom1_wad_path.to_str().unwrap()),
        (
            "TCC_RUNTIME_MANIFEST_PATH",
            tcc_runtime_manifest_path.to_str().unwrap(),
        ),
        (
            "CLANG_RUNTIME_MANIFEST_PATH",
            clang_runtime_manifest_path.to_str().unwrap(),
        ),
        (
            "POSIX_TEST_MANIFEST_PATH",
            posix_test_manifest_path.to_str().unwrap(),
        ),
        (
            "OXFS_DYNLINK_LIBC_SO_PATH",
            dynlink_libc_so_path.to_str().unwrap(),
        ),
        (
            "OXFS_DYNLINK_SMOKE_ELF_PATH",
            dynlink_smoke_elf_path.to_str().unwrap(),
        ),
    ];
    oxfs_extra_env.extend(
        oxfs_applet_paths
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    build_module_crate("oxfs", "OXFS", &oxfs_extra_env);

    // Real disk persistence (see src/drivers/ata.rs and modules/oxfs's own "Real disk persistence"
    // section): the two raw disk image *files* QEMU's `-drive` attaches, as opposed to everything
    // above, which gets embedded into the kernel/module binaries themselves via `include_bytes!`.
    write_data_disk_images();

    // Multiboot2 boot path (see CLAUDE.md's Multiboot2 section): a genuinely separate final ELF,
    // linked against its own dedicated linker script and the `multiboot2` feature -- not another
    // `[[test]]`, since those all share the kernel's own rustflags/linker script. Not embedded
    // anywhere; its own QEMU boot is driven directly by `scripts/run_multiboot2_smoke.sh`.
    //
    // **Must stay gated by a reentrancy guard, not called unconditionally.** Unlike every other
    // `build_*_crate` call above, `smoke/multiboot2-boot-smoke` depends on the real `oxidebsd` lib
    // itself (not just freestanding `core`/`alloc`) -- so building it re-triggers *this exact
    // build script* as a dependency build. An unconditional call here recurses forever: building
    // the smoke crate builds `oxidebsd`, whose build script tries to build the smoke crate again,
    // which builds `oxidebsd` again... each level spawning a nested `cargo` that deadlocks waiting
    // on the previous level's own target-dir lock. Found live testing Stage 0: three real nested
    // `cargo`/build-script processes deep before the innermost one blocked forever on `flock`.
    //
    // `CARGO_PRIMARY_PACKAGE` looks like the obvious fix (set only when `oxidebsd` is the package
    // actually selected for building, not when it's merely a path dependency) but does **not**
    // work here -- confirmed via `cargo check -vv`: Cargo sets it for the rustc invocations that
    // compile `build.rs` itself and the final crate, but strips it before actually *running* the
    // compiled `build-script-build` binary, i.e. exactly the point where this code executes. A
    // plain `std::env::var_os("CARGO_PRIMARY_PACKAGE")` check here is always `None`, primary
    // package or not. Use an explicit marker env var instead, set by
    // `build_multiboot2_boot_smoke_crate` itself on the nested `cargo` command it spawns --
    // ordinary env inheritance means the recursive inner build of `oxidebsd` (as the smoke
    // crate's own dependency) sees it and skips this call, terminating the recursion at depth 1.
    if std::env::var_os("OXIDEBSD_BUILDING_MULTIBOOT2_SMOKE").is_none() {
        build_multiboot2_boot_smoke_crate();
    }
}

fn oxfs_env_var_name(out_name: &str) -> String {
    let suffix = if out_name == "sh" {
        "HUSH".to_string()
    } else {
        out_name.to_uppercase()
    };
    format!("OXFS_{suffix}_ELF_PATH")
}

/// Each `BUSYBOX_APPLETS` entry's own out-of-tree build directory follows a fixed, predictable
/// shape (`target/busybox-<out_name>/busybox`, `build_busybox_applet`'s own `out_dir.join("busybox")`
/// return value) -- re-derived here rather than plumbed through as a second return value, since
/// `busybox_applet_elfs` (built above) only kept the *bytes*, not the path, and oxfs's own
/// `extra_env` needs a path string, not bytes.
fn target_dir_busybox_elf(out_name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join(format!("target/busybox-{out_name}"))
        .join("busybox")
        .to_str()
        .unwrap()
        .to_string()
}

/// Configures, builds, and installs the vendored, OxideBSD-patched musl (`third_party/musl` -- a
/// submodule pointing at a personal fork, patched on its own `oxidebsd` branch to speak this
/// kernel's native ABI directly -- see `CLAUDE.md`'s musl section) into `target/musl-sysroot`,
/// producing a `musl-gcc`-style wrapper this build script can shell out to for
/// `userland/musl-smoke/`. Uses musl's own build system directly (`configure`/`make`/
/// `make install`) -- there's no Cargo/Rust involved at all, it's a plain C library. Skips
/// `./configure` if a `config.mak` already exists (configure itself takes several seconds
/// re-probing the host compiler on every run; `make`/`make install` are already fast, idempotent
/// no-ops when nothing changed, so only configure needs this guard).
fn build_musl_sysroot() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let musl_dir = Path::new(manifest_dir).join("third_party/musl");
    let sysroot = Path::new(manifest_dir).join("target/musl-sysroot");

    println!(
        "cargo:rerun-if-changed={}",
        musl_dir.join("arch/x86_64").display()
    );
    println!("cargo:rerun-if-changed={}", musl_dir.join("src").display());

    if !musl_dir.join("config.mak").exists() {
        // Run via its own path (not `sh configure`, and not a bare relative "configure"): the
        // script derives its own source directory from `${0%/configure}` (build.rs:201 in
        // musl's own configure) -- given anything that doesn't literally end in "/configure",
        // that substitution is a no-op and it tries to `cd` into a nonexistent directory named
        // after whatever `$0` was. `./configure` (a real, executable path ending in "/configure")
        // is the one invocation shape that satisfies its own self-location logic.
        let status = Command::new("./configure")
            .current_dir(&musl_dir)
            .args([
                "--disable-shared",
                &format!("--prefix={}", sysroot.display()),
                // Found live, via TinyCC (see CLAUDE.md's TinyCC section): this project's dev
                // host's own real gcc defaults to PIE (confirmed directly: `echo | gcc -E -dM -`
                // defines `__PIC__`/`__PIE__` with *no* flags at all -- a real, common modern
                // distro default, not something this project's own toolchain chose). musl's own
                // `configure` (`trycppif __PIC__ ...`, this file's own line ~578) auto-detects
                // that and lets PIE-style GOT-indirect codegen leak into every musl object it
                // builds, including plain `crt1.o` -- confirmed directly: `readelf -r crt1.o`
                // showed real `R_X86_64_REX_GOTPCRELX` relocations referencing `main`/`_init`/
                // `_fini` from `_start_c`. Every *other* consumer of this sysroot links via
                // `musl-gcc` -> real GNU ld, which silently performs the standard GOTPCRELX
                // link-time relaxation (rewriting the GOT-indirect load into a direct `lea` once
                // it knows the final static address) -- hiding this completely. TinyCC's own
                // linker doesn't implement that relaxation: it reserves a real GOT slot and is
                // *supposed* to fill it with the resolved address (traced through
                // `third_party/tinycc/tccelf.c`'s `build_got_entries`/`fill_got_entry`), but the
                // real, live symptom (a `hello.elf` tcc itself both compiled and linked with no
                // errors at all faulted on a garbage instruction-fetch address the instant it
                // ran) shows that path isn't reliable for this exact case. `-fno-pie -fno-PIC`
                // forces genuinely old-style, non-GOT-indirect codegen for every musl object
                // regardless of host default -- confirmed directly: recompiling `crt1.c` this way
                // produces only plain `R_X86_64_32`/`PC32`/`PLT32` relocations, no GOTPCRELX at
                // all, which is what let this project's very first BusyBox/musl-smoke binaries
                // already work (they happened to get real relaxation from GNU ld, this makes the
                // *input* to any linker unambiguous instead of depending on that relaxation).
                // `obj/crt/Scrt1.o`/`obj/crt/rcrt1.o` (musl's own real PIE crt variants) still
                // force `-fPIC` back on for themselves specifically
                // (`third_party/musl/Makefile`'s own `CFLAGS_ALL += -fPIC` line for those two
                // files only) -- unaffected, and also never embedded into this project's own tcc
                // runtime manifest in the first place (see `write_tcc_runtime_manifest`'s own
                // doc comment on why those two are skipped).
                "CFLAGS=-fno-pie -fno-PIC",
            ])
            .status()
            .unwrap_or_else(|e| panic!("failed to run musl's configure: {e}"));
        if !status.success() {
            panic!("musl configure failed: {status}");
        }
    }

    let jobs = build_jobs();
    let status = Command::new("make")
        .current_dir(&musl_dir)
        .args(["-j", &jobs.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("failed to run make for musl: {e}"));
    if !status.success() {
        panic!("musl build failed: {status}");
    }

    let status = Command::new("make")
        .current_dir(&musl_dir)
        .arg("install")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make install for musl: {e}"));
    if !status.success() {
        panic!("musl install failed: {status}");
    }

    sysroot
}

/// Cross-builds `userland/musl-smoke/main.c` against `sysroot` (see `build_musl_sysroot` above),
/// at a load address (`0x80c0000`, was `0x40c0000` before the whole family's own `+0x4000000`
/// move -- see `module::MODULE_VA_BASE`'s own doc comment) clear of both the kernel's own image
/// (the actually-binding constraint today, not the bootloader's fixed ~6 MiB identity-mapped
/// low-memory region -- see `userland/ring3-smoke/linker.ld`'s own comment for the full story of
/// why this floor moves and how to re-derive it) and every other
/// userland crate's load base (`0x8000000`-`0x8080000`) -- confirmed empirically via `readelf -hl`
/// before this was written, the same discipline CLAUDE.md's own `ring3-smoke` load-address
/// collision story already established. Unlike every other `userland/*` crate this isn't a Rust
/// crate at all -- musl-smoke exists specifically to
/// exercise a real musl static binary, so it's built with `musl-gcc` directly, no cargo involved.
/// Ensures `libunwind.a` exists in *our own* musl sysroot, copied from the pinned nightly's own
/// bundled self-contained object set for `x86_64-unknown-linux-musl`. musl itself has no unwind
/// library; `std`'s prebuilt `.rlib`s for this target hard-depend on `-lunwind` regardless of
/// `-C panic=abort` (confirmed live: `std`'s own backtrace machinery links it unconditionally).
/// **Deliberately not done via an extra `-L <rustup self-contained dir>` linker flag** — that was
/// tried first and found to silently win `-lc` resolution too (GCC's `%{L*}` spec expansion
/// collects *every* `-L` argument, wherever it appears on the command line, ahead of
/// `musl-gcc.specs`'s own injected `-L`), producing a binary statically linked against the
/// *unpatched* bundled musl instead of ours — confirmed via disassembly, `open()` came back
/// byte-identical to the bundled copy, not this project's own patched (path_ptr, path_len, flags,
/// mode)-over-R10 implementation. Copying just this one file in means our own sysroot's `-L`
/// (already correctly prioritized by `musl-gcc.specs`) is the only one on the command line at all.
fn ensure_libunwind_in_sysroot(sysroot: &Path) {
    let dest = sysroot.join("lib/libunwind.a");
    if dest.exists() {
        return;
    }
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_sysroot = Command::new(&rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .unwrap_or_else(|e| panic!("failed to query rustc sysroot: {e}"));
    let rustc_sysroot = String::from_utf8(rustc_sysroot.stdout)
        .expect("rustc --print sysroot produced non-UTF8 output")
        .trim()
        .to_string();
    let src = Path::new(&rustc_sysroot)
        .join("lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libunwind.a");
    std::fs::copy(&src, &dest).unwrap_or_else(|e| {
        panic!(
            "failed to copy {} to {}: {e}",
            src.display(),
            dest.display()
        )
    });
}

/// Real `std` on OxideBSD (see `userland-std/std-hello/src/main.rs`'s own doc comment for the
/// full rationale). Built via a direct `rustc` invocation, not `cargo build` -- **not just a
/// Phase-0 shortcut, a confirmed-necessary choice**: `userland-std/std-hello` has its own real
/// `Cargo.toml` + `userland-std/.cargo/config.toml` (`target = "x86_64-unknown-linux-musl"`,
/// `[unstable] build-std = []`), but `cargo build` from that crate still pulls in the *repo
/// root's* `.cargo/config.toml` `[unstable] build-std = ["core","alloc","compiler_builtins"]`
/// regardless -- confirmed via `cargo -Z unstable-options config get unstable.build-std` --
/// because cargo's config-file directory-tree walk-up is unconditional (there's no boundary a
/// nested `.cargo/config.toml` or an empty `[workspace]` table stops it at), **and array-typed
/// config keys merge across every discovered file instead of a closer file overriding a farther
/// one** -- confirmed three ways: an explicit empty array in the closer file, `--config
/// 'unstable.build-std=[]'` on the CLI (docs claim CLI config has the highest priority; still
/// merged), and `CARGO_UNSTABLE_BUILD_STD=""` as an env var (also merged, and a `"[]"`-string
/// value got appended as a literal element rather than parsed as an empty list). Scalar keys
/// (`build.target`) *do* cleanly override across the same files -- only the array case is stuck.
/// Net effect if this used `cargo build`: `core`/`alloc`/`compiler_builtins` would silently
/// rebuild from `rust-src` for `x86_64-unknown-linux-musl` instead of using the real prebuilt
/// ones this target already ships -- wasteful at best, a real divergence risk at worst. A direct
/// `rustc` invocation has no directory-tree config-discovery mechanism at all, sidestepping the
/// whole problem. (The crate's own `Cargo.toml`/`userland-std/.cargo/config.toml` are still real
/// and useful for local iteration -- `cd userland-std/std-hello && cargo build` works today, just
/// slower than it should be from the redundant core/alloc rebuild; not what this function uses
/// for the actual embedded artifact.) If a future `userland-std/*` crate needs genuine Cargo
/// dependencies (breaking the "single `rustc`-compiled file" model this function assumes), the
/// known escape hatch -- not yet implemented -- is to have `build.rs` copy that crate's source to
/// a location outside this repo's directory tree entirely (e.g. under the OS temp dir) before
/// invoking `cargo build` from there, so the walk-up never reaches this repo's root config.
///
/// Flags, each verified individually against a real linked+disassembled binary before trusting it
/// (see the plan this spike came from):
/// - `-C target-feature=+crt-static -C link-self-contained=no -C linker=<our musl-gcc>`: forces
///   the link to go through *our own* sysroot's `musl-gcc` wrapper (its `musl-gcc.specs` already
///   points `-L`/crt startfile/endfile paths at `target/musl-sysroot`), rather than rustc silently
///   linking its own bundled self-contained musl objects.
/// - `-C panic=abort`: matches every other binary in this project; also required in practice --
///   without it, rustc still tries to pull in `libpanic_unwind`/`-lunwind` regardless (see
///   `ensure_libunwind_in_sysroot` above for why `-lunwind` needs to exist in *our* sysroot at all).
/// - `-C link-arg=-no-pie -C link-arg=-Wl,-Ttext-segment=<addr>`: fixed-address `ET_EXEC`, same
///   convention as `build_musl_smoke`'s own `-Wl,-Ttext-segment=`.
fn build_std_hello_spike(sysroot: &Path) -> PathBuf {
    ensure_libunwind_in_sysroot(sysroot);

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland-std/std-hello/src/main.rs");
    let target_dir = Path::new(manifest_dir).join("target/std-hello");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/std-hello");
    let out = target_dir.join("std-hello");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    // 0x14000000 -- next free slot past every currently-claimed userland load address (the
    // musl-gcc/C family's own highest, doomgeneric's 0x13000000, as of this spike's own
    // addition), with real headroom (this binary statically links the whole of Rust `std`, ~4.3
    // MiB as of this addition -- re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd
    // | grep -A1 LOAD` plus this binary's own size before trusting this if either has grown.
    let status = Command::new(&rustc)
        .arg("--target")
        .arg("x86_64-unknown-linux-musl")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("target-feature=+crt-static")
        .arg("-C")
        .arg("link-self-contained=no")
        .arg("-C")
        .arg(format!("linker={}", musl_gcc.display()))
        .arg("-C")
        .arg("link-arg=-no-pie")
        .arg("-C")
        .arg("link-arg=-Wl,-Ttext-segment=0x14000000")
        .arg("-O")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTFLAGS", "")
        .status()
        .unwrap_or_else(|e| panic!("failed to run rustc for std-hello spike: {e}"));
    if !status.success() {
        panic!("building the std-hello spike failed: {status}");
    }
    out
}

/// Constructs (idempotently -- cheap, just symlinks, safe to call every build) a hybrid rustc
/// sysroot directory at a stable, repo-relative location so `-Z build-std` compiles against
/// *our own* forked `rust-lang/rust` (`third_party/rust`, the `oxidebsd` branch) instead of the
/// pinned nightly's stock `rust-src` component.
///
/// **Why this specific shape, not something simpler** -- both gotchas below were found live,
/// each confirmed by direct experiment before trusting the fix (see the "Rust std target" plan
/// and its own `project_rust_fork_buildstd_mechanism` memory for the full investigation):
/// - `rustc --print sysroot` self-detection does **not** work off `current_exe()`/argv0 the way
///   `xargo`/`cargo-sysroot`-style tooling assumes -- neither a symlinked nor a hardlinked
///   `bin/rustc` at an alternate location changes what it reports (a distributed rustup rustc
///   binary appears to bake its install sysroot in at build time). The one thing that reliably
///   overrides it is the explicit `--sysroot=<path>` CLI flag -- but cargo's own internal
///   build-std source-discovery step calls `<rustc> --print sysroot` itself without forwarding
///   user `RUSTFLAGS`, so `build_std_oxidebsd_userland_crate` forces it via `RUSTC_WRAPPER`
///   instead (cargo's standard rustc-interception env var, the same one `sccache` uses -- wraps
///   *every* rustc invocation cargo makes, including that internal query).
/// - Pointing `lib/rustlib/src/rust` straight at the `third_party/rust` checkout fails (`cannot
///   specify features for packages outside of workspace`) -- the real, rustup-shipped `rust-src`
///   component is *not* the whole monorepo, just bare `library/` + `src/` directories with **no
///   top-level `Cargo.toml`** above them; our full clone's own root `[workspace]` (which doesn't
///   list `library/` as a member) confuses cargo's workspace resolution once `library/std` is
///   reached through it. Fixed by mirroring just those two directories (no ancestor Cargo.toml)
///   and pointing `lib/rustlib/src/rust` at *that* instead.
///
/// Everything else in the hybrid sysroot is a plain symlink straight to the *real* pinned
/// toolchain's own directory (`bin/`, top-level `.so`s, `lib/rustlib/<host-target>`,
/// `lib/rustlib/<other-targets>` for prebuilt target libs/linking) -- only `lib/rustlib/src/rust`
/// differs. No `rustup toolchain link` needed; this is purely a `--sysroot` value.
fn build_oxidebsd_rust_sysroot() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rust_fork = Path::new(manifest_dir).join("third_party/rust");
    let sysroot_dir = Path::new(manifest_dir).join("target/oxidebsd-rust-sysroot");
    let src_mirror = Path::new(manifest_dir).join("target/oxidebsd-rust-src-mirror");

    std::fs::create_dir_all(&src_mirror).expect("failed to create target/oxidebsd-rust-src-mirror");
    for name in ["library", "src"] {
        symlink_if_missing(&rust_fork.join(name), &src_mirror.join(name));
    }

    let toolchain_dir = PathBuf::from(rustc_output(manifest_dir, &["--print", "sysroot"]));

    std::fs::create_dir_all(sysroot_dir.join("lib/rustlib/src"))
        .expect("failed to create target/oxidebsd-rust-sysroot/lib/rustlib/src");
    for entry in dir_entry_names(&toolchain_dir) {
        if entry != "lib" {
            symlink_if_missing(&toolchain_dir.join(&entry), &sysroot_dir.join(&entry));
        }
    }
    for entry in dir_entry_names(&toolchain_dir.join("lib")) {
        if entry != "rustlib" {
            symlink_if_missing(
                &toolchain_dir.join("lib").join(&entry),
                &sysroot_dir.join("lib").join(&entry),
            );
        }
    }
    for entry in dir_entry_names(&toolchain_dir.join("lib/rustlib")) {
        if entry != "src" {
            symlink_if_missing(
                &toolchain_dir.join("lib/rustlib").join(&entry),
                &sysroot_dir.join("lib/rustlib").join(&entry),
            );
        }
    }
    symlink_if_missing(&src_mirror, &sysroot_dir.join("lib/rustlib/src/rust"));

    sysroot_dir
}

fn symlink_if_missing(target: &Path, link: &Path) {
    if link.exists() {
        return;
    }
    std::os::unix::fs::symlink(target, link).unwrap_or_else(|e| {
        panic!(
            "failed to symlink {} -> {}: {e}",
            link.display(),
            target.display()
        )
    });
}

fn dir_entry_names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("failed to read a dir entry in {}: {e}", dir.display()))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// Writes (always -- cheap, keeps it correct across a changed sysroot path) the small
/// `RUSTC_WRAPPER` script `build_std_oxidebsd_userland_crate` uses to force every rustc
/// invocation cargo makes onto our hybrid sysroot. `RUSTC_WRAPPER` is invoked as
/// `$RUSTC_WRAPPER $RUSTC <args...>` -- `$1` is the real (stock) rustc path cargo resolved.
fn write_oxidebsd_rustc_wrapper(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir).join("target/oxidebsd-rustc-wrapper.sh");
    let script = format!(
        "#!/bin/sh\nreal_rustc=\"$1\"\nshift\nexec \"$real_rustc\" --sysroot=\"{}\" \"$@\"\n",
        sysroot.display()
    );
    std::fs::write(&path, script).expect("failed to write target/oxidebsd-rustc-wrapper.sh");
    let mut perms = std::fs::metadata(&path)
        .expect("failed to stat target/oxidebsd-rustc-wrapper.sh")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&path, perms)
        .expect("failed to chmod target/oxidebsd-rustc-wrapper.sh");
    path
}

/// Builds a real userland crate against OxideBSD's own `x86_64-unknown-oxidebsd` target (see
/// `x86_64-unknown-oxidebsd.json` and `third_party/rust`'s `oxidebsd` branch) -- the genuine
/// target-identity path, as opposed to `build_std_hello_spike`'s cheaper
/// `x86_64-unknown-linux-musl` one. **Real, permanent, disclosed cost**: every build here
/// genuinely recompiles `std`/`core`/`alloc`/`panic_abort` from source via `-Z
/// build-std=std,core,alloc,panic_abort` (~40s observed) -- there is no prebuilt `std` for a
/// brand-new custom target the way there is for a real Tier-1/2 one. `crate_name` must name a
/// real crate directory under `userland-std/` with its own empty `[workspace]` table (see
/// `userland-std/std-hello-oxidebsd/Cargo.toml`). No `#![feature(restricted_std)]` needed --
/// `library/std/build.rs` lists `target_os = "oxidebsd"` in its supported-platform allowlist, and
/// `library/Cargo.toml`'s `[patch.crates-io]` routes `libc` at our own `libc-crate-oxidebsd` fork
/// (its `oxidebsd` branch reuses the real `linux`/musl cfg-gated code paths throughout, since our
/// musl fork's public C ABI is unchanged from stock).
fn build_std_oxidebsd_userland_crate(crate_name: &str, env_var: &str, musl_sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let crate_dir = Path::new(manifest_dir)
        .join("userland-std")
        .join(crate_name);
    let target_spec = Path::new(manifest_dir).join("x86_64-unknown-oxidebsd.json");
    let target_dir = Path::new(manifest_dir)
        .join("target/userland-std-oxidebsd")
        .join(crate_name);

    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("Cargo.toml").display()
    );
    println!("cargo:rerun-if-changed={}", target_spec.display());
    // Once *any* rerun-if-changed is emitted, cargo stops implicitly watching the whole package
    // directory -- without watching `third_party/rust` too, a patch to our own forked
    // `library/std` source doesn't trigger a rebuild here at all. **Found live, a real, not
    // fully root-caused gotcha**: watching the `library` directory alone was NOT reliable --
    // confirmed via direct experiment, `std::env::consts::OS` kept reporting an empty string
    // after a real fix landed in `third_party/rust`, across multiple plain `cargo test` reruns,
    // until `target/x86_64-oxidebsd/debug/build/oxidebsd-*` (cargo's own build-script fingerprint
    // cache) was deleted by hand to force a genuinely fresh build.rs invocation. Suspected but
    // unconfirmed cause: `third_party/rust/library` contains a *nested* submodule
    // (`library/backtrace`, its own separate `.git` boundary) that may confuse cargo's recursive
    // directory-change scan. Watching the submodule's own git ref file directly (updates on every
    // commit, unlike `.git/modules/.../HEAD` itself which only changes on branch switch) is a
    // more reliable second signal, kept alongside the directory watch rather than replacing it.
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(manifest_dir).join("third_party/rust/library").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(manifest_dir)
            .join(".git/modules/third_party/rust/refs/heads/oxidebsd")
            .display()
    );

    let rust_sysroot = build_oxidebsd_rust_sysroot();
    let wrapper = write_oxidebsd_rustc_wrapper(&rust_sysroot);

    let cargo = cargo_bin();
    let status = Command::new(&cargo)
        .current_dir(manifest_dir)
        .args([
            "build",
            "--release",
            "-Z",
            "build-std=std,core,alloc,panic_abort",
            "-Z",
            "json-target-spec",
            "--manifest-path",
            crate_dir.join("Cargo.toml").to_str().unwrap(),
            "--target",
            target_spec.to_str().unwrap(),
            "--target-dir",
            target_dir.to_str().unwrap(),
        ])
        // Same discipline as build_userland_crate -- see that function's own doc comment for
        // why CARGO_ENCODED_RUSTFLAGS must be cleared before setting our own RUSTFLAGS.
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTC_WRAPPER", &wrapper)
        .env(
            "RUSTFLAGS",
            format!(
                "-C link-self-contained=no -C linker={}/bin/musl-gcc -C link-arg=-no-pie -C link-arg=-Wl,-Ttext-segment=0x16000000",
                musl_sysroot.display()
            ),
        )
        .status()
        .unwrap_or_else(|e| panic!("failed to run cargo for {crate_name} (oxidebsd target): {e}"));

    if !status.success() {
        panic!("building the {crate_name} oxidebsd-target binary failed: {status}");
    }

    let elf_path = target_dir
        .join("x86_64-unknown-oxidebsd/release")
        .join(crate_name);
    assert!(
        elf_path.exists(),
        "{crate_name} (oxidebsd target) build reported success but {} doesn't exist",
        elf_path.display()
    );
    println!("cargo:rustc-env={env_var}={}", elf_path.display());
    elf_path
}

fn build_musl_smoke(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/musl-smoke/main.c");
    let target_dir = Path::new(manifest_dir).join("target/musl-smoke");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/musl-smoke");
    let out = target_dir.join("musl-smoke");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-Wl,-Ttext-segment=0x80c0000") // was 0x40c0000; +0x4000000, see module::MODULE_VA_BASE's own doc comment
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for musl-smoke: {e}"));
    if !status.success() {
        panic!("building musl-smoke failed: {status}");
    }
    out
}

/// Derisk check for the fbdoom/doomgeneric port -- see `userland/float-smoke/main.c`'s own doc
/// comment for why. Same `build_musl_smoke` recipe, next free slot in that family
/// (`0x8200000`, clear of `sem-open-smoke`/its neighbors' own `0x81c0000`).
/// The real id Software Doom engine sources this build compiles, matching `third_party/
/// doomgeneric/doomgeneric/Makefile.linuxvt`'s own `SRC_DOOM` list -- the closest existing
/// upstream Makefile to this port (no SDL/X11, real framebuffer + input) -- **minus** `i_video`/
/// `i_input`/`doomgeneric_linuxvt` (real Linux fbdev/evdev-specific; `i_video.c` doesn't even
/// compile against this musl fork's sysroot, which vendors no `<linux/fb.h>`), **plus** this
/// port's own `doomgeneric_oxidebsd`/`i_video_oxidebsd` (see those two files' own doc comments).
const DOOMGENERIC_SOURCES: &[&str] = &[
    "dummy",
    "am_map",
    "doomdef",
    "doomstat",
    "dstrings",
    "d_event",
    "d_items",
    "d_iwad",
    "d_loop",
    "d_main",
    "d_mode",
    "d_net",
    "f_finale",
    "f_wipe",
    "g_game",
    "hu_lib",
    "hu_stuff",
    "info",
    "i_cdmus",
    "i_endoom",
    "i_joystick",
    "i_scale",
    "i_sound",
    "i_system",
    "i_timer",
    "memio",
    "m_argv",
    "m_bbox",
    "m_cheat",
    "m_config",
    "m_controls",
    "m_fixed",
    "m_menu",
    "m_misc",
    "m_random",
    "p_ceilng",
    "p_doors",
    "p_enemy",
    "p_floor",
    "p_inter",
    "p_lights",
    "p_map",
    "p_maputl",
    "p_mobj",
    "p_plats",
    "p_pspr",
    "p_saveg",
    "p_setup",
    "p_sight",
    "p_spec",
    "p_switch",
    "p_telept",
    "p_tick",
    "p_user",
    "r_bsp",
    "r_data",
    "r_draw",
    "r_main",
    "r_plane",
    "r_segs",
    "r_sky",
    "r_things",
    "sha1",
    "sounds",
    "statdump",
    "st_lib",
    "st_stuff",
    "s_sound",
    "tables",
    "v_video",
    "wi_stuff",
    "w_checksum",
    "w_file",
    "w_main",
    "w_wad",
    "z_zone",
    "w_file_stdc",
    "mus2mid",
    "doomgeneric",
    "doomgeneric_oxidebsd",
    "i_video_oxidebsd",
];

/// Same three-way staleness-check shape `build_tinycc` established (`build.rs`'s own mtime,
/// `musl_sysroot/lib/libc.a`'s mtime, a recursive source-tree walk) -- reuses `latest_mtime`
/// directly rather than a bespoke walker, since this tree has no generated build artifacts of its
/// own to skip (compiled straight into `target/doomgeneric/`, never in-tree).
fn build_doomgeneric(musl_sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let doomgeneric_dir = Path::new(manifest_dir).join("third_party/doomgeneric/doomgeneric");
    // Found live fixing the Space-doesn't-open-doors bug: this function's own `already_fresh`
    // mtime check is dead code without this -- cargo only reruns build.rs at all for paths it's
    // explicitly told to watch (once any `cargo:rerun-if-changed` is emitted anywhere, cargo's
    // default "watch the whole package" behavior is disabled), and nothing registered this
    // directory. A source-only edit here silently never rebuilt `doom` until something unrelated
    // (e.g. editing `build.rs` itself) happened to invalidate the build-script cache too. Same
    // whole-directory registration precedent `busybox_dir`/`musl_dir` already use elsewhere in
    // this file.
    println!("cargo:rerun-if-changed={}", doomgeneric_dir.display());
    let target_dir = Path::new(manifest_dir).join("target/doomgeneric");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/doomgeneric");
    let out = target_dir.join("doom");

    let build_rs_mtime = std::fs::metadata(Path::new(manifest_dir).join("build.rs"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let musl_mtime = std::fs::metadata(musl_sysroot.join("lib/libc.a"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let freshness_floor = build_rs_mtime
        .max(musl_mtime)
        .max(latest_mtime(&doomgeneric_dir));
    let already_fresh = std::fs::metadata(&out)
        .and_then(|m| m.modified())
        .map(|m| m >= freshness_floor)
        .unwrap_or(false);
    if already_fresh {
        return out;
    }

    let sources: Vec<std::path::PathBuf> = DOOMGENERIC_SOURCES
        .iter()
        .map(|name| doomgeneric_dir.join(format!("{name}.c")))
        .collect();

    let musl_gcc = musl_sysroot.join("bin/musl-gcc");
    let invocation = compiler_invocation(&musl_gcc);
    let mut cmd = Command::new(&invocation[0]);
    cmd.args(&invocation[1..]);
    cmd.arg("-static")
        .arg("-no-pie")
        // 0x13000000 -- next free slot past every currently-claimed userland load address (the
        // Rust smoke-test family's own highest, keyevent-syscall-smoke's 0x12800000, as of this
        // crate's own addition) -- re-derive via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd
        // | grep -A1 LOAD` before trusting this if the kernel image has grown meaningfully since.
        .arg("-Wl,-Ttext-segment=0x13000000")
        .arg("-O2")
        .arg("-DNORMALUNIX")
        .arg("-DLINUX") // Real upstream's own portable-POSIX-behavior guard, not Linux-specific.
        .arg("-D_DEFAULT_SOURCE")
        .arg("-Wno-implicit-function-declaration")
        .arg("-o")
        .arg(&out);
    for src in &sources {
        cmd.arg(src);
    }
    cmd.arg("-lm");
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for doomgeneric: {e}"));
    if !status.success() {
        panic!("building doomgeneric failed: {status}");
    }
    out
}

fn build_float_smoke(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/float-smoke/main.c");
    let target_dir = Path::new(manifest_dir).join("target/float-smoke");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/float-smoke");
    let out = target_dir.join("float-smoke");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-Wl,-Ttext-segment=0x8200000")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for float-smoke: {e}"));
    if !status.success() {
        panic!("building float-smoke failed: {status}");
    }
    out
}

/// "Real threading" phases 1-5's own finish line -- see `userland/pthread-smoke/main.c`'s own doc
/// comment for the scenario. Same `build_musl_smoke` recipe, one slot further along
/// (`0x8100000`, clear of `musl-smoke`'s `0x80c0000`) -- this binary is `fork`+`execve`'d fresh by
/// `userland/pthread-syscall-smoke/`, never co-resident with any other fixed-base image (unlike
/// `build_dynlink_smoke`'s own interpreter-coexistence case), so it only needs to stay clear of the
/// kernel's own image/heap/phys-mem window, not any other userland crate specifically.
fn build_pthread_smoke(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/pthread-smoke/main.c");
    let target_dir = Path::new(manifest_dir).join("target/pthread-smoke");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/pthread-smoke");
    let out = target_dir.join("pthread-smoke");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-pthread")
        .arg("-Wl,-Ttext-segment=0x8100000") // was 0x4100000; +0x4000000, see module::MODULE_VA_BASE's own doc comment
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for pthread-smoke: {e}"));
    if !status.success() {
        panic!("building pthread-smoke failed: {status}");
    }
    out
}

/// Real cross-process named-semaphore coordination (`sem_open()`+`fork()`) -- see
/// `userland/sem-open-smoke/main.c`'s own doc comment for the scenario, and
/// `process::limits::futex_key`'s own doc comment (`src/process/limits.rs`) for the real
/// physical-address-keyed `FUTEX_WAIT`/`FUTEX_WAKE` fix this proves. Same `build_musl_smoke`
/// recipe `build_pthread_smoke` above already establishes, one slot further along (`0x8140000`,
/// clear of `pthread-smoke`'s own `0x8100000`) -- this binary is `fork`+`execve`'d fresh by
/// `userland/sem-open-syscall-smoke/`, never co-resident with any other fixed-base image, so it
/// only needs to stay clear of the kernel's own image/heap/phys-mem window.
fn build_sem_open_smoke(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/sem-open-smoke/main.c");
    let target_dir = Path::new(manifest_dir).join("target/sem-open-smoke");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/sem-open-smoke");
    let out = target_dir.join("sem-open-smoke");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-Wl,-Ttext-segment=0x8140000")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for sem-open-smoke: {e}"));
    if !status.success() {
        panic!("building sem-open-smoke failed: {status}");
    }
    out
}

/// Reproduces the Open POSIX Test Suite's own `pthread_cancel/5-1.c` scenario in isolation -- see
/// `userland/pthread-cancel-crash/main.c`'s own doc comment for why (a real, expected crash inside
/// that pilot file seemed to leave the whole kernel wedged for the rest of a full-corpus boot; this
/// isolates the crash from the ~1700-file harness to find out why). Same `build_musl_smoke` recipe
/// `build_pthread_smoke` above already establishes (needs `-pthread` for the same reason that one
/// does -- real `pthread_create`/`pthread_join`/`pthread_cancel`), one slot further along
/// (`0x8180000`, clear of `sem-open-smoke`'s own `0x8140000`).
fn build_pthread_cancel_crash(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/pthread-cancel-crash/main.c");
    let target_dir = Path::new(manifest_dir).join("target/pthread-cancel-crash");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/pthread-cancel-crash");
    let out = target_dir.join("pthread-cancel-crash");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-pthread")
        .arg("-Wl,-Ttext-segment=0x8180000")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for pthread-cancel-crash: {e}"));
    if !status.success() {
        panic!("building pthread-cancel-crash failed: {status}");
    }
    out
}

/// Isolates the real cross-process `pthread_mutex`/`pthread_cond` (`PTHREAD_PROCESS_SHARED`)
/// mechanism from the Open POSIX Test Suite's own `pthread_cond_broadcast/1-2.c`, which appears to
/// genuinely stall somewhere in its real `fork==1` scenarios during a full pilot run -- see
/// `userland/pshared-cond-crash/main.c`'s own doc comment for the exact narrower scenario this
/// reproduces (one forked child, not up to `MAX_PROCESS_CHILDREN = 200`). Same `build_musl_smoke`
/// recipe (needs `-pthread`), one slot further along (`0x81c0000`, clear of
/// `pthread-cancel-crash`'s own `0x8180000`).
fn build_pshared_cond_crash(sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/pshared-cond-crash/main.c");
    let target_dir = Path::new(manifest_dir).join("target/pshared-cond-crash");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/pshared-cond-crash");
    let out = target_dir.join("pshared-cond-crash");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg("-pthread")
        .arg("-Wl,-Ttext-segment=0x81c0000")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for pshared-cond-crash: {e}"));
    if !status.success() {
        panic!("building pshared-cond-crash failed: {status}");
    }
    out
}

/// A **second, separate** musl build producing real shared objects (`libc.so`, and
/// `ld-musl-x86_64.so.1` as musl's own install step symlinks it to the same file -- upstream musl
/// has no separate `ld.so` binary) with genuine `-fPIC` codegen, linked at its own natural
/// (near-zero) default base -- **deliberately not** fixed at link time via `-Wl,-Ttext-segment=`
/// the way every other userland binary in this codebase is. Found the hard way, via a real page
/// fault: a fixed-link-time base bakes *already-absolute* addresses into the interpreter's own
/// `.rela.dyn`/`DT_RELA` table (confirmed via `readelf -r`), and real musl's own self-relocation
/// bootstrap (`ldso/dlstart.c`) always computes `real_addr = AT_BASE + stored_value`, expecting
/// `stored_value` to be zero-based -- a fixed-base link double-counts the base and produces a wild
/// pointer. `src/process/elf.rs`'s `elf::load` now applies a real, kernel-chosen runtime bias instead (see
/// its own doc comment and `src/process/lifecycle.rs`'s `INTERP_LOAD_BASE`) -- this build only needs to
/// produce a normally-linked, real `-fPIC` shared object, the same shape any real musl
/// distro ships.
///
/// **Deliberately builds from a fresh copy of `third_party/musl`, not in the same tree
/// `build_musl_sysroot` already builds the static sysroot in.** That static build configures with
/// `--disable-shared CFLAGS=-fno-pie -fno-PIC` -- exactly wrong for real shared objects (genuine
/// PIC codegen, not the anti-PIE workaround TinyCC's static linking needed, see that function's
/// own doc comment) -- and both builds happen in-place (no out-of-tree `O=` mechanism musl's
/// Makefile supports, confirmed against `build_musl_sysroot`'s own precedent). Running a second,
/// differently-flagged configure+make in the same source directory would silently corrupt the
/// static `libc.a` that TinyCC and the whole BusyBox roster already depend on. The copy is a
/// one-time cost (gated on the destination not already existing) -- this deliberately does not try
/// to detect a stale copy against upstream source changes the way `build_busybox_applet`'s
/// staleness floor does; re-syncing this copy after a real `third_party/musl` patch is a manual
/// step for now (`rm -rf target/musl-src-shared`), matching this milestone's own deliberately
/// narrow scope.
///
/// **`--prefix`/`--syslibdir` both point inside the sysroot itself** (not a real target-visible
/// path like `/usr`/`/lib`), matching `build_musl_sysroot`'s own "no `DESTDIR`, prefix ==
/// final-usage location" shape -- confirmed empirically the only way `musl-gcc`'s own installed
/// wrapper (which bakes in `-specs <libdir>/musl-gcc.specs` at install time, read at every future
/// invocation) stays directly usable as a host-side cross-compiler without a second relocation
/// step. This means the *default* dynamic-linker path baked into anything linked against this
/// sysroot would be this host's own absolute sysroot path, not the real target path
/// (`/lib/ld-musl-x86_64.so.1`, matching where `modules/oxfs` seeds it) -- `build_dynlink_smoke`
/// below overrides it explicitly per-link via `-Wl,--dynamic-linker=...` rather than trying to
/// thread a real target-relative prefix through (confirmed via direct `readelf -p .interp`
/// experimentation that this override wins over the specs file's own default).
fn build_musl_sysroot_shared() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let real_musl_dir = Path::new(manifest_dir).join("third_party/musl");
    let musl_dir = Path::new(manifest_dir).join("target/musl-src-shared");
    let sysroot = Path::new(manifest_dir).join("target/musl-sysroot-shared");

    if !musl_dir.exists() {
        let status = Command::new("cp")
            .args(["-a", "--", "."])
            .arg(&musl_dir)
            .current_dir(&real_musl_dir)
            .status()
            .unwrap_or_else(|e| {
                panic!("failed to copy third_party/musl for the shared build: {e}")
            });
        if !status.success() {
            panic!("copying third_party/musl for the shared build failed: {status}");
        }
        // `cp -a` faithfully copies whatever build state `third_party/musl` itself happens to be
        // in right now -- including, almost always, `build_musl_sysroot`'s own already-built
        // static `config.mak`/`obj/`/`lib/*.a` (musl builds in place, no `O=` out-of-tree
        // mechanism, same reasoning `build_musl_sysroot`'s own doc comment already gives). Left
        // alone, the copy's `config.mak` presence check right below would wrongly treat *that*
        // static config as "already configured for this shared build" and skip `./configure`
        // entirely -- and even a plain `rm config.mak` alone wouldn't be enough, since `make`'s own
        // incremental tracking compares object mtimes against source mtimes, not compiler flags,
        // so stale non-PIC `.o`/`.lo` files from the static build would silently survive into a
        // supposedly-`-fPIC` build (the same class of bug CLAUDE.md's BusyBox section documents
        // for a stale out-of-tree build directory). `make distclean` (`rm -rf obj lib` +
        // `rm -f config.mak`) guarantees a truly pristine tree regardless of what state
        // `third_party/musl` was in at copy time -- run exactly once, right after a fresh copy,
        // not on every subsequent `cargo build` (which would defeat this build's own incremental
        // compilation once it's genuinely configured for real).
        let status = Command::new("make")
            .args(["distclean"])
            .current_dir(&musl_dir)
            .status()
            .unwrap_or_else(|e| panic!("failed to distclean the copied musl tree: {e}"));
        if !status.success() {
            panic!("distclean of the copied musl tree failed: {status}");
        }
    }

    if !musl_dir.join("config.mak").exists() {
        let status = Command::new("./configure")
            .current_dir(&musl_dir)
            .args([
                &format!("--prefix={}", sysroot.display()),
                &format!("--syslibdir={}", sysroot.join("lib").display()),
                "CFLAGS=-fPIC",
            ])
            .status()
            .unwrap_or_else(|e| panic!("failed to run musl's configure (shared): {e}"));
        if !status.success() {
            panic!("musl configure (shared) failed: {status}");
        }
    }

    let jobs = build_jobs();
    let status = Command::new("make")
        .current_dir(&musl_dir)
        .args(["-j", &jobs.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("failed to run make for musl (shared): {e}"));
    if !status.success() {
        panic!("musl build (shared) failed: {status}");
    }

    let status = Command::new("make")
        .current_dir(&musl_dir)
        .arg("install")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make install for musl (shared): {e}"));
    if !status.success() {
        panic!("musl install (shared) failed: {status}");
    }

    sysroot
}

/// Cross-builds `userland/dynlink-smoke/main.c` (one `write()` call) against `sysroot` (see
/// `build_musl_sysroot_shared` above) as a real, dynamically-linked `ET_EXEC` binary: `-no-pie`
/// (matching `build_musl_smoke`'s own reasoning -- keeps this the *main binary*, not itself an
/// `ET_DYN` image, so only the interpreter needs `src/process/elf.rs`'s new `ET_DYN` handling), fixed at
/// `fixture_base` (must stay clear of `src/process/lifecycle.rs`'s `INTERP_LOAD_BASE` -- both images load
/// into the *same* address space for a real `PT_INTERP` exec, unlike every other fixed-base
/// userland binary in this codebase, which never coexists with another image), and an explicit
/// `-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1` overriding the sysroot's own host-path default
/// (see `build_musl_sysroot_shared`'s own doc comment) so the baked-in `PT_INTERP` string matches
/// the real target path `modules/oxfs` seeds this at.
fn build_dynlink_smoke(sysroot: &Path, fixture_base: u64) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = Path::new(manifest_dir).join("userland/dynlink-smoke/main.c");
    let target_dir = Path::new(manifest_dir).join("target/dynlink-smoke");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/dynlink-smoke");
    let out = target_dir.join("dynlink-smoke");

    println!("cargo:rerun-if-changed={}", src.display());

    let musl_gcc = sysroot.join("bin/musl-gcc");
    let status = Command::new(&musl_gcc)
        .arg("-no-pie")
        .arg(format!("-Wl,-Ttext-segment={fixture_base:#x}"))
        .arg("-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1")
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for dynlink-smoke: {e}"));
    if !status.success() {
        panic!("building dynlink-smoke failed: {status}");
    }
    out
}

/// Cross-builds TinyCC (`third_party/tinycc`, real upstream `release_0_9_27` vendored on this
/// project's own `oxidebsd` submodule branch -- same pin/update procedure as musl/BusyBox) against
/// `musl_sysroot` via `musl-gcc`, the same "shell out to the real toolchain, no cargo" idiom
/// `build_musl_smoke`/`build_busybox_applet` already use. Unlike BusyBox this is a plain,
/// non-Kconfig `./configure` + `make` project -- `--config-musl` is real, maintained upstream musl
/// support (confirmed against a real build: Alpine Linux, a musl distro, ships tcc in production
/// the same way) -- so there's no per-applet flip/oldconfig dance, one configure and one make.
///
/// `--prefix=/usr` does **not** touch the host's real `/usr` -- it only becomes a compiled-in
/// default baked into the `tcc` binary itself, i.e. where *it* looks for headers/crt objects/its
/// own runtime library once *it* is running on OxideBSD. Confirmed against the real generated
/// `config.h`: `CONFIG_TCCDIR` = `/usr/lib/tcc`, `CONFIG_TCC_CRTPREFIX` = `/usr/lib`,
/// `CONFIG_TCC_SYSINCLUDEPATHS` includes `/usr/include` -- exactly the layout `modules/oxfs`'s own
/// seeding wires up (`seed_tree`/`format_fresh_filesystem`, once Milestone B lands), so no extra
/// `-B`/`-I`/`-L` flags are needed at `tcc` invocation time on target.
///
/// **`libtcc1.a` (tcc's own runtime helper library) deliberately does not use tcc's normal
/// self-hosting recipe.** tcc's own `Makefile` builds it as `libtcc1.a : tcc$(EXESUF) FORCE`,
/// running the just-built `tcc` binary *on the host* to compile `lib/*.c`. Confirmed live that this
/// cannot work here: the just-built `tcc` is linked against this project's own *patched* musl
/// (carry-flag errno conversion, remapped `__NR_*` values -- see CLAUDE.md's musl-port section), so
/// every syscall it issues is misinterpreted by the real host kernel's real Linux ABI -- running it
/// directly on the host doesn't crash, it silently does nothing (`./tcc --version` exits `0` with
/// no output at all). tcc's own Makefile has a documented escape hatch for exactly this shape of
/// problem, normally meant for cross-architecture builds: `<target>-libtcc1-usegcc=yes`, which
/// swaps in a real, host-executable `$(CC)` instead of self-hosting via the freshly built `tcc`.
/// Safe here because `libtcc1.a`'s own sources (`lib/*.c`, `lib/*.S`) are pure freestanding
/// numeric helper routines (softfloat/int64 conversions) with no syscalls at all -- compiling them
/// with the host-executable `musl-gcc` wrapper directly (a real host tool, unlike the cross-built
/// `tcc` itself) produces object code that's ABI-correct for the target either way.
///
/// **Built in-place inside the submodule** (matching `build_musl_sysroot`'s own precedent, not
/// `build_busybox_applet`'s out-of-tree `O=` build -- tcc's Makefile has no equivalent out-of-tree
/// mechanism), so unlike `build_busybox_applet`'s freshness-floor check, this deliberately does
/// **not** `cargo:rerun-if-changed` the submodule directory: tcc's own build outputs (`tcc`, `.o`
/// files, `libtcc1.a`) land in the exact same directories as its source, so watching that tree
/// would make every build's own output look like a source change to cargo on the *next* build,
/// forcing a real rebuild every single time regardless of whether anything actually changed. The
/// same reasoning is why source-mtime staleness here can't just be `latest_mtime(&tinycc_dir)`
/// either -- that would walk right back over the build's own prior output sitting in the same
/// directory, making it look perpetually newer than itself. `tinycc_source_mtime` (below) is
/// `latest_mtime`'s same walk with the exact build-output names/extensions
/// `clean_tinycc_build_outputs` already excludes skipped. Real source patches now exist
/// (`x86_64-link.c`'s own `ELF_START_ADDR`, see CLAUDE.md's TinyCC section for why a real
/// on-target-compiled program needs its own safe default link address) -- found live the same way
/// the freshness-floor lesson itself was learned elsewhere in this file, so this tracks it from the
/// start rather than deferring the way an earlier version of this comment once said to.
fn build_tinycc(musl_sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let tinycc_dir = Path::new(manifest_dir).join("third_party/tinycc");
    let tcc_bin = tinycc_dir.join("tcc");
    let libtcc1 = tinycc_dir.join("libtcc1.a");

    let build_rs_mtime = std::fs::metadata(Path::new(manifest_dir).join("build.rs"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let musl_mtime = std::fs::metadata(musl_sysroot.join("lib/libc.a"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let freshness_floor = build_rs_mtime
        .max(musl_mtime)
        .max(tinycc_source_mtime(&tinycc_dir));
    let already_fresh = [&tcc_bin, &libtcc1].into_iter().all(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .map(|m| m >= freshness_floor)
            .unwrap_or(false)
    });
    if already_fresh {
        return tcc_bin;
    }

    clean_tinycc_build_outputs(&tinycc_dir);

    let musl_gcc = musl_sysroot.join("bin/musl-gcc");
    if !tinycc_dir.join("config.mak").exists() {
        let status = Command::new("./configure")
            .current_dir(&tinycc_dir)
            .arg(format!("--cc={}", musl_gcc.display()))
            .arg("--config-musl")
            .arg("--prefix=/usr")
            // Explicit, not derived from --prefix alone: confirmed live that tinycc's own
            // configure (only when NOT given a --cross-prefix, which this build.rs invocation
            // never does) probes the *build host's* own `/usr/lib64/crti.o` to decide whether to
            // bake in `lib64` instead of `lib` (`CONFIG_LDDIR`, used to derive
            // `CONFIG_TCC_LIBPATHS`/`CONFIG_TCC_CRTPREFIX`) -- a real host-environment quirk
            // (whether *this build machine's* distro happens to split `/usr/lib64`) completely
            // unrelated to the target musl sysroot's own layout, which is always flat `/usr/lib`
            // (confirmed against `target/musl-sysroot/lib`'s own real `make install` output --
            // musl doesn't do a lib64 multilib split at all). Found live: a first build without
            // these three flags produced a `tcc` that reported `file 'crt1.o' not found`/
            // `library 'c' not found` at real runtime inside QEMU, since it was searching
            // `/usr/lib64` on target, which oxfs never seeds anything into. These three flags
            // bypass that host-autodetection entirely by stating the real target layout directly
            // (matches CLAUDE.md's TinyCC section for the full story).
            .arg("--crtprefix=/usr/lib")
            .arg("--libpaths=/usr/lib")
            .arg("--sysincludepaths=/usr/include")
            .status()
            .unwrap_or_else(|e| panic!("failed to run tinycc's configure: {e}"));
        if !status.success() {
            panic!("tinycc configure failed: {status}");
        }
    }

    // 0xe280000 (was 0xa280000; +0x4000000, see module::MODULE_VA_BASE's own doc comment): next
    // free slot past the BusyBox applet range (highest in use is CRYPTPW's 0xe240000, was
    // 0xe240000 (was 0xa240000), in `BUSYBOX_APPLETS_PASS2`) -- tcc lives in the same "standalone binary embedded
    // into oxfs's /bin" bucket as every applet, just built from its own upstream project instead
    // of BusyBox's.
    let status = Command::new("make")
        .current_dir(&tinycc_dir)
        .arg("tcc")
        .arg("LDFLAGS=-static -no-pie -Wl,-Ttext-segment=0xe280000")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make tcc: {e}"));
    if !status.success() {
        panic!("building tcc failed: {status}");
    }

    let status = Command::new("make")
        .current_dir(&tinycc_dir)
        .arg("x86_64-libtcc1-usegcc=yes")
        .arg(format!("CC={}", musl_gcc.display()))
        .arg("libtcc1.a")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make libtcc1.a: {e}"));
    if !status.success() {
        panic!("building tinycc's libtcc1.a failed: {status}");
    }

    tcc_bin
}

/// Removes tinycc's own previous build outputs (not its source) from an in-place build -- see
/// `build_tinycc`'s own doc comment for why a stale binary needs to be actively cleared rather than
/// relying on `make`'s incremental tracking (no dependency on `musl_sysroot`'s installed headers at
/// all). Scoped to exactly the two directories tinycc ever writes into (`third_party/tinycc` itself
/// and its `lib/` subdirectory, for `libtcc1.a`'s own object files) and a fixed set of known
/// build-output names/extensions -- never touches `win32/`/`tests/`/etc, and never deletes a real
/// source file.
fn clean_tinycc_build_outputs(tinycc_dir: &Path) {
    for dir in [tinycc_dir.to_path_buf(), tinycc_dir.join("lib")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_tinycc_build_output(name) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Shared exclusion list between `clean_tinycc_build_outputs` and `tinycc_source_mtime` -- kept as
/// one function specifically so the two can't silently drift apart (a name added to one but not
/// the other would either leave a stale build output uncleaned or make a real build output look
/// like a perpetually-changing "source" file).
fn is_tinycc_build_output(name: &str) -> bool {
    name == "tcc"
        || name == "config.mak"
        || name == "config.h"
        || name.ends_with(".o")
        || name.ends_with(".a")
}

/// Like `latest_mtime`, but skips tinycc's own build outputs (`is_tinycc_build_output`) -- see
/// `build_tinycc`'s own doc comment for why this can't just be `latest_mtime(&tinycc_dir)`
/// directly (built in-place, so that would walk right back over the build's own prior output).
///
/// **Also emits `cargo:rerun-if-changed` for every real source file it walks past** -- load-
/// bearing, not a nicety: found live, the hard way, right after `x86_64-link.c`'s own
/// `ELF_START_ADDR` was first patched -- a `cargo build` right afterward finished in `0.09s` and
/// silently kept using the *stale* `tcc` binary, because nothing in this build script had ever
/// told cargo that `third_party/tinycc`'s source was worth watching at all. Cargo only re-invokes
/// `main()` when a path from a *previous run's own* `rerun-if-changed` set changes -- with none
/// registered for tinycc, a real source edit there was completely invisible to cargo's own decision
/// of whether to re-run this file, so `tinycc_source_mtime`'s own freshness check (correct in
/// isolation) never even got a chance to run. Same class of bug as the freshness-floor lesson
/// `build_busybox_applet` already documents, just one level up the stack (cargo not re-invoking
/// `build.rs` at all, rather than this function's own logic making the wrong call once invoked).
fn tinycc_source_mtime(tinycc_dir: &Path) -> std::time::SystemTime {
    let mut latest = std::time::UNIX_EPOCH;
    let mut stack = vec![tinycc_dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if name_str.starts_with('.') {
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if !is_tinycc_build_output(name_str) {
                let path = entry.path();
                println!("cargo:rerun-if-changed={}", path.display());
                if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                    latest = latest.max(modified);
                }
            }
        }
    }
    latest
}

/// Latest mtime across every real source file under `dir`, skipping VCS metadata (any directory
/// starting with `.`) -- computed once per `cargo build` invocation, not once per applet (see
/// `build_busybox_applet`'s own doc comment for why that distinction matters at ~300 applets). A
/// plain recursive walk rather than a crate dependency: this only runs when build.rs's own
/// `cargo:rerun-if-changed` gate already decided `third_party/busybox` changed, so it's a rare,
/// not hot-path, cost -- not worth a `walkdir`-style dependency for.
fn latest_mtime(dir: &Path) -> std::time::SystemTime {
    let mut latest = std::time::UNIX_EPOCH;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.starts_with('.'))
            {
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                latest = latest.max(modified);
            }
        }
    }
    latest
}

/// Recursively collects every real file under `dir`, returning `(relative_path, absolute_path)`
/// pairs with `/`-separated relative paths (not platform-`PathBuf`-component-dependent) -- used to
/// enumerate `musl_sysroot/include`/`musl_sysroot/lib` and tinycc's own bundled `include/` for
/// `write_tcc_runtime_manifest` below. Shares `latest_mtime`'s own stack-based walk shape and
/// dotfile-skipping, but returns paths instead of a single max mtime.
fn collect_dir_files(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel_dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(dir.join(&rel_dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            if name.to_str().is_some_and(|s| s.starts_with('.')) {
                continue;
            }
            let rel_path = rel_dir.join(&name);
            if file_type.is_dir() {
                stack.push(rel_path);
            } else {
                let rel_str = rel_path
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel_str, entry.path()));
            }
        }
    }
    out
}

/// Generates a single Rust source file declaring `MUSL_INCLUDE_FILES`/`MUSL_LIB_FILES`/
/// `TCC_RUNTIME_FILES` -- `&[(&str, &[u8])]` arrays of (path relative to their own eventual
/// `/usr/...` destination, embedded content) -- consumed by `modules/oxfs/src/lib.rs`'s
/// `format_fresh_filesystem` via a single `include!(env!("TCC_RUNTIME_MANIFEST_PATH"))`, feeding
/// its own `seed_tree` helper. See CLAUDE.md's TinyCC section for why this is real, on-target
/// runtime content tcc needs (musl's headers/crt/`libc.a`, tcc's own `libtcc1.a` + bundled
/// compiler-magic headers), not just the compiler binary itself.
///
/// Written as a real generated file with literal absolute `include_bytes!` paths, not the
/// `env!()`-indirected `cargo:rustc-env`-per-file pattern every other embedded ELF in this build
/// script uses -- deliberately: this is ~230 individual files (217 musl headers alone), not a
/// handful of named applets each already needing its own unique identifier for other reasons (a
/// Kconfig symbol, a load address). Inventing and sanitizing ~230 one-off env var names for data
/// that has no other reason to need a name would be pure ceremony. The generated file is itself a
/// build artifact -- never checked in, already host-specific -- so embedding this host's own
/// absolute paths directly is no less portable than the indirection used elsewhere.
fn write_tcc_runtime_manifest(musl_sysroot: &Path, tinycc_dir: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_dir = Path::new(manifest_dir).join("target/generated");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/generated");
    let out_path = out_dir.join("tcc_runtime_manifest.rs");

    let mut src = String::new();
    let write_array = |src: &mut String, array_name: &str, files: &[(String, PathBuf)]| {
        src.push_str(&format!("pub static {array_name}: &[(&str, &[u8])] = &[\n"));
        for (rel, abs) in files {
            src.push_str(&format!(
                "    ({rel:?}, include_bytes!({:?})),\n",
                abs.display()
            ));
        }
        src.push_str("];\n\n");
    };

    // /usr/include -- musl's own real header tree, embedded whole (not a hand-curated subset --
    // see CLAUDE.md's TinyCC section for why: even a trivial `printf` pulls in a nontrivial
    // closure of internal `bits/*.h`/`features.h` headers, and the full tree is already sitting
    // here post-`make install` at zero extra build cost).
    let mut headers = collect_dir_files(&musl_sysroot.join("include"));
    headers.sort();
    write_array(&mut src, "MUSL_INCLUDE_FILES", &headers);

    // /usr/lib -- crt objects + every musl-produced `.a` (libc.a plus its small stub archives, for
    // real `-lm`/`-lpthread`/etc. link-line compatibility even though musl merges everything into
    // libc.a itself). `rcrt1.o`/`Scrt1.o` (PIE-only crt variants) and `musl-gcc.specs` (a host
    // build-tool artifact, meaningless inside a target sysroot) are deliberately skipped -- tcc on
    // this kernel always links `-static`, never PIE (a real, separate decision made in
    // `third_party/tinycc/libtcc.c`'s own `tcc_new()`, not a missing kernel capability -- `elf.rs`
    // does now have real `PT_INTERP` support, see CLAUDE.md's "Dynamic linking" section, just never
    // wired up for tcc's own output).
    let mut lib_files: Vec<(String, PathBuf)> = collect_dir_files(&musl_sysroot.join("lib"))
        .into_iter()
        .filter(|(rel, _)| !matches!(rel.as_str(), "rcrt1.o" | "Scrt1.o" | "musl-gcc.specs"))
        .collect();
    lib_files.sort();
    write_array(&mut src, "MUSL_LIB_FILES", &lib_files);

    // /usr/lib/tcc -- tcc's own runtime helper library plus its own bundled compiler-magic headers
    // (`stdarg.h`/`stddef.h`/`float.h`/... -- distinct from musl's real userspace headers above,
    // needed because tcc's preprocessor wants its own compatible versions of a handful of
    // compiler-intrinsic headers). Confirmed against tcc's own `tcc.h`
    // (`CONFIG_TCC_SYSINCLUDEPATHS`'s first entry is `{B}/include`, `{B}` == `CONFIG_TCCDIR` ==
    // `/usr/lib/tcc`) that these belong at `tcc/include/*.h`, not flat under `tcc/`.
    let mut tcc_runtime_files: Vec<(String, PathBuf)> =
        vec![("libtcc1.a".to_string(), tinycc_dir.join("libtcc1.a"))];
    let mut tcc_headers = collect_dir_files(&tinycc_dir.join("include"));
    tcc_headers.sort();
    tcc_runtime_files.extend(
        tcc_headers
            .into_iter()
            .map(|(rel, abs)| (format!("include/{rel}"), abs)),
    );
    write_array(&mut src, "TCC_RUNTIME_FILES", &tcc_runtime_files);

    std::fs::write(&out_path, src)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));
    out_path
}

/// The triple this project's real on-target Clang/LLVM port builds for -- genuine `Triple::
/// OxideBSD` OS identity (see `third_party/llvm-project`'s `oxidebsd` branch), `musl` environment
/// so LLVM/Clang's existing `Triple::isMusl()`-gated behavior (dynamic-linker naming, static/PIE
/// defaults, CRT object selection in `Gnu.cpp`) applies for free, matching real musl-linux
/// conventions the project's musl fork already provides on disk.
const CLANG_TARGET_TRIPLE: &str = "x86_64-unknown-oxidebsd-musl";

/// Recursively copies `src` into `dest`, creating directories as needed. Only used by
/// `vendor_linux_uapi_headers` below, which needs a plain directory copy from a location outside
/// this repo (the host's own `/usr/include`) -- `collect_dir_files` isn't a fit since that returns
/// `include_bytes!`-ready paths for a generated Rust source, not a real filesystem copy.
fn copy_dir_recursive(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap_or_else(|e| panic!("failed to create {}: {e}", dest.display()));
    let Ok(entries) = std::fs::read_dir(src) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let dest_path = dest.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path);
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dest_path)
                .unwrap_or_else(|e| panic!("failed to copy {}: {e}", entry.path().display()));
        }
    }
}

/// Idempotently vendors a handful of real Linux kernel uapi headers (`linux/`, `asm/`,
/// `asm-generic/`) from the *host's* own `/usr/include` into the musl sysroot. Needed only by
/// libc++'s own `src/atomic.cpp` (`#ifdef __linux__ #include <linux/futex.h>`, unconditional in
/// this LLVM version) -- neither musl nor tcc need any of this. Safe to vendor verbatim:
/// `linux/futex.h`'s `FUTEX_WAIT=0`/`FUTEX_WAKE=1`/`FUTEX_PRIVATE=128` are confirmed to exactly
/// match this kernel's own real `do_futex` opcode numbering (`src/process/limits.rs`), and the
/// whole directory is GPL-2.0-with-Linux-syscall-note licensed specifically to permit this exact
/// kind of userspace consumption (same exception real libc's like musl/glibc themselves rely on).
/// A one-time copy (checked via `linux/futex.h`'s own presence) -- these never change once copied.
fn vendor_linux_uapi_headers(musl_sysroot: &Path) {
    if musl_sysroot.join("include/linux/futex.h").exists() {
        return;
    }
    for name in ["linux", "asm", "asm-generic"] {
        let src = Path::new("/usr/include").join(name);
        if src.exists() {
            copy_dir_recursive(&src, &musl_sysroot.join("include").join(name));
        }
    }
}

/// Builds a *host-executable* Clang+LLD cross compiler (`--target=x86_64-unknown-oxidebsd-musl`)
/// from `third_party/llvm-project` -- see CLAUDE.md's Clang/LLVM port section. First stage of a
/// two-stage bootstrap: this compiler runs on the build host but targets OxideBSD, and exists only
/// to build the target's own C++ runtime (`build_llvm_target_runtimes`) and the *real*,
/// on-target-executable clang+lld (`build_llvm_target_toolchain`) below.
///
/// X86-only, clang+lld only (no clang-tools-extra/lldb/mlir/polly), no tests/docs/examples --
/// this is a build tool, not a product install. `LLVM_ENABLE_EH`/`RTTI=OFF` matches LLVM's own
/// upstream default. Real, multi-hour-on-a-clean-checkout cost -- staleness-gated the same way
/// `build_tinycc` is, but **not** a full recursive walk of `third_party/llvm-project` (600+MB,
/// tens of thousands of files): `cargo:rerun-if-changed` is scoped to just the directories this
/// project actually patches, matching `build_musl_sysroot`'s own directory-level (not per-file)
/// scoping.
fn build_llvm_host_toolchain() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let llvm_root = Path::new(manifest_dir).join("third_party/llvm-project");
    let build_dir = Path::new(manifest_dir).join("target/llvm-host-build");
    let clang_bin = build_dir.join("bin/clang-23");
    let lld_bin = build_dir.join("bin/lld");

    for dir in [
        "clang/lib/Driver",
        "clang/lib/Basic",
        "llvm/include/llvm/TargetParser",
    ] {
        println!("cargo:rerun-if-changed={}", llvm_root.join(dir).display());
    }

    let build_rs_mtime = std::fs::metadata(Path::new(manifest_dir).join("build.rs"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let freshness_floor = build_rs_mtime.max(latest_mtime(&llvm_root.join("clang/lib/Driver")));
    let already_fresh = [&clang_bin, &lld_bin].into_iter().all(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .map(|m| m >= freshness_floor)
            .unwrap_or(false)
    });
    if already_fresh {
        return build_dir;
    }

    if !build_dir.join("build.ninja").exists() {
        std::fs::create_dir_all(&build_dir).expect("failed to create target/llvm-host-build");
        let status = Command::new("cmake")
            .args(["-G", "Ninja", "-S"])
            .arg(llvm_root.join("llvm"))
            .arg("-B")
            .arg(&build_dir)
            .args([
                "-DLLVM_ENABLE_PROJECTS=clang;lld",
                "-DLLVM_TARGETS_TO_BUILD=X86",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DLLVM_ENABLE_EH=OFF",
                "-DLLVM_ENABLE_RTTI=OFF",
                "-DLLVM_INCLUDE_TESTS=OFF",
                "-DLLVM_INCLUDE_EXAMPLES=OFF",
                "-DLLVM_INCLUDE_BENCHMARKS=OFF",
                "-DLLVM_INCLUDE_DOCS=OFF",
                "-DLLVM_BUILD_TOOLS=ON",
                "-DCLANG_INCLUDE_TESTS=OFF",
                "-DCLANG_ENABLE_ARCMT=OFF",
                "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
                "-DCLANG_BUILD_TOOLS=ON",
                "-DLLVM_ENABLE_ZLIB=OFF",
                "-DLLVM_ENABLE_ZSTD=OFF",
                "-DLLVM_ENABLE_LIBXML2=OFF",
                "-DLLVM_ENABLE_TERMINFO=OFF",
                "-DLLVM_ENABLE_LIBPFM=OFF",
                "-DLLVM_ENABLE_LIBEDIT=OFF",
                "-DLLVM_CCACHE_BUILD=ON",
                "-DLLVM_PARALLEL_LINK_JOBS=2",
            ])
            .status()
            .unwrap_or_else(|e| panic!("failed to run cmake for llvm-host-build: {e}"));
        if !status.success() {
            panic!("cmake configure for llvm-host-build failed: {status}");
        }
    }

    let status = Command::new("ninja")
        .current_dir(&build_dir)
        .args(["clang", "lld"])
        .status()
        .unwrap_or_else(|e| panic!("failed to run ninja for llvm-host-build: {e}"));
    if !status.success() {
        panic!("building llvm-host-build (host clang+lld) failed: {status}");
    }

    build_dir
}

/// Builds the target's fully statically self-contained C++ runtime (libc++/libc++abi/libunwind)
/// and compiler-rt's builtins library, both using `build_llvm_host_toolchain`'s cross compiler --
/// LLVM/Clang's own source is C++ and needs a real *target* C++ standard library to compile
/// against, so this must happen before `build_llvm_target_toolchain` below, not after.
///
/// **Both `LIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY` and its libunwind-side counterpart
/// (`LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY`) are real, independent, non-cascading
/// flags** -- found live: setting only `LIBCXX_ENABLE_STATIC_ABI_LIBRARY` (whose doc text implies
/// it controls this) merges libc++abi's own symbols into `libc++.a` but leaves libunwind's
/// (`_Unwind_Resume`, etc.) undefined at final link time. Without both, a real link against
/// `libc++.a` alone (as OxideBSD's own Clang driver does -- see `OxideBSD::AddCXXStdlibLibArgs`)
/// fails with undefined `__cxa_throw`/`_Unwind_Resume`/exception-class vtable symbols.
fn build_llvm_target_runtimes(host_build: &Path, musl_sysroot: &Path) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let llvm_root = Path::new(manifest_dir).join("third_party/llvm-project");
    let libcxx_out = host_build.join(format!("lib/{CLANG_TARGET_TRIPLE}/libc++.a"));
    let compiler_rt_build = Path::new(manifest_dir).join("target/compiler-rt-target-build");
    let builtins_dest = host_build.join(format!(
        "lib/clang/23/lib/{CLANG_TARGET_TRIPLE}/libclang_rt.builtins.a"
    ));

    let freshness_floor = std::fs::metadata(host_build.join("bin/clang-23"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let already_fresh = [&libcxx_out, &builtins_dest].into_iter().all(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .map(|m| m >= freshness_floor)
            .unwrap_or(false)
    });
    if already_fresh {
        return;
    }

    // compiler-rt builtins: a standalone, bare-metal-style configure with no OS-specific detection
    // at all -- these are freestanding numeric helpers, the same role `libtcc1.a` plays for tcc.
    if !compiler_rt_build.join("build.ninja").exists() {
        std::fs::create_dir_all(&compiler_rt_build)
            .expect("failed to create target/compiler-rt-target-build");
        let host_clang = host_build.join("bin/clang");
        let status = Command::new("cmake")
            .args(["-G", "Ninja", "-S"])
            .arg(llvm_root.join("compiler-rt"))
            .arg("-B")
            .arg(&compiler_rt_build)
            .arg(format!(
                "-DLLVM_CMAKE_DIR={}",
                host_build.join("lib/cmake/llvm").display()
            ))
            .arg(format!("-DCMAKE_C_COMPILER={}", host_clang.display()))
            .arg(format!("-DCMAKE_ASM_COMPILER={}", host_clang.display()))
            .arg(format!("-DCMAKE_C_COMPILER_TARGET={CLANG_TARGET_TRIPLE}"))
            .arg(format!("-DCMAKE_ASM_COMPILER_TARGET={CLANG_TARGET_TRIPLE}"))
            .arg(format!("-DCMAKE_SYSROOT={}", musl_sysroot.display()))
            .args([
                "-DCMAKE_C_FLAGS=-static",
                "-DCOMPILER_RT_BUILD_BUILTINS=ON",
                "-DCOMPILER_RT_BUILD_SANITIZERS=OFF",
                "-DCOMPILER_RT_BUILD_XRAY=OFF",
                "-DCOMPILER_RT_BUILD_LIBFUZZER=OFF",
                "-DCOMPILER_RT_BUILD_PROFILE=OFF",
                "-DCOMPILER_RT_BUILD_MEMPROF=OFF",
                "-DCOMPILER_RT_BUILD_ORC=OFF",
                "-DCOMPILER_RT_BUILD_CTX_PROFILE=OFF",
                "-DCOMPILER_RT_BAREMETAL_BUILD=ON",
                "-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON",
                "-DCMAKE_SYSTEM_NAME=Generic",
                "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
            ])
            .status()
            .unwrap_or_else(|e| panic!("failed to run cmake for compiler-rt-target-build: {e}"));
        if !status.success() {
            panic!("cmake configure for compiler-rt-target-build failed: {status}");
        }
    }
    let status = Command::new("ninja")
        .current_dir(&compiler_rt_build)
        .arg("clang_rt.builtins-x86_64")
        .status()
        .unwrap_or_else(|e| panic!("failed to build compiler-rt builtins: {e}"));
    if !status.success() {
        panic!("building compiler-rt builtins failed: {status}");
    }
    std::fs::create_dir_all(builtins_dest.parent().unwrap())
        .expect("failed to create compiler-rt builtins install dir");
    std::fs::copy(
        compiler_rt_build.join("lib/generic/libclang_rt.builtins-x86_64.a"),
        &builtins_dest,
    )
    .unwrap_or_else(|e| panic!("failed to install compiler-rt builtins: {e}"));

    // libc++/libc++abi/libunwind: reconfigures host_build in place to add LLVM's multi-target
    // "runtimes" mechanism -- the officially supported way to build these three interdependent
    // runtimes against a fresh Clang for an arbitrary target. `RUNTIMES_<target>_FOO` cache
    // variables are forwarded generically as `-DFOO=...` to the nested configure (`llvm/runtimes/
    // CMakeLists.txt`'s `append_passthrough_options`) -- not a fixed allowlist, so every flag
    // needed for full static self-containment can be set directly on this first configure.
    let p = format!("RUNTIMES_{CLANG_TARGET_TRIPLE}_");
    let status = Command::new("cmake")
        .current_dir(host_build)
        .arg("-DLLVM_ENABLE_RUNTIMES=libcxx;libcxxabi;libunwind")
        .arg(format!("-DLLVM_RUNTIME_TARGETS={CLANG_TARGET_TRIPLE}"))
        .arg(format!("-D{p}CMAKE_SYSROOT={}", musl_sysroot.display()))
        .arg(format!("-D{p}CMAKE_BUILD_TYPE=MinSizeRel"))
        .arg(format!("-D{p}CMAKE_C_FLAGS=-static"))
        .arg(format!("-D{p}CMAKE_CXX_FLAGS=-static"))
        .arg(format!("-D{p}LIBCXX_ENABLE_SHARED=OFF"))
        .arg(format!("-D{p}LIBCXX_ENABLE_STATIC=ON"))
        .arg(format!("-D{p}LIBCXX_ENABLE_FILESYSTEM=ON"))
        .arg(format!("-D{p}LIBCXX_ENABLE_THREADS=ON"))
        .arg(format!("-D{p}LIBCXX_HAS_MUSL_LIBC=ON"))
        .arg(format!("-D{p}LIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON"))
        .arg(format!("-D{p}LIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY=ON"))
        .arg(format!("-D{p}LIBCXXABI_ENABLE_SHARED=OFF"))
        .arg(format!("-D{p}LIBCXXABI_ENABLE_STATIC=ON"))
        .arg(format!("-D{p}LIBCXXABI_USE_LLVM_UNWINDER=ON"))
        .arg(format!("-D{p}LIBCXXABI_ENABLE_STATIC_UNWINDER=ON"))
        .arg(format!(
            "-D{p}LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY=ON"
        ))
        .arg(format!("-D{p}LIBUNWIND_ENABLE_SHARED=OFF"))
        .arg(format!("-D{p}LIBUNWIND_ENABLE_STATIC=ON"))
        .arg(".")
        .status()
        .unwrap_or_else(|e| panic!("failed to reconfigure llvm-host-build for runtimes: {e}"));
    if !status.success() {
        panic!("cmake reconfigure for target runtimes failed: {status}");
    }
    let status = Command::new("ninja")
        .current_dir(host_build)
        .arg(format!("runtimes-{CLANG_TARGET_TRIPLE}"))
        .status()
        .unwrap_or_else(|e| panic!("failed to build target runtimes: {e}"));
    if !status.success() {
        panic!("building target runtimes (libc++/libc++abi/libunwind) failed: {status}");
    }
}

/// Builds the real, on-target-executable clang+lld (this port's actual deliverable) using
/// `build_llvm_host_toolchain`'s cross compiler as `CMAKE_C_COMPILER`/`CMAKE_CXX_COMPILER` --
/// build=host, host=target=OxideBSD (an ordinary two-stage cross-compile, not a true three-system
/// "Canadian Cross" -- see CLAUDE.md's Clang/LLVM port section). Reuses the host build's own
/// already-built `llvm-tblgen`/`clang-tblgen` via `LLVM_NATIVE_BUILD`/`CLANG_NATIVE_BUILD` (target
/// binaries can't run on this host during a `cmake`/`try_compile` step). `CMAKE_FIND_ROOT_PATH*`
/// is load-bearing, not boilerplate: without it, CMake's own `find_package(Backtrace)` (and
/// similar) search the *host's* `/usr/include` and incorrectly find host-only glibc headers musl
/// doesn't provide (`execinfo.h` is the real one that broke this live). `-DCLANG_DEFAULT_SYSROOT=
/// /usr` bakes in oxfs's real on-target musl layout (`/usr/include`, `/usr/lib` -- see
/// `format_fresh_filesystem`'s own tcc seeding) so on-target invocations need no extra
/// `--sysroot` flag, matching tcc's own `--prefix=/usr` convenience.
fn build_llvm_target_toolchain(host_build: &Path, musl_sysroot: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let llvm_src = Path::new(manifest_dir).join("third_party/llvm-project/llvm");
    let build_dir = Path::new(manifest_dir).join("target/llvm-target-build");
    let clang_bin = build_dir.join("bin/clang-23");
    let lld_bin = build_dir.join("bin/lld");

    let freshness_floor = std::fs::metadata(host_build.join(format!(
        "lib/{CLANG_TARGET_TRIPLE}/libc++.a"
    )))
    .and_then(|m| m.modified())
    .unwrap_or(std::time::SystemTime::now());
    let already_fresh = [&clang_bin, &lld_bin].into_iter().all(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .map(|m| m >= freshness_floor)
            .unwrap_or(false)
    });
    if already_fresh {
        return build_dir;
    }

    if !build_dir.join("build.ninja").exists() {
        std::fs::create_dir_all(&build_dir).expect("failed to create target/llvm-target-build");
        let host_clang = host_build.join("bin/clang");
        let host_clangxx = host_build.join("bin/clang++");
        let status = Command::new("cmake")
            .args(["-G", "Ninja", "-S"])
            .arg(&llvm_src)
            .arg("-B")
            .arg(&build_dir)
            .arg("-DCMAKE_SYSTEM_NAME=Linux")
            .arg("-DCMAKE_SYSTEM_PROCESSOR=x86_64")
            .arg(format!("-DCMAKE_C_COMPILER={}", host_clang.display()))
            .arg(format!("-DCMAKE_CXX_COMPILER={}", host_clangxx.display()))
            .arg(format!("-DCMAKE_ASM_COMPILER={}", host_clang.display()))
            .arg(format!("-DCMAKE_C_COMPILER_TARGET={CLANG_TARGET_TRIPLE}"))
            .arg(format!("-DCMAKE_CXX_COMPILER_TARGET={CLANG_TARGET_TRIPLE}"))
            .arg(format!("-DCMAKE_ASM_COMPILER_TARGET={CLANG_TARGET_TRIPLE}"))
            .arg(format!("-DCMAKE_SYSROOT={}", musl_sysroot.display()))
            .arg("-DCMAKE_C_FLAGS=-static -fuse-ld=lld")
            .arg("-DCMAKE_CXX_FLAGS=-static -fuse-ld=lld")
            .arg("-DCMAKE_EXE_LINKER_FLAGS=-static -fuse-ld=lld")
            .arg("-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY")
            .arg("-DCMAKE_CROSSCOMPILING=TRUE")
            .arg(format!(
                "-DCMAKE_FIND_ROOT_PATH={}",
                musl_sysroot.display()
            ))
            .args([
                "-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER",
                "-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY",
                "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY",
                "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY",
            ])
            .arg(format!("-DLLVM_NATIVE_BUILD={}", host_build.display()))
            .arg(format!("-DCLANG_NATIVE_BUILD={}", host_build.display()))
            .args([
                "-DLLVM_ENABLE_PROJECTS=clang;lld",
                "-DLLVM_TARGETS_TO_BUILD=X86",
                "-DCMAKE_BUILD_TYPE=MinSizeRel",
                "-DLLVM_ENABLE_EH=OFF",
                "-DLLVM_ENABLE_RTTI=OFF",
                "-DLLVM_ENABLE_THREADS=OFF",
                "-DLLVM_INCLUDE_TESTS=OFF",
                "-DLLVM_INCLUDE_EXAMPLES=OFF",
                "-DLLVM_INCLUDE_BENCHMARKS=OFF",
                "-DLLVM_INCLUDE_DOCS=OFF",
                "-DLLVM_BUILD_TOOLS=ON",
                "-DCLANG_INCLUDE_TESTS=OFF",
                "-DCLANG_ENABLE_ARCMT=OFF",
                "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
                "-DCLANG_BUILD_TOOLS=ON",
                "-DCLANG_DEFAULT_SYSROOT=/usr",
                "-DLLVM_ENABLE_ZLIB=OFF",
                "-DLLVM_ENABLE_ZSTD=OFF",
                "-DLLVM_ENABLE_LIBXML2=OFF",
                "-DLLVM_ENABLE_TERMINFO=OFF",
                "-DLLVM_ENABLE_LIBPFM=OFF",
                "-DLLVM_ENABLE_LIBEDIT=OFF",
                "-DLLVM_CCACHE_BUILD=ON",
                "-DLLVM_PARALLEL_LINK_JOBS=2",
            ])
            .status()
            .unwrap_or_else(|e| panic!("failed to run cmake for llvm-target-build: {e}"));
        if !status.success() {
            panic!("cmake configure for llvm-target-build failed: {status}");
        }
    }

    let status = Command::new("ninja")
        .current_dir(&build_dir)
        .args(["clang", "lld"])
        .status()
        .unwrap_or_else(|e| panic!("failed to run ninja for llvm-target-build: {e}"));
    if !status.success() {
        panic!("building llvm-target-build (on-target clang+lld) failed: {status}");
    }

    // This build's own resource dir needs the compiler-rt builtins archive too, not just the
    // host build's (`build_llvm_target_runtimes` only installed it into `host_build`'s resource
    // dir, used by the *host* cross compiler during bootstrap) -- `write_clang_runtime_manifest`
    // below embeds whatever's actually present here, and the on-target clang's own binary-
    // relative resource-dir lookup needs to find it at this exact path. Found live: a real,
    // on-target `ld.lld` invocation failed with a silent exit 1 (see this port's own diagnostic
    // history) tracing back to a raw `open("/lib/clang/23/lib/.../libclang_rt.builtins.a")`
    // returning `ENOENT` -- every *other* runtime file opened fine.
    let target_builtins_dest = build_dir.join(format!(
        "lib/clang/23/lib/{CLANG_TARGET_TRIPLE}/libclang_rt.builtins.a"
    ));
    std::fs::create_dir_all(target_builtins_dest.parent().unwrap())
        .expect("failed to create target build's own compiler-rt builtins install dir");
    std::fs::copy(
        host_build.join(format!(
            "lib/clang/23/lib/{CLANG_TARGET_TRIPLE}/libclang_rt.builtins.a"
        )),
        &target_builtins_dest,
    )
    .expect("failed to install compiler-rt builtins into the target build's own resource dir");

    // Strip before embedding -- real ~30% size reduction, pure symbol/debug-info removal.
    for bin in [&clang_bin, &lld_bin] {
        let status = Command::new(host_build.join("bin/llvm-strip"))
            .arg(bin)
            .status()
            .unwrap_or_else(|e| panic!("failed to strip {}: {e}", bin.display()));
        if !status.success() {
            panic!("stripping {} failed: {status}", bin.display());
        }
    }

    build_dir
}

/// Generates `CLANG_RESOURCE_FILES` (mirrors `write_tcc_runtime_manifest`'s own pattern): clang's
/// own resource-dir intrinsic headers (`stddef.h`/`stdarg.h`/x86 intrinsics/...) plus the
/// compiler-rt builtins archive `build_llvm_target_runtimes` installs, seeded on-target under
/// `/lib/clang/23` -- clang's own binary-relative default resource-dir location (`<bindir>/../lib/
/// clang/<ver>`), distinct from `--sysroot`/`CLANG_DEFAULT_SYSROOT` (which only governs
/// `/usr/include`+`/usr/lib`).
fn write_clang_runtime_manifest(target_build: &Path) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_dir = Path::new(manifest_dir).join("target/generated");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/generated");
    let out_path = out_dir.join("clang_runtime_manifest.rs");

    let mut files = collect_dir_files(&target_build.join("lib/clang/23"));
    files.sort();

    let mut src = String::from("pub static CLANG_RESOURCE_FILES: &[(&str, &[u8])] = &[\n");
    for (rel, abs) in &files {
        src.push_str(&format!(
            "    ({rel:?}, include_bytes!({:?})),\n",
            abs.display()
        ));
    }
    src.push_str("];\n");

    std::fs::write(&out_path, src)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));
    out_path
}

/// Two files, both under `sigwait`/`timer_settime`, **confirmed by direct testing** to hang
/// permanently against `t0`'s own `alarm(40)` rescue rather than merely run long: each blocks
/// `SIGALRM` in-process (`sigprocmask(SIG_BLOCK, ...)`) before its own real, potentially-unbounded
/// wait -- since `t0 execvp`s straight into the test binary, the alarm and the test share one
/// process/signal mask, so the pending rescue alarm never actually gets delivered.
/// `timer_settime/2-1.c` alone was confirmed hanging past a real 9+ minute ceiling before this was
/// understood. Excluded here rather than left for `discover_posix_test_files` to find blind --
/// this is hard-won, specific knowledge from prior runs, not a guess. Every *other* file also
/// matching this same `SIG_BLOCK`+`SIGALRM` shape (`pthread_sigmask`/`sigprocmask`'s own 4/7/8/12-1
/// variants, `pthread_spin_lock/1-1.c`, `timer_settime/9-2.c`, `clock_settime/4-1.c` -- the last
/// already confirmed *not* to hang, see CLAUDE.md's "real timer-signal wake bug" section) is
/// **not** pre-excluded -- untested against the now-full corpus, and blocking `SIGALRM` alone isn't
/// sufficient to hang (only blocking it *and then never reaching an unblock or a bounded wait*
/// is). If a real full run finds one of these genuinely wedged, add it here the same way these two
/// were added, then re-run -- the same "found live, fixed forward" discipline every other exclusion
/// in this codebase's history follows, not something to pre-solve by static reading alone.
// `fork/11-1.c`: **FIXED**, confirmed PASS via an isolated canary run -- root cause was two real,
// independent musl bugs, not a kernel bug at all (patched on `third_party/musl`'s `oxidebsd`
// branch, `src/process/_Fork.c` and `src/stdio/ftrylockfile.c`):
// (1) `_Fork()`'s `__post_Fork` correctly resets the surviving thread's own `tid` and
//     `__thread_list_lock` in the child, but never touched any `FILE`'s own `.lock` word -- a
//     `flockfile(stdout)` held by the parent before `fork()` left `stdout`'s lock word holding a
//     "ghost" tid in the child's eager-copied memory, one that no longer refers to any live thread
//     in that address space, so any later `ftrylockfile()`/`flockfile()` call in the child --
//     regardless of which thread -- permanently failed or deadlocked. Real glibc avoids this via
//     its own `pthread_atfork`-registered stdio-lock-reset handler (`_IO_list_resetlock`); stock
//     musl has no equivalent. Fixed by resetting every known `FILE`'s lock (`stdin`/`stdout`/
//     `stderr` plus the open-file list) to unlocked in `__post_Fork`'s child branch, matching
//     glibc's real behavior.
// (2) Once (1) let the test's new thread successfully lock `stdout`, a second, genuinely
//     fork-independent musl bug surfaced: that thread exits without ever calling `funlockfile()`
//     (legal -- POSIX doesn't require balancing flockfile/funlockfile before thread exit), and
//     musl's own `__do_orphaned_stdio_locks()` marked the lock with a poison bit (`MAYBE_WAITERS`,
//     owner bits cleared) instead of actually releasing it -- permanently unrecoverable, since
//     nothing ever calls `__wake()` on that address afterward. The process's own later `exit()`-
//     time stdio flush then deadlocked trying to re-lock `stdout` for good. Fixed by making the
//     orphan handler do a real release-and-wake, matching `__unlockfile()`'s own established
//     pattern.
// Both confirmed via an isolated canary run (`POSIX_PILOT_CANARY_ONLY=1`): clean `PASS`, clean
// QEMU exit -- not just "no longer hangs."
const POSIX_KNOWN_HANGS: &[&str] = &[
    // `sigwait/4-1.c`/`timer_settime/{2-1,6-1,9-1}.c`: **FIXED**, all four confirmed PASS via an
    // isolated canary run -- same staleness class as `pthread_atfork/3-3.c`/
    // `pthread_attr_destroy/1-1.c` just below: added to this array before the real
    // `wake_if_sigwaiting`-on-timer-expiry fix (CLAUDE.md's "A real timer-signal wake bug"
    // section) landed, never revisited since. All four share one shape (`sigprocmask(SIG_BLOCK,
    // SIGALRM)`, arm a real timer via `alarm()`/`timer_settime()`, then `sigwait()` for it) --
    // exactly the delivery path that fix closed. Removed from this list entirely.
    //
    // `fork/8-1.c`: **FIXED**, removed from this list entirely. The real busy loop wasn't the
    // parent's own `do { cur = times(&t); } while (cur - start < sysconf(_SC_CLK_TCK))` (its
    // return value, `crate::cpu::interrupts::ticks()`, was always real) -- it was the *child*'s
    // own `while ((child_tms.tms_utime + child_tms.tms_stime) <= 0)`, which an unconditionally
    // all-zero `tms` struct (`sys_times`'s own doc comment in `src/syscall/ffi.rs` explains why --
    // that call site predated `Process::cpu_ticks`, added later purely for `clock_gettime`, and
    // was never revisited) could never satisfy. Root cause found by tracing the test's own actual
    // blocking primitive, same as the `pthread_cond_timedwait` fixes above -- not the live
    // dispatch trace this entry previously called for. Fixed by wiring real `cpu_ticks`/a new
    // `Process::child_cpu_ticks` accumulator (folded in by `do_wait4` at reap time, for real
    // `tms_cutime`/`tms_cstime`) into `sys_times`. Confirmed via an isolated canary run: `PASS`,
    // full 74-file standing canary suite otherwise unchanged.
    // `pthread_atfork/3-3.c`/`pthread_attr_destroy/1-1.c`: both **FIXED** (root causes: real
    // thread-group-wide `kill(getpid(), sig)` delivery for the former, the `SYS_EXIT_GROUP`/
    // `pthread_attr_init/2-1.c` fix for the latter -- see git history for the full write-up this
    // array used to carry inline). **Actually removed from the array now**, correcting a real
    // staleness bug: both used to say "kept only as a historical marker, still excluded in effect
    // by the wholesale `pthread_*`/`aio_*`/`lio_listio*` prefix filter below regardless" -- true
    // when written, but that filter's own code was deleted on 2026-09-02 (see
    // `discover_posix_test_files`'s own doc comment/history just below), and these two entries
    // were never revisited afterward. They were quietly live-excluding two already-fixed,
    // passing files for no real reason since that date. **Any future "kept as a historical
    // marker, a filter below still catches it" entry needs to be re-verified against the filter
    // it names actually still existing, not trusted at face value.**
    //
    // `sched_yield/1-1.c`: **FIXED, or rather, never actually needed SMP at all** -- a real,
    // long-standing staleness bug in this exclusion's own reasoning, caught by simply re-reading
    // the test's own source before repeating the old claim. The test forks `ncpu-1` CPU-blocking
    // children specifically to *reserve* every core but one -- on a genuinely single-core report
    // (`ncpu == 1`, which `sysconf(_SC_NPROCESSORS_ONLN)` already correctly derives from
    // `sched_getaffinity`'s real single-bit mask), that loop forks *zero* children. What's left is
    // two equal-priority (`SCHED_FIFO`) threads round-robining via `sched_yield()` against each
    // other -- a real, single-core-achievable scheduling property, not an SMP one at all. Confirmed
    // via an isolated canary run: clean `PASS` (a harmless `unrecognized syscall number 203` --
    // `sched_setaffinity`, which the test's own affinity helper only `perror()`s on failure and
    // continues past -- doesn't affect the outcome). The original "hung with ~41% CPU usage"
    // observation this entry used to cite was never re-verified after later scheduler/threading
    // fixes landed; it's removed from this list entirely rather than left as a stale claim.
    // Real, multi-*process* named-semaphore coordination (`sem_open` + real `fork()`), **FIXED**:
    // `sem_unlink/{2-2,3-1}.c`/`sem_wait/7-1.c` all confirmed PASS via an isolated canary run
    // (`POSIX_PILOT_CANARY_ONLY=1`); `sem_post/8-1.c` confirmed clean `UNTESTED` (it early-returns
    // on `#ifndef _POSIX_PRIORITY_SCHEDULING` before ever touching a semaphore or forking at all --
    // it was swept into this list by a proactive `grep -l sem_open sem_*/*.c | xargs grep -l
    // 'fork('` pattern match, not an individually confirmed hang, and never actually needed this
    // fix). Root cause was `process::limits::do_futex`'s own `FUTEX_WAIT`/`FUTEX_WAKE` keying every
    // wait/wake pair on `(tgid, addr)` alone -- correct for a *private* futex, but a real
    // `sem_open()` semaphore is `pshared` (real, unmodified musl clears `FUTEX_PRIVATE` for it),
    // and its backing `/dev/shm`-mapped `MAP_SHARED` page generally lands at a *different* virtual
    // address in each of two independent `fork()`ed processes (`NEXT_MMAP_PAGE`, `src/process/
    // mm.rs`'s own bump allocator, is one global counter shared across every process, never reset
    // per caller) -- so a waiter's own `FUTEX_WAIT` and a waker's own `FUTEX_WAKE` almost never
    // agreed on the same key. Fixed via `process::limits::futex_key` (`src/process/limits.rs`): a
    // *shared* futex now resolves `addr` through the caller's own address space to the real
    // physical address backing it instead, identical across every process mapping the same
    // physical frame regardless of virtual address; a private futex is unaffected, still keyed by
    // `(tgid, addr)` exactly as before. Also verified end to end via `tests/
    // sem_open_syscall_smoke.rs` (a genuinely unmodified `sem_open()`+`fork()`+`sem_post()`/
    // `sem_wait()` C fixture, `userland/sem-open-smoke/main.c`). Removed from this list entirely,
    // same as `sigwait/6-1.c`/`6-2.c`/`fork/11-1.c` below -- none of these four live under a
    // `pthread_*`/`aio_*`/`lio_listio*` prefix, so removing them here is what actually re-includes
    // them in a real full-corpus run.
    //
    // `sigwait/6-1.c`/`6-2.c`: **FIXED**, both confirmed PASS via isolated canary runs -- two real,
    // independent bugs in `process::signals::resolve_signal_recipient` (a real thread-group-wide
    // `kill(getpid(), sig)`/`sigqueue` re-router added to fix `pthread_atfork/3-3.c` above), not a
    // "broken real-threading" gap at all:
    // (1) its fallback preferred the literal thread-group *leader* when no sibling had reached its
    //     own `sigwait()` call yet (a real, unavoidable race any of these tests can hit -- create
    //     several threads, then immediately signal, with no synchronization guaranteeing any of
    //     them have actually run) -- since the leader itself never calls `sigwait()`, the signal
    //     sat pending-but-blocked on it forever. Fixed by preferring any *other* live group member
    //     as the fallback instead, relying on `do_sigtimedwait`'s own real check-before-block loop
    //     to consume it correctly once that sibling actually reaches `sigwait()` (`6-1.c`, which
    //     uses `kill(getpid(), SIGUSR1)`).
    // (2) the re-router applied unconditionally to *every* `kill`/`sigqueue` call, including a real
    //     `pthread_kill(exact_thread, sig)` -- this ABI has no separate `tkill`/`tgkill` number, so
    //     that call reaches the exact same code as a real process-directed `kill()`, but must
    //     target *precisely* the named thread, never substituted. Fixed via `route_signal_target`,
    //     gating the whole-group reroute to only fire when the literal target names its own
    //     group's leader (real `kill(pid,...)`'s `pid` always does; a `pthread_kill`-shaped target
    //     naming a non-leader thread never should be rerouted) (`6-2.c`, which uses
    //     `pthread_kill(ch[0], SIGUSR1)`).
    // Removed from this list entirely (unlike `pthread_atfork/3-3.c` just above, which stays as a
    // historical marker only because the wholesale prefix filter below still catches it
    // regardless) -- neither file lives under a `pthread_*`/`aio_*`/`lio_listio*` prefix, so
    // removing them here is what actually re-includes them in a real full-corpus run. `fork/11-1.c`
    // (see this array's own doc comment above) is the same story -- also removed entirely, also
    // outside that prefix filter.
    //
    // `shm_open/23-1.c`: **FIXED, removed from this list entirely (2026-09-05)** -- was never a
    // real hang (it correctly `TIMEOUT`s at `t0`'s own 40s bound), but the fd leak it caused used
    // to cascade into misclassifying hundreds of unrelated later files as FAIL (a full pilot run
    // once reported 210 of 268 FAILs as `sigaction/1-N.c`, individually confirmed `PASS` in
    // isolation -- root-caused to this file, not `sigaction` at all). It forks `NPROCESS=1000`
    // children, each looping `NLOOP=1000` times calling `shm_open(name, O_RDONLY|O_CREAT|O_EXCL,
    // ...)` with **no `close(fd)` anywhere in the loop** -- a real bug in the test's own
    // `child_func` on any system, but harmless on real POSIX platforms since fd exhaustion there is
    // scoped *per-process* (bounded by that process's own `RLIMIT_NOFILE`). `modules/oxfs`'s
    // `OPEN_FILES` table (`MAX_OPEN_FILES`) was **global**, not per-process, and every slot paid a
    // full `MAX_WRITE_BUFFER` (128 KiB) regardless of use -- so even a generous static bump (8 ->
    // 256) only delayed exhaustion, it couldn't survive this test's up-to-1000-simultaneous-real-
    // objects peak without an unaffordable memory cost.
    //
    // **The real fix**: `OpenFile::Write`'s own content buffer moved out of the `OPEN_FILES` enum
    // entirely into a separate, smaller `WRITE_BUFFERS` pool, claimed lazily only by a fd that
    // actually calls `write()` (see that pool's own doc comment in `modules/oxfs/src/lib.rs`) --
    // most concurrently-open fds across this whole corpus, including every one of this test's own
    // 1000 objects (`O_RDONLY`, never written to), never touch it at all. This let `MAX_OPEN_FILES`
    // scale 256 -> 2048 while *lowering* total static memory cost (~8 MiB vs. the old ~32 MiB for
    // 256 slots) -- see `MAX_OPEN_FILES`'s own doc comment for the concrete numbers.
    //
    // **Confirmed via an isolated canary run** (`POSIX_PILOT_CANARY_ONLY=1`, this file included
    // alongside every other `shm_open`/`shm_unlink` file and `sigaction/1-{1,2}.c` -- the exact
    // combination that originally exposed the cascade): `shm_open/23-1.c` itself still `TIMEOUT`s
    // (confirmed genuine and not just "needs a bit more time" -- re-run with `t0`'s own alarm
    // manually raised to 180s, 4.5x its normal 40s bound, and it *still* timed out; the real
    // remaining bottleneck is raw scheduling throughput for 1000 concurrent forked processes under
    // this kernel's single-core, TCG-emulated execution, a separate, much deeper problem this fix
    // was never going to solve), but every file after it -- `shm_open/24-1.c` through
    // `shm_unlink/*.c` and, critically, `sigaction/1-1.c`/`1-2.c` themselves -- gets its own
    // correct, individual classification again, with zero cascade. Full 78-file tally
    // (`55P/2F/1U/14UT/5TO/1CR`) matches the pre-existing 77-file baseline exactly plus this file's
    // own legitimate `TIMEOUT`. Kept in the `POSIX_PILOT_CANARY_ONLY` standing regression suite
    // below as `shm_open/23-1.c` itself, no longer needing a `POSIX_KNOWN_HANGS` entry at all --
    // it's now safe to include in a normal full-corpus run, contributing one bounded `TIMEOUT`
    // like any other heavy stress test rather than corrupting everything that runs after it.
    // `pthread_attr_setstacksize/2-1.c`/`pthread_cancel/5-2.c`: **neither was ever a real permanent
    // hang** -- both removed from this list entirely. The original full-corpus supervised run's own
    // "exclude whatever file happened to be running when a stall was detected" heuristic
    // misattributed some *other* file's real stall to these two, the same failure mode
    // `pthread_atfork/3-3.c` suffered before it (see this array's own doc comment on that historical
    // pattern). Confirmed by testing each in genuine, complete isolation (`POSIX_PILOT_CANARY_ONLY`
    // narrowed to just the one file): both run to completion in seconds/within `t0`'s own bound.
    // `pthread_attr_setstacksize/2-1.c` reported a real, narrow `FAIL`: real, unmodified musl's own
    // `pthread_create.c` rounds a requested stack size up to a page boundary plus TLS/TSD overhead
    // before storing it, so `pthread_getattr_np()` never round-tripped the *exact* raw
    // `PTHREAD_STACK_MIN` this test requested. **Since fixed on the `oxidebsd` musl branch**
    // (confirmed live against the host's own real glibc first: this test genuinely passes there,
    // so it wasn't a bogus test) -- `struct pthread` gained a `requested_stack_size` field, set
    // once at creation to the real logical size the caller asked for, independent of the actual
    // allocator-padded extent; `pthread_getattr_np()` reports that instead of deriving it from
    // `stack - stack_limit`. Now `PASS`. `pthread_cancel/5-2.c` surfaced two real, since-fixed
    // kernel bugs along the way (see `process::do_kill`'s own doc comment for the real `SIGCANCEL`
    // signal-range fix and `ThreadGroupShared::sigactions`'s own doc comment for the real
    // cross-thread signal-disposition-sharing fix this exposed) before settling on a clean, bounded
    // `TIMEOUT` -- one thread genuinely livelocks in musl's own real `SIGCANCEL`-resend-via-`tkill`
    // retry loop (intentional musl behavior for a target that never reaches an actual POSIX
    // cancellation point), a separate, deep single-core scheduling question not chased further here,
    // but a bounded `TIMEOUT` doesn't threaten to cascade into the rest of a full-corpus run the way
    // an actual unbounded hang does. Both kept in the `POSIX_PILOT_CANARY_ONLY` standing regression
    // suite below.
    // `pthread_cond_timedwait/{2-5,4-1}.c`: both were real, genuine, permanent hangs -- `t0`'s own
    // 40s rescue alarm never fired for either, unlike the `pthread_cond_broadcast`/
    // `pthread_cond_destroy` files this session's scheduler/signal-termination fix already closed.
    // Both now fixed, removed from this list entirely (unlike `pthread_atfork/3-3.c` above, which
    // stays as a historical marker) -- two real, independent bugs, found by tracing each file's own
    // actual blocking primitive rather than more source-reading:
    //
    // (1) `4-1.c` (a plain single `pthread_create`, no `PTHREAD_PROCESS_SHARED` involved): the
    //     worker thread calls a real `exit()` (== `exit_group`) after its own timed condvar wait,
    //     while the main thread (the real thread-group *leader*) sits blocked in `pthread_join()`'s
    //     own futex wait. `terminate_thread_group`'s loop used to kill every "sibling" (everyone but
    //     the caller) first, then the caller itself last -- correct only when the caller happens to
    //     *be* the leader. Here the caller is the non-leader worker and the leader is one of the
    //     "siblings", so the leader got processed while the worker (the caller, not yet reached in
    //     the loop) was still alive -- `terminate_process`'s own `other_thread_alive` check saw that
    //     and wrongly treated the *leader* as a disposable non-leader thread, silently stranding it
    //     with no parent notification. Fixed in `src/process/lifecycle.rs::terminate_thread_group`:
    //     every non-leader group member is terminated first, the leader (`pid == tgid`) always last,
    //     regardless of whether it's the original caller or one of its "siblings".
    // (2) `2-5.c` (100 threads, two mutexes, real contended condvar hand-off): musl's own
    //     `pthread_cond_timedwait.c::unlock_requeue` moves a waiting thread from the condvar's
    //     internal barrier word onto the mutex's futex word via real `FUTEX_REQUEUE` whenever more
    //     than one waiter is queued -- this kernel's `do_futex` treated that op (and
    //     `FUTEX_CMP_REQUEUE`) as a silent no-op, so a thread already blocked in a real kernel
    //     `FUTEX_WAIT` on the old address had nothing left to ever wake it. Real `FUTEX_REQUEUE`
    //     doesn't fit this ABI's plain 4-register `SYS_FUTEX` wire format (real `futex(2)` needs 6
    //     args for this op), so a dedicated `SYS_FUTEX_REQUEUE=557` was added instead, and the one
    //     real call site (`unlock_requeue`) patched on the `oxidebsd` musl branch to call it
    //     directly -- see `src/process/limits.rs::do_futex_requeue`'s own doc comment. This alone
    //     doesn't make `2-5.c` fully `PASS` (it now reaches a real `UNRESOLVED` from something else
    //     in its own giant pshared/altclock scenario matrix, not a hang), but it's no longer a
    //     permanent hang, and its previously-unreachable neighbors `4-2.c`/`4-3.c` -- blocked from
    //     ever running by whichever of `2-5.c`/`4-1.c` hung first -- both now cleanly `PASS`.
    //
    // `pthread_kill/6-1.c`: **FIXED, removed from this list entirely.** Was a real, unbounded-
    // VM-halting `EXCEPTION: INVALID OPCODE` at the real fault-trampoline's own `ud2` sentinel
    // (`VirtAddr(0x1ffffffff011)`), found live 2026-09-06 chasing the real `do_munmap` frame-leak
    // fix -- fixing that leak let a full-corpus run finally get past its old exhaustion point for
    // the first time, reaching this file (previously always masked; genuinely unrelated to the
    // munmap fix itself). Root cause: this file calls `pthread_kill()` on an already-joined,
    // no-longer-existent tid, whose real musl implementation dereferences it -- a genuine page
    // fault into memory `pthread_join()`'s own real stack `munmap()` already freed, occurring
    // *while* musl's own `__block_all_sigs()` had `SIGSEGV` blocked (real, unmodified musl's own
    // `pthread_kill()`/`pthread_cancel()` mask every signal for a short internal critical section).
    // `interrupts::page_fault_handler`'s own ring-3 fault-to-signal redirect used to record this
    // exactly like an ordinary async `kill()` self-signal -- respecting the target's own blocked-
    // signal mask, correct for `kill()` but wrong for a *synchronously*-generated fault signal,
    // which real POSIX documents as undefined behavior to block and real Linux resolves via
    // `force_sig()`'s own "unblock this one signal, then queue it" semantics. With `SIGSEGV`
    // blocked, `deliver_pending_signal`'s own `take_deliverable_signal` correctly refused to act on
    // it, leaving the trampoline's own `SYS_FAULT_PUMP` dispatch with nothing to deliver -- falling
    // through to `ud2`. Fixed via `process::signals::force_fault_signal` (used by both
    // `page_fault_handler` and `general_protection_fault_handler`'s identical self-signal call):
    // force-clears just the one bit being delivered from `blocked_signals` before recording it,
    // matching real Linux's own scope (every *other* signal `pthread_kill()`'s own critical section
    // blocked stays blocked). Confirmed fixed: this file now cleanly `CRASH(139)`s (a real, normal,
    // per-process `SIGSEGV` termination -- accessing already-`munmap()`'d memory via a stale
    // `pthread_t` is genuine real-world undefined behavior a real system might also crash on;
    // what mattered was containing it to one process instead of halting the whole VM) instead of
    // taking the whole boot down. `mmap_syscall_smoke`/`pthread_cancel_crash_smoke`/
    // `pshared_cond_crash_smoke` (all real fault-to-signal exercises) confirmed still passing clean.
    //
    // `pthread_cond_init/4-2.c` and `timer_settime/2-1.c`: **not regressions, real, pre-existing
    // flakiness** -- found live re-running the standing canary suite right after the fix above.
    // `pthread_cond_init/4-2.c`: 2 of 3 isolated re-runs `PASS`, 1 `CRASH(139)`, same file, same
    // build, no source changes between runs -- unrelated to `force_fault_signal` (never calls
    // `pthread_kill`/`pthread_cancel`), most likely a genuine timing-dependent race in real thread
    // creation/destruction, the same *class* `pthread_attr_setdetachstate/2-1.c` had before its own
    // fix made it deterministic. `timer_settime/2-1.c`: one `FAIL` then 3/3 clean `PASS` in
    // isolation immediately after -- real-time-based tests are sensitive to host-load-induced QEMU/
    // TCG timing variance, matching this project's own established precedent for this exact test
    // family. Neither excluded (both are normal, contained, non-hanging outcomes) or chased
    // further tonight -- noted here so a future "why did the canary tally shift slightly" isn't
    // mistaken for a new regression.
];

/// Walks `conformance/interfaces/` and returns every real assertion file's path relative to
/// `interfaces_dir`, in the codebase's usual `/`-separated form -- the full ~1750-file suite, not
/// the 488-file curated dedup this pilot ran against before. Two exclusion classes, both narrow:
///
/// - **`*-buildonly.c`/`*-core-buildonly.c`** (10 files): expect a real `argv[1]` selecting which
///   of several sub-cases to run (normally supplied by the suite's own multi-invocation driver
///   script, which this pilot doesn't have) -- run with none, they just return `PTS_UNRESOLVED`
///   unconditionally, adding no real signal. `sigaltstack/9-buildonly.c` is the one exception：
///   still excluded from *this* list, but built and seeded separately just below (`9-1.c`'s own
///   real assertion `execl()`s into it directly by its literal upstream path).
/// - **`POSIX_KNOWN_HANGS`** above -- **empty again as of 2026-09-06** (kept as an array, not
///   deleted, purely as a landing spot for the next real one). Every file this array or a fresh
///   full-corpus supervised run has ever flagged -- `fork/8-1.c`, `sched_yield/1-1.c`,
///   `pthread_attr_setstacksize/2-1.c`, `pthread_cancel/5-2.c`, `pthread_cond_timedwait/
///   {2-5,4-1}.c`, `shm_open/23-1.c` (a real global-fd-table-exhaustion cascade, fixed by moving
///   `OpenFile::Write`'s content buffer out of `modules/oxfs`'s `OPEN_FILES` table into its own
///   separate, lazily-claimed `WRITE_BUFFERS` pool -- see that pool's own doc comment), and
///   `pthread_kill/6-1.c` (the last to go: a real fault-to-signal-delivery bug, a synchronously-
///   generated `SIGSEGV` occurring while blocked -- fixed via `process::signals::
///   force_fault_signal`, see that entry's own doc comment) -- is confirmed either genuinely fixed
///   or to have never actually been a real hang at all (see this array's own doc comment on each
///   entry for the full story -- `sched_yield/1-1.c` in particular was excluded on a claim ("needs
///   real SMP") that was simply never re-verified against the test's own source until it was
///   re-checked).
///
/// Deliberately **not** filtered by "references `pthread_create`/`testfrmw.h`" any more -- real
/// `clone(2)`/`pthread_create`/`pthread_join` landed (see CLAUDE.md's "Real threading" section),
/// closing the reason that filter existed. A source file needing the suite's own tiny shared
/// test-framework helper pulls it in itself, via a literal `#include "testfrmw.c"` (confirmed by
/// reading several -- this suite compiles it as *text* folded into the same translation unit, not
/// a separate linked object; `write_posix_test_manifest`'s own build loop compiles every
/// discovered file completely standalone, matching this). Everything else (a helper file with no
/// standalone `main()` at all -- `testfrmw.c`/`coverage.c` themselves, discovered like any other
/// `.c` file and simply failing alone -- a source needing headers this musl port doesn't have,
/// real upstream oddities like `pthread_create/15-1.c`/`pthread_exit/6-2.c` that don't build
/// alone) is **not** pre-filtered here either -- that build loop is best-effort per file (skip and
/// log, not panic) specifically so this function can stay a plain filesystem walk instead of
/// trying to statically prove every file buildable.
fn discover_posix_test_files(interfaces_dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".c") || name.ends_with("buildonly.c") {
                continue;
            }
            let rel = path
                .strip_prefix(base)
                .expect("walked path must be under base")
                .to_string_lossy()
                .replace('\\', "/");
            out.push(rel);
        }
    }
    let mut out = Vec::new();
    walk(interfaces_dir, interfaces_dir, &mut out);
    // TEMPORARY validation hook: `POSIX_PILOT_CANARY_ONLY=1` shrinks the whole discovered corpus
    // down to a handful of specific known-hang/regression files (see `POSIX_KNOWN_HANGS`'s own doc
    // comment) so a candidate fix can be checked end to end in minutes instead of rebuilding/
    // booting the full ~1700-file corpus. Not wired into any normal build. Every file below is
    // already fixed and confirmed `PASS` (`sem_post/8-1.c` confirmed clean `UNTESTED`; the
    // `shm_open`/`shm_unlink` block's own `TIMEOUT`/two narrow `ENAMETOOLONG` FAILs are expected,
    // real, individually-classified outcomes, not a symptom of the bug this block regression-tests
    // -- see below) via this exact mechanism -- kept as a standing regression suite for any future
    // futex/threading/fork/signal-delivery/timer/fd-table change, not emptied out:
    // `fork/11-1.c`/`pthread_attr_destroy/1-1.c`/`pthread_atfork/3-3.c` (real thread-group signal
    // delivery + `exit_group(2)`), the four named-semaphore files (real physical-address-keyed
    // shared-futex, `process::limits::futex_key` in `src/process/limits.rs`), `sigwait/4-1.c`/
    // `timer_settime/{2-1,6-1,9-1}.c` (real timer-expiry signal wake, `wake_if_sigwaiting`),
    // `clock_settime/7-2.c` (a `clock_settime(CLOCK_REALTIME, ...)` forwarding the wall clock past
    // an already-sleeping `clock_nanosleep()` target now actively re-wakes it,
    // `process::timers::wake_realtime_sleepers_after_clock_change`), `aio_write/2-1.c` (real
    // `F_GETFL` `O_APPEND` reporting, `crate::fs::fd::FdIsAppend` -- real, unmodified musl's own
    // AIO code needs this bit to serialize concurrent writes to the same fd; also fixed
    // `resolve_write_fd_inode` to keep re-committing on every call instead of only the first,
    // `modules/oxfs/src/lib.rs`), and the full
    // `shm_open`+`shm_unlink`+`sigaction/1-{1,2}.c` block **including** `shm_open/23-1.c`
    // itself (the real `MAX_OPEN_FILES`/`WRITE_BUFFERS` global-fd-table-exhaustion-cascade fix,
    // `modules/oxfs/src/lib.rs` -- `shm_open/23-1.c` no longer needs excluding at all, see
    // `POSIX_KNOWN_HANGS`'s own doc comment; its own `TIMEOUT` here is a real, expected, bounded
    // outcome, not a symptom of the bug this block regression-tests). Add to this list, don't just
    // replace it, so a real regression gets caught immediately.
    //
    // `rerun-if-env-changed`, not just relying on the file-content watch above: plain
    // `std::env::var` reads aren't tracked by cargo at all on their own -- toggling this var on/off
    // between builds (nothing else changed) could otherwise silently reuse a stale cached manifest
    // built under the *other* setting. Same reasoning for `POSIX_EXTRA_EXCLUDE_FILE`'s own *value*
    // (as opposed to that path's file content, already watched above).
    println!("cargo:rerun-if-env-changed=POSIX_PILOT_CANARY_ONLY");
    println!("cargo:rerun-if-env-changed=POSIX_EXTRA_EXCLUDE_FILE");
    println!("cargo:rerun-if-env-changed=POSIX_DEBUG_SINGLE_FILE");
    // Ad-hoc single/few-file isolation for chasing a *specific* non-PASS result found by a full or
    // canary run, without waiting on either -- pass a comma-separated list of exact
    // `relative/path.c` entries (as printed by a prior run's own `PASS:`/`FAIL:`/etc. lines).
    // Distinct from `POSIX_PILOT_CANARY_ONLY`'s fixed, curated regression-suite list: this one is
    // meant to be thrown away/reused per investigation, not accumulated.
    if let Ok(single) = std::env::var("POSIX_DEBUG_SINGLE_FILE") {
        return single.split(',').map(|s| s.trim().to_string()).collect();
    }
    if std::env::var("POSIX_PILOT_CANARY_ONLY").is_ok() {
        const CANARY: &[&str] = &[
            "fork/11-1.c",
            "pthread_attr_destroy/1-1.c",
            "pthread_atfork/3-3.c",
            "sem_unlink/2-2.c",
            "sem_unlink/3-1.c",
            "sem_wait/7-1.c",
            "sem_post/8-1.c",
            "sigwait/4-1.c",
            "timer_settime/2-1.c",
            "timer_settime/6-1.c",
            "timer_settime/9-1.c",
            "clock_settime/7-2.c",
            "aio_write/2-1.c",
            "shm_open/1-1.c",
            "shm_open/10-1.c",
            "shm_open/11-1.c",
            "shm_open/12-1.c",
            "shm_open/13-1.c",
            "shm_open/14-2.c",
            "shm_open/15-1.c",
            "shm_open/16-1.c",
            "shm_open/17-1.c",
            "shm_open/18-1.c",
            "shm_open/19-1.c",
            "shm_open/2-1.c",
            "shm_open/20-1.c",
            "shm_open/20-2.c",
            "shm_open/20-3.c",
            "shm_open/21-1.c",
            "shm_open/22-1.c",
            "shm_open/23-1.c",
            "shm_open/24-1.c",
            "shm_open/25-1.c",
            "shm_open/26-1.c",
            "shm_open/26-2.c",
            "shm_open/27-1.c",
            "shm_open/28-1.c",
            "shm_open/28-2.c",
            "shm_open/28-3.c",
            "shm_open/29-1.c",
            "shm_open/3-1.c",
            "shm_open/32-1.c",
            "shm_open/34-1.c",
            "shm_open/36-1.c",
            "shm_open/37-1.c",
            "shm_open/38-1.c",
            "shm_open/39-1.c",
            "shm_open/39-2.c",
            "shm_open/41-1.c",
            "shm_open/42-1.c",
            "shm_open/5-1.c",
            "shm_open/6-1.c",
            "shm_open/7-1.c",
            "shm_open/8-1.c",
            "shm_open/9-1.c",
            "shm_unlink/1-1.c",
            "shm_unlink/10-1.c",
            "shm_unlink/10-2.c",
            "shm_unlink/11-1.c",
            "shm_unlink/2-1.c",
            "shm_unlink/3-1.c",
            "shm_unlink/5-1.c",
            "shm_unlink/6-1.c",
            "shm_unlink/8-1.c",
            "shm_unlink/9-1.c",
            "sigaction/1-1.c",
            "sigaction/1-2.c",
            // `pthread_attr_setdetachstate/2-1.c`: real regression coverage for the per-process
            // scheduler quantum fix (`Process::quantum_ticks_left`, see its own doc comment) --
            // this file's own `pthread_join()`/`pthread_detach()` against an already-detached
            // thread raced that thread's own exit (`__unmapself` unmapping the very memory holding
            // `detach_state`) badly enough to flakily `CRASH`/hang before that fix.
            "pthread_attr_setdetachstate/2-1.c",
            // `pthread_cond_broadcast/2-3.c,4-2.c`: were permanently hung (not just this one file)
            // in the same supervised run before the scheduler-quantum fix above -- confirmed via
            // this exact canary mechanism to be the *same* underlying bug, not separate ones. Both
            // now genuinely `PASS` -- see the later, dedicated `pthread_cond_broadcast` block below
            // (the real `__NR_futex_requeue` name-collision fix) for why; kept here too as
            // regression coverage for *this* file's own scheduler-quantum fix specifically.
            // `pthread_cond_destroy/2-1.c`: same story, also closed by that same later fix.
            "pthread_cond_destroy/2-1.c",
            // `pthread_cond_init/4-2.c`: also flagged by that same supervised run, confirmed fixed
            // (or stale) -- passes cleanly now, kept here as regression coverage.
            "pthread_cond_init/4-2.c",
            // `pthread_cond_timedwait/{2-5,4-1,4-2,4-3}.c`: real regression coverage for the
            // `terminate_thread_group` leader-ordering fix and the new real `SYS_FUTEX_REQUEUE`
            // handler -- see `POSIX_KNOWN_HANGS`'s own doc comment above (both files used to be
            // permanent hangs listed there) and `src/process/lifecycle.rs::terminate_thread_group`/
            // `src/process/limits.rs::do_futex_requeue` for the real fixes. Confirmed via this exact
            // canary mechanism: `4-1.c`/`4-2.c`/`4-3.c` now cleanly `PASS`; `2-5.c` no longer hangs
            // but reaches a real `UNRESOLVED` from something else in its own giant scenario matrix,
            // a legitimate outcome kept here to catch any future regression back to a real hang.
            "pthread_cond_timedwait/2-5.c",
            "pthread_cond_timedwait/4-1.c",
            "pthread_cond_timedwait/4-2.c",
            "pthread_cond_timedwait/4-3.c",
            // `fork/8-1.c`: real regression coverage for the `sys_times`/`child_cpu_ticks` fix --
            // see `POSIX_KNOWN_HANGS`'s own doc comment above (used to be a permanent hang listed
            // there) and `src/syscall/ffi.rs::sys_times` for the real fix. Confirmed `PASS`.
            "fork/8-1.c",
            // `pthread_attr_setstacksize/2-1.c`: **was never actually a hang** -- confirmed via a
            // genuinely isolated single-file canary run (the full-corpus supervised run that
            // originally flagged it as a permanent hang misattributed the real stall to this file,
            // the same class of misattribution `pthread_atfork/3-3.c` suffered before it). Its own
            // real, narrow `FAIL` (`ssize != stack_size`, real, unmodified musl's own
            // `pthread_create.c` rounding a requested stack size up to a page boundary plus TLS/TSD
            // overhead before storing `stack_size`) is now also fixed on the `oxidebsd` musl branch
            // (`struct pthread`'s own `requested_stack_size` field, see that field's own doc
            // comment) -- confirmed live against the host's own real glibc first that this wasn't a
            // bogus test. Now `PASS`. Removed from `POSIX_KNOWN_HANGS` entirely (it never needed to
            // be there); kept here as regression coverage.
            "pthread_attr_setstacksize/2-1.c",
            // `pthread_cancel/5-2.c`: not a permanent hang either, once two real bugs it surfaced
            // were fixed (see `process::do_kill`'s own doc comment for the `SIGCANCEL`/signal-range
            // fix and `ThreadGroupShared::sigactions`'s own doc comment for the real cross-thread
            // signal-disposition-sharing fix) -- confirmed via isolated canary runs at each step:
            // `UNRESOLVED` (real `EINVAL` from the signal-range bug) -> `CRASH(161)` (real
            // cross-thread sigaction-sharing bug, `SIGCANCEL`'s handler installed on the wrong
            // thread) -> a clean, bounded `TIMEOUT`. That last `TIMEOUT` is real and not chased
            // further here: one thread genuinely livelocks in musl's own `cancel_handler` real
            // `SIGCANCEL`-resend-via-`tkill` retry loop (intentional, real musl behavior for a
            // target thread that never reaches an actual POSIX cancellation point -- this test's
            // own target spins on bare `sched_yield()`, which isn't one) -- on real multi-core
            // hardware the target thread's own userspace code still gets scheduling gaps to notice
            // `do_it==0` between resends; whether a resumed thread on this single-core kernel
            // always gets at least one real instruction before an immediately-redeliverable signal
            // redirects it again is a genuinely separate, deep scheduling question, not something
            // to chase inside this same investigation. Removed from `POSIX_KNOWN_HANGS` entirely --
            // a bounded `TIMEOUT` doesn't threaten to cascade into the rest of a full-corpus run the
            // way an actual unbounded hang does.
            "pthread_cancel/5-2.c",
            // `sched_yield/1-1.c`: **never actually needed SMP** -- a real, long-standing staleness
            // bug in this project's own exclusion reasoning, caught by re-reading the test's own
            // source instead of repeating an old, never-re-verified claim. See `POSIX_KNOWN_HANGS`'s
            // own doc comment above for the full story. Confirmed `PASS` via an isolated canary run.
            "sched_yield/1-1.c",
            // `pthread_kill/6-1.c`: real regression coverage for `process::signals::
            // force_fault_signal` -- see `POSIX_KNOWN_HANGS`'s own doc comment above (used to be a
            // whole-VM-halting `EXCEPTION: INVALID OPCODE`, now a clean, contained `CRASH(139)`).
            "pthread_kill/6-1.c",
            // `pthread_detach/{1-2,4-3}.c`: both started hitting a real `CRASH(139)` once the musl
            // `PTHREAD_STACK_MIN` fix unmasked them from `UNTESTED` -- decoded directly from the
            // cross-compiled test ELFs' own disassembly (no host repro needed: a native from-scratch
            // build of this exact musl fork turned out to be a broken comparison baseline on its own
            // -- even a trivial `int main(){return 0;}` segfaulted at `__init_tls`, an unrelated
            // host-toolchain issue).
            // `1-2.c`: `main()` deliberately calls `pthread_join()` on a thread that already
            // self-detached and exited (its own explicit test design) -- a real, genuinely
            // undetectable use-after-free in musl's `__pthread_timedjoin_np`, reading
            // `t->detach_state` from the target's own TCB after its `__unmapself` already freed
            // that memory. Same documented-UB class already established for
            // `pthread_attr_setdetachstate/2-1.c` -- `CRASH(139)` remains the correct, expected
            // outcome; not fixable without a much larger design change (keeping every detached
            // thread's TCB reserved indefinitely, which musl doesn't do).
            // `4-3.c`: was a *different*, actually-fixable case -- real, unmodified musl's own
            // `pthread_detach()` (`third_party/musl/src/thread/pthread_detach.c`) unconditionally
            // fell back to an internal `__pthread_join(t, 0)` call whenever its own
            // `a_cas(&t->detach_state, DT_JOINABLE, DT_DETACHED)` failed, even when the failure
            // meant "already detached, not exiting" -- a case it could detect directly from the
            // CAS's own return value. This file's `threaded()` unconditionally calls
            // `pthread_detach(pthread_self())` even for scenarios whose attribute already created
            // the thread `PTHREAD_CREATE_DETACHED`, so the CAS reliably failed that way and musl's
            // own join fallback hit `__pthread_timedjoin_np`'s internal `a_crash()` (a raw ring-3
            // `hlt`, real Linux's own `#GP`-to-`SIGSEGV` translation applies identically) --
            // confirmed via a `[diag-fault]` per-tgid process-table dump (temporarily added, removed
            // after) that the faulting pid really was one of `test()`'s own short-lived worker
            // threads, not a misattribution. Unlike `1-2.c`, this case is memory-safe to detect
            // directly (the target is always `pthread_self()`, so its TCB is guaranteed still
            // resident) and POSIX's own error contract explicitly wants `EINVAL` here -- **fixed**
            // on the `oxidebsd` musl branch: `pthread_detach()` now returns `EINVAL` directly for
            // this exact case instead of ever reaching `__pthread_join()`. Confirmed via an isolated
            // canary run: `4-3.c` now cleanly `TIMEOUT`s instead of crashing (a real, heavy
            // thread-creation-plus-signal-storm workload hitting `t0`'s 40s bound under this
            // kernel's own thread-creation throughput ceiling -- same accepted class as
            // `shm_open/23-1.c`), with zero regressions across the rest of this canary suite.
            "pthread_detach/1-2.c",
            "pthread_detach/4-3.c",
            // `sched_setparam/23-6.c`: drops to a real non-root uid via `setuid()`, then tries to
            // raise its own already-`SCHED_FIFO` priority by one, expecting real `EPERM` --
            // nothing in `do_sched_setparam` ever checked "appropriate privilege" (`CAP_SYS_NICE`
            // on real Linux) before this, only uid-ownership (`has_sched_permission`), so the
            // raise silently succeeded. Fixed via `limits::sched_priority_raise_permitted`
            // (`src/process/limits.rs`), wired into both `do_sched_setscheduler`/`do_sched_setparam`.
            "sched_setparam/23-6.c",
            // `mmap/6-2.c`: real `PROT_NONE` enforcement -- a mapping's covered pages simply never
            // get a page-table entry when neither `PROT_READ` nor `PROT_WRITE` is set, reusing
            // `signal_for_user_fault`'s existing default (`SIGSEGV` for anything not in a region's
            // own reserved-but-unbacked tail) with no new machinery. `mmap/6-4.c`/`6-6.c`: real
            // POSIX MPR fd-access-mode checks (`crate::fs::fd::access_mode_of`, backed by a new
            // `oxfs_access_mode` callback) -- a fd must have been opened with read permission
            // regardless of `prot`, and needs write permission too for `PROT_WRITE`+`MAP_SHARED`.
            // `mmap/24-2.c`: `MAP_FIXED`'s own overflow/non-canonical-range check now returns real
            // `ENOMEM` (the actual POSIX-mandated errno for "range exceeds the address space of a
            // process") instead of `EINVAL` -- needed no real `RLIMIT_AS` enforcement at all, since
            // `RLIMIT_AS`'s own default `RLIM_INFINITY` already makes `addr + len` overflow `u64`
            // outright for this test's own request shape.
            "mmap/6-2.c",
            "mmap/6-4.c",
            "mmap/6-6.c",
            "mmap/24-2.c",
            // Every other `mmap`/`munmap` file: `do_mmap`/`do_mmap_file_backed` are shared code
            // paths every one of these already exercises -- added wholesale (not just the four
            // above) so a regression in any of them is caught immediately, same "add to this list,
            // don't just replace it" discipline this array's own doc comment establishes elsewhere.
            "mmap/10-1.c",
            "mmap/11-1.c",
            "mmap/11-2.c",
            "mmap/11-3.c",
            "mmap/11-4.c",
            "mmap/11-5.c",
            "mmap/1-1.c",
            "mmap/12-1.c",
            "mmap/1-2.c",
            "mmap/13-1.c",
            "mmap/14-1.c",
            "mmap/18-1.c",
            "mmap/19-1.c",
            "mmap/21-1.c",
            "mmap/23-1.c",
            "mmap/24-1.c",
            "mmap/27-1.c",
            "mmap/28-1.c",
            "mmap/31-1.c",
            "mmap/3-1.c",
            "mmap/5-1.c",
            "mmap/6-1.c",
            "mmap/6-3.c",
            "mmap/6-5.c",
            "mmap/7-1.c",
            "mmap/7-2.c",
            "mmap/7-3.c",
            "mmap/7-4.c",
            "mmap/9-1.c",
            "munmap/1-1.c",
            "munmap/1-2.c",
            "munmap/2-1.c",
            "munmap/3-1.c",
            "munmap/4-1.c",
            "munmap/8-1.c",
            "munmap/9-1.c",
            // `pthread_attr_setstack/{1,2,4,6,7}-1.c`: all five UNRESOLVED at the exact same,
            // kernel-independent point -- real, unmodified musl's own `pthread_attr_getstack()`
            // used to unconditionally EINVAL for a freshly `pthread_attr_init()`'d attr (before
            // ever calling `pthread_attr_setstack()`), which every one of these files calls first
            // purely to read back the attr's own current/default values. Confirmed a real musl bug
            // (not intentional, not a POSIX ambiguity) live against the host's own real glibc: a
            // fresh attr's `pthread_attr_getstack()` succeeds there, reporting `addr=NULL`. Fixed
            // on the `oxidebsd` musl branch (`src/thread/pthread_attr_get.c`) -- see that fix's own
            // comment for detail.
            "pthread_attr_setstack/1-1.c",
            "pthread_attr_setstack/2-1.c",
            "pthread_attr_setstack/4-1.c",
            "pthread_attr_setstack/6-1.c",
            "pthread_attr_setstack/7-1.c",
            // `pthread_rwlock_rdlock/2-{1,2,3}.c`: found chasing these -- `do_sched_setscheduler`
            // returning the former policy (not `0`) on success broke `pthread_setschedparam()`'s
            // own real, unmodified internal `-__syscall(...)` negation idiom whenever a caller's
            // own prior policy was already non-`SCHED_OTHER`. Fixed in `src/process/limits.rs` --
            // see `do_sched_setscheduler`'s own doc comment for the real host-verified detail. Not
            // a full fix for these three files' own real assertions (real priority-aware rwlock
            // reader/writer preference, which real Linux's own default pthread_rwlock doesn't
            // implement either per a live host check -- 2-1.c/2-2.c genuinely `FAIL` on real
            // musl/glibc too, only 2-3.c is expected to `PASS`), but closes the spurious
            // `UNRESOLVED` every one of them hit before ever reaching that real assertion.
            "pthread_rwlock_rdlock/2-1.c",
            "pthread_rwlock_rdlock/2-2.c",
            "pthread_rwlock_rdlock/2-3.c",
            // Full sched_setscheduler directory, added alongside the do_sched_setscheduler fix
            // above -- shared code path, want a regression caught immediately (same "add to this
            // list, don't just replace it" discipline already established elsewhere).
            "sched_setscheduler/10-1.c",
            "sched_setscheduler/11-1.c",
            "sched_setscheduler/1-1.c",
            "sched_setscheduler/12-1.c",
            "sched_setscheduler/13-1.c",
            "sched_setscheduler/14-1.c",
            "sched_setscheduler/15-1.c",
            "sched_setscheduler/15-2.c",
            "sched_setscheduler/16-1.c",
            "sched_setscheduler/17-1.c",
            "sched_setscheduler/17-2.c",
            "sched_setscheduler/17-3.c",
            "sched_setscheduler/17-4.c",
            "sched_setscheduler/17-5.c",
            "sched_setscheduler/17-6.c",
            "sched_setscheduler/17-7.c",
            "sched_setscheduler/19-1.c",
            "sched_setscheduler/19-2.c",
            "sched_setscheduler/19-3.c",
            "sched_setscheduler/19-4.c",
            "sched_setscheduler/19-5.c",
            "sched_setscheduler/20-1.c",
            "sched_setscheduler/21-1.c",
            "sched_setscheduler/2-1.c",
            "sched_setscheduler/22-1.c",
            "sched_setscheduler/22-2.c",
            "sched_setscheduler/4-1.c",
            "sched_setscheduler/5-1.c",
            "sched_setscheduler/6-1.c",
            "sched_setscheduler/7-1.c",
            "sched_setscheduler/9-1.c",
            // `pthread_cond_broadcast/{1-1,2-1,2-2,2-3,4-1,4-2}.c`: real bug, confirmed via direct
            // host testing (all 6 pass cleanly on real musl 1.2.6 and real glibc, unlike the
            // pthread_rwlock_rdlock/pthread-stale-tid clusters above). Root cause: a real syscall
            // *name* collision on the musl `oxidebsd` branch -- this ABI's own invented
            // `__NR_futex_requeue=557` (a collision-free *number*) reused a macro *name* the same
            // vendored header already defines elsewhere for real Linux's own unrelated futex2-
            // family syscall 456, which silently won the plain-C `#define` redefinition. Every
            // private-condvar broadcast/signal chain-wake beyond the first directly-woken waiter
            // issued syscall 456 (never registered here) instead of 557, permanently stranding the
            // rest. Fixed by renaming the macro to `__NR_oxidebsd_futex_requeue` -- see
            // `third_party/musl/arch/x86_64/bits/syscall.h.in`'s own doc comment on that macro for
            // the full story. Also closes `pthread_cond_timedwait/2-5.c` (stuck `UNRESOLVED` for
            // multiple prior sessions) and `pthread_cond_destroy/2-1.c` -- same root cause, one fix.
            "pthread_cond_broadcast/1-1.c",
            "pthread_cond_broadcast/2-1.c",
            "pthread_cond_broadcast/2-2.c",
            "pthread_cond_broadcast/2-3.c",
            "pthread_cond_broadcast/4-1.c",
            "pthread_cond_broadcast/4-2.c",
            // `do_sigreturn`'s own synchronous signal-stack chaining used to redeliver a signal
            // unconditionally, entirely *inside* the sigreturn syscall itself, before the restored
            // frame was ever actually resumed as real userspace execution -- correct for signals
            // already queued *before* the cascade began (sigqueue/4-1.c/8-1.c below, which need
            // several already-queued instances delivered with no syscall in between an unblock and
            // a check), but wrong for a signal that becomes pending only as a *side effect* of a
            // handler running *during* the same cascade -- real, unmodified musl's own
            // `pthread_cancel()` resend (`cancel_handler` issuing a raw `tkill(self, SIGCANCEL)`
            // from inside itself) is exactly this shape, and could spin forever redelivering to
            // the exact same restored RIP without it ever executing even once (found live via
            // pthread_join/3-1.c's real hang: SYS_SIGRETURN firing thousands of times with an
            // identical restored RIP). Fixed via `Process::cascade_budget` -- a real snapshot of
            // what was already deliverable at the cascade's own outermost delivery, consulted only
            // by `do_sigreturn`'s own chained call; once exhausted, chaining stops and the frame
            // actually resumes, exactly like real hardware. Closes pthread_join/3-1.c and
            // pthread_cancel/5-2.c (previously an accepted bounded livelock/TIMEOUT, now a clean
            // PASS) without regressing sigqueue/4-1.c/8-1.c, which this list also re-verifies.
            "sigqueue/4-1.c",
            "sigqueue/8-1.c",
            "pthread_join/3-1.c",
            "pthread_cancel/5-2.c",
            // `timer_gettime/1-4.c`: real `it_interval` round-trip bug -- `PosixTimer` used to
            // only store a periodic timer's reload value as a tick count (`interval_ticks`,
            // necessarily lossy at this kernel's fixed `TIMER_HZ=100`/10ms granularity), so
            // `timer_gettime`/`timer_settime`'s own `old_value` reported a rounded, reconstructed
            // interval instead of what the caller actually requested (a real 2ms fractional
            // component came back as 10ms). Fixed via `Process::PosixTimer::interval_requested`,
            // the exact caller-supplied `(sec, nsec)` remembered verbatim and reported unmodified
            // -- `it_value`/remaining time still has to be genuinely tick-derived (no "exact"
            // value to store), only the fixed interval itself benefits from this.
            "timer_gettime/1-4.c",
            // `mlockall/3-7.c`: the real `mprotect(2)`-adjacent `MCL_CURRENT`/`msync(MS_INVALIDATE)`
            // -> `EBUSY` mechanism (`MmapFileRegion::locked`, landed alongside `mlockall/3-6.c`'s
            // own fix well before this entry) was already correct -- the real, actual gap was that
            // this is the *only* file in the whole corpus that `open()`s its own source by a
            // relative path (`conformance/interfaces/mlockall/3-7.c`), and nothing ever seeded that
            // path, so the test's own `open()` failed `ENOENT` before ever reaching its real
            // assertion. Fixed by adding a second `POSIX_TEST_EXTRA_FILES` entry (see that array's
            // own generation comment above) seeding the literal source text at the exact path pid
            // 1's own root cwd resolves it against, the same convention `sigaltstack/9-1.c`'s own
            // fixture already established.
            "mlockall/3-7.c",
            // `timer_getoverrun/2-2.c`: needed real sub-10ms timer resolution -- this kernel's
            // fixed `TIMER_HZ=100` (10ms) tick rounded a requested sub-tick interval *up* to a
            // whole tick, and `clock_getres` always reported the coarse 10ms value regardless of
            // `clockid`. Closed by a real ACPI HPET overlay (`cpu::hpet`, counter-only, never an
            // interrupt source -- see that module's own doc comment) backing `clock_getres`'s
            // real resolution report and `PosixTimer::deadline_ns`'s own exact elapsed-nanosecond
            // overrun catch-up math (`interrupts.rs`'s posix_timers expiry loop) for a relative-
            // mode `CLOCK_REALTIME`/`CLOCK_MONOTONIC` timer, plus a real HPET top-off in
            // `do_nanosleep` itself (PIT-tick-counted sleep duration can measurably lag a directly
            // -read HPET counter by a few ms over one short sleep -- real KVM virtual-PIT
            // imprecision, not a logic bug). **`timer_getoverrun/2-3.c` deliberately excluded from
            // this list, not fixed**: passes reliably in isolation, but reliably (not flakily)
            // FAILs once it's ~170 files into one long, continuously-running QEMU boot -- PIT
            // `ticks()` and HPET's own counter are two independently-clocked sources with no
            // cross-calibration, and their relative *rates* measurably diverge over several
            // minutes of sustained guest uptime under KVM (a known category of virtual-PIT timing
            // imprecision, not something a per-call top-off can close). Matches this project's own
            // existing precedent for real-time tests sensitive to host/VM timing variance
            // (`timer_settime/2-1.c`, `pthread_cond_init/4-2.c`) -- not chased further.
            "timer_getoverrun/2-2.c",
        ];
        out.retain(|rel| CANARY.contains(&rel.as_str()));
        out.sort();
        return out;
    }
    out.retain(|rel| !POSIX_KNOWN_HANGS.contains(&rel.as_str()));
    // `POSIX_EXTRA_EXCLUDE_FILE=<path>` (optional, defaults to `target/posix_extra_excludes.txt`):
    // a plain text file, one `relative/path.c` per line, merged into the exclusion set the same
    // way `POSIX_KNOWN_HANGS` is -- lets `scripts/run_posix_pilot_supervised.sh` (a host-side
    // supervisor that kills a genuinely wedged QEMU boot and retries with the stuck file excluded,
    // since a kernel-level hang can't be rescued by `t0`'s own userspace `alarm()` -- see that
    // script's own header comment) drive a real full-corpus run to completion across several
    // retries without hand-editing `POSIX_KNOWN_HANGS` (and triggering this whole file's
    // `cargo:rerun-if-changed` on itself) between every iteration. A file newly found stuck by that
    // script should still graduate into a real, documented `POSIX_KNOWN_HANGS` entry once
    // root-caused -- this is a fast iteration aid, not a permanent exclusion mechanism.
    //
    // The `rerun-if-changed` registration below is **unconditional**, not gated on the env var
    // being set -- found live, the hard way: cargo's own watch list for a build script is exactly
    // whatever that script's *most recent* invocation emitted, not a union across every past
    // invocation. An earlier plain `cargo build` (no env var set, run to sanity-check an unrelated
    // change) took what used to be the `if let Ok(extra_path) = ...` branch's *else* -- emitting no
    // watch directive for this file at all -- which made cargo "forget" to watch it, so every
    // later `POSIX_EXTRA_EXCLUDE_FILE`-driven invocation silently kept reusing the stale cached
    // manifest regardless of how many new lines the supervisor script appended. Always watching
    // the same fixed default path (whether or not this exact build set the env var) keeps the
    // watch list stable across every build, mixed-env-var or not.
    let extra_path = std::env::var("POSIX_EXTRA_EXCLUDE_FILE")
        .unwrap_or_else(|_| "target/posix_extra_excludes.txt".to_string());
    println!("cargo:rerun-if-changed={extra_path}");
    if let Ok(contents) = std::fs::read_to_string(&extra_path) {
        let extra: Vec<&str> = contents
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        out.retain(|rel| !extra.contains(&rel.as_str()));
    }
    // Real, live-found reliability problem, not a static guess: individually excluding
    // `POSIX_KNOWN_HANGS` one file at a time originally surfaced a *vanilla* `pthread_create()` +
    // `sleep(1)`-poll-on-a-shared-flag test (`pthread_attr_init/2-1.c`, no garbage attrs, no
    // signal blocking) hanging the same way the garbage-attr/atfork/futex-adjacent ones did.
    // **`pthread_attr_init/2-1.c` is now FIXED** (confirmed PASS via an isolated canary run) --
    // root cause was `SYS_exit_group` sharing the exact same syscall number as a bare per-thread
    // `SYS_exit` (see `third_party/musl/arch/x86_64/bits/syscall.h.in`'s `__NR_exit_group` doc
    // comment and `process::do_exit_group`'s own doc comment in the OxideBSD tree): `main()`
    // returning on the thread-group leader only ever tore down the leader itself, silently
    // orphaning this test's still-sleeping detached child thread, which later deadlocked in its
    // own `pthread_exit()` cleanup against musl's userspace thread-list bookkeeping -- not the
    // "thread creation/scheduling itself is unreliable" theory this comment originally floated.
    // **`pthread_attr_destroy/1-1.c` and `fork/11-1.c` are now also FIXED** (see `POSIX_KNOWN_HANGS`'s
    // own doc comments above for both) -- so the specific "known survivors" this wholesale
    // exclusion was originally scoped around are all resolved.
    //
    // **2026-09-02: lifted, per explicit user direction**, re-including the ~600
    // `pthread_*`/`aio_*`/`lio_listio*` files this prefix filter used to drop. It was never proven
    // that the three fixed hangs above were the *only* real hangs under this prefix, only that
    // they were the ones a partial run happened to find before the filter went in -- this run is
    // what actually finds out. If it surfaces a genuine new permanent hang, add it to
    // `POSIX_KNOWN_HANGS` by name (the established "found live, fixed forward" discipline this
    // whole file follows) rather than reinstating a blanket prefix filter.
    out.sort();
    out
}

/// Generates `target/generated/posix_test_manifest.rs` (same `include!`-a-generated-file idiom
/// `write_tcc_runtime_manifest` above already established, for the same reason: real file content
/// embedded via literal-path `include_bytes!`, not the `env!()`-per-file pattern every hand-written
/// embedded ELF in this codebase uses -- there's no reason to invent ~70 one-off names for data
/// with no other identity need). `discover_posix_test_files` above is the single source of truth
/// for *which* files get attempted; this function's own best-effort build loop decides which of
/// those actually get embedded.
///
/// **Cross-compiled with `musl-gcc` on the host, not compiled on-target by `tcc`** -- an earlier
/// version of this pilot seeded real `.c` source and compiled it on-target, exercising `tcc` as
/// the real toolchain any on-target C program would use. Found live, the hard way: `tcc`'s own
/// linker generates unresolved GOT/PLT indirection for calls into specific musl functions
/// (`sigaction`, `fflush` confirmed; `printf`/`clock_gettime`/`kill`/etc. unaffected) even under a
/// fully `-static` link -- the same *class* of bug CLAUDE.md's TinyCC section already documents
/// finding and partially fixing (`tccelf.c`'s `build_got_entries`), but that fix evidently doesn't
/// cover every code path. Symptom: a real ring-3 null-pointer read fault before the affected
/// binary's own first instruction, and -- found investigating the crash -- real stdio output was
/// silently never reaching the console for *any* on-target-compiled pilot binary at all, tcc bug
/// or not. Cross-compiling with the same real, already-proven `musl-gcc` toolchain
/// `build_musl_smoke`/`build_dynlink_smoke` already use sidesteps both problems at once, at the
/// cost of losing "exercises tcc" as a side benefit -- an acceptable trade for a conformance
/// baseline whose job is testing the *kernel*, not `tcc`. (The underlying `tcc` bug itself is
/// still real and un-fixed -- worth its own investigation later, tracked separately from this
/// pilot.)
///
/// Every pilot file shares one fixed load address (`POSIX_TEST_LOAD_BASE`, `0xe800000`, was
/// `0xa800000` before the whole low-VA family's own `+0x4000000` move -- see
/// `module::MODULE_VA_BASE`'s own doc comment) -- see this function's own leading comment for why
/// sharing one address is safe now (grew past the ~704-slot ceiling a per-file-unique-address
/// scheme could fit in the gap before `module::MODULE_VA_BASE`, once the corpus expanded from a
/// 488-file curated dedup to the ~1700-file full suite). Before that, each file got its own
/// `POSIX_TEST_LOAD_BASE + index * POSIX_TEST_LOAD_STEP` slot -- moved down from an original
/// `0xcf40000`/`0x40000`-step layout (only ~195 slots in the same gap) when the list first grew
/// past 68 files. `0xe800000` itself sits comfortably above `tcc`'s own `0xe280000` load
/// (`build_tinycc`'s own comment) plus its real ~1.1 MiB size, not just past the BusyBox applet
/// range's own ceiling (`0xe240000`) tcc's base was originally chosen relative to. `t0` (the
/// suite's own real timeout-wrapper utility, see
/// `posix_conformance.sh`'s own doc comment for why a real `alarm()`-based wrapper matters on a
/// kernel with no preemption) is cross-compiled the same way, at its own fixed base just below the
/// pilot range. Embeds each compiled ELF's real bytes at `bin/<relative-path-with-.c-extension>`
/// (the `.c` suffix is a real file's real relative identity carried through unchanged from the
/// source tree, not a claim about its own content -- avoids needing any extension-rewriting logic
/// in the shell runner, which would need real string manipulation hush may not support cleanly)
/// and writes out a plain-text `manifest.txt` (one relative path per line) generated from the same
/// list, so the seeded corpus and the runner script's own iteration list can never drift apart.
fn write_posix_test_manifest(musl_sysroot: &Path, posixtestsuite_dir: &Path) -> PathBuf {
    // One single shared load address for every pilot binary, not a unique slot per file: each
    // runs as its own `fork`+`execve`'d process in a completely fresh `AddressSpace` (see
    // CLAUDE.md's "User-mode execution" section) and never coexists with another pilot binary in
    // the same address space (no `PT_INTERP` here, unlike `libc.so`'s own real dynamic-linking
    // case) -- so, unlike every hand-written `userland/*` crate's own `linker.ld` (which follows a
    // "give every embedded ELF a distinct base" convention that was never a hard requirement, just
    // a longstanding habit), there is no real technical reason these need to differ. This stopped
    // being optional once the corpus grew past the ~704 slots the old
    // `POSIX_TEST_LOAD_BASE`..`module::MODULE_VA_BASE` gap could fit at a per-file step wide
    // enough to clear the largest real observed binary (~76 KiB) -- ~1700 files at that same step
    // would need ~218 MiB of VA space against an ~88 MiB gap.
    // Both +0x4000000 (was 0xa800000/0xa780000) alongside every other fixed userland/BusyBox/
    // module address -- see module::MODULE_VA_BASE's own doc comment.
    const POSIX_TEST_LOAD_BASE: u64 = 0xe800000;
    const T0_LOAD_BASE: u64 = 0xe780000;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_dir = Path::new(manifest_dir).join("target/generated");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/generated");
    let out_path = out_dir.join("posix_test_manifest.rs");
    let bin_dir = Path::new(manifest_dir).join("target/posix-test-pilot");
    std::fs::create_dir_all(&bin_dir).expect("failed to create target/posix-test-pilot");

    let interfaces_dir = posixtestsuite_dir.join("conformance/interfaces");
    let include_dir = posixtestsuite_dir.join("include");
    let musl_gcc = musl_sysroot.join("bin/musl-gcc");

    // Watches the whole tree recursively (cargo's own documented behavior for a directory path),
    // not one `println!` per discovered file like the old hand-curated list needed -- correctly
    // picks up a file being added/removed/edited anywhere under here without needing build.rs
    // itself touched.
    println!("cargo:rerun-if-changed={}", interfaces_dir.display());

    let all_files = discover_posix_test_files(&interfaces_dir);

    // Parallel across test files (mirrors `build_busybox_applet`'s own work-stealing pool over a
    // shared atomic index -- see that call site's comment for why: a plain thread-per-file pool
    // would vastly oversubscribe an 8-core host at this corpus size). Best-effort per file, not
    // `panic!` on the first failure: unlike the old hand-curated 488, this is every file the
    // upstream suite ships, including real helper files with no standalone `main()`
    // (`testfrmw.c`/`coverage.c`) and a handful of genuine upstream oddities (see
    // `discover_posix_test_files`'s own doc comment) -- a build failure here is expected, routine
    // signal for *some* files, not a build-breaking bug.
    let jobs = build_jobs();
    let next_idx = std::sync::atomic::AtomicUsize::new(0);
    let built: std::sync::Mutex<Vec<(String, PathBuf)>> = std::sync::Mutex::new(Vec::new());
    let skipped: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(rel) = all_files.get(i) else {
                        break;
                    };
                    let source = interfaces_dir.join(rel);
                    let out = bin_dir.join(rel.replace('/', "_"));
                    let invocation = compiler_invocation(&musl_gcc);
                    let mut cmd = Command::new(&invocation[0]);
                    cmd.args(&invocation[1..]);
                    cmd.arg("-static")
                        .arg("-no-pie")
                        .arg(format!("-Wl,-Ttext-segment={POSIX_TEST_LOAD_BASE:#x}"))
                        .arg("-I")
                        .arg(&include_dir)
                        // Real, found-live upstream-vs-modern-host-GCC frictions, not this
                        // codebase's own patches (same "cross-compiler is stricter than the
                        // suite's original ~2004-2005 toolchain" class of bug `t0.c`'s own
                        // `-include string.h` already works around): (1) this suite's own
                        // `testfrmw.c` (the shared test-framework helper) is meant to be pulled in
                        // via a literal `#include "testfrmw.c"` *inside* whichever test file needs
                        // it, inheriting that file's own already-included headers -- **not**
                        // compiled as a separate translation unit and linked (confirmed live: the
                        // latter produces real duplicate-symbol link errors against files that
                        // already `#include` it themselves, which is why this loop doesn't try to
                        // pair it in at all). (2) plenty of files rely on an implicit `open()`/
                        // `S_IRUSR`-family declaration this host's GCC 16 now hard-errors on
                        // regardless of `-std=`, and are simply missing `fcntl.h`/`sys/stat.h`
                        // outright (real upstream omissions, not a musl-vs-glibc header gap) --
                        // `-Wno-implicit-function-declaration` downgrades the former back to a
                        // warning (harmless: musl's own real prototype still governs the actual
                        // call), the `-include`s backfill the latter. Harmless no-ops for any file
                        // that already includes these itself (real header guards).
                        .arg("-Wno-implicit-function-declaration")
                        .arg("-Wno-implicit-int")
                        // Same "modern strict-by-default GCC vs. this suite's real ~2004-2005
                        // toolchain" friction as the pair above, different diagnostic: plenty of
                        // files pass a `void *(*)(void)` thread-start function where real
                        // `pthread_create`'s prototype wants `void *(*)(void *)` (a real, common
                        // relaxed-C89-era style this host's GCC 16 now hard-errors on) or assign a
                        // same-shaped mismatched handler into a `struct sigaction`. Demoted back to
                        // a warning, same reasoning as the pair above -- musl's own real prototype
                        // still governs the actual call ABI-compatibly on this target.
                        .arg("-Wno-incompatible-pointer-types")
                        .arg("-Wno-int-conversion")
                        .arg("-include")
                        .arg("stdio.h")
                        .arg("-include")
                        .arg("stdarg.h")
                        .arg("-include")
                        .arg("stdlib.h")
                        .arg("-include")
                        .arg("string.h")
                        .arg("-include")
                        .arg("unistd.h")
                        .arg("-include")
                        .arg("fcntl.h")
                        .arg("-include")
                        .arg("sys/stat.h")
                        .arg("-include")
                        .arg("sys/types.h")
                        .arg("-o")
                        .arg(&out)
                        .arg(&source);
                    let ok = cmd.status().is_ok_and(|s| s.success());
                    if ok {
                        built.lock().unwrap().push((rel.clone(), out));
                    } else {
                        skipped.lock().unwrap().push(rel.clone());
                    }
                }
            });
        }
    });

    let mut built = built.into_inner().unwrap();
    built.sort_by(|a, b| a.0.cmp(&b.0));
    let mut skipped = skipped.into_inner().unwrap();
    skipped.sort();
    println!(
        "cargo:warning=posix pilot: built {} of {} discovered files ({} skipped -- see target/generated/posix_test_manifest_skipped.txt)",
        built.len(),
        all_files.len(),
        skipped.len()
    );
    let skipped_path = out_dir.join("posix_test_manifest_skipped.txt");
    std::fs::write(&skipped_path, skipped.join("\n"))
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", skipped_path.display()));

    let mut src = String::new();
    src.push_str("pub static POSIX_TEST_FILES: &[(&str, &[u8])] = &[\n");
    let mut manifest_txt = String::new();
    for (rel, out) in &built {
        src.push_str(&format!(
            "    (\"bin/{rel}\", include_bytes!({:?})),\n",
            out.display()
        ));
        manifest_txt.push_str(rel);
        manifest_txt.push('\n');
    }

    let t0_c = posixtestsuite_dir.join("t0.c");
    println!("cargo:rerun-if-changed={}", t0_c.display());
    let t0_out = bin_dir.join("t0");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg(format!("-Wl,-Ttext-segment={T0_LOAD_BASE:#x}"))
        // A real bug in the vendored suite's own t0.c: calls `strcmp` without `#include
        // <string.h>` -- TCC let this slide (an implicit declaration is only a warning there);
        // this host's real GCC treats it as a hard error by default. `-include string.h` forces
        // the real declaration in without patching the vendored source itself.
        .arg("-include")
        .arg("string.h")
        .arg("-o")
        .arg(&t0_out)
        .arg(&t0_c)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for posix pilot's t0: {e}"));
    if !status.success() {
        panic!("building posix pilot's t0 failed: {status}");
    }
    src.push_str(&format!(
        "    (\"t0\", include_bytes!({:?})),\n",
        t0_out.display()
    ));

    let manifest_txt_path = out_dir.join("posix_test_manifest.txt");
    std::fs::write(&manifest_txt_path, &manifest_txt)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", manifest_txt_path.display()));
    src.push_str(&format!(
        "    (\"manifest.txt\", include_bytes!({:?})),\n",
        manifest_txt_path.display()
    ));
    src.push_str("];\n");

    // `sigaltstack/9-1.c`'s own real assertion needs a genuine second process it `execl()`s into
    // to check that no alt stack survives `exec` -- the suite's own test tree ships this as a
    // separate "-buildonly.c" companion file (excluded from `discover_posix_test_files` itself, like
    // every other "-buildonly.c" file, since it's not runnable as its own standalone assertion --
    // see this function's own doc comment above), built and referenced only by `9-1.c` via a
    // literal relative path copied verbatim from the upstream suite's own build-tree convention:
    // `conformance/interfaces/sigaltstack/9-buildonly.test`, resolved against pid 1's own root cwd
    // at the point the pilot script runs (`/`) -- so it has to be seeded at that *exact* path, not
    // under `/posix-tests/` like every other pilot binary. Kept in a second, separate generated
    // array (`POSIX_TEST_EXTRA_FILES`) seeded directly at oxfs's own root rather than folded into
    // `POSIX_TEST_FILES` above, which `modules/oxfs` seeds under `/posix-tests` specifically.
    // +0x4000000 (was 0xa7a0000) alongside every other fixed userland/BusyBox/module address --
    // see module::MODULE_VA_BASE's own doc comment.
    const SIGALTSTACK_9_BUILDONLY_LOAD_BASE: u64 = 0xe7a0000;
    let sigaltstack_9_buildonly_c = interfaces_dir.join("sigaltstack/9-buildonly.c");
    println!(
        "cargo:rerun-if-changed={}",
        sigaltstack_9_buildonly_c.display()
    );
    let sigaltstack_9_buildonly_out = bin_dir.join("sigaltstack_9-buildonly.test");
    let status = Command::new(&musl_gcc)
        .arg("-static")
        .arg("-no-pie")
        .arg(format!(
            "-Wl,-Ttext-segment={SIGALTSTACK_9_BUILDONLY_LOAD_BASE:#x}"
        ))
        .arg("-I")
        .arg(&include_dir)
        .arg("-o")
        .arg(&sigaltstack_9_buildonly_out)
        .arg(&sigaltstack_9_buildonly_c)
        .status()
        .unwrap_or_else(|e| panic!("failed to run musl-gcc for sigaltstack/9-buildonly.c: {e}"));
    if !status.success() {
        panic!("building sigaltstack/9-buildonly.c failed: {status}");
    }
    // `mlockall/3-7.c`'s own real assertion `open()`s its *own source file* by the identical
    // upstream-relative-path convention as `sigaltstack/9-1.c` just above (the suite's own build
    // tree assumes the whole `conformance/` source tree is present alongside the compiled
    // binaries) -- resolved against the same pid-1 root cwd (`/`) the pilot script runs from, so
    // it needs the literal source text (not a compiled binary -- the test only ever reads it as
    // opaque bytes to mmap, never executes it) seeded at that exact path. No other file in the
    // whole corpus does this (`grep -rl 'open("conformance/interfaces'` confirms it), so one more
    // `POSIX_TEST_EXTRA_FILES` entry is simpler than generalizing this into its own mechanism.
    let mlockall_3_7_c = interfaces_dir.join("mlockall/3-7.c");
    println!("cargo:rerun-if-changed={}", mlockall_3_7_c.display());
    src.push_str(&format!(
        "pub static POSIX_TEST_EXTRA_FILES: &[(&str, &[u8])] = &[\n    (\"conformance/interfaces/sigaltstack/9-buildonly.test\", include_bytes!({:?})),\n    (\"conformance/interfaces/mlockall/3-7.c\", include_bytes!({:?})),\n];\n",
        sigaltstack_9_buildonly_out.display(),
        mlockall_3_7_c.display()
    ));

    std::fs::write(&out_path, src)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));
    out_path
}

/// Cross-builds the userland crate at `userland/<crate_name>/` and exposes its resulting ELF's
/// path via `cargo:rustc-env=<env_var>=<path>`, and returns that same path so callers that need
/// the raw bytes on the host side (`main`, for embedding `ring3-smoke` into the FAT32 image) don't
/// have to re-derive it.
fn build_userland_crate(crate_name: &str, env_var: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let userland_dir = Path::new(manifest_dir).join("userland").join(crate_name);
    let target_dir = Path::new(manifest_dir).join("target/userland");

    println!(
        "cargo:rerun-if-changed={}",
        userland_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        userland_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        userland_dir.join("linker.ld").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        userland_dir.join("build.rs").display()
    );

    let cargo = cargo_bin();
    let status = Command::new(&cargo)
        .current_dir(manifest_dir)
        .args([
            "build",
            "--manifest-path",
            userland_dir.join("Cargo.toml").to_str().unwrap(),
            "--release",
            "--target-dir",
            target_dir.to_str().unwrap(),
        ])
        // Building a userland crate is itself a `cargo build` invocation; without clearing these,
        // it inherits the outer build's CARGO_* env vars (wrong package name/manifest dir/etc.)
        // from when *this* build script was invoked.
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_PKG_NAME")
        // Cargo's own rustflags-source priority is `CARGO_ENCODED_RUSTFLAGS` env var > `RUSTFLAGS`
        // env var > `.cargo/config.toml`'s `[target.*] rustflags` -- and, found live via a real
        // regression this exact gap caused, **cargo sets `CARGO_ENCODED_RUSTFLAGS` in a build
        // script's own process environment** whenever the outer build resolved rustflags via
        // config (this crate's own `[target.x86_64-oxidebsd] rustflags`), which then gets
        // silently *inherited* by any `Command` this build script spawns unless explicitly
        // cleared -- a plain `.env("RUSTFLAGS", ...)` override below is not enough by itself,
        // since the still-present, higher-priority encoded var wins regardless. Without clearing
        // it here, the kernel's own `-C link-arg=-Tx86_64-oxidebsd.ld` (`ENTRY(kmain)`) leaked into
        // this nested build, fighting each crate's own `ENTRY(_start)` linker script (set via its
        // own `build.rs`'s `cargo:rustc-link-arg=-T...`) and silently producing a broken ELF with
        // no entry point/program headers.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // No userland crate needs the kernel's `chacha20_backend` cfg, so blanking `RUSTFLAGS`
        // entirely (matching `build_module_crate`'s own precedent) is correct, not just a
        // workaround.
        .env("RUSTFLAGS", "")
        .status()
        .unwrap_or_else(|e| panic!("failed to run cargo for {crate_name}: {e}"));

    if !status.success() {
        panic!("building the {crate_name} userland binary failed: {status}");
    }

    let elf_path: PathBuf = target_dir.join("x86_64-oxidebsd/release").join(crate_name);
    assert!(
        elf_path.exists(),
        "{crate_name} build reported success but {} doesn't exist",
        elf_path.display()
    );
    println!("cargo:rustc-env={env_var}={}", elf_path.display());
    elf_path
}

/// Cross-builds the Multiboot2 boot-path smoke test (`smoke/multiboot2-boot-smoke/`, wrapping
/// `tests/multiboot2_boot_smoke.rs`) into a final linked ELF, using the dedicated
/// `x86_64-oxidebsd-multiboot2.ld` linker script instead of the kernel's own `x86_64-oxidebsd.ld`.
/// Modeled directly on `build_userland_crate` above -- see CLAUDE.md's Multiboot2 section for why
/// no other mechanism (`.cargo/config.toml`'s shared rustflags, `rustc-link-arg-bin`/`-tests`) can
/// give one binary its own linker script under this workspace's otherwise-shared target.
fn build_multiboot2_boot_smoke_crate() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let smoke_dir = Path::new(manifest_dir).join("smoke/multiboot2-boot-smoke");
    let target_dir = Path::new(manifest_dir).join("target/multiboot2-boot-smoke");

    println!(
        "cargo:rerun-if-changed={}",
        Path::new(manifest_dir)
            .join("tests/multiboot2_boot_smoke.rs")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        smoke_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        smoke_dir.join("build.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        Path::new(manifest_dir)
            .join("x86_64-oxidebsd-multiboot2.ld")
            .display()
    );

    let cargo = cargo_bin();
    let status = Command::new(&cargo)
        .current_dir(manifest_dir)
        .args([
            "build",
            "--manifest-path",
            smoke_dir.join("Cargo.toml").to_str().unwrap(),
            "--release",
            "--target-dir",
            target_dir.to_str().unwrap(),
        ])
        // Same rationale as build_userland_crate below: without clearing these, this nested build
        // inherits the outer build script's own CARGO_* env vars and (more importantly) the
        // higher-priority CARGO_ENCODED_RUSTFLAGS cargo stashes from the outer build's own
        // config-resolved rustflags, which would otherwise leak the kernel's `-Tx86_64-oxidebsd.ld`
        // in ahead of this crate's own build.rs-supplied `-T`.
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // Unlike a plain userland crate (which blanks RUSTFLAGS entirely), this crate links the
        // real `oxidebsd` lib, which pulls in `chacha20` -- needs the same soft-backend cfg
        // `.cargo/config.toml`'s shared rustflags give the kernel/tests build (see that file's own
        // comment for why `chacha20`/SSE-disabled targets need it).
        .env("RUSTFLAGS", "--cfg chacha20_backend=\"soft\"")
        // Reentrancy guard -- see this function's own call site in `main()` for why this can't be
        // `CARGO_PRIMARY_PACKAGE`. Plain env inheritance carries this into the nested build's own
        // `oxidebsd` build-script invocation, which checks for it and skips recursing.
        .env("OXIDEBSD_BUILDING_MULTIBOOT2_SMOKE", "1")
        .status()
        .unwrap_or_else(|e| panic!("failed to run cargo for multiboot2-boot-smoke: {e}"));

    if !status.success() {
        panic!("building the multiboot2-boot-smoke binary failed: {status}");
    }

    let elf_path: PathBuf = target_dir
        .join("x86_64-oxidebsd/release")
        .join("multiboot2-boot-smoke");
    assert!(
        elf_path.exists(),
        "multiboot2-boot-smoke build reported success but {} doesn't exist",
        elf_path.display()
    );

    let dest = Path::new(manifest_dir).join("target/multiboot2-boot-smoke.elf");
    std::fs::copy(&elf_path, &dest).unwrap_or_else(|e| {
        panic!(
            "failed to copy multiboot2-boot-smoke ELF to {}: {e}",
            dest.display()
        )
    });
    dest
}

/// Cross-builds the kernel module crate at `modules/<crate_name>/` into a single relocatable
/// (`ET_REL`) object file, ready for `src/module.rs` to load and relocate at boot, and exposes it
/// via `cargo:rustc-env=<name_var>_MOD_PATH=<path>` (`name_var` is `env_var` upper-cased). See
/// `CLAUDE.md`'s module-loading section for the full rationale; in short:
///
/// - Module crates are plain `#![no_std]` `lib` crates -- no `_start`, no linker script, no final
///   link. `cargo rustc -- --emit=obj -C codegen-units=1` produces exactly one `ET_REL` object,
///   skipping the link step entirely.
/// - `-C relocation-model=static` (scoped to this nested build only, via `RUSTFLAGS`) keeps every
///   relocation a simple absolute/PC-relative form -- no GOT -- in exchange for requiring the
///   module's eventual mapped address to stay within the low 2 GiB (see `src/module.rs`'s
///   `MODULE_VA_BASE`).
/// - The module's own object alone has an open-ended, code-content-dependent set of undefined
///   symbols (anything from `memcpy` to `core::fmt::write` to panic machinery, depending on what
///   the module's code happens to do) -- not something a hand-curated kernel API table can
///   practically enumerate in advance. A build-time partial relink (`rust-lld -r`, not a final
///   link) against the exact `core`/`alloc`/`compiler_builtins` rlibs this same build produced
///   closes over all of that, leaving only the module's genuine calls into the kernel API plus
///   one fixed, compiler-synthesized panic-entry symbol (discovered below, not hardcoded, since
///   its exact mangled name is toolchain-dependent) unresolved.
///
/// `extra_env` is passed straight through to the nested `cargo rustc` invocation -- used by the
/// `oxfs` module to receive each seeded ELF's own build path (`OXFS_<NAME>_ELF_PATH`) for its own
/// `include_bytes!(env!(...))` calls, since modules have no `build.rs` of their own (there's no
/// linker script to pass, they're never linked at all).
fn build_module_crate(crate_name: &str, env_var: &str, extra_env: &[(&str, &str)]) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let module_dir = Path::new(manifest_dir).join("modules").join(crate_name);
    let target_dir = Path::new(manifest_dir).join("target/modules");

    println!(
        "cargo:rerun-if-changed={}",
        module_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        module_dir.join("Cargo.toml").display()
    );

    let cargo = cargo_bin();
    let mut command = Command::new(&cargo);
    command
        .current_dir(manifest_dir)
        .args([
            "rustc",
            "--manifest-path",
            module_dir.join("Cargo.toml").to_str().unwrap(),
            "--release",
            "--lib",
            "--target-dir",
            target_dir.to_str().unwrap(),
            // Structured output, parsed below to find the real `--emit=obj` artifact path
            // directly rather than guessing a filename convention (`{crate}-<hash>.o`) that isn't
            // part of any stability guarantee -- found live on a newer nightly (rustc
            // 1.99.0-nightly) where that guessed pattern no longer matched anything cargo actually
            // wrote, even though the build itself succeeded. `-render-diagnostics` keeps warning/
            // error text human-readable inside the JSON stream (in each message's own `rendered`
            // field) rather than needing a second pass to reformat raw diagnostic spans.
            "--message-format=json-render-diagnostics",
            "--",
            "--emit=obj",
            "-C",
            "codegen-units=1",
        ])
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_PKG_NAME")
        // See `build_userland_crate`'s own doc comment for why this is required, not just
        // defensive: cargo silently inherits `CARGO_ENCODED_RUSTFLAGS` (higher-priority than the
        // plain `RUSTFLAGS` env var set just below) from this build script's own process
        // environment into any `Command` it spawns, which would otherwise let the kernel's own
        // `[target.x86_64-oxidebsd] rustflags` silently override the `relocation-model=static`
        // this nested build genuinely needs.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // See the doc comment above: eliminates GOT-indirected relocations everywhere, including
        // inside the precompiled core/alloc this nested `-Z build-std` invocation produces (which
        // doesn't inherit the trailing `--emit=obj`-style flags, only RUSTFLAGS).
        //
        // `-C code-model=kernel`: found live, the *first* time `CARGO_ENCODED_RUSTFLAGS` above was
        // actually cleared and `relocation-model=static` genuinely took effect for a module build
        // (previously silently never applied -- see the doc comment above). LLVM's *default* code
        // model under `relocation-model=static` (`small`) assumes absolute references fit the
        // unsigned low 4 GiB and emits `R_X86_64_32` for them (e.g. a function pointer taken as an
        // integer, as `module_init` does registering each syscall handler) -- correct for the old
        // `MODULE_VA_BASE=0x10000000`, but `RelocationOverflow` for the current one
        // (`0xffffffff90000000`, moved into the kernel's own top-2GiB region specifically so
        // `R_X86_64_PC32`/`PLT32` calls into real kernel functions resolve -- see `src/module.rs`'s
        // own `MODULE_VA_BASE` doc comment). `code-model=kernel` is x86_64 LLVM's dedicated model
        // for exactly this placement: it emits sign-extending `R_X86_64_32S` instead, correctly
        // representable for any address in the top 2 GiB (`0xffffffff80000000`-
        // `0xffffffffffffffff`), which `MODULE_VA_BASE`/`MODULE_REGION_CEILING` both fall inside.
        .env(
            "RUSTFLAGS",
            "-C relocation-model=static -C code-model=kernel",
        );
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("failed to run cargo rustc for module {crate_name}: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout);

    if !output.status.success() {
        panic!(
            "building the {crate_name} module's object file failed: {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let sysroot = rustc_output(manifest_dir, &["--print", "sysroot"]);
    let host = host_triple(manifest_dir);
    let llvm_bin = Path::new(&sysroot)
        .join("lib/rustlib")
        .join(&host)
        .join("bin");

    let deps_dir = target_dir.join("x86_64-oxidebsd/release/deps");
    let module_obj = find_artifact_file(&stdout, crate_name, ".o")
        .or_else(|| newest_matching(&deps_dir, &format!("{crate_name}-"), ".o"))
        .unwrap_or_else(|| {
            // Last resort -- confirmed live on rustc 1.99.0-nightly: cargo's own JSON build
            // output can report a crate's `compiler-artifact` message with only its `.rlib`/
            // `.rmeta` in `filenames`, no `.o` at all, even though `--emit=obj` was passed and the
            // build genuinely succeeded -- `--emit=obj` silently dropped, not just renamed. Pull
            // the real compiled object straight out of the `.rlib` cargo always produces instead
            // of depending on that flag working at all (see `extract_object_from_rlib`'s own doc
            // comment).
            let rlib = find_artifact_file(&stdout, crate_name, ".rlib")
                .or_else(|| newest_matching(&deps_dir, &format!("lib{crate_name}-"), ".rlib"))
                .unwrap_or_else(|| {
                    panic!(
                        "{crate_name}: no object file *or* rlib found anywhere -- cargo's own \
                         JSON build output:\n{stdout}"
                    )
                });
            let extract_dir = target_dir.join(format!("{crate_name}-rlib-extract"));
            extract_object_from_rlib(&llvm_bin, &rlib, &extract_dir, crate_name)
        });

    let merged_obj = target_dir.join(format!("{crate_name}-merged.o"));
    partial_link(
        crate_name,
        &stdout,
        &llvm_bin,
        &deps_dir,
        &module_obj,
        &merged_obj,
    );

    let panic_symbol = discover_panic_symbol(&llvm_bin, &merged_obj);

    println!(
        "cargo:rustc-env={env_var}_MOD_PATH={}",
        merged_obj.display()
    );
    println!(
        "cargo:rustc-env={env_var}_MOD_PANIC_SYMBOL={}",
        panic_symbol.as_deref().unwrap_or("")
    );
}

/// Scans `cargo rustc --message-format=json-render-diagnostics`'s own stdout (plain ndjson, one
/// JSON object per line, no pretty-printing) for the `compiler-artifact` message naming
/// `crate_name`'s own build, and returns whichever path in its real `filenames` array ends in
/// `suffix` (`".o"` or `".rlib"`) -- the artifact's actual, cargo-reported location, not a guessed
/// `{crate}-<hash>.<ext>` filename pattern (see `build_module_crate`'s own doc comment on why
/// guessing broke on a newer nightly: that naming convention was never a stability guarantee to
/// begin with). Returns `None` both when the message itself is missing and when the message
/// exists but no filename with that suffix is in it -- confirmed live (rustc 1.99.0-nightly) that
/// the latter genuinely happens for `.o`: cargo's own `compiler-artifact` message for a `--lib`
/// build can list only `.rlib`/`.rmeta`, silently dropping `--emit=obj` from the emitted set.
///
/// Hand-rolled substring scanning, not a `serde_json` build-dependency: cargo's message-format
/// output is simple single-line JSON with no nested arrays inside `filenames`, and this project's
/// own paths never contain characters needing JSON escaping (no quotes/backslashes) -- a real
/// parser would be more correct in the abstract but pure ceremony for this one shape of input.
fn find_artifact_file(cargo_json_stdout: &str, crate_name: &str, suffix: &str) -> Option<PathBuf> {
    let name_needle = format!("\"name\":\"{crate_name}\"");
    for line in cargo_json_stdout.lines() {
        if !line.contains("\"reason\":\"compiler-artifact\"") || !line.contains(&name_needle) {
            continue;
        }
        let Some(list_start) = line.find("\"filenames\":[") else {
            continue;
        };
        let list_start = list_start + "\"filenames\":[".len();
        let Some(list_len) = line[list_start..].find(']') else {
            continue;
        };
        for raw in line[list_start..list_start + list_len].split(',') {
            let path = raw.trim().trim_matches('"');
            if path.ends_with(suffix) {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Last-resort fallback for getting a module's compiled object code when cargo's own `--emit=obj`
/// passthrough produces nothing usable (see `find_artifact_file`'s own doc comment for when this
/// happens). An `.rlib` is itself just an `ar` archive whose members are the crate's real compiled
/// object code (one member per codegen unit) plus a `lib.rmeta` metadata member -- `llvm-ar x`
/// extracts them directly, sidestepping `--emit` entirely rather than depending on cargo choosing
/// to honor it. `-C codegen-units=1` (already passed at every module's own build_module_crate call
/// site) should mean exactly one extracted member ends in `.o`; this panics loudly rather than
/// guessing if that invariant doesn't hold, since silently picking one of several codegen units
/// would link a module missing most of its own code.
fn extract_object_from_rlib(
    llvm_bin: &Path,
    rlib: &Path,
    extract_dir: &Path,
    crate_name: &str,
) -> PathBuf {
    std::fs::create_dir_all(extract_dir)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", extract_dir.display()));

    let llvm_ar = llvm_bin.join("llvm-ar");
    let status = Command::new(&llvm_ar)
        .arg("x")
        .arg(rlib)
        .current_dir(extract_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to run llvm-ar on {}: {e}", rlib.display()));
    if !status.success() {
        panic!("llvm-ar failed to extract {}: {status}", rlib.display());
    }

    let objects: Vec<PathBuf> = std::fs::read_dir(extract_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", extract_dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "o"))
        .collect();

    match objects.as_slice() {
        [only] => only.clone(),
        [] => panic!(
            "{crate_name}: extracted {} but it contains no .o member -- is it actually an rlib?",
            rlib.display()
        ),
        many => panic!(
            "{crate_name}: rlib {} contained {} object members ({many:?}), expected exactly one \
             -- codegen-units=1 may not have taken effect for this build",
            rlib.display(),
            many.len()
        ),
    }
}

/// Merges `module_obj` with the exact `core`/`alloc`/`compiler_builtins` rlibs found in
/// `deps_dir` via a relocatable ("partial") link -- `-r`, not a final link -- so that any symbol
/// the module's code references from those crates resolves at build time. Archive members are
/// pulled in only if actually referenced (ordinary linker semantics), wrapped in
/// `--start-group`/`--end-group` since `core`/`alloc`/`compiler_builtins` reference each other
/// and a single pass wouldn't otherwise guarantee a resolving order.
///
/// `--gc-sections -u module_init`: archive-member selection is coarse (a whole `.o` file, which
/// for `-Z build-std`'s own precompiled `core`/`alloc` can bundle many unrelated functions
/// together), so referencing just one symbol from a bundled member can otherwise pull in
/// everything else defined alongside it. This was discovered as a real, non-optional requirement
/// (not the "nice to have, defer it" size optimization an earlier draft of this design assumed
/// it'd be) when `modules/fat32/`'s very first boot attempt exhausted the kernel's small heap:
/// referencing `core::panicking::panic_bounds_check` (reachable from any ordinary slice
/// indexing) alone pulled in most of `core::fmt`'s numeric/Unicode tables, ballooning that one
/// module to 3+ MB across ~2900 sections. `-u module_init` marks every module's sole real entry
/// point as a GC root (`-r` produces no executable with an implicit entry point of its own, so
/// nothing is reachable by default) -- `--gc-sections` then prunes every section not transitively
/// reachable from it, which brought that same object down to ~60 sections.
fn partial_link(
    crate_name: &str,
    cargo_json_stdout: &str,
    llvm_bin: &Path,
    deps_dir: &Path,
    module_obj: &Path,
    merged_obj: &Path,
) {
    let lld = llvm_bin.join("rust-lld");
    assert!(
        lld.exists(),
        "rust-lld not found at {} -- is the llvm-tools-preview rustup component installed? \
         (see rust-toolchain.toml)",
        lld.display()
    );

    // Prefer cargo's own JSON build output over guessing `deps_dir`'s layout -- confirmed live
    // (rustc 1.99.0-nightly) that `-Z build-std`'s sysroot crates (`core`/`alloc`/
    // `compiler_builtins`) don't land in `deps/` at all on this toolchain, but under their own
    // `build/<crate>/<hash>/out/` directory instead (same class of drift as
    // `find_artifact_file`'s own doc comment documents for `--emit=obj`). Falls back to the old
    // `deps_dir` glob for whatever toolchain still uses that layout.
    let find_rlib = |name: &str| {
        find_artifact_file(cargo_json_stdout, name, ".rlib")
            .or_else(|| newest_matching(deps_dir, &format!("lib{name}-"), ".rlib"))
            .unwrap_or_else(|| {
                panic!(
                    "{crate_name}: no {name} rlib found via cargo's own JSON build output, nor \
                     in {} -- is `-Z build-std` producing one?",
                    deps_dir.display()
                )
            })
    };
    let core_rlib = find_rlib("core");
    let alloc_rlib = find_rlib("alloc");
    let compiler_builtins_rlib = find_rlib("compiler_builtins");

    let status = Command::new(&lld)
        .args([
            "-flavor",
            "gnu",
            "-r",
            "--gc-sections",
            "-u",
            "module_init",
            "-o",
            merged_obj.to_str().unwrap(),
            module_obj.to_str().unwrap(),
            "--start-group",
        ])
        .args([&core_rlib, &alloc_rlib, &compiler_builtins_rlib])
        .arg("--end-group")
        .status()
        .unwrap_or_else(|e| panic!("failed to run rust-lld for module {crate_name}: {e}"));

    if !status.success() {
        panic!("partial link for module {crate_name} failed: {status}");
    }
}

/// Scans `object`'s undefined symbols for the compiler-synthesized panic entry point
/// (`core::panicking`'s internal `rust_begin_unwind` declaration, called by every panicking-path
/// function `core`/`alloc` contain). Its exact mangled name embeds a crate-metadata hash that's
/// toolchain-dependent and not worth hardcoding -- `rust_begin_unwind` still appears as a literal
/// substring of the mangled name (Rust's v0 mangling spells out path components as length-prefixed
/// text), so a substring search is enough to find it reliably. Returns `None` if the module's code
/// never actually references it (e.g. no panicking-capable operations survived optimization) --
/// that's fine, `src/module.rs`'s resolver only needs entries for symbols a module actually uses.
fn discover_panic_symbol(llvm_bin: &Path, object: &Path) -> Option<String> {
    let nm = llvm_bin.join("llvm-nm");
    let output = Command::new(&nm)
        .args(["--undefined-only", "--format=just-symbols"])
        .arg(object)
        .output()
        .unwrap_or_else(|e| panic!("failed to run llvm-nm on {}: {e}", object.display()));
    assert!(
        output.status.success(),
        "llvm-nm failed for {}",
        object.display()
    );
    String::from_utf8(output.stdout)
        .expect("llvm-nm output wasn't valid UTF-8")
        .lines()
        .find(|line| line.contains("rust_begin_unwind"))
        .map(|s| s.trim().to_string())
}

/// Mirrors `modules/oxfs/src/lib.rs`'s own on-disk block-layout constants (see that file's "Real
/// disk persistence" section) -- duplicated here, not imported, since a `build.rs` can't depend on
/// a `#![no_std]` module crate. Must be kept in sync by hand if oxfs's own constants ever change --
/// the same "two things that must agree, flagged rather than shared" duplication this codebase
/// already accepts elsewhere (e.g. `Cargo.toml`'s `test-success-exit-code` vs. `src/qemu.rs`'s
/// `QemuExitCode`).
const OXFS_BLOCK_SIZE: u64 = 4096;
// 16384 -> 65536 (64 -> 256 MiB) and 2048 -> 8192 inodes: the POSIX pilot corpus grew from a
// 488-file curated dedup to the full ~1700-file suite (see `discover_posix_test_files`), each a
// new inode plus its own data blocks, and ~104 previously-unseeded `pthread_*`/`aio_*`/
// `lio_listio` directories add real new directory inodes too. Measured the new corpus's own
// compiled-binary weight directly (~34 KiB average per pilot ELF over a 495-file sample) before
// picking these -- generous headroom over the ~60 MiB the full corpus's own binaries alone need,
// not a guess.
//
// 65536 -> 262144 (256 MiB -> 1 GiB) alongside the real max-file-size redesign (`Inode::
// double_indirect` in `modules/oxfs/src/lib.rs`, see that field's own doc comment) -- see that
// constant's own doc comment for why 1 GiB, not something bigger or smaller.
const OXFS_NUM_BLOCKS: u64 = 262144;
const OXFS_MAX_INODES: u64 = 8192;
const OXFS_INODE_STRIDE: u64 = 128;
/// 1 superblock + inode-table blocks (`OXFS_MAX_INODES` inodes at `OXFS_INODE_STRIDE` bytes each,
/// rounded up to a whole block) + `OXFS_BITMAP_BLOCKS` block-used bitmap blocks -- computed from
/// the same real inputs `modules/oxfs/src/lib.rs`'s own `INODE_TABLE_BLOCKS`/`BITMAP_BLOCKS` are,
/// not separately hand-picked numbers.
/// **Found live as a real, hand-duplicated staleness bug, not just a theoretical risk this comment
/// warns about**: this constant was left at its old value (a literal `18`, correct only for the
/// pre-TinyCC `MAX_INODES = 512`) when that constant was bumped to `1024` (see CLAUDE.md's TinyCC
/// section) -- silently sizing every *newly created* `oxfs_disk.img` 16 blocks (64 KiB) too small
/// for the real on-disk layout the kernel-side code actually uses, not just leaving a
/// *pre-existing* stale file too small. Confirmed live against a real, already-formatted disk
/// predating this fix: `mount_from_disk`'s own per-block data read failed partway through (the
/// last ~16 real data blocks physically don't exist in a file sized this way), which is what first
/// surfaced this bug — see `reset_real_pool_for_fresh_format`'s own doc comment in
/// `modules/oxfs/src/lib.rs` for the *other* real bug that same failure mode exposed.
///
/// **A second, real instance of this exact staleness class, found alongside the max-file-size
/// redesign**: this hardcoded a flat `1` block for the bitmap, correct only while `OXFS_NUM_BLOCKS`
/// fit within `OXFS_BLOCK_SIZE * 8` (32768) bits -- already silently wrong the moment
/// `OXFS_NUM_BLOCKS` first passed that (65536, well before this pass's own further bump to
/// 262144). Fixed the same way `modules/oxfs/src/lib.rs`'s own `BITMAP_BLOCKS` was: a real,
/// computed span, not a hand-picked one.
const OXFS_BITMAP_BLOCKS: u64 = (OXFS_NUM_BLOCKS * 8).div_ceil(OXFS_BLOCK_SIZE * 8);
const OXFS_METADATA_BLOCKS: u64 =
    1 + (OXFS_MAX_INODES * OXFS_INODE_STRIDE).div_ceil(OXFS_BLOCK_SIZE) + OXFS_BITMAP_BLOCKS;
const OXFS_DISK_IMAGE_BYTES: u64 = (OXFS_METADATA_BLOCKS + OXFS_NUM_BLOCKS) * OXFS_BLOCK_SIZE;

/// Writes the two raw disk images `Cargo.toml`'s `run-args`/`test-args` attach to QEMU as
/// `src/drivers/ata.rs`'s fixed data-disk target (see that module's own doc comment for why secondary
/// channel/master specifically).
///
/// `oxfs_disk.img` is the real, persistent dev disk `cargo run` uses -- created **only if it
/// doesn't already exist**. That's load-bearing, not an optimization: this is what makes it
/// survive across `cargo run` invocations at all, the entire point of real disk persistence. A
/// rebuild must never re-zero it, or there would be nothing left to prove "install OxideBSD"
/// actually works (see the implementation plan's own manual verification steps).
///
/// `oxfs_test_disk.img` is the opposite: always freshly regenerated (zeroed) on every build, so
/// `tests/ata_smoke.rs`/`tests/oxfs_persistence_syscall_smoke.rs` always start from the same
/// known-empty state, independent of whatever a previous test run left behind.
fn write_data_disk_images() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest_dir).join("target");
    std::fs::create_dir_all(&target_dir).expect("failed to create target/");
    let zeroed = vec![0u8; OXFS_DISK_IMAGE_BYTES as usize];

    let dev_disk_path = target_dir.join("oxfs_disk.img");
    // Load-bearing, not a nicety: this file lives under `target/`, never touched by any other
    // `rerun-if-changed` path this build script declares, so a plain `cargo run` after someone
    // deletes it (e.g. to force a reformat/reseed) would otherwise skip this whole function --
    // cargo only reruns a build script when a declared watched path actually changed, and an
    // untracked deletion doesn't qualify. Cargo's own documented behavior for a `rerun-if-changed`
    // path that doesn't exist is "always rerun the build script" -- exactly the case that needs
    // covering here. Emitted unconditionally (both branches below), not just in the `Err` arm, so
    // this stays watched on every future run too, including the ordinary case where the file
    // already exists at the right size and nothing else needs to happen to it.
    println!("cargo:rerun-if-changed={}", dev_disk_path.display());
    match std::fs::metadata(&dev_disk_path) {
        Err(_) => {
            std::fs::write(&dev_disk_path, &zeroed)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", dev_disk_path.display()));
            println!(
                "cargo:warning=oxfs: created a fresh persistent dev disk at {}",
                dev_disk_path.display()
            );
        }
        Ok(meta) if meta.len() < OXFS_DISK_IMAGE_BYTES => {
            // An existing disk written under an older, smaller layout (e.g. a prior
            // `OXFS_METADATA_BLOCKS`/`NUM_BLOCKS`/`MAX_INODES`) -- grow it in place by appending
            // zeros rather than truncating/rewriting, so real existing content stays intact for
            // `mount_from_disk`'s own superblock-layout check (see that function's doc comment in
            // `modules/oxfs/src/lib.rs`) to accept or reject on its own terms. A superblock that
            // no longer matches this build's layout still cleanly falls back to reformatting; a
            // file left too small would instead fail with a real, physical out-of-bounds read
            // before that check ever gets the chance to run.
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&dev_disk_path)
                .unwrap_or_else(|e| panic!("failed to open {}: {e}", dev_disk_path.display()));
            let old_len = meta.len();
            f.seek(SeekFrom::End(0)).expect("failed to seek dev disk");
            let padding = vec![0u8; (OXFS_DISK_IMAGE_BYTES - old_len) as usize];
            f.write_all(&padding)
                .unwrap_or_else(|e| panic!("failed to grow {}: {e}", dev_disk_path.display()));
            println!(
                "cargo:warning=oxfs: grew existing persistent dev disk at {} from {} to {} bytes",
                dev_disk_path.display(),
                old_len,
                OXFS_DISK_IMAGE_BYTES
            );
        }
        Ok(_) => {}
    }

    let test_disk_path = target_dir.join("oxfs_test_disk.img");
    std::fs::write(&test_disk_path, &zeroed)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", test_disk_path.display()));
}

/// Finds the file matching `<prefix>*<suffix>` most recently modified in `dir` -- filenames under
/// `deps/` carry a non-deterministic metadata hash, so an exact name can't be predicted, and
/// picking the newest (rather than asserting exactly one) tolerates stale artifacts left behind by
/// a prior build with different flags reusing the same target-dir.
fn newest_matching(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(prefix) && name.ends_with(suffix)
        })
        .max_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok())
        .map(|entry| entry.path())
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn rustc_output(manifest_dir: &str, args: &[&str]) -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(&rustc)
        .current_dir(manifest_dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run rustc {args:?}: {e}"));
    assert!(output.status.success(), "rustc {args:?} failed");
    String::from_utf8(output.stdout)
        .expect("rustc output wasn't valid UTF-8")
        .trim()
        .to_string()
}

fn host_triple(manifest_dir: &str) -> String {
    let verbose = rustc_output(manifest_dir, &["-vV"]);
    verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV output missing a 'host:' line")
        .to_string()
}
