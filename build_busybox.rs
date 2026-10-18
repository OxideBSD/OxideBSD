// `BUSYBOX_APPLETS`/`BUSYBOX_APPLETS_PASS2` and the functions that turn them into real applet
// binaries (`build_busybox_applet`/`configure_busybox_single_applet`/
// `resolve_busybox_new_config_options`) -- split out of `build.rs` itself specifically so this
// file's own mtime, not `build.rs`'s whole-file mtime, is what `build_busybox_applet`'s own
// freshness floor watches.
//
// **Real bug this split fixes, found live**: `build_busybox_applet` used to compare each cached
// applet binary's mtime against `build.rs`'s own mtime as one of three freshness-floor inputs (a
// real, deliberate check -- a load-address or Kconfig-flip change in this file genuinely can
// change what an applet's own binary should contain). But `build.rs` also contains everything
// *else* this project's build does (musl, Clang/LLVM, every `regress/*`/`modules/*` crate, the POSIX
// conformance pilot's own manifest generator, ...) -- editing *any* of that unrelated code still
// touches `build.rs`'s own mtime, which made every one of the 256+ already-built applet binaries
// look stale and forced a full ~20-30 minute BusyBox roster rebuild on the next `cargo build`,
// regardless of whether anything BusyBox-relevant actually changed. Included via
// `include!("build_busybox.rs")` at `build.rs`'s own top level (not a separate crate/module --
// keeps every item here directly callable from `main()` with no path prefix, same as before the
// split), with its own explicit `cargo:rerun-if-changed` registration (an `include!`'d file isn't
// automatically watched by cargo the way `build.rs` itself is).

    // The BusyBox roster (OxideBSD-doc `BUSYBOX_APPLETS.md`, `HIER.md` for where each goes):
    // `(Kconfig symbol, name, load address)`. Each applet is its own standalone static binary
    // (`build_busybox_applet`), not a multi-call `busybox` dispatching on argv[0]. Fixed-address
    // (`-Ttext-segment`): each load address must sit above the kernel's low reservations and below
    // the module region at `0x2000_0000` (CLAUDE.md, Memory). They're kept distinct, at `0x40000`
    // steps (every applet is under 256 KiB). `distrib/install.mtree` installs each one
    // from `OXFS_<NAME>_ELF_PATH`.
    //
    // Editing this file rebuilds every applet (20 to 40 minutes): batch roster changes.
    //
    // Two arrays only for history: the first, small batch, and the second, a probe of every
    // applet that built.
    const BUSYBOX_APPLETS: &[(&str, &str, u64)] = &[
        ("YES", "yes", 0x8600000),
        ("HEAD", "head", 0x8e00000),
        ("TAIL", "tail", 0x8f00000),
        ("WC", "wc", 0x9000000),
        ("BASENAME", "basename", 0x9100000),
        ("DIRNAME", "dirname", 0x9200000),
        ("PRINTF", "printf", 0x9300000),
        ("SEQ", "seq", 0x9400000),
        ("CUT", "cut", 0x9500000),
        ("SORT", "sort", 0x9600000),
        ("UNIQ", "uniq", 0x9700000),
    ];

    /// The second pass itself -- see `OxideBSD-doc/BUSYBOX_APPLETS.md` for what every one of these
    /// actually needs at runtime (most need *something* OxideBSD doesn't implement yet; the
    /// doc tags each one) and for the full list of candidates that didn't even build.
    const BUSYBOX_APPLETS_PASS2: &[(&str, &str, u64)] = &[
        ("AR", "ar", 0x9ac0000),
        ("AWK", "awk", 0x9c00000),
        ("BASE64", "base64", 0x9c80000),
        ("BB_ARCH", "arch", 0x9d80000),
        ("BC", "bc", 0x9e00000),
        ("BUNZIP2", "bunzip2", 0x9ec0000),
        ("BZCAT", "bzcat", 0x9f00000),
        ("BZIP2", "bzip2", 0x9f40000),
        ("CAL", "cal", 0x9f80000),
        ("CHAT", "chat", 0x9fc0000),
        ("CHGRP", "chgrp", 0xa040000),
        ("CHOWN", "chown", 0xa0c0000),
        ("CHROOT", "chroot", 0xa140000),
        ("CKSUM", "cksum", 0xa200000),
        ("CMP", "cmp", 0xa280000),
        ("COMM", "comm", 0xa2c0000),
        ("CPIO", "cpio", 0xa300000),
        ("DC", "dc", 0xa480000),
        ("DIFF", "diff", 0xa680000),
        ("DU", "du", 0xa840000),
        ("ENV", "env", 0xa9c0000),
        ("EXPAND", "expand", 0xaa40000),
        ("FIND", "find", 0xad00000),
        ("FLOCK", "flock", 0xad80000),
        ("FOLD", "fold", 0xadc0000),
        ("FSYNC", "fsync", 0xaf00000),
        ("GETOPT", "getopt", 0xb040000),
        ("GROUPS", "groups", 0xb100000),
        ("HEXDUMP", "hexdump", 0xb240000),
        ("INSTALL", "install", 0xb480000),
        ("LOGNAME", "logname", 0xb840000),
        ("MD5SUM", "md5sum", 0xbc40000),
        ("MKTEMP", "mktemp", 0xbe80000),
        ("NC", "nc", 0xc000000),
        ("NICE", "nice", 0xc0c0000),
        ("NL", "nl", 0xc100000),
        ("NOHUP", "nohup", 0xc180000),
        ("NTPD", "ntpd", 0xc280000),
        ("OD", "od", 0xc300000),
        ("PASTE", "paste", 0xc380000),
        ("PATCH", "patch", 0xc3c0000),
        ("PRINTENV", "printenv", 0xc680000),
        ("READLINK", "readlink", 0xc840000),
        ("RENICE", "renice", 0xc980000),
        ("REV", "rev", 0xca80000),
        ("SHA1SUM", "sha1sum", 0xd000000),
        ("SHA256SUM", "sha256sum", 0xd040000),
        ("SHA512SUM", "sha512sum", 0xd0c0000),
        ("SPLIT", "split", 0xd240000),
        ("SSL_CLIENT", "ssl_client", 0xd280000),
        ("STAT", "stat", 0xd300000),
        ("STRINGS", "strings", 0xd340000),
        ("SUM", "sum", 0xd440000),
        ("TEE", "tee", 0xd700000),
        ("TELNET", "telnet", 0xd740000),
        ("TIME", "time", 0xd800000),
        ("TR", "tr", 0xd8c0000),
        ("TRACEROUTE", "traceroute", 0xd900000),
        ("TRUNCATE", "truncate", 0xd980000),
        ("TSORT", "tsort", 0xda00000),
        ("TTY", "tty", 0xda40000),
        ("UNCOMPRESS", "uncompress", 0xdb80000),
        ("UNEXPAND", "unexpand", 0xdbc0000),
        ("UNXZ", "unxz", 0xdd40000),
        ("UNZIP", "unzip", 0xdd80000),
        ("UPTIME", "uptime", 0xddc0000),
        ("UUDECODE", "uudecode", 0xde40000),
        ("UUENCODE", "uuencode", 0xde80000),
        ("WGET", "wget", 0xdfc0000),
        ("WHICH", "which", 0xe000000),
        ("WHOAMI", "whoami", 0xe040000),
        ("WHOIS", "whois", 0xe080000),
        ("XARGS", "xargs", 0xe0c0000),
        ("XZCAT", "xzcat", 0xe140000),
        // Appended out of alphabetical order (rest of the list above was already full) --
        // `uname -a` needed `SYS_UNAME` (see CLAUDE.md's "BusyBox gap analysis") registered first,
        // so this applet wasn't part of the original exhaustive probe.
        ("UNAME", "uname", 0xe1c0000),
        // Same story as UNAME above: CONFIG_HOSTNAME's own `//applet:` marker sits right next to
        // DNSDOMAINNAME's (already in the roster, tagged NEEDS_NETWORK -- it unconditionally takes
        // hostname.c's DNS-lookup path) but was missed by the original extraction. Unlike
        // dnsdomainname, plain `hostname` (no args, or `-s`) only needs safe_gethostname(), which
        // is just uname() under the hood -- no new syscall required now that SYS_UNAME exists;
        // only its `-d`/`-f`/`-i` flags (real DNS resolution) stay NEEDS_NETWORK.
        // The 2026-10-14 batch (OxideBSD-doc `BUSYBOX_APPLETS.md` §3): BSD base tools nothing else
        // provided (`ipcrm` since went native, with `ipcs`, over the `kern.ipc` sysctls).
        // `who`/`w`/`users`/`wall`/`last` read the utmpx and wtmpx files musl's utmpx(3) and
        // login(1) keep (see `configure_busybox_single_applet`); `ps` replaces `minips`.
        ("ID", "id", 0xe240000),
        ("LAST", "last", 0xe300000),
        ("MESG", "mesg", 0xe340000),
        ("MKFIFO", "mkfifo", 0xe380000),
        ("SCRIPT", "script", 0xe400000),
        ("USERS", "users", 0xe440000),
        ("UUIDGEN", "uuidgen", 0xe480000),
        ("W", "w", 0xe4c0000),
        ("WALL", "wall", 0xe500000),
        ("WHO", "who", 0xe540000),
    ];

    // `BUSYBOX_APPLETS` above is a `&[(&str, &str, u64)]`, not `&[(&str, &str, u64); N]` --
    // `const` slice concatenation isn't expressible without either unstable const-eval tricks or a
    // build-dependency, so the ~300-entry second pass lives in its own array
    // (`BUSYBOX_APPLETS_PASS2`, above) and gets flattened into one iterator at the actual
    // build-loop call site (in `main()`, `build.rs`) instead of at the `const` declaration itself.

/// Cross-builds a single, standalone BusyBox applet (`applet_symbol`, e.g. `"TRUE"`/`"ECHO"` --
/// the exact Kconfig symbol name, confirmed against the vendored source's own `//config:` comments
/// in `coreutils/true.c`/`coreutils/echo.c`) against the musl sysroot `build_musl_sysroot` already
/// produced -- BusyBox's own build system (`make`), not Cargo, the same "shell out to the real
/// toolchain" idiom `build_musl_smoke` already uses for a single `.c` file.
///
/// Follows BusyBox's own documented recipe for a minimal, non-interactive single-applet config --
/// the comment at `external/gpl2/busybox/scripts/kconfig/Makefile:22`: `make allnoconfig`, flip the
/// one applet's config line to `=y` by hand, then build directly. Confirmed empirically (not just
/// followed blindly) that this produces a real `NUM_APPLETS == 1` build -- checked below via
/// `include/NUM_APPLETS.h` -- which is what makes BusyBox's own `main()` (`libbb/appletlib.c`)
/// skip all argv[0]/basename-based applet dispatch entirely and call the applet's `_main` function
/// directly (the `SINGLE_APPLET_MAIN` path). That matters specifically because this codebase's
/// `execve` doesn't pass a real, chosen argv[0] through at all yet (see CLAUDE.md's BusyBox
/// section) -- a multi-applet `busybox` binary relying on argv[0] to pick an applet wouldn't work
/// here at all, but a genuinely single-applet binary doesn't need argv[0] for anything.
///
/// `allnoconfig`'s own defaults also have to be overridden for the "which shell provides `sh`"
/// choice (`SH_IS_ASH` by default, never `SH_IS_NONE`) -- left alone, that default drags in a
/// second applet (`ash`) and `NUM_APPLETS` becomes 2, not 1 (confirmed the hard way; BusyBox's own
/// `make_single_applets.sh` script carries a comment about this exact same trap).
///
/// **Staleness-checked, unlike `build_musl_sysroot`'s own `config.mak`-exists guard**: skips the
/// entire `allnoconfig`/flip/`oldconfig`/`make` sequence if `out_dir`'s own `busybox` binary
/// already exists and is newer than `busybox_source_mtime` (the latest mtime across all of
/// `external/gpl2/busybox`, computed once by the caller -- see `latest_mtime`'s own doc comment --
/// not per applet), `build_busybox.rs` itself (so editing *this file's own recipe* -- flips, load
/// address, applet roster -- invalidates every cached binary too, not just a real source edit),
/// and `musl_sysroot`'s own `libc.a` (every applet links against it, so a musl source edit has to
/// invalidate cached applet binaries too -- missed in an earlier version of this function, which
/// only compared the first two and left every already-built applet silently linked against a
/// stale libc after a musl-side fix).
/// Went from "always regenerate, `allnoconfig` is roughly a second" to this once `BUSYBOX_APPLETS`
/// grew from ~24 entries to ~300 (see CLAUDE.md's BusyBox section): at that scale, "roughly a
/// second" per applet is minutes added to *every* `cargo build`, even when nothing changed.
/// `out_name` is used both for this applet's own `target/busybox-<out_name>` out-of-tree (`O=`)
/// build directory and to describe it in panics; `load_addr` becomes its
/// `-Wl,-Ttext-segment=` link address, which -- like every other userland binary's load base in
/// this codebase -- must stay clear of every other one already claimed.
fn build_busybox_applet(
    applet_symbol: &str,
    out_name: &str,
    load_addr: u64,
    musl_sysroot: &Path,
    busybox_source_mtime: std::time::SystemTime,
) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let busybox_dir = Path::new(manifest_dir).join("external/gpl2/busybox");
    let out_dir = Path::new(manifest_dir).join(format!("target/busybox-{out_name}"));
    let binary_path = out_dir.join("busybox");

    let build_rs_mtime = std::fs::metadata(Path::new(manifest_dir).join("build_busybox.rs"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    // Every applet links against musl_sysroot's own libc.a -- a musl source edit (this branch
    // patches it directly, see CLAUDE.md's musl section) has to invalidate cached applet binaries
    // too, or they keep silently linking a stale libc. Missed once already: a getdents64 fix here
    // rebuilt musl but every already-built applet's cached binary looked "fresh" regardless, since
    // only busybox_source_mtime/build_rs_mtime were ever compared.
    let musl_mtime = std::fs::metadata(musl_sysroot.join("lib/libc.a"))
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::now());
    let freshness_floor = busybox_source_mtime.max(build_rs_mtime).max(musl_mtime);
    if let Ok(modified) = std::fs::metadata(&binary_path).and_then(|m| m.modified())
        && modified >= freshness_floor
    {
        return binary_path;
    }

    // A real, previously-undiscovered bug found live: this staleness check correctly notices
    // when `musl_sysroot`'s own `libc.a` (or busybox's own source, or this file) is newer than
    // `out_dir`'s existing `busybox` binary, but re-running `make allnoconfig` + `make` against
    // that *same, already-populated* `O=` directory doesn't actually guarantee every object file
    // gets recompiled -- BusyBox's own incremental build tracks its own source files, but not
    // musl's *installed* sysroot headers (`toolchain/x86_64-unknown-oxidebsd/include/...`, copied out of
    // `external/mit/musl` by `build_musl_sysroot`'s own `make install`) as a dependency at all.
    // Confirmed live: after a real musl syscall-number fix, `libbb/change_identity.o` inside an
    // already-built applet's own `O=` directory still had a five-day-old mtime predating the fix
    // entirely -- only a handful of this applet's ~177 object files were newer than the changed
    // header, the rest silently relinked from stale, pre-fix objects into a "freshly rebuilt"
    // (by mtime) binary that still ran the old code. A full `rm -rf` of the stale `O=` directory
    // whenever this function's own freshness check decides a rebuild is warranted is the only
    // reliable fix -- trusting BusyBox's own incremental tracking here has already been proven
    // wrong. More expensive than a true incremental rebuild would be, but correctness over speed:
    // this only runs when something genuinely changed, not on every `cargo build`.
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", out_dir.display()));

    let out_arg = format!("O={}", out_dir.display());
    let status = Command::new("make")
        .current_dir(&busybox_dir)
        .arg(&out_arg)
        .arg("allnoconfig")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make allnoconfig for busybox {out_name}: {e}"));
    if !status.success() {
        panic!("busybox allnoconfig for {out_name} failed: {status}");
    }

    configure_busybox_single_applet(&out_dir, applet_symbol);
    // An applet's config tree can grow newly visible sub-options once its own symbol flips on
    // (`resolve_busybox_new_config_options`), so this runs for every applet.
    resolve_busybox_new_config_options(&busybox_dir, &out_arg);

    let musl_gcc = musl_sysroot.join("bin/musl-gcc");
    // `-j1`, not `available_parallelism()`: the real concurrency now comes from building many
    // applets at once (see this function's caller in `main`), not from parallelizing one applet's
    // own handful of source files -- oversubscribing both levels at once (N applets each spawning
    // N compiler jobs) thrashes far more than it helps.
    let status = Command::new("make")
        .current_dir(&busybox_dir)
        .arg(&out_arg)
        .arg(format!("CC={}", compiler_invocation(&musl_gcc).join(" ")))
        .arg(format!(
            "EXTRA_LDFLAGS=-static -no-pie -Wl,-Ttext-segment={load_addr:#x}"
        ))
        .args(["-j", "1"])
        .status()
        .unwrap_or_else(|e| panic!("failed to run make for busybox {out_name}: {e}"));
    if !status.success() {
        panic!("building busybox {out_name} failed: {status}");
    }

    let num_applets_path = out_dir.join("include/NUM_APPLETS.h");
    let num_applets = std::fs::read_to_string(&num_applets_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", num_applets_path.display()));
    assert!(
        num_applets.trim() == "#define NUM_APPLETS 1",
        "busybox {out_name} build produced {:?} ({}), not a standalone single-applet binary -- \
         argv[0]-based applet dispatch would be required, which this codebase's execve doesn't \
         support",
        num_applets.trim(),
        num_applets_path.display()
    );

    out_dir.join("busybox")
}

/// Rewrites the `.config` `make allnoconfig` (in `out_dir`) just produced so exactly one applet
/// (`applet_symbol`) plus `CONFIG_STATIC` are enabled and the `sh`-provider choice is forced to
/// `SH_IS_NONE` (see `build_busybox_applet`'s own doc comment for why) -- by direct text
/// replacement of the exact lines `allnoconfig` is known (confirmed empirically) to produce,
/// rather than shelling out to `sed` as BusyBox's own documented recipe does, so a shape this
/// doesn't expect fails loudly (the `assert!` below) instead of silently doing nothing.
///
fn configure_busybox_single_applet(out_dir: &Path, applet_symbol: &str) {
    let config_path = out_dir.join(".config");
    let mut config = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));
    let mut flips = vec![
        (
            format!("# CONFIG_{applet_symbol} is not set"),
            format!("CONFIG_{applet_symbol}=y"),
        ),
        (
            "# CONFIG_STATIC is not set".to_string(),
            "CONFIG_STATIC=y".to_string(),
        ),
        (
            "CONFIG_SH_IS_ASH=y".to_string(),
            "# CONFIG_SH_IS_ASH is not set".to_string(),
        ),
        (
            "# CONFIG_SH_IS_NONE is not set".to_string(),
            "CONFIG_SH_IS_NONE=y".to_string(),
        ),
        // Real usage text for `--help` (e.g. `cat`'s own "Usage: cat [FILE]... Concatenate
        // FILEs..."), not the generic "No help available." `bb_show_usage` falls back to when
        // this is off -- `allnoconfig` disables both despite their own `default y`, the same way
        // it disables everything else this function already has to flip back on. Discovered as a
        // real gap, not preemptively enabled: `cat.elf --help` printed nothing at all until
        // sys/syscall/'s stderr fix (fd 2) landed, and even with that fix would have only shown
        // the generic fallback without this -- see CLAUDE.md's BusyBox section.
        (
            "# CONFIG_SHOW_USAGE is not set".to_string(),
            "CONFIG_SHOW_USAGE=y".to_string(),
        ),
        (
            "# CONFIG_FEATURE_VERBOSE_USAGE is not set".to_string(),
            "CONFIG_FEATURE_VERBOSE_USAGE=y".to_string(),
        ),
    ];
    if applet_symbol == "UNAME" {
        // `allnoconfig` emits `CONFIG_UNAME_OSNAME=""` (the string option's own Kconfig `default
        // "GNU/Linux"` doesn't apply while `depends on UNAME` is unsatisfied -- confirmed by
        // reading an already-built applet's generated `.config`) -- overridden here so `uname -a`'s
        // trailing `-o`/`--all` field reads "OxideBSD" instead of either the empty string or
        // BusyBox's own Linux-flavored default.
        flips.push((
            "CONFIG_UNAME_OSNAME=\"\"".to_string(),
            "CONFIG_UNAME_OSNAME=\"OxideBSD\"".to_string(),
        ));
    }
    if applet_symbol == "TAR" || applet_symbol == "CPIO" || applet_symbol == "AR" {
        // These three archive-creation features (`FEATURE_TAR_CREATE`/`FEATURE_CPIO_O`/
        // `FEATURE_AR_CREATE`) all have a real upstream `default y` -- but that default never
        // applied: `allnoconfig` writes an explicit "not set" for
        // every symbol in the whole Kconfig tree up front, including ones invisible at the time
        // (`FEATURE_TAR_CREATE` while `CONFIG_TAR` was still off), so the later `oldconfig` pass
        // -- which only prompts for symbols with *no* prior answer at all -- never gets a chance
        // to apply the real default once the parent symbol becomes visible. Found live: a real
        // roster-wide BusyBox self-test (`sh /test_busybox.sh`) hit `tar: unrecognized option: c`
        // and `ar: unrecognized option: r` -- this build's `tar`/`cpio`/`ar` could only extract or
        // list, never actually create an archive, silently defeating half of what each tool is
        // for. Flipped directly here, by the same text replacement as the applet's own symbol,
        // rather than relying on oldconfig's default-acceptance (which doesn't apply to these).
        flips.push(match applet_symbol {
            "TAR" => (
                "# CONFIG_FEATURE_TAR_CREATE is not set".to_string(),
                "CONFIG_FEATURE_TAR_CREATE=y".to_string(),
            ),
            "CPIO" => (
                "# CONFIG_FEATURE_CPIO_O is not set".to_string(),
                "CONFIG_FEATURE_CPIO_O=y".to_string(),
            ),
            _ => (
                "# CONFIG_FEATURE_AR_CREATE is not set".to_string(),
                "CONFIG_FEATURE_AR_CREATE=y".to_string(),
            ),
        });
    }
    if applet_symbol == "PING" {
        // Same root cause, same fix, as the TAR/CPIO/AR block above -- `FEATURE_FANCY_PING` also
        // has a real upstream `default y` that never applied. Without it, this build's `ping` uses
        // BusyBox's "mini ping" implementation instead, which has no real flag parsing at all (not
        // even `getopt`) -- found live: `ping -c 1 10.0.2.2` failed `ping: bad address '-c'`,
        // mini-ping's own argv[1]-is-the-target logic trying to resolve the literal string "-c" as
        // a hostname. Fancy ping is what every real invocation in this port's roster (and this
        // project's own test script) actually assumes.
        flips.push((
            "# CONFIG_FEATURE_FANCY_PING is not set".to_string(),
            "CONFIG_FEATURE_FANCY_PING=y".to_string(),
        ));
    }
    if matches!(applet_symbol, "WHO" | "W" | "USERS" | "WALL" | "LAST") {
        // They depend on `FEATURE_UTMP` (`last` on `FEATURE_WTMP` too), real upstream `default y`
        // that never applies, the TAR/CPIO/AR block's root cause. musl's utmpx(3) here is real
        // (OxideBSD-doc `LOGIN.md` §8), so the files have records to read.
        flips.push((
            "# CONFIG_FEATURE_UTMP is not set".to_string(),
            "CONFIG_FEATURE_UTMP=y".to_string(),
        ));
        if applet_symbol == "LAST" {
            flips.push((
                "# CONFIG_FEATURE_WTMP is not set".to_string(),
                "CONFIG_FEATURE_WTMP=y".to_string(),
            ));
        }
    }
    if applet_symbol == "SCRIPT" {
        // Without `FEATURE_DEVPTS` (upstream `default y`, never applied: the TAR/CPIO/AR root
        // cause) `xgetpty` scans old BSD `/dev/ptyXX` names; with it, `posix_openpt` opens
        // `/dev/ptmx`, the only pty interface OxideBSD has. Found live: "can't find free pty".
        flips.push((
            "# CONFIG_FEATURE_DEVPTS is not set".to_string(),
            "CONFIG_FEATURE_DEVPTS=y".to_string(),
        ));
    }
    if applet_symbol == "WGET" {
        // BusyBox ships its own self-contained minimal TLS 1.2 client (networking/tls.c) --
        // enabling it needs no external crypto library port (CONFIG_FEATURE_WGET_OPENSSL, left
        // off, would need one). Without this, wget can only speak plain HTTP -- useless against
        // GitHub, which redirects/refuses everything but HTTPS (github.com,
        // raw.githubusercontent.com, codeload.github.com all require it).
        flips.extend([
            (
                "# CONFIG_TLS is not set".to_string(),
                "CONFIG_TLS=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_WGET_HTTPS is not set".to_string(),
                "CONFIG_FEATURE_WGET_HTTPS=y".to_string(),
            ),
        ]);
    }
    for (from, to) in flips {
        assert!(
            config.contains(&from),
            "busybox .config for {applet_symbol} is missing the expected line {from:?} -- \
             allnoconfig's output shape may have changed"
        );
        config = config.replacen(&from, &to, 1);
    }
    std::fs::write(&config_path, config)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", config_path.display()));
}

/// Turning on an applet (or one of its features) can make a tree of previously invisible
/// sub-options (`FEATURE_EDITING_MAX_LEN`, `FEATURE_EDITING_HISTORY`, ...) newly visible -- Kconfig only ever emits a symbol into `.config` at
/// `allnoconfig` time if its own dependencies are already satisfied, so none of these existed as
/// lines `configure_busybox_single_applet`'s direct text-replacement approach could edit at all.
/// The normal build's own internal `silentoldconfig` step refuses to guess a default for a
/// genuinely new `int`/`string` option when stdin isn't a real terminal (`Console input/output is
/// redirected` -- a real failure hit and diagnosed live, not a hypothetical), so this runs an
/// explicit `make oldconfig` first, with stdin fed a large supply of blank lines (`\n`, matching
/// what pressing Enter at every prompt would do) rather than closed/`/dev/null` -- confirmed
/// empirically that `/dev/null` (immediate EOF) still hits the exact same "NEW... " hard failure
/// for `int`-typed options specifically (bool prompts alone tolerate EOF fine), while a live
/// stream of blank lines lets `conf` walk through and accept every prompt's own Kconfig-declared
/// default, `int`/`string` ones included, right through to a clean exit.
///
/// Runs after every applet's `configure_busybox_single_applet`: many applets pull in their own
/// `FEATURE_*` sub-tree when their symbol flips on.
/// Cheap to run even when there's nothing new to resolve -- `conf` just exits quickly once no
/// prompt remains unanswered.
fn resolve_busybox_new_config_options(busybox_dir: &Path, out_arg: &str) {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("make")
        .current_dir(busybox_dir)
        .arg(out_arg)
        .arg("oldconfig")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run make oldconfig for busybox applet: {e}"));

    // A generous supply of "just press Enter" answers -- bounded (this config tree has, at most,
    // a few hundred prompts), written then dropped (closing the pipe) so `conf` sees EOF only
    // once every real prompt it could possibly ask has already been answered.
    let mut stdin = child.stdin.take().expect("child stdin was piped");
    let blank_lines = "\n".repeat(10_000);
    // A child process reading slower than this writes can deadlock a pipe write once the OS
    // buffer fills -- write from a separate thread so this function's own main-thread `wait()`
    // below can keep draining the child's stdout/stderr concurrently rather than blocking on it.
    std::thread::spawn(move || {
        let _ = stdin.write_all(blank_lines.as_bytes());
    });

    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("failed to wait for busybox oldconfig: {e}"));
    if !output.status.success() {
        panic!(
            "busybox oldconfig failed: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
