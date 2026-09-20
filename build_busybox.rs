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
// *else* this project's build does (musl, Clang/LLVM, every `userland/*`/`modules/*` crate, the POSIX
// conformance pilot's own manifest generator, ...) -- editing *any* of that unrelated code still
// touches `build.rs`'s own mtime, which made every one of the 256+ already-built applet binaries
// look stale and forced a full ~20-30 minute BusyBox roster rebuild on the next `cargo build`,
// regardless of whether anything BusyBox-relevant actually changed. Included via
// `include!("build_busybox.rs")` at `build.rs`'s own top level (not a separate crate/module --
// keeps every item here directly callable from `main()` with no path prefix, same as before the
// split), with its own explicit `cargo:rerun-if-changed` registration (an `include!`'d file isn't
// automatically watched by cargo the way `build.rs` itself is).

    // BusyBox applets ported to OxideBSD -- see CLAUDE.md's BusyBox section. Each is its own
    // genuinely standalone, single-applet static binary (not a multi-call `busybox` binary
    // dispatching on argv[0], which this codebase's execve doesn't support -- see
    // build_busybox_applet's own doc comment), embedded into oxfs's inode table by build.rs's own
    // oxfs-seeding code further down (originally the FAT32 image, back when FAT32 was still the
    // live filesystem -- see CLAUDE.md's oxfs section). Data-driven (a plain list, not one
    // hand-duplicated block of variables per applet like the original TRUE/ECHO-only version of
    // this function) specifically so adding the next applet is a one-line addition here. Load
    // addresses continue the existing `0x<b|c|d...>00000` sequence every prior userland/BusyBox
    // binary in this codebase already claimed one of (see CLAUDE.md's "User-mode execution"
    // section) -- each must stay clear of every other one already in use.
    //
    // `cat` is the first applet added after `true`/`echo` that actually calls `open()` on a real
    // path -- see CLAUDE.md's musl-port section for the open()/SYS_OPEN argument-convention fix
    // (musl's `open()` is now patched to speak fat32_open's own (path_ptr, path_len, flags) wire
    // format directly) that had to land before this could work at all.
    //
    // "HUSH" (embedded as SH.ELF, not HUSH.ELF -- this codebase's own choice of filename, same as
    // every other applet here) is BusyBox's smaller/simpler shell, not "ASH" -- deliberately:
    // `CONFIG_HUSH_INTERACTIVE` is left off (`allnoconfig`'s own default), so hush just reads and
    // executes commands from stdin like a script, no prompt/readline/job-control machinery that
    // would need real termios/ioctl support this kernel doesn't have. See CLAUDE.md's BusyBox
    // section for what this needed: real pipe(2)/dup2(2) (modules/posix_compat, src/fs/pipe.rs,
    // src/fs/fd.rs), discovered the same iterative "boot and see what's unrecognized" way musl/cat's
    // own new syscalls were.
    // "FALSE"/"YES"/"MORE" continue the same load-address sequence right past HUSH's own
    // 0xe00000. `more`'s own isatty()/TIOCGWINSZ probe hits the same already-documented,
    // confirmed-harmless ioctl gap `cat`'s stdout write path already exercises (see the musl-port
    // section) -- without a real terminal, it just falls back to dumping the whole file, the same
    // shape `cat` already has.
    //
    // The next batch (`mkdir` through `uniq`) directly exercises the syscalls `modules/oxfs` added
    // over `modules/fat32` -- `mkdir`/`rmdir`/`rm`/`mv` map straight onto
    // `mkdir`/`rmdir`/`unlink`/`rename`, all real (`rm`'s directory-recursion mode, `-r`, isn't
    // exercised or expected to work -- it needs `lstat`/`readdir`, neither implemented). `cp`/
    // `touch` may call `fstat`/`utimensat`-family syscalls this kernel doesn't implement at all
    // (unmapped, so a real ENOSYS -- see CLAUDE.md's oxfs section on why `stat`/`fstat` was
    // deliberately skipped) and could misbehave or fail outright depending on how gracefully
    // BusyBox's own code tolerates that; not pre-verified line-by-line, same "boot it and see"
    // discovery process every applet before it went through. `head`/`tail`/`wc`/`cut`/`sort`/
    // `uniq` are plain stdin/stdout/file text tools needing nothing beyond `open`/`read`/`write`/
    // `close`; `basename`/`dirname`/`printf`/`seq` do no filesystem I/O at all beyond `write`ing
    // their result, the same shape `echo`/`true`/`false` already have. `kill` was included once
    // `modules/signal` (see CLAUDE.md) made real process signaling exist -- the gap that had
    // blocked it.
    //
    // Everything from `ADDGROUP` on is a later, much larger pass: once `SYS_STAT`/`SYS_FSTAT`/
    // `SYS_LSTAT`/`SYS_GETDENTS` existed (see CLAUDE.md's oxfs section), an exhaustive per-applet
    // build probe was run against every Kconfig applet symbol BusyBox's own `//applet:` source
    // markers define (393 candidates) using this exact recipe. **"Builds" is a much weaker bar
    // than "works"**: musl provides a fairly complete libc surface, so plenty of applets that make
    // no sense on this kernel (networking, mount, `/proc`-reading, uid/passwd-db tools) still
    // compile and link cleanly -- they just fail cleanly at runtime (usually `ENOSYS` from an
    // unregistered syscall). They're kept anyway (build success is the bar this pass used), but
    // every one is tagged with exactly what it's still missing in `OxideBSD-doc/BUSYBOX_APPLETS.md`, along
    // with the full list -- and reasons -- for every candidate that didn't even build. Load
    // addresses use smaller (`0x40000`, not `0x100000`) steps than the original 24, purely to fit
    // this much larger roster comfortably below `module::MODULE_VA_BASE` (`0x20000000`) -- every
    // applet built so far stays well under 256 KiB. **All of these have moved twice now** from
    // their original, smaller values (`0xb00000`-`0x2200000` for the original 24) once the
    // kernel's own image grew past them, then again -- this array's own base `0x4100000` ->
    // `0x8100000`, `+0x4000000` -- once the POSIX conformance pilot's own full-corpus expansion
    // (see `build.rs`'s `discover_posix_test_files`) grew the kernel image past *that* floor too.
    // See this array's own base and `userland/ring3-smoke/linker.ld`'s doc comment for the full
    // story of why, and how to re-derive the safe floor before trusting any of these numbers
    // again.
    const BUSYBOX_APPLETS: &[(&str, &str, u64)] = &[
        ("TRUE", "true", 0x8100000),
        ("ECHO", "echo", 0x8200000),
        ("CAT", "cat", 0x8300000),
        ("HUSH", "sh", 0x8400000),
        ("FALSE", "false", 0x8500000),
        ("YES", "yes", 0x8600000),
        ("MORE", "more", 0x8700000),
        ("MKDIR", "mkdir", 0x8800000),
        ("RMDIR", "rmdir", 0x8900000),
        ("RM", "rm", 0x8a00000),
        ("MV", "mv", 0x8b00000),
        ("CP", "cp", 0x8c00000),
        ("TOUCH", "touch", 0x8d00000),
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
        ("KILL", "kill", 0x9800000),
    ];

    /// The second pass itself -- see `OxideBSD-doc/BUSYBOX_APPLETS.md` for what every one of these
    /// actually needs at runtime (most need *something* OxideBSD doesn't implement yet; the
    /// doc tags each one) and for the full list of candidates that didn't even build.
    const BUSYBOX_APPLETS_PASS2: &[(&str, &str, u64)] = &[
        ("ADDGROUP", "addgroup", 0x9a00000),
        ("ADDUSER", "adduser", 0x9a40000),
        ("ADJTIMEX", "adjtimex", 0x9a80000),
        ("AR", "ar", 0x9ac0000),
        ("ARP", "arp", 0x9b00000),
        ("ARPING", "arping", 0x9b40000),
        ("ASCII", "ascii", 0x9b80000),
        ("ASH", "ash", 0x9bc0000),
        ("AWK", "awk", 0x9c00000),
        ("BASE32", "base32", 0x9c40000),
        ("BASE64", "base64", 0x9c80000),
        ("BASH_IS_ASH", "bash_ash", 0x9cc0000),
        ("BASH_IS_HUSH", "bash", 0x9d00000),
        ("BBCONFIG", "bbconfig", 0x9d40000),
        ("BB_ARCH", "arch", 0x9d80000),
        ("BB_SYSCTL", "sysctl", 0x9dc0000),
        ("BC", "bc", 0x9e00000),
        ("BOOTCHARTD", "bootchartd", 0x9e80000),
        ("BUNZIP2", "bunzip2", 0x9ec0000),
        ("BZCAT", "bzcat", 0x9f00000),
        ("BZIP2", "bzip2", 0x9f40000),
        ("CAL", "cal", 0x9f80000),
        ("CHAT", "chat", 0x9fc0000),
        ("CHGRP", "chgrp", 0xa040000),
        ("CHMOD", "chmod", 0xa080000),
        ("CHOWN", "chown", 0xa0c0000),
        ("CHPASSWD", "chpasswd", 0xa100000),
        ("CHROOT", "chroot", 0xa140000),
        ("CHRT", "chrt", 0xa180000),
        ("CKSUM", "cksum", 0xa200000),
        ("CLEAR", "clear", 0xa240000),
        ("CMP", "cmp", 0xa280000),
        ("COMM", "comm", 0xa2c0000),
        ("CPIO", "cpio", 0xa300000),
        ("CRC32", "crc32", 0xa340000),
        ("CROND", "crond", 0xa380000),
        ("CRONTAB", "crontab", 0xa3c0000),
        ("CRYPTPW", "cryptpw", 0xe240000),
        ("CTTYHACK", "cttyhack", 0xa400000),
        ("DATE", "date", 0xa440000),
        ("DC", "dc", 0xa480000),
        ("DD", "dd", 0xa4c0000),
        ("DELGROUP", "delgroup", 0xa540000),
        ("DF", "df", 0xa600000),
        ("DHCPRELAY", "dhcprelay", 0xa640000),
        ("DIFF", "diff", 0xa680000),
        ("DMESG", "dmesg", 0xa6c0000),
        ("DNSD", "dnsd", 0xa700000),
        ("DNSDOMAINNAME", "dnsdomainname", 0xa740000),
        ("DOS2UNIX", "dos2unix", 0xa780000),
        ("DPKG", "dpkg", 0xa7c0000),
        ("DPKG_DEB", "dpkg_deb", 0xa800000),
        ("DU", "du", 0xa840000),
        ("DUMPLEASES", "dumpleases", 0xa8c0000),
        ("ED", "ed", 0xa900000),
        ("EGREP", "egrep", 0xa940000),
        ("ENV", "env", 0xa9c0000),
        ("ENVUIDGID", "envuidgid", 0xaa00000),
        ("EXPAND", "expand", 0xaa40000),
        ("EXPR", "expr", 0xaa80000),
        ("FACTOR", "factor", 0xaac0000),
        ("FAKEIDENTD", "fakeidentd", 0xab00000),
        ("FALLOCATE", "fallocate", 0xab40000),
        ("FGREP", "fgrep", 0xacc0000),
        ("FIND", "find", 0xad00000),
        ("FLOCK", "flock", 0xad80000),
        ("FOLD", "fold", 0xadc0000),
        ("FREE", "free", 0xae00000),
        ("FSYNC", "fsync", 0xaf00000),
        ("FTPD", "ftpd", 0xaf40000),
        ("FTPGET", "ftpget", 0xaf80000),
        ("FTPPUT", "ftpput", 0xafc0000),
        ("FUSER", "fuser", 0xb000000),
        ("GETOPT", "getopt", 0xb040000),
        ("GETTY", "getty", 0xb080000),
        ("GREP", "grep", 0xb0c0000),
        ("GROUPS", "groups", 0xb100000),
        ("GUNZIP", "gunzip", 0xb140000),
        ("GZIP", "gzip", 0xb180000),
        ("HALT", "halt", 0xb1c0000),
        ("HEXDUMP", "hexdump", 0xb240000),
        ("HEXEDIT", "hexedit", 0xb280000),
        ("HOSTID", "hostid", 0xb2c0000),
        ("HTTPD", "httpd", 0xb300000),
        ("HWCLOCK", "hwclock", 0xb340000),
        ("IFCONFIG", "ifconfig", 0xb380000),
        ("IFDOWN", "ifdown", 0xb3c0000),
        ("INETD", "inetd", 0xb400000),
        ("INSTALL", "install", 0xb480000),
        ("IOSTAT", "iostat", 0xb4c0000),
        ("IPCALC", "ipcalc", 0xb500000),
        ("KILLALL5", "killall5", 0xb5c0000),
        ("LESS", "less", 0xb640000),
        ("LINK", "link", 0xb680000),
        ("LN", "ln", 0xb740000),
        ("LOGIN", "login", 0xb800000),
        ("LOGNAME", "logname", 0xb840000),
        ("LPD", "lpd", 0xb8c0000),
        ("LPQ", "lpq", 0xb900000),
        ("LPR", "lpr", 0xb940000),
        ("LS", "ls", 0xb980000),
        ("LSOF", "lsof", 0xba00000),
        ("LSPCI", "lspci", 0xba40000),
        ("LSSCSI", "lsscsi", 0xba80000),
        ("LSUSB", "lsusb", 0xbac0000),
        ("LZCAT", "lzcat", 0xbb00000),
        ("LZOP", "lzop", 0xbb40000),
        ("MAKEDEVS", "makedevs", 0xbb80000),
        ("MAKEMIME", "makemime", 0xbbc0000),
        ("MAN", "man", 0xbc00000),
        ("MD5SUM", "md5sum", 0xbc40000),
        ("MINIPS", "minips", 0xbd00000),
        ("MKNOD", "mknod", 0xbdc0000),
        ("MKPASSWD", "mkpasswd", 0xbe00000),
        ("MKTEMP", "mktemp", 0xbe80000),
        ("MOUNT", "mount", 0xbf00000),
        ("MOUNTPOINT", "mountpoint", 0xbf40000),
        ("MPSTAT", "mpstat", 0xbf80000),
        ("NC", "nc", 0xc000000),
        ("NETCAT", "netcat", 0xc040000),
        ("NETSTAT", "netstat", 0xc080000),
        ("NICE", "nice", 0xc0c0000),
        ("NL", "nl", 0xc100000),
        ("NMETER", "nmeter", 0xc140000),
        ("NOHUP", "nohup", 0xc180000),
        ("NPROC", "nproc", 0xc1c0000),
        ("NSLOOKUP", "nslookup", 0xc240000),
        ("NTPD", "ntpd", 0xc280000),
        ("NUKE", "nuke", 0xc2c0000),
        ("OD", "od", 0xc300000),
        ("PASSWD", "passwd", 0xc340000),
        ("PASTE", "paste", 0xc380000),
        ("PATCH", "patch", 0xc3c0000),
        ("PGREP", "pgrep", 0xc400000),
        ("PIDOF", "pidof", 0xc440000),
        ("PING", "ping", 0xc480000),
        ("PIPE_PROGRESS", "pipe_progress", 0xc4c0000),
        ("PKILL", "pkill", 0xc540000),
        ("PMAP", "pmap", 0xc580000),
        ("POPMAILDIR", "popmaildir", 0xc5c0000),
        ("POWEROFF", "poweroff", 0xc600000),
        ("POWERTOP", "powertop", 0xc640000),
        ("PRINTENV", "printenv", 0xc680000),
        ("PSCAN", "pscan", 0xc6c0000),
        ("PSTREE", "pstree", 0xc700000),
        ("PWD", "pwd", 0xc740000),
        ("PWDX", "pwdx", 0xc780000),
        ("RDATE", "rdate", 0xc7c0000),
        ("READLINK", "readlink", 0xc840000),
        ("REALPATH", "realpath", 0xc8c0000),
        ("REFORMIME", "reformime", 0xc900000),
        ("REMOVE_SHELL", "remove", 0xc940000),
        ("RENICE", "renice", 0xc980000),
        ("RESET", "reset", 0xc9c0000),
        ("RESIZE", "resize", 0xca00000),
        ("REV", "rev", 0xca80000),
        ("ROUTE", "route", 0xcac0000),
        ("RPM", "rpm", 0xcb00000),
        ("RPM2CPIO", "rpm2cpio", 0xcb40000),
        ("RTCWAKE", "rtcwake", 0xcb80000),
        ("RUN_PARTS", "run", 0xcc40000),
        ("SED", "sed", 0xcd40000),
        ("SENDMAIL", "sendmail", 0xcd80000),
        ("SETSID", "setsid", 0xcf80000),
        ("SETUIDGID", "setuidgid", 0xcfc0000),
        ("SHA1SUM", "sha1sum", 0xd000000),
        ("SHA256SUM", "sha256sum", 0xd040000),
        ("SHA3SUM", "sha3sum", 0xd080000),
        ("SHA512SUM", "sha512sum", 0xd0c0000),
        ("SHRED", "shred", 0xd100000),
        ("SHUF", "shuf", 0xd140000),
        ("SLEEP", "sleep", 0xd180000),
        ("SMEMCAP", "smemcap", 0xd1c0000),
        ("SOFTLIMIT", "softlimit", 0xd200000),
        ("SPLIT", "split", 0xd240000),
        ("SSL_CLIENT", "ssl_client", 0xd280000),
        ("START_STOP_DAEMON", "start", 0xd2c0000),
        ("STAT", "stat", 0xd300000),
        ("STRINGS", "strings", 0xd340000),
        ("STTY", "stty", 0xd380000),
        ("SU", "su", 0xd3c0000),
        ("SULOGIN", "sulogin", 0xd400000),
        ("SUM", "sum", 0xd440000),
        ("SYNC", "sync", 0xd580000),
        ("TAC", "tac", 0xd600000),
        ("TAR", "tar", 0xd640000),
        ("TASKSET", "taskset", 0xd680000),
        ("TCPSVD", "tcpsvd", 0xd6c0000),
        ("TEE", "tee", 0xd700000),
        ("TELNET", "telnet", 0xd740000),
        ("TELNETD", "telnetd", 0xd780000),
        ("TEST", "test", 0xd7c0000),
        ("TIME", "time", 0xd800000),
        ("TIMEOUT", "timeout", 0xd840000),
        ("TOP", "top", 0xd880000),
        ("TR", "tr", 0xd8c0000),
        ("TRACEROUTE", "traceroute", 0xd900000),
        ("TREE", "tree", 0xd940000),
        ("TRUNCATE", "truncate", 0xd980000),
        ("TS", "ts", 0xd9c0000),
        ("TSORT", "tsort", 0xda00000),
        ("TTY", "tty", 0xda40000),
        ("TTYSIZE", "ttysize", 0xda80000),
        ("UDHCPD", "udhcpd", 0xdac0000),
        ("UDPSVD", "udpsvd", 0xdb00000),
        ("UMOUNT", "umount", 0xdb40000),
        ("UNCOMPRESS", "uncompress", 0xdb80000),
        ("UNEXPAND", "unexpand", 0xdbc0000),
        ("UNIT_TEST", "unit", 0xdc00000),
        ("UNIX2DOS", "unix2dos", 0xdc40000),
        ("UNLINK", "unlink", 0xdc80000),
        ("UNLZMA", "unlzma", 0xdcc0000),
        ("UNXZ", "unxz", 0xdd40000),
        ("UNZIP", "unzip", 0xdd80000),
        ("UPTIME", "uptime", 0xddc0000),
        ("USLEEP", "usleep", 0xde00000),
        ("UUDECODE", "uudecode", 0xde40000),
        ("UUENCODE", "uuencode", 0xde80000),
        ("VCONFIG", "vconfig", 0xdec0000),
        ("VI", "vi", 0xdf00000),
        ("VOLNAME", "volname", 0xdf40000),
        ("WATCH", "watch", 0xdf80000),
        ("WGET", "wget", 0xdfc0000),
        ("WHICH", "which", 0xe000000),
        ("WHOAMI", "whoami", 0xe040000),
        ("WHOIS", "whois", 0xe080000),
        ("XARGS", "xargs", 0xe0c0000),
        ("XXD", "xxd", 0xe100000),
        ("XZCAT", "xzcat", 0xe140000),
        ("ZCAT", "zcat", 0xe180000),
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
        ("HOSTNAME", "hostname", 0xe200000),
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
/// the comment at `third_party/busybox/scripts/kconfig/Makefile:22`: `make allnoconfig`, flip the
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
/// `third_party/busybox`, computed once by the caller -- see `latest_mtime`'s own doc comment --
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
    let busybox_dir = Path::new(manifest_dir).join("third_party/busybox");
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
    // musl's *installed* sysroot headers (`target/musl-sysroot/include/...`, copied out of
    // `third_party/musl` by `build_musl_sysroot`'s own `make install`) as a dependency at all.
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
    // Every applet's config tree can grow a cascade of newly-visible sub-options once its own
    // symbol flips on (not just HUSH's own FEATURE_EDITING/HUSH_INTERACTIVE tree -- see
    // `resolve_busybox_new_config_options`'s own doc comment) once the roster covers ~300 applets
    // instead of two dozen hand-picked ones, so this now runs unconditionally rather than being
    // special-cased to `applet_symbol == "HUSH"`.
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
/// For `HUSH` specifically (only), also flips on real interactive mode -- `CONFIG_HUSH_INTERACTIVE`
/// (prompt + `$-`), `CONFIG_HUSH_JOB` (needed to reach `hush`'s own real `FEATURE_EDITING`
/// initialization at all -- see CLAUDE.md's "Interactive shell" section for the exact code path
/// traced through `shell/hush.c` that makes this true, and why enabling it doesn't actually
/// require real job control to work despite the name: `tcgetpgrp` cleanly failing, via this
/// kernel's own `ENOTTY` for the unimplemented `TIOCGPGRP` request, degrades `hush`'s own job-
/// control setup into a no-op rather than a crash), `CONFIG_FEATURE_EDITING` (real line editing),
/// and `CONFIG_FEATURE_EDITING_FANCY_PROMPT` (a real `$PWD $`-style `PS1`, not a blank prompt).
/// Left off deliberately: `CONFIG_HUSH_SAVEHISTORY`/`CONFIG_FEATURE_EDITING_SAVEHISTORY` (no
/// `HISTFILE` persistence -- in-session history only, one less thing to get right this pass) and
/// `CONFIG_FEATURE_EDITING_WINCH` (nothing in this kernel ever sends `SIGWINCH`, so tracking it
/// would be pure unused surface).
///
/// Also for `HUSH` specifically: a second block of flips (below, in the function body -- see its
/// own comment) turns on real script control flow (`if`/`for`/`while`/`until`/`case`, functions,
/// command substitution, `$((...))` arithmetic, and most of hush's other real builtins). Without
/// these, hush could only run a flat sequence of individual commands -- no control flow at all --
/// since `make allnoconfig` writes an explicit "not set" line for every symbol in the whole
/// Kconfig tree up front (confirmed empirically), so `resolve_busybox_new_config_options`'s later
/// `make oldconfig` pass never gets a chance to apply their real `default y` the way it does for a
/// symbol with no prior answer at all.
///
/// Every other applet stays exactly as narrow as it already was.
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
        // src/syscall/'s stderr fix (fd 2) landed, and even with that fix would have only shown
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
    if applet_symbol == "HUSH" {
        flips.extend([
            (
                "# CONFIG_HUSH_INTERACTIVE is not set".to_string(),
                "CONFIG_HUSH_INTERACTIVE=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_JOB is not set".to_string(),
                "CONFIG_HUSH_JOB=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_EDITING is not set".to_string(),
                "CONFIG_FEATURE_EDITING=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_EDITING_FANCY_PROMPT is not set".to_string(),
                "CONFIG_FEATURE_EDITING_FANCY_PROMPT=y".to_string(),
            ),
        ]);
        // `allnoconfig` writes an explicit "# CONFIG_X is not set" line for every symbol in the
        // whole Kconfig tree, including ones invisible at the time (e.g. everything under
        // `if SHELL_HUSH` while `CONFIG_HUSH` was still off) -- confirmed by grepping an already-
        // built non-shell applet's own `.config` for `CONFIG_FEATURE_SH_MATH` and finding the same
        // "not set" line there too. That's why `resolve_busybox_new_config_options`'s `make
        // oldconfig` pass doesn't help here: oldconfig only prompts for symbols with *no* line at
        // all in `.config`, and every one of these already has an explicit "not set" answer from
        // the initial allnoconfig run -- it never re-evaluates an already-answered symbol against
        // its Kconfig `default`, even after growing newly visible via `CONFIG_HUSH`'s own `select
        // SHELL_HUSH`. Left unflipped, hush had **no real control flow at all**: no `if`/`for`/
        // `while`/`case`, no functions, no command substitution, no `$((...))` arithmetic -- only
        // a flat sequence of individual command lines, which is why `modules/oxfs/src/
        // test_busybox.sh` (see CLAUDE.md's BusyBox section) had to be written as one instead of
        // using any real script control flow. Flipped directly here, the same
        // known-shape-text-replacement way as everything else in this function, rather than
        // relying on oldconfig's default-acceptance (which doesn't apply to these at all).
        //
        // Left off deliberately, matching real upstream `default n`/already-documented reasons:
        // `CONFIG_HUSH_BASH_SOURCE_CURDIR` (explicitly non-standard per its own Kconfig help),
        // `CONFIG_HUSH_MEMLEAK` (debugging only), `CONFIG_HUSH_SAVEHISTORY` (already left off above
        // -- no `HISTFILE` persistence), `CONFIG_FEATURE_SH_STANDALONE` (re-execs `/proc/self/exe`,
        // which doesn't exist on this kernel), `CONFIG_FEATURE_SH_NOFORK` (calls `<applet>_main`
        // directly instead of fork/exec -- meaningless in a single-applet-per-binary build, and a
        // real behavior change if it silently did anything), `CONFIG_FEATURE_SH_EMBEDDED_SCRIPTS`
        // (embeds scripts from a build-time `embed/` directory this codebase doesn't populate --
        // no benefit here).
        flips.extend([
            (
                "# CONFIG_HUSH_BASH_COMPAT is not set".to_string(),
                "CONFIG_HUSH_BASH_COMPAT=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_BRACE_EXPANSION is not set".to_string(),
                "CONFIG_HUSH_BRACE_EXPANSION=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_LINENO_VAR is not set".to_string(),
                "CONFIG_HUSH_LINENO_VAR=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_TICK is not set".to_string(),
                "CONFIG_HUSH_TICK=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_IF is not set".to_string(),
                "CONFIG_HUSH_IF=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_LOOPS is not set".to_string(),
                "CONFIG_HUSH_LOOPS=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_CASE is not set".to_string(),
                "CONFIG_HUSH_CASE=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_FUNCTIONS is not set".to_string(),
                "CONFIG_HUSH_FUNCTIONS=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_LOCAL is not set".to_string(),
                "CONFIG_HUSH_LOCAL=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_RANDOM_SUPPORT is not set".to_string(),
                "CONFIG_HUSH_RANDOM_SUPPORT=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_MODE_X is not set".to_string(),
                "CONFIG_HUSH_MODE_X=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_ECHO is not set".to_string(),
                "CONFIG_HUSH_ECHO=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_PRINTF is not set".to_string(),
                "CONFIG_HUSH_PRINTF=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_TEST is not set".to_string(),
                "CONFIG_HUSH_TEST=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_HELP is not set".to_string(),
                "CONFIG_HUSH_HELP=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_EXPORT is not set".to_string(),
                "CONFIG_HUSH_EXPORT=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_EXPORT_N is not set".to_string(),
                "CONFIG_HUSH_EXPORT_N=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_READONLY is not set".to_string(),
                "CONFIG_HUSH_READONLY=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_KILL is not set".to_string(),
                "CONFIG_HUSH_KILL=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_WAIT is not set".to_string(),
                "CONFIG_HUSH_WAIT=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_COMMAND is not set".to_string(),
                "CONFIG_HUSH_COMMAND=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_TRAP is not set".to_string(),
                "CONFIG_HUSH_TRAP=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_TYPE is not set".to_string(),
                "CONFIG_HUSH_TYPE=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_TIMES is not set".to_string(),
                "CONFIG_HUSH_TIMES=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_READ is not set".to_string(),
                "CONFIG_HUSH_READ=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_SET is not set".to_string(),
                "CONFIG_HUSH_SET=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_UNSET is not set".to_string(),
                "CONFIG_HUSH_UNSET=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_ULIMIT is not set".to_string(),
                "CONFIG_HUSH_ULIMIT=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_UMASK is not set".to_string(),
                "CONFIG_HUSH_UMASK=y".to_string(),
            ),
            (
                "# CONFIG_HUSH_GETOPTS is not set".to_string(),
                "CONFIG_HUSH_GETOPTS=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_MATH is not set".to_string(),
                "CONFIG_FEATURE_SH_MATH=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_MATH_64 is not set".to_string(),
                "CONFIG_FEATURE_SH_MATH_64=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_MATH_BASE is not set".to_string(),
                "CONFIG_FEATURE_SH_MATH_BASE=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_EXTRA_QUIET is not set".to_string(),
                "CONFIG_FEATURE_SH_EXTRA_QUIET=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_READ_FRAC is not set".to_string(),
                "CONFIG_FEATURE_SH_READ_FRAC=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_SH_HISTFILESIZE is not set".to_string(),
                "CONFIG_FEATURE_SH_HISTFILESIZE=y".to_string(),
            ),
        ]);
    }
    if applet_symbol == "LS" {
        // `FEATURE_LS_COLOR`/`FEATURE_LS_COLOR_IS_DEFAULT` (`depends on LS && LONG_OPTS`) all have
        // a real upstream `default y`, same "allnoconfig writes an explicit not-set line before
        // the parent symbol is even visible, so oldconfig never gets a chance to apply the real
        // default" reason as every other flip in this function. Without these, `ls` never colors
        // its output at all, `--color` included -- real Ctrl+C/job-control work landed alongside
        // this (see CLAUDE.md's session/controlling-tty notes) made a working interactive prompt
        // worth actually looking at.
        flips.extend([
            (
                "# CONFIG_LONG_OPTS is not set".to_string(),
                "CONFIG_LONG_OPTS=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_LS_COLOR is not set".to_string(),
                "CONFIG_FEATURE_LS_COLOR=y".to_string(),
            ),
            (
                "# CONFIG_FEATURE_LS_COLOR_IS_DEFAULT is not set".to_string(),
                "CONFIG_FEATURE_LS_COLOR_IS_DEFAULT=y".to_string(),
            ),
        ]);
    }
    if applet_symbol == "TAR" || applet_symbol == "CPIO" || applet_symbol == "AR" {
        // These three archive-creation features (`FEATURE_TAR_CREATE`/`FEATURE_CPIO_O`/
        // `FEATURE_AR_CREATE`) all have a real upstream `default y` -- but that default never
        // applied, for the same root-cause reason CONFIG_HUSH_INTERACTIVE/HUSH_JOB/HUSH_IF/...
        // needed their own explicit flip above: `allnoconfig` writes an explicit "not set" for
        // every symbol in the whole Kconfig tree up front, including ones invisible at the time
        // (`FEATURE_TAR_CREATE` while `CONFIG_TAR` was still off), so the later `oldconfig` pass
        // -- which only prompts for symbols with *no* prior answer at all -- never gets a chance
        // to apply the real default once the parent symbol becomes visible. Found live: a real
        // roster-wide BusyBox self-test (`sh /test_busybox.sh`) hit `tar: unrecognized option: c`
        // and `ar: unrecognized option: r` -- this build's `tar`/`cpio`/`ar` could only extract or
        // list, never actually create an archive, silently defeating half of what each tool is
        // for. Flipped directly here, the same known-shape-text-replacement way as HUSH's own
        // control-flow symbols, rather than relying on oldconfig's default-acceptance (which
        // doesn't apply to any of these either).
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

/// Turning on `CONFIG_HUSH_INTERACTIVE`/`CONFIG_HUSH_JOB`/`CONFIG_FEATURE_EDITING` makes a whole
/// tree of previously-invisible sub-options (`FEATURE_EDITING_MAX_LEN`, `FEATURE_EDITING_HISTORY`,
/// `HUSH_BASH_COMPAT`, ...) newly visible -- Kconfig only ever emits a symbol into `.config` at
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
/// Originally only invoked for `HUSH` itself (`FEATURE_EDITING`/`HUSH_INTERACTIVE`'s own cascade
/// was the only one the original ~24-applet roster ever hit) -- now runs after every applet's
/// `configure_busybox_single_applet` call unconditionally, since a much broader roster (see
/// CLAUDE.md's BusyBox section) hits this same "single symbol flip reveals a whole options
/// sub-tree" shape for plenty of other applets too (anything pulling in its own `FEATURE_*` tree).
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
