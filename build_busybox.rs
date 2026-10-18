// The BusyBox roster and the build that makes one multi-call binary of it, split out of
// `build.rs` so that editing the rest of `build.rs` doesn't rebuild BusyBox: this file's own
// mtime is one of the build's freshness inputs (`include!`d at `build.rs`'s top level, with its
// own `cargo:rerun-if-changed`).

/// The BusyBox roster (OxideBSD-doc `BUSYBOX_APPLETS.md`; `HIER.md` for where each goes):
/// `(Kconfig symbol, name)`. All of them are one binary, `/usr/libexec/busybox`, a dynamic PIE
/// on `/lib/libc.so` like the rest of `/usr`; `distrib/install.mtree` gives it a hard link per
/// name, and BusyBox picks the applet from `argv[0]`. Editing this file rebuilds BusyBox
/// (several minutes): batch roster changes.
const BUSYBOX_APPLETS: &[(&str, &str)] = &[
    ("AR", "ar"),
    ("BB_ARCH", "arch"),
    ("AWK", "awk"),
    ("BASE64", "base64"),
    ("BASENAME", "basename"),
    ("BC", "bc"),
    ("BUNZIP2", "bunzip2"),
    ("BZCAT", "bzcat"),
    ("BZIP2", "bzip2"),
    ("CAL", "cal"),
    ("CHAT", "chat"),
    ("CHGRP", "chgrp"),
    ("CHOWN", "chown"),
    ("CHROOT", "chroot"),
    ("CKSUM", "cksum"),
    ("CMP", "cmp"),
    ("COMM", "comm"),
    ("CPIO", "cpio"),
    ("CUT", "cut"),
    ("DC", "dc"),
    ("DIFF", "diff"),
    ("DIRNAME", "dirname"),
    ("DU", "du"),
    ("ENV", "env"),
    ("EXPAND", "expand"),
    ("FIND", "find"),
    ("FLOCK", "flock"),
    ("FOLD", "fold"),
    ("FSYNC", "fsync"),
    ("GETOPT", "getopt"),
    ("GROUPS", "groups"),
    ("HEAD", "head"),
    ("HEXDUMP", "hexdump"),
    ("ID", "id"),
    ("INSTALL", "install"),
    ("LAST", "last"),
    ("LOGNAME", "logname"),
    ("MD5SUM", "md5sum"),
    ("MESG", "mesg"),
    ("MKFIFO", "mkfifo"),
    ("MKTEMP", "mktemp"),
    ("NC", "nc"),
    ("NICE", "nice"),
    ("NL", "nl"),
    ("NOHUP", "nohup"),
    ("NTPD", "ntpd"),
    ("OD", "od"),
    ("PASTE", "paste"),
    ("PATCH", "patch"),
    ("PRINTENV", "printenv"),
    ("PRINTF", "printf"),
    ("READLINK", "readlink"),
    ("RENICE", "renice"),
    ("REV", "rev"),
    ("SCRIPT", "script"),
    ("SEQ", "seq"),
    ("SHA1SUM", "sha1sum"),
    ("SHA256SUM", "sha256sum"),
    ("SHA512SUM", "sha512sum"),
    ("SORT", "sort"),
    ("SPLIT", "split"),
    ("SSL_CLIENT", "ssl_client"),
    ("STAT", "stat"),
    ("STRINGS", "strings"),
    ("SUM", "sum"),
    ("TAIL", "tail"),
    ("TEE", "tee"),
    ("TELNET", "telnet"),
    ("TIME", "time"),
    ("TR", "tr"),
    ("TRACEROUTE", "traceroute"),
    ("TRUNCATE", "truncate"),
    ("TSORT", "tsort"),
    ("TTY", "tty"),
    ("UNAME", "uname"),
    ("UNCOMPRESS", "uncompress"),
    ("UNEXPAND", "unexpand"),
    ("UNIQ", "uniq"),
    ("UNXZ", "unxz"),
    ("UNZIP", "unzip"),
    ("UPTIME", "uptime"),
    ("USERS", "users"),
    ("UUDECODE", "uudecode"),
    ("UUENCODE", "uuencode"),
    ("UUIDGEN", "uuidgen"),
    ("W", "w"),
    ("WALL", "wall"),
    ("WC", "wc"),
    ("WGET", "wget"),
    ("WHICH", "which"),
    ("WHO", "who"),
    ("WHOAMI", "whoami"),
    ("WHOIS", "whois"),
    ("XARGS", "xargs"),
    ("XZCAT", "xzcat"),
    ("YES", "yes"),
];

/// Builds the roster (`BUSYBOX_APPLETS`) as one multi-call BusyBox, against the musl sysroot,
/// in its own out-of-tree directory (`target/busybox`), and returns the binary.
///
/// BusyBox's own recipe for a chosen set of applets: `make allnoconfig`, turn each one on in
/// `.config` (`configure_busybox`), `make oldconfig` for the options that turning them on made
/// visible, then `make`. The build is skipped while the binary is newer than BusyBox's sources
/// (`busybox_source_mtime`, from the caller), this file, and the sysroot's `libc.a`; a rebuild
/// starts from an empty directory, since BusyBox's makefiles don't track musl's installed
/// headers (an incremental build once relinked objects compiled against an older musl).
fn build_busybox(musl_sysroot: &Path, busybox_source_mtime: std::time::SystemTime) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let busybox_dir = Path::new(manifest_dir).join("external/gpl2/busybox");
    let out_dir = Path::new(manifest_dir).join("target/busybox");
    let binary_path = out_dir.join("busybox");

    let mtime = |p: &Path| {
        std::fs::metadata(p).and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::now())
    };
    let freshness_floor = busybox_source_mtime
        .max(mtime(&Path::new(manifest_dir).join("build_busybox.rs")))
        .max(mtime(&musl_sysroot.join("lib/libc.a")));
    if let Ok(modified) = std::fs::metadata(&binary_path).and_then(|m| m.modified())
        && modified >= freshness_floor
    {
        return binary_path;
    }

    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", out_dir.display()));
    let out_arg = format!("O={}", out_dir.display());
    let status = Command::new("make")
        .current_dir(&busybox_dir)
        .arg(&out_arg)
        .arg("allnoconfig")
        .status()
        .unwrap_or_else(|e| panic!("failed to run make allnoconfig for busybox: {e}"));
    if !status.success() {
        panic!("busybox allnoconfig failed: {status}");
    }
    configure_busybox(&out_dir);
    resolve_busybox_new_config_options(&busybox_dir, &out_arg);

    let musl_gcc = musl_sysroot.join("bin/musl-gcc");
    let status = Command::new("make")
        .current_dir(&busybox_dir)
        .arg(&out_arg)
        .arg(format!("CC={}", compiler_invocation(&musl_gcc).join(" ")))
        .args(["-j", &build_jobs().to_string()])
        .status()
        .unwrap_or_else(|e| panic!("failed to run make for busybox: {e}"));
    if !status.success() {
        panic!("building busybox failed: {status}");
    }

    // Every roster entry became an applet, and nothing else did (an option's default can drag
    // one in: `SH_IS_ASH`, below).
    let num_applets_path = out_dir.join("include/NUM_APPLETS.h");
    let num_applets = std::fs::read_to_string(&num_applets_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", num_applets_path.display()));
    let want = format!("#define NUM_APPLETS {}", BUSYBOX_APPLETS.len());
    assert!(
        num_applets.trim() == want,
        "busybox built {:?}, not the roster's {} applets ({})",
        num_applets.trim(),
        BUSYBOX_APPLETS.len(),
        num_applets_path.display()
    );
    binary_path
}

/// Rewrites the `.config` `make allnoconfig` (in `out_dir`) produced: every roster applet on,
/// a PIE, no shell (`SH_IS_ASH`, the default, would add `ash`: `/bin/sh` is OxideBSD's own), the
/// usage texts, and the features below. The lines are replaced by exact text, so a change in
/// `allnoconfig`'s output fails the build instead of passing unnoticed.
///
/// A feature whose Kconfig default is `y` still has to be turned on by hand when its applet is:
/// `allnoconfig` writes "not set" for every symbol, visible or not, and `oldconfig` asks only
/// about symbols with no answer yet.
fn configure_busybox(out_dir: &Path) {
    let config_path = out_dir.join(".config");
    let mut config = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));
    let on = |symbol: &str| (format!("# CONFIG_{symbol} is not set"), format!("CONFIG_{symbol}=y"));
    let mut flips: Vec<(String, String)> = BUSYBOX_APPLETS.iter().map(|&(symbol, _)| on(symbol)).collect();
    flips.extend([
        on("PIE"),
        ("CONFIG_SH_IS_ASH=y".to_string(), "# CONFIG_SH_IS_ASH is not set".to_string()),
        on("SH_IS_NONE"),
        // `--help` prints the applet's usage, not "No help available".
        on("SHOW_USAGE"),
        on("FEATURE_VERBOSE_USAGE"),
        // `uname -o` says OxideBSD (allnoconfig leaves it empty).
        ("CONFIG_UNAME_OSNAME=\"\"".to_string(), "CONFIG_UNAME_OSNAME=\"OxideBSD\"".to_string()),
        // cpio and ar create archives, not only list and extract them.
        on("FEATURE_CPIO_O"),
        on("FEATURE_AR_CREATE"),
        // who, w, users, wall and last read utmpx and wtmpx (musl's utmpx(3), LOGIN.md §8).
        on("FEATURE_UTMP"),
        on("FEATURE_WTMP"),
        // script opens /dev/ptmx (posix_openpt), not BSD /dev/ptyXX names.
        on("FEATURE_DEVPTS"),
        // wget speaks HTTPS with BusyBox's own TLS client (networking/tls.c).
        on("TLS"),
        on("FEATURE_WGET_HTTPS"),
    ]);
    for (from, to) in flips {
        assert!(
            config.contains(&from),
            "busybox .config is missing the expected line {from:?}: allnoconfig's output shape \
             may have changed"
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
