//! `gzip(1)`, `gunzip(1)`, `zcat(1)`: compress and expand files in the gzip format.
//!
//! ```text
//! gzip [-123456789cdfhklNnqrtVv] [-S suffix] [file ...]
//! gunzip [-cfhklNnqrtVv] [-S suffix] [file ...]
//! zcat [-fhV] [file ...]
//! ```
//!
//! One binary under four names, dispatched on `argv[0]`: `gunzip` is `gzip -d`, `zcat` (and
//! FreeBSD's `gzcat`) is `gzip -dc`. The options are those of the BSDs' gzip (FreeBSD's is
//! NetBSD's), which are GNU gzip's; DEFLATE itself is OxideBSD's `flate` crate.
//!
//! - A file `f` is replaced by `f.gz` (or `f` + `-S`'s suffix), which keeps its mode, owner
//!   and times; `-k` keeps `f` too, `-c` writes to the standard output and keeps it. With no
//!   file, or `-`, the standard input goes to the standard output.
//! - Expanding, a name must end in a known suffix (`.gz`, `-gz`, `.z`, `-z`, `_z`, `-S`'s;
//!   `.tgz` and `.taz` become `.tar`) unless the output is the standard output. A file may hold
//!   several members, expanded as one; data after the last one is a warning
//!   ("trailing garbage ignored", exit 2), the output being kept.
//! - `-N` (the default when compressing) stores the original name and time in the header; when
//!   expanding it names the output after the stored name, in the input's directory and never
//!   anywhere else (only the stored name's last component counts), and sets the stored time.
//!   `-n` stores neither and, expanding, ignores both (the default when expanding).
//! - `-f` forces: compressed output to a terminal, overwriting without asking, files with other
//!   links; `zcat -f` (`gzip -dcf`) copies input that is not gzip through unchanged.
//! - `-l` lists sizes and ratio, `-t` tests integrity, `-r` descends into directories (their
//!   symbolic links are left alone), `-v` reports each file, `-q` hides warnings.
//! - Options may also come from the `GZIP` environment variable, before the command line's.
//!
//! An interrupted run removes the output file it was writing.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicPtr, Ordering};

use flate::Error as FlateError;
use flate::crc32::Crc32;
use flate::gzip::{GzDecoder, GzEncoder, Header};

const BUF: usize = 64 * 1024;

fn strerror(e: &io::Error) -> String {
    if let Some(n) = e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        return unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned();
    }
    match FlateError::from_io(e) {
        Some(f) => f.to_string(),
        None if e.kind() == io::ErrorKind::UnexpectedEof => "unexpected end of file".into(),
        None => e.to_string(),
    }
}

fn cpath(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_default()
}

fn isatty(fd: i32) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

// --- removing a half-written output on a signal ----------------------------------------------

/// The output file being written, as a leaked C string, or null.
static OUTPUT: AtomicPtr<libc::c_char> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn on_signal(sig: libc::c_int) {
    let p = OUTPUT.swap(std::ptr::null_mut(), Ordering::SeqCst);
    // SAFETY: unlink and _exit are async-signal-safe; p came from CString::into_raw.
    unsafe {
        if !p.is_null() {
            libc::unlink(p);
        }
        libc::_exit(128 + sig);
    }
}

fn set_output(p: Option<&Path>) {
    let new = p.map_or(std::ptr::null_mut(), |p| cpath(p).into_raw());
    let old = OUTPUT.swap(new, Ordering::SeqCst);
    if !old.is_null() {
        // SAFETY: from CString::into_raw, and no longer reachable by the handler.
        drop(unsafe { CString::from_raw(old) });
    }
}

fn catch_signals() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: installing a handler; an ignored signal (nohup) stays ignored.
        unsafe {
            let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            if libc::signal(sig, handler) == libc::SIG_IGN {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }
}

// --- options ---------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Compress,
    Decompress,
    Test,
    List,
}

struct Opts {
    mode: Mode,
    stdout: bool,
    force: bool,
    keep: bool,
    /// -N (Some(true)) or -n (Some(false)); None is each direction's default.
    name: Option<bool>,
    quiet: bool,
    recursive: bool,
    suffix: Option<Vec<u8>>,
    verbose: bool,
    level: u32,
}

impl Opts {
    fn save_name(&self) -> bool {
        self.name.unwrap_or(true)
    }
    fn restore_name(&self) -> bool {
        self.name.unwrap_or(false)
    }
    fn suffix(&self) -> &[u8] {
        self.suffix.as_deref().unwrap_or(b".gz")
    }
}

fn usage(prog: &str) {
    if prog == "zcat" || prog == "gzcat" {
        eprintln!("usage: {prog} [-fhV] [file ...]");
    } else {
        eprintln!("usage: {prog} [-123456789cdfhklNnqrtVv] [-S suffix] [file ...]");
    }
}

fn help(prog: &str) {
    usage(prog);
    eprint!(
        " -1 --fast            fastest (worst) compression\n \
         -2 .. -8             set compression level\n \
         -9 --best            best (slowest) compression\n \
         -c --stdout          write to stdout, keep original files\n    \
            --to-stdout\n \
         -d --decompress      uncompress files\n    \
            --uncompress\n \
         -f --force           force overwriting & compress links\n \
         -h --help            display this help\n \
         -k --keep            don't delete input files during operation\n \
         -l --list            list compressed file contents\n \
         -N --name            save or restore original file name and time stamp\n \
         -n --no-name         don't save original file name or time stamp\n \
         -q --quiet           output no warnings\n \
         -r --recursive       recursively compress files in directories\n \
         -S .suf              use suffix .suf instead of .gz\n    \
            --suffix .suf\n \
         -t --test            test compressed file\n \
         -V --version         display program version\n \
         -v --verbose         print extra statistics\n"
    );
}

enum Parsed {
    Run(Opts, Vec<OsString>),
    Exit(ExitCode),
}

fn parse(prog: &str, args: Vec<OsString>) -> Parsed {
    let mut o = Opts {
        mode: Mode::Compress,
        stdout: false,
        force: false,
        keep: false,
        name: None,
        quiet: false,
        recursive: false,
        suffix: None,
        verbose: false,
        level: 6,
    };
    match prog {
        "gunzip" => o.mode = Mode::Decompress,
        "zcat" | "gzcat" => {
            o.mode = Mode::Decompress;
            o.stdout = true;
        }
        _ => {}
    }
    let mut decompress = o.mode == Mode::Decompress;
    let (mut test, mut list) = (false, false);
    let mut files = Vec::new();
    let mut i = 0;
    let bad = |what: String| {
        eprintln!("{prog}: {what}");
        usage(prog);
        Parsed::Exit(ExitCode::from(1))
    };
    while i < args.len() {
        let a = args[i].as_bytes().to_vec();
        i += 1;
        if a == b"--" {
            files.extend(args[i..].iter().cloned());
            break;
        }
        if a.len() < 2 || a[0] != b'-' {
            files.push(OsString::from_vec(a));
            continue;
        }
        if a.starts_with(b"--") {
            let s = String::from_utf8_lossy(&a[2..]).into_owned();
            let (name, val) = match s.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (s.clone(), None),
            };
            match name.as_str() {
                "fast" => o.level = 1,
                "best" => o.level = 9,
                "stdout" | "to-stdout" => o.stdout = true,
                "decompress" | "uncompress" => decompress = true,
                "force" => o.force = true,
                "help" => {
                    help(prog);
                    return Parsed::Exit(ExitCode::SUCCESS);
                }
                "keep" => o.keep = true,
                "list" => list = true,
                "name" => o.name = Some(true),
                "no-name" => o.name = Some(false),
                "quiet" | "silent" => {
                    o.quiet = true;
                    o.verbose = false;
                }
                "recursive" => o.recursive = true,
                "suffix" => {
                    let v = match val {
                        Some(v) => v.into_bytes(),
                        None if i < args.len() => {
                            i += 1;
                            args[i - 1].as_bytes().to_vec()
                        }
                        None => return bad("option `--suffix' requires an argument".into()),
                    };
                    o.suffix = Some(v);
                }
                "test" => test = true,
                "verbose" => {
                    o.verbose = true;
                    o.quiet = false;
                }
                "version" => {
                    println!("OxideBSD gzip 0.1.0");
                    return Parsed::Exit(ExitCode::SUCCESS);
                }
                _ => return bad(format!("unrecognized option `--{name}'")),
            }
            continue;
        }
        let mut j = 1;
        while j < a.len() {
            let c = a[j];
            j += 1;
            match c {
                b'1'..=b'9' => o.level = u32::from(c - b'0'),
                b'c' => o.stdout = true,
                b'd' => decompress = true,
                b'f' => o.force = true,
                b'h' => {
                    help(prog);
                    return Parsed::Exit(ExitCode::SUCCESS);
                }
                b'k' => o.keep = true,
                b'l' => list = true,
                b'N' => o.name = Some(true),
                b'n' => o.name = Some(false),
                b'q' => {
                    o.quiet = true;
                    o.verbose = false;
                }
                b'r' => o.recursive = true,
                b'S' => {
                    let v = if j < a.len() {
                        let v = a[j..].to_vec();
                        j = a.len();
                        v
                    } else if i < args.len() {
                        i += 1;
                        args[i - 1].as_bytes().to_vec()
                    } else {
                        return bad("option requires an argument -- S".into());
                    };
                    o.suffix = Some(v);
                }
                b't' => test = true,
                b'V' => {
                    println!("OxideBSD gzip 0.1.0");
                    return Parsed::Exit(ExitCode::SUCCESS);
                }
                b'v' => {
                    o.verbose = true;
                    o.quiet = false;
                }
                // FreeBSD's -a (ASCII line ends) and -L (licence) are not provided.
                _ => return bad(format!("illegal option -- {}", c as char)),
            }
        }
    }
    if o.suffix.as_deref() == Some(b"") && !decompress && !test && !list {
        eprintln!("{prog}: incorrect suffix: ''");
        return Parsed::Exit(ExitCode::from(1));
    }
    if o.suffix.as_ref().is_some_and(|s| s.len() > 30 || s.contains(&b'/')) {
        eprintln!("{prog}: incorrect suffix: '{}'", String::from_utf8_lossy(o.suffix.as_ref().unwrap()));
        return Parsed::Exit(ExitCode::from(1));
    }
    o.mode = if list {
        Mode::List
    } else if test {
        Mode::Test
    } else if decompress {
        Mode::Decompress
    } else {
        Mode::Compress
    };
    Parsed::Run(o, files)
}

// --- the work --------------------------------------------------------------------------------

/// A `Write` that counts what passes through it.
struct Count<W> {
    w: W,
    n: u64,
}

impl<W: Write> Write for Count<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.w.write(b)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// Where an I/O error came from: the input (its name is the operand's) or the output.
enum Fail {
    In(io::Error),
    Out(io::Error),
}

/// How a decompression ended when it did not fail outright.
#[derive(PartialEq, Eq)]
enum End {
    Clean,
    Garbage,
}

struct Totals {
    comp: u64,
    uncomp: u64,
    files: u32,
}

struct Run {
    prog: String,
    o: Opts,
    status: u8,
    list_header: bool,
    totals: Totals,
}

fn ratio(small: u64, big: u64) -> String {
    if big == 0 {
        return "  0.0%".into();
    }
    format!("{:5.1}%", 100.0 * (big as f64 - small as f64) / big as f64)
}

fn basename(p: &[u8]) -> &[u8] {
    let t = p.strip_suffix(b"/").unwrap_or(p);
    match t.iter().rposition(|&b| b == b'/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

impl Run {
    fn error(&mut self, msg: impl std::fmt::Display) {
        eprintln!("{}: {msg}", self.prog);
        self.status = 1;
    }

    /// A skipped operand: shown unless -q; still a failure.
    fn warn(&mut self, msg: impl std::fmt::Display) {
        if !self.o.quiet {
            eprintln!("{}: {msg}", self.prog);
        }
        self.status = 1;
    }

    fn garbage(&mut self, what: &str) {
        if !self.o.quiet {
            eprintln!("{}: {what}: trailing garbage ignored", self.prog);
        }
        if self.status == 0 {
            self.status = 2;
        }
    }

    fn report(&mut self, name: &str, f: Fail) {
        match f {
            Fail::In(e) => self.error(format_args!("{name}: {}", strerror(&e))),
            Fail::Out(e) => self.error(format_args!("stdout: {}", strerror(&e))),
        }
    }

    // --- operands ---

    fn operand(&mut self, f: &OsStr) {
        if f == "-" {
            return self.stdin();
        }
        let p = Path::new(f);
        let md = match fs::metadata(p) {
            Ok(m) => m,
            Err(e) => return self.error(format_args!("{}: {}", p.display(), strerror(&e))),
        };
        if md.is_dir() {
            if self.o.recursive {
                return self.walk(p);
            }
            return self.warn(format_args!("{} is a directory", p.display()));
        }
        self.file(p, &md);
    }

    /// -r: every regular file under `dir`; symbolic links are not followed.
    fn walk(&mut self, dir: &Path) {
        let mut names: Vec<PathBuf> = match fs::read_dir(dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
            Err(e) => return self.error(format_args!("{}: {}", dir.display(), strerror(&e))),
        };
        names.sort();
        for p in names {
            match fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => self.walk(&p),
                Ok(m) if m.is_file() => self.file(&p, &m),
                Ok(_) => {}
                Err(e) => self.error(format_args!("{}: {}", p.display(), strerror(&e))),
            }
        }
    }

    fn file(&mut self, p: &Path, md: &fs::Metadata) {
        // Only reading (and -c) may take a FIFO or a device; replacing one makes no sense.
        let reading_only = self.o.stdout || matches!(self.o.mode, Mode::Test | Mode::List);
        if !md.is_file() && !reading_only {
            return self.warn(format_args!("{} is not a regular file -- ignored", p.display()));
        }
        match self.o.mode {
            Mode::Compress => self.compress_file(p, md),
            _ => self.decompress_file(p, md),
        }
    }

    // --- compressing ---

    fn compress_file(&mut self, p: &Path, md: &fs::Metadata) {
        let bytes = p.as_os_str().as_bytes();
        let sfx = self.o.suffix().to_vec();
        if !self.o.stdout && !self.o.force && bytes.len() > sfx.len() && bytes.ends_with(&sfx) {
            return self.warn(format_args!(
                "{} already has {} suffix -- unchanged",
                p.display(),
                String::from_utf8_lossy(&sfx)
            ));
        }
        if !self.o.stdout && !self.o.force && md.nlink() > 1 {
            let n = md.nlink() - 1;
            return self.warn(format_args!(
                "{} has {n} other link{} -- unchanged",
                p.display(),
                if n == 1 { "" } else { "s" }
            ));
        }
        let mut input = match File::open(p) {
            Ok(f) => f,
            Err(e) => return self.error(format_args!("{}: {}", p.display(), strerror(&e))),
        };
        let name = p.display().to_string();
        let mut h = Header::default();
        if self.o.save_name() {
            h.name = Some(basename(bytes).to_vec());
            h.mtime = u32::try_from(md.mtime()).unwrap_or(0);
        }
        if self.o.stdout {
            if !self.o.force && isatty(1) {
                return self.error("standard output is a terminal -- ignoring");
            }
            let out = io::stdout().lock();
            match compress(&mut input, BufWriter::with_capacity(BUF, out), self.o.level, &h) {
                Ok((i, n)) => {
                    if self.o.verbose {
                        eprintln!("{name}:\t{}", ratio(n, i));
                    }
                }
                Err(f) => self.report(&name, f),
            }
            return;
        }
        let mut out_name = bytes.to_vec();
        out_name.extend_from_slice(&sfx);
        let out_path = PathBuf::from(OsString::from_vec(out_name));
        let Some(out) = self.create(&out_path) else { return };
        match compress(&mut input, BufWriter::with_capacity(BUF, &out), self.o.level, &h) {
            Ok((i, n)) => {
                self.finish(p, &out_path, &out, md, None);
                if self.o.verbose {
                    eprintln!("{name}:\t{} -- replaced with {}", ratio(n, i), out_path.display());
                }
            }
            Err(f) => {
                self.abandon(&out_path);
                match f {
                    Fail::In(e) => self.error(format_args!("{name}: {}", strerror(&e))),
                    Fail::Out(e) => self.error(format_args!("{}: {}", out_path.display(), strerror(&e))),
                }
            }
        }
    }

    /// Opens a new output file, asking (on a terminal) or refusing to replace one unless -f.
    fn create(&mut self, out: &Path) -> Option<File> {
        if fs::symlink_metadata(out).is_ok() {
            if !self.o.force {
                if isatty(0) && !self.o.quiet {
                    eprint!("{}: {} already exists -- do you wish to overwrite (y or n)? ", self.prog, out.display());
                    let _ = io::stderr().flush();
                    let mut line = String::new();
                    let _ = io::stdin().lock().read_line(&mut line);
                    if !matches!(line.trim_start().as_bytes().first(), Some(b'y' | b'Y')) {
                        eprintln!("\tnot overwriting");
                        self.status = 1;
                        return None;
                    }
                } else {
                    self.warn(format_args!("{} already exists -- skipping", out.display()));
                    return None;
                }
            }
            if let Err(e) = fs::remove_file(out) {
                self.error(format_args!("{}: {}", out.display(), strerror(&e)));
                return None;
            }
        }
        set_output(Some(out));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(out) {
            Ok(f) => Some(f),
            Err(e) => {
                set_output(None);
                self.error(format_args!("{}: {}", out.display(), strerror(&e)));
                None
            }
        }
    }

    fn abandon(&mut self, out: &Path) {
        let _ = fs::remove_file(out);
        set_output(None);
    }

    /// The output is complete: give it the input's owner, mode and times (the stored time
    /// for `mtime`, with -N), then remove the input unless -k.
    fn finish(&mut self, input: &Path, out_path: &Path, out: &File, md: &fs::Metadata, mtime: Option<i64>) {
        let fd = out.as_raw_fd();
        let mut mode = md.mode() & 0o7777;
        // SAFETY: fchown, fchmod and futimens on an open descriptor.
        unsafe {
            if libc::fchown(fd, md.uid(), md.gid()) != 0 {
                mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
            }
            if libc::fchmod(fd, mode as libc::mode_t) != 0 {
                let e = io::Error::last_os_error();
                self.error(format_args!("{}: {}", out_path.display(), strerror(&e)));
            }
            let ts = [
                libc::timespec { tv_sec: md.atime() as _, tv_nsec: md.atime_nsec() as _ },
                match mtime {
                    Some(t) => libc::timespec { tv_sec: t as _, tv_nsec: 0 },
                    None => libc::timespec { tv_sec: md.mtime() as _, tv_nsec: md.mtime_nsec() as _ },
                },
            ];
            if libc::futimens(fd, ts.as_ptr()) != 0 {
                let e = io::Error::last_os_error();
                self.error(format_args!("{}: {}", out_path.display(), strerror(&e)));
            }
        }
        set_output(None);
        if !self.o.keep
            && let Err(e) = fs::remove_file(input)
        {
            self.error(format_args!("{}: {}", input.display(), strerror(&e)));
        }
    }

    // --- expanding ---

    /// The output name for `p`: its name without a known suffix, or None.
    fn strip_suffix(&self, p: &[u8]) -> Option<Vec<u8>> {
        let base = basename(p);
        let mut list: Vec<(&[u8], &[u8])> = Vec::new();
        if let Some(s) = self.o.suffix.as_deref()
            && !s.is_empty()
        {
            list.push((s, b""));
        }
        list.extend_from_slice(&[
            (b".gz", b""),
            (b"-gz", b""),
            (b".z", b""),
            (b"-z", b""),
            (b"_z", b""),
            (b".tgz", b".tar"),
            (b".taz", b".tar"),
        ]);
        for (s, repl) in list {
            if base.len() > s.len() && base.ends_with(s) {
                let mut v = p[..p.len() - s.len()].to_vec();
                v.extend_from_slice(repl);
                return Some(v);
            }
        }
        None
    }

    fn decompress_file(&mut self, p: &Path, md: &fs::Metadata) {
        let bytes = p.as_os_str().as_bytes();
        let name = p.display().to_string();
        let stem = self.strip_suffix(bytes);
        let to_file = self.o.mode == Mode::Decompress && !self.o.stdout;
        if to_file && stem.is_none() {
            return self.warn(format_args!("{name}: unknown suffix -- ignored"));
        }
        let input = match File::open(p) {
            Ok(f) => f,
            Err(e) => return self.error(format_args!("{name}: {}", strerror(&e))),
        };
        let shown = stem.as_deref().map_or_else(|| name.clone(), |s| String::from_utf8_lossy(s).into_owned());
        match self.o.mode {
            Mode::Test => self.test(input, &name),
            Mode::List => self.list(input, &name, &shown, md.is_file().then(|| md.len())),
            _ if self.o.stdout => self.to_stdout(input, &name),
            _ => self.to_file(p, input, md, stem.unwrap()),
        }
    }

    fn to_file(&mut self, p: &Path, input: File, md: &fs::Metadata, stem: Vec<u8>) {
        let name = p.display().to_string();
        let mut r = BufReader::with_capacity(BUF, input);
        // The header comes first: with -N it names the output.
        let mut d = GzDecoder::new(&mut r);
        let mut buf = vec![0u8; BUF];
        let (first, end) = match d.read(&mut buf) {
            Ok(n) => (n, None),
            Err(e) if FlateError::from_io(&e) == Some(FlateError::TrailingGarbage) => (0, Some(End::Garbage)),
            Err(e) => return self.error(format_args!("{name}: {}", strerror(&e))),
        };
        let mut out_path = PathBuf::from(OsString::from_vec(stem));
        let mut mtime = None;
        if self.o.restore_name()
            && let Some(h) = d.header()
        {
            if let Some(n) = &h.name {
                // Only the last component, and only a real name: never ../x or /etc/x.
                let b = basename(n);
                if !b.is_empty() && b != b"." && b != b".." {
                    let dir = p.parent().unwrap_or(Path::new(""));
                    out_path = dir.join(OsStr::from_bytes(b));
                }
            }
            if h.mtime != 0 {
                mtime = Some(i64::from(h.mtime));
            }
        }
        let Some(out) = self.create(&out_path) else { return };
        let mut w = Count { w: BufWriter::with_capacity(BUF, &out), n: 0 };
        let res = match end {
            Some(e) => Ok(e),
            None => w.write_all(&buf[..first]).map_err(Fail::Out).and_then(|()| pump(&mut d, &mut w, &mut buf)),
        };
        let res = res.and_then(|e| w.flush().map(|()| e).map_err(Fail::Out));
        match res {
            Ok(e) => {
                let written = w.n;
                drop(w);
                if e == End::Garbage {
                    self.garbage(&name);
                }
                self.finish(p, &out_path, &out, md, mtime);
                if self.o.verbose {
                    eprintln!("{name}:\t{} -- replaced with {}", ratio(md.len(), written), out_path.display());
                }
            }
            Err(f) => {
                drop(w);
                self.abandon(&out_path);
                match f {
                    Fail::In(e) => self.error(format_args!("{name}: {}", strerror(&e))),
                    Fail::Out(e) => self.error(format_args!("{}: {}", out_path.display(), strerror(&e))),
                }
            }
        }
    }

    fn to_stdout(&mut self, input: impl Read, name: &str) {
        let mut r = Peek::new(input);
        let out = io::stdout().lock();
        let mut w = BufWriter::with_capacity(BUF, out);
        let res = match r.magic() {
            Err(e) => Err(Fail::In(e)),
            // gzip -dcf / zcat -f: what is not gzip goes through as it is.
            Ok(false) if self.o.force => copy(&mut r, &mut w),
            Ok(_) => {
                let mut b = BufReader::with_capacity(BUF, r);
                let mut d = GzDecoder::new(&mut b);
                pump(&mut d, &mut w, &mut vec![0u8; BUF])
            }
        };
        let res = res.and_then(|e| w.flush().map(|()| e).map_err(Fail::Out));
        match res {
            Ok(End::Clean) => {}
            Ok(End::Garbage) => self.garbage(name),
            Err(f) => self.report(name, f),
        }
    }

    fn test(&mut self, input: impl Read, name: &str) {
        let mut b = BufReader::with_capacity(BUF, input);
        let mut d = GzDecoder::new(&mut b);
        match pump(&mut d, &mut io::sink(), &mut vec![0u8; BUF]) {
            Ok(End::Clean) => {
                if self.o.verbose {
                    eprintln!("{name}:\tOK");
                }
            }
            Ok(End::Garbage) => self.garbage(name),
            Err(f) => self.report(name, f),
        }
    }

    fn list(&mut self, input: impl Read, name: &str, shown: &str, size: Option<u64>) {
        let mut b = BufReader::with_capacity(BUF, CountRead { r: input, n: 0 });
        let mut d = GzDecoder::new(&mut b);
        let mut sink = CrcSink { crc: Crc32::new(), n: 0 };
        let res = pump(&mut d, &mut sink, &mut vec![0u8; BUF]);
        let (mtime, hname) = d.header().map_or((0, None), |h| (h.mtime, h.name.clone()));
        let comp = size.unwrap_or_else(|| b.get_ref().n);
        match res {
            Ok(End::Clean) => {}
            Ok(End::Garbage) => self.garbage(name),
            Err(f) => return self.report(name, f),
        }
        let shown = match hname {
            Some(n) if self.o.restore_name() => String::from_utf8_lossy(basename(&n)).into_owned(),
            _ => shown.to_string(),
        };
        let mut out = io::stdout().lock();
        if !self.list_header {
            self.list_header = true;
            if self.o.verbose {
                let _ = write!(out, "method  crc     date  time  ");
            }
            if !self.o.quiet {
                let _ = writeln!(out, "  compressed uncompressed  ratio uncompressed_name");
            }
        }
        if self.o.verbose {
            let _ = write!(out, "defla {:08x} {} ", sink.crc.value(), stamp(i64::from(mtime)));
        }
        let _ = writeln!(out, "{comp:12} {:12} {} {shown}", sink.n, ratio(comp, sink.n));
        self.totals.comp += comp;
        self.totals.uncomp += sink.n;
        self.totals.files += 1;
    }

    fn list_totals(&mut self) {
        if self.totals.files > 1 {
            let t = &self.totals;
            let mut out = io::stdout().lock();
            if self.o.verbose {
                let _ = write!(out, "                            ");
            }
            let _ = writeln!(out, "{:12} {:12} {} (totals)", t.comp, t.uncomp, ratio(t.comp, t.uncomp));
        }
    }

    // --- the standard input ---

    fn stdin(&mut self) {
        let input = io::stdin().lock();
        match self.o.mode {
            Mode::Compress => {
                if !self.o.force && isatty(1) {
                    return self.error("standard output is a terminal -- ignoring");
                }
                let mut input = input;
                let out = io::stdout().lock();
                match compress(&mut input, BufWriter::with_capacity(BUF, out), self.o.level, &Header::default()) {
                    Ok((i, n)) => {
                        if self.o.verbose {
                            eprintln!("stdin:\t{}", ratio(n, i));
                        }
                    }
                    Err(f) => self.report("stdin", f),
                }
            }
            _ => {
                if !self.o.force && isatty(0) {
                    return self.error("standard input is a terminal -- ignoring");
                }
                match self.o.mode {
                    Mode::Test => self.test(input, "stdin"),
                    Mode::List => self.list(input, "stdin", "stdout", None),
                    _ => self.to_stdout(input, "stdin"),
                }
            }
        }
    }
}

/// "Mon dd hh:mm" in local time, for -lv.
fn stamp(t: i64) -> String {
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // SAFETY: localtime_r fills the tm it is given.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let tt = t as _;
        libc::localtime_r(&tt, &mut tm);
        tm
    };
    format!("{} {:2} {:02}:{:02}", MON[tm.tm_mon.clamp(0, 11) as usize], tm.tm_mday, tm.tm_hour, tm.tm_min)
}

/// Reads the first two bytes of a stream to see whether it is gzip, then gives them back.
struct Peek<R> {
    head: [u8; 2],
    pos: usize,
    len: usize,
    r: R,
}

impl<R: Read> Peek<R> {
    fn new(r: R) -> Self {
        Peek { head: [0; 2], pos: 0, len: 0, r }
    }

    fn magic(&mut self) -> io::Result<bool> {
        while self.len < 2 {
            match self.r.read(&mut self.head[self.len..]) {
                Ok(0) => break,
                Ok(n) => self.len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        // An empty input is not gzip either; without -f, the decoder says it is truncated.
        Ok(self.len == 2 && self.head == [0x1f, 0x8b] || self.len < 2 && self.head[..self.len] == [0x1f][..self.len])
    }
}

impl<R: Read> Read for Peek<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.len {
            let n = (self.len - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.head[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.r.read(buf)
    }
}

struct CountRead<R> {
    r: R,
    n: u64,
}

impl<R: Read> Read for CountRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}

struct CrcSink {
    crc: Crc32,
    n: u64,
}

impl Write for CrcSink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.crc.update(b);
        self.n += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compresses `input` into one member on `out`: (bytes read, bytes written).
fn compress<W: Write>(input: &mut dyn Read, out: W, level: u32, h: &Header) -> Result<(u64, u64), Fail> {
    let enc = GzEncoder::with_header(Count { w: out, n: 0 }, level, h)
        .map_err(|e| Fail::In(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    let mut enc = enc;
    let mut buf = vec![0u8; BUF];
    let mut total = 0u64;
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Fail::In(e)),
        };
        total += n as u64;
        enc.write_all(&buf[..n]).map_err(Fail::Out)?;
    }
    let mut c = enc.finish().map_err(Fail::Out)?;
    c.flush().map_err(Fail::Out)?;
    Ok((total, c.n))
}

/// Decompresses `d` into `w`. A decoder error is an input error.
fn pump(d: &mut impl Read, w: &mut impl Write, buf: &mut [u8]) -> Result<End, Fail> {
    loop {
        match d.read(buf) {
            Ok(0) => return Ok(End::Clean),
            Ok(n) => w.write_all(&buf[..n]).map_err(Fail::Out)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if FlateError::from_io(&e) == Some(FlateError::TrailingGarbage) => return Ok(End::Garbage),
            Err(e) => return Err(Fail::In(e)),
        }
    }
}

fn copy(r: &mut impl Read, w: &mut impl Write) -> Result<End, Fail> {
    let mut buf = vec![0u8; BUF];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(End::Clean),
            Ok(n) => w.write_all(&buf[..n]).map_err(Fail::Out)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Fail::In(e)),
        }
    }
}

fn main() -> ExitCode {
    let mut argv = std::env::args_os();
    let arg0 = argv.next().unwrap_or_else(|| "gzip".into());
    let prog = String::from_utf8_lossy(basename(arg0.as_bytes())).into_owned();
    let prog = match prog.as_str() {
        "gunzip" | "zcat" | "gzcat" => prog,
        _ => "gzip".to_string(),
    };
    // GZIP holds default options, as in every gzip.
    let mut args: Vec<OsString> = std::env::var_os("GZIP")
        .map(|v| {
            v.as_bytes()
                .split(|b| b.is_ascii_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| OsString::from_vec(s.to_vec()))
                .collect()
        })
        .unwrap_or_default();
    args.extend(argv);
    let (o, files) = match parse(&prog, args) {
        Parsed::Run(o, f) => (o, f),
        Parsed::Exit(c) => return c,
    };
    catch_signals();
    let mut run = Run { prog, o, status: 0, list_header: false, totals: Totals { comp: 0, uncomp: 0, files: 0 } };
    if files.is_empty() {
        run.stdin();
    } else {
        for f in &files {
            run.operand(f);
        }
    }
    if run.o.mode == Mode::List {
        run.list_totals();
    }
    if let Err(e) = io::stdout().flush() {
        eprintln!("{}: stdout: {}", run.prog, strerror(&e));
        return ExitCode::from(1);
    }
    ExitCode::from(run.status)
}
