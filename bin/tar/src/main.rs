//! `tar(1)`: create, list, update and extract tape archives.
//!
//! ```text
//! tar {-c | -r | -t | -u | -x} [-aHhkLmnOoPpqUvz] [-b blocks] [-C dir] [-f archive]
//!     [-s /old/new/[gpHRS]] [-T file] [-X file] [--exclude pattern] [--zstd] [file | pattern ...]
//! ```
//!
//! OxideBSD's own tar, after bsdtar (FreeBSD's, and the BSDs' common ground with OpenBSD's and
//! NetBSD's): the same options and messages, ustar archives with pax extended headers only for
//! what ustar cannot hold, and the same safe defaults when extracting.
//!
//! - The first argument may be old-style bundled options without a `-` (`tar xvf a.tar`); the
//!   arguments of `b`, `C`, `f`, `I`, `s`, `T`, `X` among them follow it in order.
//! - With no `-f`, the archive is `$TAPE`, else the standard input or output. (The BSDs' default
//!   is a tape drive, `/dev/sa0` or `/dev/rst0`; OxideBSD has none.)
//! - `-z` compresses with gzip and `--zstd` with zstd(1); reading, the compression is recognised
//!   from the data and `-z` is not needed. bzip2 (`-j`), xz (`-J`) and compress (`-Z`) are not
//!   supported. `-a` picks the compression from the archive's name.
//! - `-C dir` among the file operands of `-c`, `-r` and `-u` changes directory before the files
//!   after it, as in bsdtar.
//!
//! Extraction assumes a hostile archive (bsdtar's `SECURE_*` defaults): leading `/` is removed
//! and a name with a `..` component is refused unless `-P`; every directory on the way to a
//! member is opened without following symbolic links (`O_NOFOLLOW`), so nothing is ever written
//! through a link the archive (or anyone) planted, again unless `-P`; an existing file is
//! removed, never written through, before its replacement is created exclusively. Owners are
//! restored, and permissions kept whole, only for root (or with `-p`), and set-user-ID and
//! set-group-ID bits only where the owner could be set. Listings show control characters in
//! names as octal escapes, so a name cannot drive the terminal.

mod archive;
mod create;
mod extract;
mod header;
mod pattern;

use std::ffi::{CStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::ExitCode;

use archive::Comp;
use header::Format;
use pattern::Subst;

pub fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

/// A name for messages and listings: printable ASCII and UTF-8 as they are, anything else
/// (control characters, invalid bytes) as `\ooo`, a backslash as `\\`.
pub fn shown(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    for chunk in name.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                c if c.is_control() => {
                    let mut b = [0u8; 4];
                    for x in c.encode_utf8(&mut b).bytes() {
                        out.push_str(&format!("\\{x:03o}"));
                    }
                }
                c => out.push(c),
            }
        }
        for &x in chunk.invalid() {
            out.push_str(&format!("\\{x:03o}"));
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Create,
    Append,
    List,
    Update,
    Extract,
}

/// One operand, in order: a name (a file to add, or a pattern to select) or a `-C dir`.
#[derive(Clone, Debug)]
pub enum Operand {
    Name(Vec<u8>),
    Chdir(Vec<u8>),
}

pub struct Opts {
    pub mode: Mode,
    pub file: OsString,
    pub verbose: u32,
    pub comp: Comp,
    pub auto_comp: bool,
    pub chdir: Vec<Vec<u8>>,
    pub preserve_perms: bool,
    pub same_owner: bool,
    pub numeric_owner: bool,
    pub no_mtime: bool,
    pub keep_old: bool,
    pub follow: bool,
    pub follow_cmdline: bool,
    pub absolute: bool,
    pub to_stdout: bool,
    pub no_recurse: bool,
    pub fast_read: bool,
    pub excludes: Vec<Vec<u8>>,
    pub subst: Vec<Subst>,
    pub format: Format,
    pub record: usize,
    pub strip: usize,
    pub null: bool,
    pub files_from: Vec<OsString>,
    pub exclude_from: Vec<OsString>,
    pub operands: Vec<Operand>,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: tar {{-c | -r | -t | -u | -x}} [-aHhkLmnOoPpqUvz] [-b blocks] [-C dir]\n           \
         [-f archive] [-s /old/new/[gpHRS]] [-T file] [-X file] [--exclude pattern]\n           \
         [--zstd] [file | pattern ...]"
    );
    ExitCode::from(1)
}

fn help() -> ExitCode {
    print!(
        "OxideBSD tar: manipulate archive files\n\
         First option must be a mode specifier:\n  \
         -c Create  -r Add/Replace  -t List  -u Update  -x Extract\n\
         Common Options:\n  \
         -b #  Use # 512-byte records per I/O block\n  \
         -f <filename>  Location of archive (default: $TAPE or stdin/stdout)\n  \
         -v    Verbose\n  \
         -w    Interactive (not supported)\n\
         Create: tar -c [options] [<file> | <dir> | -C <dir> ]\n  \
         <file>, <dir>  add these items to archive\n  \
         -z, --zstd  Compress archive with gzip/zstd\n  \
         -a    Choose the compression from the archive's suffix\n  \
         --format {{ustar|pax|restricted}}  Select archive format\n  \
         --exclude <pattern>  Skip files that match pattern\n  \
         -C <dir>  Change to <dir> before processing remaining files\n  \
         -s /old/new/  Rename members (basic regular expressions)\n\
         List: tar -t [options] [<patterns>]\n  \
         <patterns>  If specified, list only entries that match\n\
         Extract: tar -x [options] [<patterns>]\n  \
         <patterns>  If specified, extract only entries that match\n  \
         -k    Keep (don't overwrite) existing files\n  \
         -m    Don't restore modification times\n  \
         -O    Write entries to stdout, don't restore to disk\n  \
         -p    Restore permissions (including ACLs, owner, file flags)\n  \
         -P    Allow absolute paths, '..' and extraction through symlinks\n"
    );
    ExitCode::SUCCESS
}

/// Short options that take an argument.
fn takes_arg(c: u8) -> bool {
    matches!(c, b'b' | b'C' | b'f' | b'I' | b's' | b'T' | b'X')
}

fn bad(msg: &str) -> Result<Opts, ExitCode> {
    eprintln!("tar: {msg}");
    Err(usage())
}

fn set_mode(o: &mut Option<Mode>, m: Mode, c: char) -> Result<(), String> {
    let name = |m: Mode| match m {
        Mode::Create => 'c',
        Mode::Append => 'r',
        Mode::List => 't',
        Mode::Update => 'u',
        Mode::Extract => 'x',
    };
    match *o {
        Some(old) if old != m => Err(format!("Can't specify both -{} and -{c}", name(old))),
        _ => {
            *o = Some(m);
            Ok(())
        }
    }
}

fn parse(mut args: Vec<Vec<u8>>) -> Result<Opts, ExitCode> {
    // Old-style bundled options: the first argument, without a dash.
    if let Some(first) = args.first()
        && !first.is_empty()
        && first[0] != b'-'
    {
        let first = args.remove(0);
        let mut rest = args.into_iter();
        let mut new = Vec::new();
        for &c in &first {
            new.push(vec![b'-', c]);
            if takes_arg(c) {
                match rest.next() {
                    Some(a) => new.push(a),
                    None => return bad(&format!("Option {} requires an argument", c as char)),
                }
            }
        }
        new.extend(rest);
        args = new;
    }
    let uid0 = unsafe { libc::geteuid() } == 0;
    let mut o = Opts {
        mode: Mode::List,
        file: std::env::var_os("TAPE").unwrap_or_else(|| "-".into()),
        verbose: 0,
        comp: Comp::None,
        auto_comp: false,
        chdir: Vec::new(),
        preserve_perms: uid0,
        same_owner: uid0,
        numeric_owner: false,
        no_mtime: false,
        keep_old: false,
        follow: false,
        follow_cmdline: false,
        absolute: false,
        to_stdout: false,
        no_recurse: false,
        fast_read: false,
        excludes: Vec::new(),
        subst: Vec::new(),
        format: Format::Restricted,
        record: 20 * 512,
        strip: 0,
        null: false,
        files_from: Vec::new(),
        exclude_from: Vec::new(),
        operands: Vec::new(),
    };
    let mut mode: Option<Mode> = None;
    let mut i = 0;
    let unsupported = |what: &str| {
        eprintln!("tar: {what} compression is not supported");
        Err(ExitCode::from(1))
    };
    while i < args.len() {
        let a = args[i].clone();
        i += 1;
        if a == b"--" {
            break;
        }
        if a.len() < 2 || a[0] != b'-' {
            i -= 1;
            break;
        }
        if let Some(long) = a.strip_prefix(b"--") {
            let (name, val) = match long.iter().position(|&b| b == b'=') {
                Some(p) => (&long[..p], Some(long[p + 1..].to_vec())),
                None => (long, None),
            };
            let name = String::from_utf8_lossy(name).into_owned();
            let needs = matches!(
                name.as_str(),
                "file"
                    | "directory"
                    | "cd"
                    | "files-from"
                    | "exclude-from"
                    | "exclude"
                    | "format"
                    | "blocking-factor"
                    | "strip-components"
            );
            let val = if needs {
                match val {
                    Some(v) => v,
                    None if i < args.len() => {
                        i += 1;
                        args[i - 1].clone()
                    }
                    None => return bad(&format!("Option --{name} requires an argument")),
                }
            } else {
                if val.is_some() {
                    return bad(&format!("Option --{name} does not allow an argument"));
                }
                Vec::new()
            };
            let r = match name.as_str() {
                "create" => set_mode(&mut mode, Mode::Create, 'c'),
                "append" => set_mode(&mut mode, Mode::Append, 'r'),
                "list" => set_mode(&mut mode, Mode::List, 't'),
                "update" => set_mode(&mut mode, Mode::Update, 'u'),
                "extract" | "get" => set_mode(&mut mode, Mode::Extract, 'x'),
                "file" => {
                    o.file = OsString::from_vec(val);
                    Ok(())
                }
                "verbose" => {
                    o.verbose += 1;
                    Ok(())
                }
                "gzip" | "gunzip" | "ungzip" => {
                    o.comp = Comp::Gzip;
                    Ok(())
                }
                "zstd" => {
                    o.comp = Comp::Zstd;
                    Ok(())
                }
                "bzip2" | "bunzip2" => return unsupported("bzip2"),
                "xz" | "lzma" => return unsupported("xz"),
                "compress" | "uncompress" => return unsupported("compress"),
                "auto-compress" => {
                    o.auto_comp = true;
                    Ok(())
                }
                "directory" | "cd" => {
                    o.chdir.push(val);
                    Ok(())
                }
                "preserve-permissions" | "same-permissions" => {
                    o.preserve_perms = true;
                    Ok(())
                }
                "no-same-permissions" => {
                    o.preserve_perms = false;
                    Ok(())
                }
                "same-owner" => {
                    o.same_owner = true;
                    Ok(())
                }
                "no-same-owner" => {
                    o.same_owner = false;
                    Ok(())
                }
                "numeric-owner" => {
                    o.numeric_owner = true;
                    Ok(())
                }
                "modification-time" => {
                    o.no_mtime = true;
                    Ok(())
                }
                "keep-old-files" => {
                    o.keep_old = true;
                    Ok(())
                }
                "dereference" => {
                    o.follow = true;
                    Ok(())
                }
                "absolute-paths" => {
                    o.absolute = true;
                    Ok(())
                }
                "to-stdout" => {
                    o.to_stdout = true;
                    Ok(())
                }
                "no-recursion" => {
                    o.no_recurse = true;
                    Ok(())
                }
                "fast-read" => {
                    o.fast_read = true;
                    Ok(())
                }
                "unlink-first" | "unlink" => Ok(()),
                "null" => {
                    o.null = true;
                    Ok(())
                }
                "files-from" => {
                    o.files_from.push(OsString::from_vec(val));
                    Ok(())
                }
                "exclude-from" => {
                    o.exclude_from.push(OsString::from_vec(val));
                    Ok(())
                }
                "exclude" => {
                    o.excludes.push(val);
                    Ok(())
                }
                "format" => {
                    o.format = match &val[..] {
                        b"ustar" => Format::Ustar,
                        b"pax" | b"posix" => Format::Pax,
                        b"restricted" | b"rpax" => Format::Restricted,
                        _ => return bad(&format!("Unsupported archive format: {}", String::from_utf8_lossy(&val))),
                    };
                    Ok(())
                }
                "blocking-factor" => set_block(&mut o, &val),
                "strip-components" => match std::str::from_utf8(&val).ok().and_then(|s| s.parse().ok()) {
                    Some(n) => {
                        o.strip = n;
                        Ok(())
                    }
                    None => Err("Invalid --strip-components value".into()),
                },
                "help" => return Err(help()),
                "version" => {
                    println!("OxideBSD tar 0.1.0");
                    return Err(ExitCode::SUCCESS);
                }
                _ => return bad(&format!("Option --{name} is not supported")),
            };
            if let Err(m) = r {
                return bad(&m);
            }
            continue;
        }
        let mut j = 1;
        while j < a.len() {
            let c = a[j];
            j += 1;
            let val = if takes_arg(c) {
                if j < a.len() {
                    let v = a[j..].to_vec();
                    j = a.len();
                    v
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    return bad(&format!("Option -{} requires an argument", c as char));
                }
            } else {
                Vec::new()
            };
            let r = match c {
                b'c' => set_mode(&mut mode, Mode::Create, 'c'),
                b'r' => set_mode(&mut mode, Mode::Append, 'r'),
                b't' => set_mode(&mut mode, Mode::List, 't'),
                b'u' => set_mode(&mut mode, Mode::Update, 'u'),
                b'x' => set_mode(&mut mode, Mode::Extract, 'x'),
                b'a' => {
                    o.auto_comp = true;
                    Ok(())
                }
                b'b' => set_block(&mut o, &val),
                b'C' => {
                    o.chdir.push(val);
                    Ok(())
                }
                b'f' => {
                    o.file = OsString::from_vec(val);
                    Ok(())
                }
                b'H' => {
                    o.follow_cmdline = true;
                    Ok(())
                }
                b'h' | b'L' => {
                    o.follow = true;
                    Ok(())
                }
                b'I' | b'T' => {
                    o.files_from.push(OsString::from_vec(val));
                    Ok(())
                }
                b'j' | b'y' => return unsupported("bzip2"),
                b'J' => return unsupported("xz"),
                b'Z' => return unsupported("compress"),
                b'k' => {
                    o.keep_old = true;
                    Ok(())
                }
                b'm' => {
                    o.no_mtime = true;
                    Ok(())
                }
                b'n' => {
                    o.no_recurse = true;
                    Ok(())
                }
                b'O' => {
                    o.to_stdout = true;
                    Ok(())
                }
                b'o' => {
                    o.same_owner = false;
                    Ok(())
                }
                b'P' => {
                    o.absolute = true;
                    Ok(())
                }
                b'p' => {
                    o.preserve_perms = true;
                    Ok(())
                }
                b'q' => {
                    o.fast_read = true;
                    Ok(())
                }
                b's' => match Subst::parse(&val) {
                    Ok(s) => {
                        o.subst.push(s);
                        Ok(())
                    }
                    Err(m) => Err(m),
                },
                b'U' => Ok(()),
                b'v' => {
                    o.verbose += 1;
                    Ok(())
                }
                b'X' => {
                    o.exclude_from.push(OsString::from_vec(val));
                    Ok(())
                }
                b'z' => {
                    o.comp = Comp::Gzip;
                    Ok(())
                }
                _ => return bad(&format!("Option -{} is not supported", c as char)),
            };
            if let Err(m) = r {
                return bad(&m);
            }
        }
    }
    let Some(m) = mode else {
        return bad("Must specify one of -c, -r, -t, -u, -x");
    };
    o.mode = m;
    // Operands, with -C dir among them.
    let rest = &args[i..];
    let mut k = 0;
    while k < rest.len() {
        if rest[k] == b"-C" && k + 1 < rest.len() {
            o.operands.push(Operand::Chdir(rest[k + 1].clone()));
            k += 2;
        } else if let Some(d) = rest[k].strip_prefix(b"-C").filter(|d| !d.is_empty() && rest[k].len() > 2) {
            o.operands.push(Operand::Chdir(d.to_vec()));
            k += 1;
        } else {
            o.operands.push(Operand::Name(rest[k].clone()));
            k += 1;
        }
    }
    if o.auto_comp && matches!(m, Mode::Create) {
        let name = o.file.as_bytes();
        let ends = |s: &[u8]| name.ends_with(s);
        if ends(b".tgz") || ends(b".taz") || ends(b".tar.gz") || ends(b".gz") {
            o.comp = Comp::Gzip;
        } else if ends(b".tzst") || ends(b".tar.zst") || ends(b".zst") {
            o.comp = Comp::Zstd;
        } else if ends(b".tbz") || ends(b".tbz2") || ends(b".bz2") {
            eprintln!("tar: bzip2 compression is not supported");
            return Err(ExitCode::from(1));
        } else if ends(b".txz") || ends(b".xz") || ends(b".lzma") {
            eprintln!("tar: xz compression is not supported");
            return Err(ExitCode::from(1));
        }
    }
    Ok(o)
}

fn set_block(o: &mut Opts, v: &[u8]) -> Result<(), String> {
    match std::str::from_utf8(v).ok().and_then(|s| s.parse::<usize>().ok()) {
        Some(n) if (1..=8192).contains(&n) => {
            o.record = n * 512;
            Ok(())
        }
        _ => Err(format!("Argument to -b is out of range (1..8192): {}", String::from_utf8_lossy(v))),
    }
}

/// Reads a list of names (`-T`, `-X`): one per line, or NUL-separated with --null.
pub fn read_list(path: &OsString, null: bool) -> Result<Vec<Vec<u8>>, String> {
    use std::io::Read;
    let mut data = Vec::new();
    let r = if path == "-" {
        io::stdin().lock().read_to_end(&mut data)
    } else {
        std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut data))
    };
    r.map_err(|e| format!("{}: {}", shown(path.as_bytes()), strerror(&e)))?;
    let sep = if null { 0 } else { b'\n' };
    Ok(data
        .split(|&b| b == sep)
        .map(|l| if !null { l.strip_suffix(b"\r").unwrap_or(l) } else { l })
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

fn main() -> ExitCode {
    let args: Vec<Vec<u8>> = std::env::args_os().skip(1).map(OsString::into_vec).collect();
    let mut o = match parse(args) {
        Ok(o) => o,
        Err(c) => return c,
    };
    for x in std::mem::take(&mut o.exclude_from) {
        match read_list(&x, o.null) {
            Ok(l) => o.excludes.extend(l),
            Err(m) => {
                eprintln!("tar: {m}");
                return ExitCode::from(1);
            }
        }
    }
    // -T's names come before the operands, as in bsdtar; a "-C dir" line changes directory.
    let mut from = Vec::new();
    for t in std::mem::take(&mut o.files_from) {
        match read_list(&t, o.null) {
            Ok(l) => {
                for n in l {
                    match n.strip_prefix(b"-C") {
                        Some(d) if !o.null && !d.is_empty() => {
                            let d = d.strip_prefix(b" ").unwrap_or(d);
                            from.push(Operand::Chdir(d.to_vec()));
                        }
                        _ => from.push(Operand::Name(n)),
                    }
                }
            }
            Err(m) => {
                eprintln!("tar: {m}");
                return ExitCode::from(1);
            }
        }
    }
    from.append(&mut o.operands);
    o.operands = from;
    let ok = match o.mode {
        Mode::Create | Mode::Append | Mode::Update => create::run(&o),
        Mode::List | Mode::Extract => extract::run(&o),
    };
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
