//! `cat(1)`: concatenates files to the standard output.
//!
//! ```text
//! cat [-benstuv] [file ...]
//! ```
//!
//! With no file, or `-`, it reads the standard input. With no option the bytes are copied as they
//! are, a block at a time. The options, as in all three BSDs:
//!
//! - `-n` numbers every output line, `-b` only the non-blank ones (and implies `-n`); the count
//!   runs on across files.
//! - `-s` squeezes runs of empty lines into one.
//! - `-v` shows non-printing characters: control characters as `^X`, DEL as `^?`, bytes with the
//!   high bit set as `M-` and the low seven bits. `-e` also marks each line end with `$`, `-t`
//!   also shows tabs as `^I`; both imply `-v`.
//! - `-u` is accepted: output is never held back past the read that produced it.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::process::ExitCode;

#[derive(Default)]
struct Opts {
    number: bool,
    nonblank: bool,
    squeeze: bool,
    visible: bool,
    ends: bool,
    tabs: bool,
}

impl Opts {
    fn cooked(&self) -> bool {
        self.number || self.squeeze || self.visible
    }
}

/// The state of `-n`/`-s` carried from one file to the next, as the BSDs do.
struct Cook {
    line: u64,
    /// The last byte written was a newline (true before any output).
    at_start: bool,
    /// Within `-s`, an empty line was already written.
    gobble: bool,
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cat [-benstuv] [file ...]");
    ExitCode::from(1)
}

/// Copies `input` as it is. `Err((true, e))` is a write error, `Err((false, e))` a read error.
fn raw_copy(input: &mut dyn Read, out: &mut dyn Write, buf: &mut [u8]) -> Result<(), (bool, io::Error)> {
    loop {
        let n = match input.read(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err((false, e)),
        };
        out.write_all(&buf[..n]).map_err(|e| (true, e))?;
        out.flush().map_err(|e| (true, e))?;
    }
}

fn cook_copy(
    input: &mut dyn Read,
    out: &mut dyn Write,
    buf: &mut [u8],
    o: &Opts,
    st: &mut Cook,
) -> Result<(), (bool, io::Error)> {
    let mut piece: Vec<u8> = Vec::with_capacity(buf.len() * 2);
    loop {
        let n = match input.read(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err((false, e)),
        };
        piece.clear();
        for &ch in &buf[..n] {
            if st.at_start {
                if o.squeeze {
                    if ch == b'\n' {
                        if st.gobble {
                            continue;
                        }
                        st.gobble = true;
                    } else {
                        st.gobble = false;
                    }
                }
                if o.number {
                    if !o.nonblank || ch != b'\n' {
                        st.line += 1;
                        let _ = write!(piece, "{:6}\t", st.line);
                    } else if o.ends {
                        piece.extend_from_slice(b"      \t");
                    }
                }
            }
            st.at_start = ch == b'\n';
            if ch == b'\n' {
                if o.ends {
                    piece.push(b'$');
                }
            } else if ch == b'\t' {
                if o.tabs {
                    piece.extend_from_slice(b"^I");
                    continue;
                }
            } else if o.visible {
                let mut c = ch;
                if c & 0x80 != 0 {
                    piece.extend_from_slice(b"M-");
                    c &= 0x7f;
                }
                if c < 0x20 || c == 0x7f {
                    piece.push(b'^');
                    piece.push(if c == 0x7f { b'?' } else { c | 0x40 });
                    continue;
                }
                piece.push(c);
                continue;
            }
            piece.push(ch);
        }
        // One write per read: large for files, prompt for a terminal or a pipe.
        out.write_all(&piece).map_err(|e| (true, e))?;
        out.flush().map_err(|e| (true, e))?;
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        for c in a[1..].chars() {
            match c {
                'b' => {
                    o.nonblank = true;
                    o.number = true;
                }
                'e' => {
                    o.ends = true;
                    o.visible = true;
                }
                'n' => o.number = true,
                's' => o.squeeze = true,
                't' => {
                    o.tabs = true;
                    o.visible = true;
                }
                'u' => {}
                'v' => o.visible = true,
                _ => {
                    eprintln!("cat: illegal option -- {c}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    let mut files: Vec<&str> = args[i..].iter().map(String::as_str).collect();
    if files.is_empty() {
        files.push("-");
    }

    let stdout = io::stdout();
    let lock = stdout.lock();
    // Each read becomes one write (a console write costs about a millisecond on OxideBSD, so
    // never a write per line), and nothing is held back past it: -u is how cat always works.
    let mut out = BufWriter::with_capacity(64 * 1024, lock);
    let mut buf = vec![0u8; 64 * 1024];
    let mut st = Cook { line: 0, at_start: true, gobble: false };
    let mut status = ExitCode::SUCCESS;
    for f in files {
        let mut file;
        let stdin;
        let mut stdin_lock;
        let input: &mut dyn Read = if f == "-" {
            stdin = io::stdin();
            stdin_lock = stdin.lock();
            &mut stdin_lock
        } else {
            match File::open(f) {
                Ok(h) => {
                    file = h;
                    &mut file
                }
                Err(e) => {
                    let _ = out.flush();
                    eprintln!("cat: {f}: {}", strerror(&e));
                    status = ExitCode::from(1);
                    continue;
                }
            }
        };
        let r = if o.cooked() {
            cook_copy(input, &mut out, &mut buf, &o, &mut st)
        } else {
            raw_copy(input, &mut out, &mut buf)
        };
        match r {
            Ok(()) => {}
            Err((true, e)) => {
                eprintln!("cat: stdout: {}", strerror(&e));
                return ExitCode::from(1);
            }
            Err((false, e)) => {
                let _ = out.flush();
                let name = if f == "-" { "stdin" } else { f };
                eprintln!("cat: {name}: {}", strerror(&e));
                status = ExitCode::from(1);
            }
        }
    }
    if let Err(e) = out.flush() {
        eprintln!("cat: stdout: {}", strerror(&e));
        return ExitCode::from(1);
    }
    status
}
