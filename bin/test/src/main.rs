//! `test(1)` and `[`: evaluates a condition, exiting 0 if it is true, 1 if false, 2 on an error.
//!
//! With up to four arguments POSIX fixes the meaning by their number, which settles cases such
//! as `test -n` (one argument: true, a non-empty string) or `test ! =`; with more, the
//! expression is parsed with `!`, `-a` (binding tighter), `-o` and parentheses (XSI). Primaries:
//!
//! - files: `-b -c -d -e -f -g -h -k -L -p -r -s -S -u -w -x -O -G`, `-t fd`;
//! - strings: `-n`, `-z`, `=`, `!=`, `<`, `>`;
//! - integers: `-eq -ne -gt -ge -lt -le`;
//! - two files: `-nt`, `-ot` (newer, older), `-ef` (the same file).

use std::ffi::CString;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::ExitCode;

const UNARY: [&str; 21] = [
    "-b", "-c", "-d", "-e", "-f", "-g", "-h", "-k", "-L", "-n", "-p", "-r", "-s", "-S", "-t", "-u",
    "-w", "-x", "-z", "-O", "-G",
];
const BINARY: [&str; 13] = [
    "=", "!=", "<", ">", "-eq", "-ne", "-gt", "-ge", "-lt", "-le", "-nt", "-ot", "-ef",
];

fn is_unary(s: &str) -> bool {
    UNARY.contains(&s)
}

fn is_binary(s: &str) -> bool {
    BINARY.contains(&s)
}

type Res = Result<bool, String>;

fn access(path: &str, mode: libc::c_int) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    // SAFETY: a NUL-terminated path. The effective IDs decide, as a set-user-ID program's would.
    unsafe {
        let r = libc::faccessat(libc::AT_FDCWD, c.as_ptr(), mode, libc::AT_EACCESS);
        if r == 0 {
            return true;
        }
        matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL | libc::ENOSYS)
        ) && libc::access(c.as_ptr(), mode) == 0
    }
}

fn unary(op: &str, arg: &str) -> Res {
    let md = || std::fs::metadata(arg).ok();
    Ok(match op {
        "-n" => !arg.is_empty(),
        "-z" => arg.is_empty(),
        "-t" => {
            let fd: libc::c_int = arg
                .trim()
                .parse()
                .map_err(|_| format!("{arg}: bad number"))?;
            // SAFETY: isatty(3) on any number is harmless.
            unsafe { libc::isatty(fd) == 1 }
        }
        "-h" | "-L" => std::fs::symlink_metadata(arg).is_ok_and(|m| m.file_type().is_symlink()),
        "-e" => md().is_some(),
        "-f" => md().is_some_and(|m| m.is_file()),
        "-d" => md().is_some_and(|m| m.is_dir()),
        "-b" => md().is_some_and(|m| m.file_type().is_block_device()),
        "-c" => md().is_some_and(|m| m.file_type().is_char_device()),
        "-p" => md().is_some_and(|m| m.file_type().is_fifo()),
        "-S" => md().is_some_and(|m| m.file_type().is_socket()),
        "-s" => md().is_some_and(|m| m.len() > 0),
        "-u" => md().is_some_and(|m| m.mode() & 0o4000 != 0),
        "-g" => md().is_some_and(|m| m.mode() & 0o2000 != 0),
        "-k" => md().is_some_and(|m| m.mode() & 0o1000 != 0),
        // SAFETY: geteuid/getegid take no arguments.
        "-O" => md().is_some_and(|m| m.uid() == unsafe { libc::geteuid() }),
        "-G" => md().is_some_and(|m| m.gid() == unsafe { libc::getegid() }),
        "-r" => access(arg, libc::R_OK),
        "-w" => access(arg, libc::W_OK),
        "-x" => access(arg, libc::X_OK),
        _ => return Err(format!("{op}: unknown operator")),
    })
}

fn number(s: &str) -> Result<i64, String> {
    s.trim().parse().map_err(|_| format!("{s}: bad number"))
}

fn binary(a: &str, op: &str, b: &str) -> Res {
    let mtime = |p: &str| {
        std::fs::metadata(p)
            .ok()
            .map(|m| (m.mtime(), m.mtime_nsec()))
    };
    Ok(match op {
        "=" => a == b,
        "!=" => a != b,
        "<" => a < b,
        ">" => a > b,
        "-eq" => number(a)? == number(b)?,
        "-ne" => number(a)? != number(b)?,
        "-gt" => number(a)? > number(b)?,
        "-ge" => number(a)? >= number(b)?,
        "-lt" => number(a)? < number(b)?,
        "-le" => number(a)? <= number(b)?,
        // A file that exists is newer than one that doesn't, as on the BSDs.
        "-nt" => match (mtime(a), mtime(b)) {
            (Some(x), Some(y)) => x > y,
            (Some(_), None) => true,
            _ => false,
        },
        "-ot" => match (mtime(a), mtime(b)) {
            (Some(x), Some(y)) => x < y,
            (None, Some(_)) => true,
            _ => false,
        },
        "-ef" => match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
            _ => false,
        },
        _ => return Err(format!("{op}: unknown operator")),
    })
}

/// The XSI grammar, for more than four arguments:
/// `or := and (-o and)*`, `and := not (-a not)*`, `not := ! not | primary`,
/// `primary := ( or ) | unary-op arg | arg binary-op arg | arg`.
struct Parser<'a> {
    args: &'a [&'a str],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self, k: usize) -> Option<&'a str> {
        self.args.get(self.pos + k).copied()
    }

    fn next(&mut self) -> Option<&'a str> {
        let a = self.args.get(self.pos).copied();
        self.pos += 1;
        a
    }

    fn or(&mut self) -> Res {
        let mut v = self.and()?;
        while self.peek(0) == Some("-o") {
            self.pos += 1;
            let r = self.and()?;
            v = v || r;
        }
        Ok(v)
    }

    fn and(&mut self) -> Res {
        let mut v = self.not()?;
        while self.peek(0) == Some("-a") {
            self.pos += 1;
            let r = self.not()?;
            v = v && r;
        }
        Ok(v)
    }

    fn not(&mut self) -> Res {
        if self.peek(0) == Some("!") && self.peek(1).is_some() {
            self.pos += 1;
            return Ok(!self.not()?);
        }
        self.primary()
    }

    fn primary(&mut self) -> Res {
        let Some(a) = self.peek(0) else {
            return Err("argument expected".into());
        };
        if a == "("
            && self.peek(1).is_some()
            && !(self.peek(2) == Some(")") && is_binary(self.peek(1).unwrap()))
        {
            self.pos += 1;
            let v = self.or()?;
            if self.next() != Some(")") {
                return Err("closing paren expected".into());
            }
            return Ok(v);
        }
        if let (Some(op), Some(b)) = (self.peek(1), self.peek(2))
            && is_binary(op)
        {
            self.pos += 3;
            return binary(a, op, b);
        }
        if is_unary(a)
            && let Some(b) = self.peek(1)
        {
            self.pos += 2;
            return unary(a, b);
        }
        self.pos += 1;
        Ok(!a.is_empty())
    }
}

/// Evaluates `args` (without the program name or a closing `]`).
fn eval(args: &[&str]) -> Res {
    let negate = |r: Res| r.map(|v| !v);
    match *args {
        [] => Ok(false),
        [a] => Ok(!a.is_empty()),
        ["!", a] => Ok(a.is_empty()),
        [op, a] if is_unary(op) => unary(op, a),
        [_, _] => Err(format!("{}: unary operator expected", args[0])),
        [a, op, b] if is_binary(op) => binary(a, op, b),
        [a, "-a", b] => Ok(!a.is_empty() && !b.is_empty()),
        [a, "-o", b] => Ok(!a.is_empty() || !b.is_empty()),
        ["!", ..] if args.len() <= 4 => negate(eval(&args[1..])),
        ["(", a, ")"] => Ok(!a.is_empty()),
        ["(", a, b, ")"] => eval(&[a, b]),
        _ => {
            let mut p = Parser { args, pos: 0 };
            let v = p.or()?;
            match p.peek(0) {
                None => Ok(v),
                Some(extra) => Err(format!("{extra}: unexpected operator")),
            }
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let name = argv
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a))
        .unwrap_or("test");
    let mut args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    if name == "[" {
        if args.last() != Some(&"]") {
            eprintln!("[: missing ]");
            return ExitCode::from(2);
        }
        args.pop();
    }
    match eval(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("{name}: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Res {
        let args: Vec<&str> = if s.is_empty() {
            Vec::new()
        } else {
            s.split(' ').collect()
        };
        eval(&args)
    }

    #[test]
    fn by_count() {
        assert_eq!(t(""), Ok(false));
        assert_eq!(t("x"), Ok(true));
        assert_eq!(t("-n"), Ok(true));
        assert_eq!(t("!"), Ok(true));
        assert_eq!(t("! x"), Ok(false));
        assert_eq!(t("-z x"), Ok(false));
        assert_eq!(t("-n x"), Ok(true));
        assert!(t("x y").is_err());
        assert_eq!(t("a = a"), Ok(true));
        assert_eq!(t("a != a"), Ok(false));
        assert_eq!(t("! = ="), Ok(false));
        assert_eq!(t("( x )"), Ok(true));
        assert_eq!(t("! a = b"), Ok(true));
        assert_eq!(t("( -n x )"), Ok(true));
        assert_eq!(t("= = ="), Ok(true));
        assert_eq!(t("-n -a -z"), Ok(true));
    }

    #[test]
    fn numbers_and_strings() {
        assert_eq!(t("3 -gt 2"), Ok(true));
        assert_eq!(t("-1 -lt 0"), Ok(true));
        assert_eq!(t("2 -le 2"), Ok(true));
        assert_eq!(t("10 -eq 010"), Ok(true));
        assert!(t("x -eq 1").is_err());
        assert_eq!(t("abc < abd"), Ok(true));
        assert_eq!(t("b > a"), Ok(true));
    }

    #[test]
    fn expressions() {
        assert_eq!(t("a = a -a b = b -o x = y"), Ok(true));
        assert_eq!(t("a = b -o b = b -a c = d"), Ok(false));
        assert_eq!(t("( a = b -o b = b ) -a c = c"), Ok(true));
        assert_eq!(t("! ( a = b ) -a ! ( c = d )"), Ok(true));
        assert!(t("( a = b").is_err());
        assert!(t("a = b c d e").is_err());
    }

    #[test]
    fn files() {
        let dir = std::env::temp_dir().join(format!("test-utility-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        let empty = dir.join("empty");
        let link = dir.join("link");
        std::fs::write(&f, "data").unwrap();
        std::fs::write(&empty, "").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&f, &link).unwrap();
        let (f, empty, link, d) = (
            f.to_str().unwrap(),
            empty.to_str().unwrap(),
            link.to_str().unwrap(),
            dir.to_str().unwrap(),
        );
        assert_eq!(eval(&["-f", f]), Ok(true));
        assert_eq!(eval(&["-d", d]), Ok(true));
        assert_eq!(eval(&["-d", f]), Ok(false));
        assert_eq!(eval(&["-s", f]), Ok(true));
        assert_eq!(eval(&["-s", empty]), Ok(false));
        assert_eq!(eval(&["-h", link]), Ok(true));
        assert_eq!(eval(&["-h", f]), Ok(false));
        assert_eq!(eval(&["-e", "/nonexistent/x"]), Ok(false));
        assert_eq!(eval(&["-r", f]), Ok(true));
        assert_eq!(eval(&[link, "-ef", f]), Ok(true));
        assert_eq!(eval(&[f, "-ef", empty]), Ok(false));
        assert_eq!(eval(&[f, "-nt", "/nonexistent/x"]), Ok(true));
        assert_eq!(eval(&["/nonexistent/x", "-ot", f]), Ok(true));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
