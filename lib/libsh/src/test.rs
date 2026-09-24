//! `test` / `[` (XCU `test`): the POSIX argument-count rules for up to four arguments, and the
//! XSI `-a`/`-o`/parentheses grammar beyond that.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

pub fn eval(args: &[&str]) -> Result<bool, String> {
    match args.len() {
        0 => Ok(false),
        1 => Ok(!args[0].is_empty()),
        2 => {
            if args[0] == "!" {
                return Ok(args[1].is_empty());
            }
            if is_unary(args[0]) {
                return unary(args[0], args[1]);
            }
            Err(format!("{}: unary operator expected", args[0]))
        }
        3 => {
            if is_binary(args[1]) {
                return binary(args[0], args[1], args[2]);
            }
            if args[0] == "!" {
                return eval(&args[1..]).map(|b| !b);
            }
            if args[0] == "(" && args[2] == ")" {
                return Ok(!args[1].is_empty());
            }
            general(args)
        }
        4 => {
            if args[0] == "!" {
                return eval(&args[1..]).map(|b| !b);
            }
            if args[0] == "(" && args[3] == ")" {
                return eval(&args[1..3]);
            }
            general(args)
        }
        _ => general(args),
    }
}

fn general(args: &[&str]) -> Result<bool, String> {
    let mut p = Parser { args, pos: 0 };
    let v = p.or()?;
    if p.pos != args.len() {
        return Err(format!("{}: unexpected operator", args[p.pos]));
    }
    Ok(v)
}

struct Parser<'a> {
    args: &'a [&'a str],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.args.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<&'a str, String> {
        let a = self.args.get(self.pos).copied().ok_or_else(|| "argument expected".to_string())?;
        self.pos += 1;
        Ok(a)
    }

    fn or(&mut self) -> Result<bool, String> {
        let mut v = self.and()?;
        while self.peek() == Some("-o") {
            self.pos += 1;
            let r = self.and()?;
            v = v || r;
        }
        Ok(v)
    }

    fn and(&mut self) -> Result<bool, String> {
        let mut v = self.not()?;
        while self.peek() == Some("-a") {
            self.pos += 1;
            let r = self.not()?;
            v = v && r;
        }
        Ok(v)
    }

    fn not(&mut self) -> Result<bool, String> {
        if self.peek() == Some("!") {
            self.pos += 1;
            return self.not().map(|b| !b);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<bool, String> {
        let a = self.next()?;
        if a == "(" {
            let v = self.or()?;
            if self.next()? != ")" {
                return Err("`)' expected".into());
            }
            return Ok(v);
        }
        if is_unary(a) && self.peek().is_some() && !self.peek().is_some_and(is_binary) {
            let operand = self.next()?;
            return unary(a, operand);
        }
        if let Some(op) = self.peek()
            && is_binary(op)
        {
            self.pos += 1;
            let b = self.next()?;
            return binary(a, op, b);
        }
        Ok(!a.is_empty())
    }
}

fn is_unary(op: &str) -> bool {
    matches!(op, "-b" | "-c" | "-d" | "-e" | "-f" | "-g" | "-h" | "-L" | "-n" | "-p" | "-r" | "-S" | "-s" | "-t" | "-u" | "-w" | "-x" | "-z")
}

fn is_binary(op: &str) -> bool {
    matches!(op, "=" | "!=" | "<" | ">" | "-eq" | "-ne" | "-gt" | "-ge" | "-lt" | "-le" | "-nt" | "-ot" | "-ef")
}

fn access(path: &str, mode: i32) -> bool {
    let p = crate::sys::cstr(path);
    unsafe { libc::access(p.as_ptr(), mode) == 0 }
}

fn unary(op: &str, x: &str) -> Result<bool, String> {
    let meta = || std::fs::metadata(x);
    Ok(match op {
        "-n" => !x.is_empty(),
        "-z" => x.is_empty(),
        "-e" => meta().is_ok(),
        "-f" => meta().is_ok_and(|m| m.is_file()),
        "-d" => meta().is_ok_and(|m| m.is_dir()),
        "-b" => meta().is_ok_and(|m| m.file_type().is_block_device()),
        "-c" => meta().is_ok_and(|m| m.file_type().is_char_device()),
        "-p" => meta().is_ok_and(|m| m.file_type().is_fifo()),
        "-S" => meta().is_ok_and(|m| m.file_type().is_socket()),
        "-h" | "-L" => std::fs::symlink_metadata(x).is_ok_and(|m| m.file_type().is_symlink()),
        "-s" => meta().is_ok_and(|m| m.size() > 0),
        "-g" => meta().is_ok_and(|m| m.permissions().mode() & 0o2000 != 0),
        "-u" => meta().is_ok_and(|m| m.permissions().mode() & 0o4000 != 0),
        "-r" => access(x, libc::R_OK),
        "-w" => access(x, libc::W_OK),
        "-x" => access(x, libc::X_OK),
        "-t" => {
            let fd: i32 = x.trim().parse().map_err(|_| format!("{x}: bad number"))?;
            unsafe { libc::isatty(fd) == 1 }
        }
        _ => return Err(format!("{op}: unknown operator")),
    })
}

fn int(s: &str) -> Result<i64, String> {
    s.trim().parse::<i64>().map_err(|_| format!("{s}: bad number"))
}

fn binary(a: &str, op: &str, b: &str) -> Result<bool, String> {
    Ok(match op {
        "=" => a == b,
        "!=" => a != b,
        "<" => a < b,
        ">" => a > b,
        "-eq" => int(a)? == int(b)?,
        "-ne" => int(a)? != int(b)?,
        "-gt" => int(a)? > int(b)?,
        "-ge" => int(a)? >= int(b)?,
        "-lt" => int(a)? < int(b)?,
        "-le" => int(a)? <= int(b)?,
        "-nt" | "-ot" => {
            let t = |p: &str| std::fs::metadata(p).ok().map(|m| (m.mtime(), m.mtime_nsec()));
            match (t(a), t(b)) {
                (Some(x), Some(y)) => {
                    if op == "-nt" {
                        x > y
                    } else {
                        x < y
                    }
                }
                (Some(_), None) => op == "-nt",
                (None, Some(_)) => op == "-ot",
                (None, None) => false,
            }
        }
        "-ef" => match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
            _ => false,
        },
        _ => return Err(format!("{op}: unknown operator")),
    })
}
