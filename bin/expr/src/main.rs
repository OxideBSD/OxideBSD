//! `expr(1)`: evaluates an expression and writes the result.
//!
//! ```text
//! expr expression
//! ```
//!
//! POSIX's expr: each operator and operand is its own argument. From the lowest precedence to
//! the highest:
//!
//! - `a | b`: `a` if it is neither null nor zero, else `b` if it is neither, else `0`.
//! - `a & b`: `a` if neither is null or zero, else `0`.
//! - `a = b`, `a > b`, `a >= b`, `a < b`, `a <= b`, `a != b`: `1` or `0`; compared as integers
//!   when both are integers, else as strings (byte order: the POSIX locale's collation).
//! - `a + b`, `a - b`; `a * b`, `a / b`, `a % b`: integer arithmetic on 64-bit signed values;
//!   an operand that is not an integer, division by zero and overflow are errors.
//! - `a : re`: matches the basic regular expression `re` against `a`, anchored at its start. With
//!   a `\(...\)`, the text the first one matched (or the null string); without, the number of
//!   bytes matched.
//! - `( expr )` groups.
//!
//! An integer is an optional `-` and one or more decimal digits. The exit status is 0 when the
//! result is neither null nor zero, 1 when it is, 2 for an invalid expression (bad syntax, a
//! non-integer operand of arithmetic, a bad regular expression, division by zero, overflow),
//! and 3 when the result can't be written. A leading `--` argument is skipped, as the BSDs do.

use std::ffi::CStr;
use std::io::{self, Write};
use std::process::ExitCode;

use posixre::{CompileFlags, ExecFlags, Regex};

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Int(i64),
    Str(Vec<u8>),
}

impl Val {
    fn from_arg(s: &[u8]) -> Val {
        match parse_int(s) {
            Some(n) => Val::Int(n),
            None => Val::Str(s.to_vec()),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            Val::Int(n) => n.to_string().into_bytes(),
            Val::Str(s) => s.clone(),
        }
    }

    /// The integer this value is, if it is one (a string made of an integer counts: `1 + 1`
    /// is `2` whichever way the operands came).
    fn int(&self) -> Option<i64> {
        match self {
            Val::Int(n) => Some(*n),
            Val::Str(s) => parse_int(s),
        }
    }

    fn null_or_zero(&self) -> bool {
        match self {
            Val::Int(n) => *n == 0,
            Val::Str(s) => s.is_empty() || parse_int(s) == Some(0),
        }
    }
}

/// An optional `-` and at least one digit; `None` past the range of `i64` too (the operand is
/// then a string, and arithmetic on it an error).
fn parse_int(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: i64 = 0;
    for &d in digits {
        n = n.checked_mul(10)?;
        n = if neg { n.checked_sub((d - b'0') as i64)? } else { n.checked_add((d - b'0') as i64)? };
    }
    Some(n)
}

#[derive(Debug)]
enum Fault {
    Syntax,
    NonInteger,
    DivZero,
    Overflow,
    Regex(String),
}

impl Fault {
    fn message(&self) -> String {
        match self {
            Fault::Syntax => "syntax error".into(),
            Fault::NonInteger => "non-numeric argument".into(),
            Fault::DivZero => "division by zero".into(),
            Fault::Overflow => "overflow".into(),
            Fault::Regex(m) => m.clone(),
        }
    }
}

struct Parser<'a> {
    args: &'a [Vec<u8>],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a [u8]> {
        self.args.get(self.pos).map(Vec::as_slice)
    }

    fn eat(&mut self, op: &[u8]) -> bool {
        if self.peek() == Some(op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Val, Fault> {
        let mut a = self.and()?;
        while self.eat(b"|") {
            let b = self.and()?;
            a = if !a.null_or_zero() {
                a
            } else if !b.null_or_zero() {
                b
            } else {
                Val::Int(0)
            };
        }
        Ok(a)
    }

    fn and(&mut self) -> Result<Val, Fault> {
        let mut a = self.compare()?;
        while self.eat(b"&") {
            let b = self.compare()?;
            a = if a.null_or_zero() || b.null_or_zero() { Val::Int(0) } else { a };
        }
        Ok(a)
    }

    fn compare(&mut self) -> Result<Val, Fault> {
        let mut a = self.add()?;
        loop {
            let op = match self.peek() {
                Some(o @ (b"=" | b">" | b">=" | b"<" | b"<=" | b"!=")) => o,
                _ => return Ok(a),
            };
            self.pos += 1;
            let b = self.add()?;
            let ord = match (a.int(), b.int()) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => a.bytes().cmp(&b.bytes()),
            };
            use std::cmp::Ordering::*;
            let r = match op {
                b"=" => ord == Equal,
                b">" => ord == Greater,
                b">=" => ord != Less,
                b"<" => ord == Less,
                b"<=" => ord != Greater,
                _ => ord != Equal,
            };
            a = Val::Int(r as i64);
        }
    }

    fn add(&mut self) -> Result<Val, Fault> {
        let mut a = self.mul()?;
        loop {
            let plus = if self.eat(b"+") {
                true
            } else if self.eat(b"-") {
                false
            } else {
                return Ok(a);
            };
            let b = self.mul()?;
            let (x, y) = (a.int().ok_or(Fault::NonInteger)?, b.int().ok_or(Fault::NonInteger)?);
            let r = if plus { x.checked_add(y) } else { x.checked_sub(y) };
            a = Val::Int(r.ok_or(Fault::Overflow)?);
        }
    }

    fn mul(&mut self) -> Result<Val, Fault> {
        let mut a = self.matching()?;
        loop {
            let op = match self.peek() {
                Some(o @ (b"*" | b"/" | b"%")) => o[0],
                _ => return Ok(a),
            };
            self.pos += 1;
            let b = self.matching()?;
            let (x, y) = (a.int().ok_or(Fault::NonInteger)?, b.int().ok_or(Fault::NonInteger)?);
            let r = match op {
                b'*' => x.checked_mul(y),
                _ if y == 0 => return Err(Fault::DivZero),
                b'/' => x.checked_div(y),
                _ => x.checked_rem(y),
            };
            a = Val::Int(r.ok_or(Fault::Overflow)?);
        }
    }

    fn matching(&mut self) -> Result<Val, Fault> {
        let mut a = self.primary()?;
        while self.eat(b":") {
            let b = self.primary()?;
            a = do_match(&a.bytes(), &b.bytes())?;
        }
        Ok(a)
    }

    fn primary(&mut self) -> Result<Val, Fault> {
        let Some(t) = self.peek() else { return Err(Fault::Syntax) };
        self.pos += 1;
        if t == b"(" {
            // `( )` and `( op` with nothing after: `(` as a plain string only when it is the
            // last argument.
            if self.peek().is_none() {
                return Ok(Val::Str(t.to_vec()));
            }
            let v = self.or()?;
            if !self.eat(b")") {
                return Err(Fault::Syntax);
            }
            return Ok(v);
        }
        if t == b")" {
            return Err(Fault::Syntax);
        }
        // An operator where an operand belongs: valid only as the whole expression or next to
        // another operator (`expr = = =`), where it can only be a string.
        Ok(Val::from_arg(t))
    }
}

fn do_match(s: &[u8], pat: &[u8]) -> Result<Val, Fault> {
    let re = Regex::new(pat, CompileFlags::BASIC).map_err(|e| Fault::Regex(e.kind.message().to_string()))?;
    let caps = re.try_captures_at(s, 0..s.len(), ExecFlags::NONE).map_err(|e| Fault::Regex(e.kind.message().to_string()))?;
    // Anchored: the leftmost match must start at the beginning (if any match does, the
    // leftmost one does).
    let caps = caps.filter(|c| c[0].is_some_and(|(st, _)| st == 0));
    if re.nsub() > 0 {
        Ok(Val::Str(match caps.as_ref().and_then(|c| c.get(1).copied().flatten()) {
            Some((a, b)) => s[a..b].to_vec(),
            None => Vec::new(),
        }))
    } else {
        Ok(Val::Int(caps.map_or(0, |c| c[0].map_or(0, |(a, b)| b - a)) as i64))
    }
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn eval(args: &[Vec<u8>]) -> Result<Val, Fault> {
    let mut p = Parser { args, pos: 0 };
    let v = p.or()?;
    if p.pos != args.len() {
        return Err(Fault::Syntax);
    }
    Ok(v)
}

fn main() -> ExitCode {
    use std::os::unix::ffi::OsStringExt;
    let mut args: Vec<Vec<u8>> = std::env::args_os().skip(1).map(OsStringExt::into_vec).collect();
    if args.len() > 1 && args[0] == b"--" {
        args.remove(0);
    }
    if args.is_empty() {
        eprintln!("usage: expr expression");
        return ExitCode::from(2);
    }
    match eval(&args) {
        Ok(v) => {
            let mut b = v.bytes();
            b.push(b'\n');
            let mut out = io::stdout().lock();
            if let Err(e) = out.write_all(&b).and_then(|_| out.flush()) {
                eprintln!("expr: stdout: {}", strerror(&e));
                return ExitCode::from(3);
            }
            ExitCode::from(v.null_or_zero() as u8)
        }
        Err(f) => {
            eprintln!("expr: {}", f.message());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(s: &str) -> Result<Vec<u8>, String> {
        let a: Vec<Vec<u8>> = s.split(' ').map(|x| x.as_bytes().to_vec()).collect();
        eval(&a).map(|v| v.bytes()).map_err(|f| f.message())
    }

    #[test]
    fn basics() {
        assert_eq!(ev("1 + 2 * 3").unwrap(), b"7");
        assert_eq!(ev("( 1 + 2 ) * 3").unwrap(), b"9");
        assert_eq!(ev("10 - 3 - 2").unwrap(), b"5");
        assert_eq!(ev("-7 / 2").unwrap(), b"-3");
        assert_eq!(ev("-7 % 2").unwrap(), b"-1");
        assert_eq!(ev("10 < 9").unwrap(), b"0");
        assert_eq!(ev("10 < 9a").unwrap(), b"1");
        assert_eq!(ev("abc : a\\(b\\)c").unwrap(), b"b");
        assert_eq!(ev("abc : b").unwrap(), b"0");
        assert_eq!(ev("abc : ab*").unwrap(), b"2");
        assert_eq!(ev("abc : x\\(y\\)").unwrap(), b"");
        assert_eq!(ev(" | 0").unwrap(), b"0");
        assert_eq!(ev("a | b").unwrap(), b"a");
        assert_eq!(ev("0 | b").unwrap(), b"b");
        assert_eq!(ev("a & 0").unwrap(), b"0");
        assert_eq!(ev("a & b").unwrap(), b"a");
        assert_eq!(ev("= = =").unwrap(), b"1");
        assert_eq!(ev("9223372036854775807 + 1").unwrap_err(), "overflow");
        assert_eq!(ev("-9223372036854775808 / -1").unwrap_err(), "overflow");
        assert_eq!(ev("1 / 0").unwrap_err(), "division by zero");
        assert_eq!(ev("a + 1").unwrap_err(), "non-numeric argument");
        assert_eq!(ev("1 +").unwrap_err(), "syntax error");
        assert_eq!(ev("( 1").unwrap_err(), "syntax error");
        assert_eq!(ev("1 2").unwrap_err(), "syntax error");
        assert_eq!(ev("01 = 1").unwrap(), b"1");
        assert_eq!(ev("01 + 0").unwrap(), b"1");
    }
}
