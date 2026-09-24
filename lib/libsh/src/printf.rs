//! `printf` (XCU `printf`) and the backslash escapes it shares with `echo`.

use crate::shell::{Exec, Shell};
use crate::sys;

/// Appends `s` with backslash escapes interpreted. `echo_style`: the `echo`/`%b` set, where octal
/// is `\0nnn` and `\c` ends all output. Returns true if `\c` was seen.
pub fn push_escaped(out: &mut String, s: &str, echo_style: bool) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' || i >= chars.len() {
            out.push(c);
            continue;
        }
        let e = chars[i];
        i += 1;
        match e {
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\x0b'),
            '\\' => out.push('\\'),
            'c' if echo_style => return true,
            '0'..='7' => {
                // echo/%b: `\0` then up to three digits; format strings: up to three digits.
                let mut v: u32 = if echo_style && e == '0' { 0 } else { e.to_digit(8).unwrap() };
                let max = if echo_style && e == '0' { 3 } else { 2 };
                if echo_style && e != '0' {
                    out.push('\\');
                    out.push(e);
                    continue;
                }
                let mut n = 0;
                while n < max && i < chars.len() && chars[i].is_digit(8) {
                    v = v * 8 + chars[i].to_digit(8).unwrap();
                    i += 1;
                    n += 1;
                }
                push_byte(out, (v & 0xff) as u8);
            }
            '"' if !echo_style => out.push('"'),
            '\'' if !echo_style => out.push('\''),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    false
}

/// Bytes >= 0x80 from octal escapes are kept as Latin-1 characters; output converts them back.
fn push_byte(out: &mut String, b: u8) {
    out.push(b as char);
}

/// Converts a string built with `push_byte` back to raw bytes.
pub fn to_bytes(s: &str) -> Vec<u8> {
    // Characters U+0080..U+00FF came from single bytes; everything else is UTF-8 text.
    let mut v = Vec::with_capacity(s.len());
    for c in s.chars() {
        if (0x80..0x100).contains(&(c as u32)) {
            v.push(c as u8);
        } else {
            let mut buf = [0u8; 4];
            v.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    v
}

struct Spec {
    minus: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: Option<usize>,
    prec: Option<usize>,
}

pub fn printf(sh: &mut Shell, args: &[String]) -> Exec {
    let mut rest = &args[1..];
    if rest.first().is_some_and(|a| a == "--") {
        rest = &rest[1..];
    }
    let Some(format) = rest.first() else {
        sh.error("printf: usage: printf format [arg ...]");
        return Ok(2);
    };
    let fmt: Vec<char> = format.chars().collect();
    let operands = &rest[1..];
    let mut next = 0;
    let mut out = String::new();
    let mut status = 0;
    loop {
        let start_next = next;
        let mut i = 0;
        while i < fmt.len() {
            let c = fmt[i];
            if c == '\\' {
                // Take the escape sequence as a unit.
                let mut j = i + 1;
                if j < fmt.len() && fmt[j].is_digit(8) {
                    let mut n = 0;
                    while j < fmt.len() && fmt[j].is_digit(8) && n < 3 {
                        j += 1;
                        n += 1;
                    }
                } else {
                    j = (j + 1).min(fmt.len());
                }
                let seq: String = fmt[i..j].iter().collect();
                push_escaped(&mut out, &seq, false);
                i = j;
                continue;
            }
            if c != '%' {
                out.push(c);
                i += 1;
                continue;
            }
            i += 1;
            if i < fmt.len() && fmt[i] == '%' {
                out.push('%');
                i += 1;
                continue;
            }
            let mut spec = Spec { minus: false, plus: false, space: false, alt: false, zero: false, width: None, prec: None };
            while i < fmt.len() {
                match fmt[i] {
                    '-' => spec.minus = true,
                    '+' => spec.plus = true,
                    ' ' => spec.space = true,
                    '#' => spec.alt = true,
                    '0' => spec.zero = true,
                    _ => break,
                }
                i += 1;
            }
            let take_num = |i: &mut usize, next: &mut usize, status: &mut i32| -> Option<usize> {
                if *i < fmt.len() && fmt[*i] == '*' {
                    *i += 1;
                    let v = operands.get(*next).map(|a| parse_int(sh, a, status)).unwrap_or(0);
                    *next += 1;
                    return Some(v.max(0) as usize);
                }
                let s = *i;
                while *i < fmt.len() && fmt[*i].is_ascii_digit() {
                    *i += 1;
                }
                if s == *i { None } else { fmt[s..*i].iter().collect::<String>().parse().ok() }
            };
            spec.width = take_num(&mut i, &mut next, &mut status);
            if i < fmt.len() && fmt[i] == '.' {
                i += 1;
                spec.prec = Some(take_num(&mut i, &mut next, &mut status).unwrap_or(0));
            }
            let Some(&conv) = fmt.get(i) else {
                sh.error("printf: missing format character");
                return Ok(1);
            };
            i += 1;
            let arg = operands.get(next).map(String::as_str);
            if !matches!(conv, '%') {
                next += 1;
            }
            match conv {
                's' => {
                    let mut s = arg.unwrap_or("").to_string();
                    if let Some(p) = spec.prec {
                        s = s.chars().take(p).collect();
                    }
                    out.push_str(&pad(&s, &spec, false));
                }
                'b' => {
                    let mut s = String::new();
                    let stop = push_escaped(&mut s, arg.unwrap_or(""), true);
                    if let Some(p) = spec.prec {
                        s = s.chars().take(p).collect();
                    }
                    out.push_str(&pad(&s, &spec, false));
                    if stop {
                        let _ = sys::write_all(1, &to_bytes(&out));
                        return Ok(status);
                    }
                }
                'c' => {
                    let s: String = arg.unwrap_or("").chars().take(1).collect();
                    out.push_str(&pad(&s, &spec, false));
                }
                'd' | 'i' => {
                    let v = arg.map(|a| parse_int(sh, a, &mut status)).unwrap_or(0);
                    out.push_str(&format_int(v < 0, &v.unsigned_abs().to_string(), &spec, ""));
                }
                'o' | 'u' | 'x' | 'X' => {
                    let v = arg.map(|a| parse_int(sh, a, &mut status)).unwrap_or(0) as u64;
                    let (digits, prefix) = match conv {
                        'o' => (format!("{v:o}"), if spec.alt && v != 0 { "0" } else { "" }),
                        'x' => (format!("{v:x}"), if spec.alt && v != 0 { "0x" } else { "" }),
                        'X' => (format!("{v:X}"), if spec.alt && v != 0 { "0X" } else { "" }),
                        _ => (v.to_string(), ""),
                    };
                    let unsigned = Spec { plus: false, space: false, ..spec };
                    out.push_str(&format_int(false, &digits, &unsigned, prefix));
                }
                'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                    let v = arg.map(|a| parse_float(sh, a, &mut status)).unwrap_or(0.0);
                    let body = format_float(v.abs(), conv, spec.prec.unwrap_or(6), spec.alt);
                    let sign = if v.is_sign_negative() && v != 0.0 || v < 0.0 { "-" } else if spec.plus { "+" } else if spec.space { " " } else { "" };
                    out.push_str(&pad_numeric(sign, "", &body, &spec));
                }
                other => {
                    sh.error(&format!("printf: %{other}: invalid directive"));
                    let _ = sys::write_all(1, &to_bytes(&out));
                    return Ok(1);
                }
            }
        }
        // The format is reused while operands remain, as long as it consumed some.
        if next >= operands.len() || next == start_next {
            break;
        }
    }
    let _ = sys::write_all(1, &to_bytes(&out));
    Ok(status)
}

fn pad(s: &str, spec: &Spec, _numeric: bool) -> String {
    let len = s.chars().count();
    let w = spec.width.unwrap_or(0);
    if len >= w {
        return s.to_string();
    }
    let fill = " ".repeat(w - len);
    if spec.minus { format!("{s}{fill}") } else { format!("{fill}{s}") }
}

fn pad_numeric(sign: &str, prefix: &str, digits: &str, spec: &Spec) -> String {
    let len = sign.len() + prefix.len() + digits.len();
    let w = spec.width.unwrap_or(0);
    if len >= w {
        return format!("{sign}{prefix}{digits}");
    }
    let n = w - len;
    if spec.minus {
        format!("{sign}{prefix}{digits}{}", " ".repeat(n))
    } else if spec.zero {
        format!("{sign}{prefix}{}{digits}", "0".repeat(n))
    } else {
        format!("{}{sign}{prefix}{digits}", " ".repeat(n))
    }
}

fn format_int(negative: bool, digits: &str, spec: &Spec, prefix: &str) -> String {
    let mut d = digits.to_string();
    if let Some(p) = spec.prec {
        if p == 0 && d == "0" {
            d.clear();
        }
        while d.len() < p {
            d.insert(0, '0');
        }
    }
    let sign = if negative { "-" } else if spec.plus { "+" } else if spec.space { " " } else { "" };
    // A precision disables the `0` flag for integers.
    let s = Spec { zero: spec.zero && spec.prec.is_none(), width: spec.width, prec: None, ..*spec };
    pad_numeric(sign, prefix, &d, &s)
}

/// C-style `%e`: mantissa, `e`, sign, at least two exponent digits.
fn format_exp(v: f64, prec: usize, upper: bool) -> String {
    let s = format!("{v:.prec$e}");
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let e = if upper { 'E' } else { 'e' };
    format!("{mant}{e}{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs())
}

fn format_float(v: f64, conv: char, prec: usize, alt: bool) -> String {
    if v.is_infinite() {
        return if conv.is_ascii_uppercase() { "INF".into() } else { "inf".into() };
    }
    if v.is_nan() {
        return if conv.is_ascii_uppercase() { "NAN".into() } else { "nan".into() };
    }
    match conv {
        'f' | 'F' => format!("{v:.prec$}"),
        'e' | 'E' => format_exp(v, prec, conv == 'E'),
        _ => {
            // %g: %e if the exponent is < -4 or >= precision, else %f; trailing zeros removed.
            let p = if prec == 0 { 1 } else { prec };
            let exp = if v == 0.0 { 0 } else { format!("{v:.*e}", p - 1).split_once('e').and_then(|(_, e)| e.parse::<i32>().ok()).unwrap_or(0) };
            let mut s = if exp < -4 || exp >= p as i32 {
                format_exp(v, p - 1, conv == 'G')
            } else {
                format!("{v:.*}", (p as i32 - 1 - exp).max(0) as usize)
            };
            if !alt {
                let (num, suffix) = match s.find(['e', 'E']) {
                    Some(k) => (s[..k].to_string(), s[k..].to_string()),
                    None => (s.clone(), String::new()),
                };
                let num = if num.contains('.') { num.trim_end_matches('0').trim_end_matches('.').to_string() } else { num };
                s = format!("{num}{suffix}");
            }
            s
        }
    }
}

/// A numeric operand: decimal, `0x` hex, `0` octal, or `'c`/`"c` for a character's code.
fn parse_int(sh: &Shell, a: &str, status: &mut i32) -> i64 {
    if let Some(rest) = a.strip_prefix('\'').or_else(|| a.strip_prefix('"')) {
        return rest.chars().next().map(|c| c as i64).unwrap_or(0);
    }
    let t = a.trim_start();
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let (radix, digits) = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        (16, h)
    } else if body.len() > 1 && body.starts_with('0') {
        (8, &body[1..])
    } else {
        (10, body)
    };
    let end = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
    let v = i64::from_str_radix(&digits[..end], radix).unwrap_or(0);
    if end != digits.len() || digits.is_empty() {
        sh.error(&format!("printf: {a}: {}", if end == 0 { "expected numeric value" } else { "not completely converted" }));
        *status = 1;
    }
    if neg { -v } else { v }
}

fn parse_float(sh: &Shell, a: &str, status: &mut i32) -> f64 {
    if let Some(rest) = a.strip_prefix('\'').or_else(|| a.strip_prefix('"')) {
        return rest.chars().next().map(|c| c as u32 as f64).unwrap_or(0.0);
    }
    match a.trim().parse::<f64>() {
        Ok(v) => v,
        Err(_) => {
            sh.error(&format!("printf: {a}: expected numeric value"));
            *status = 1;
            0.0
        }
    }
}
