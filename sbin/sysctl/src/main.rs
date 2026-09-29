//! `sysctl(8)`: reads and sets the kernel's variables (OxideBSD-doc `SYSCTL.md` §7), FreeBSD's
//! utility.
//!
//! ```text
//! sysctl [-bdehiNnoqtx] [-f file] name[=value[,value...]] ...
//! sysctl [-bdehNnoqtx] -a
//! ```
//!
//! The kernel describes its own tree: `{0, 2}` walks it, `{0, 1}` names an OID, `{0, 4}` gives
//! its type and format, `{0, 5}` its description, and `sysctlnametomib(3)` turns a name into an
//! OID. Values are printed by their format: numbers, strings, and the structures FreeBSD's
//! sysctl knows (`timeval`, `clockinfo`, `loadavg`, `vmtotal`).

use std::process::ExitCode;

mod mib;

use mib::Oid;

const CTLTYPE: u32 = 0xf;
const CTLTYPE_NODE: u32 = 1;
const CTLTYPE_INT: u32 = 2;
const CTLTYPE_STRING: u32 = 3;
const CTLTYPE_S64: u32 = 4;
const CTLTYPE_OPAQUE: u32 = 5;
const CTLTYPE_UINT: u32 = 6;
const CTLTYPE_LONG: u32 = 7;
const CTLTYPE_ULONG: u32 = 8;
const CTLTYPE_U64: u32 = 9;
const CTLFLAG_WR: u32 = 0x4000_0000;

const USAGE: &str = "usage: sysctl [-bdehiNnoqtx] [-f filename] name[=value] ...\n       sysctl [-bdehNnoqtx] -a";

#[derive(Default, Clone, Copy, Debug, PartialEq)]
struct Flags {
    all: bool,
    binary: bool,
    descr: bool,
    equals: bool,
    human: bool,
    ignore_unknown: bool,
    names_only: bool,
    values_only: bool,
    opaque_hex: bool,
    quiet: bool,
    types: bool,
    all_hex: bool,
}

#[derive(Debug, PartialEq)]
struct Args {
    flags: Flags,
    file: Option<String>,
    names: Vec<String>,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut flags = Flags::default();
    let mut file = None;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        let letters: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < letters.len() {
            match letters[j] {
                'a' | 'A' => flags.all = true,
                'b' => flags.binary = true,
                'd' => flags.descr = true,
                'e' => flags.equals = true,
                'h' => flags.human = true,
                'i' => flags.ignore_unknown = true,
                'N' => flags.names_only = true,
                'n' => flags.values_only = true,
                'o' => flags.opaque_hex = true,
                'q' => flags.quiet = true,
                't' => flags.types = true,
                'x' | 'X' => flags.all_hex = true,
                'f' => {
                    let rest: String = letters[j + 1..].iter().collect();
                    file = Some(if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        argv.get(i).cloned().ok_or("option requires an argument -- f")?
                    });
                    j = letters.len();
                    continue;
                }
                c => return Err(format!("illegal option -- {c}")),
            }
            j += 1;
        }
        i += 1;
    }
    let names = argv[i..].to_vec();
    if !flags.all && file.is_none() && names.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(Args { flags, file, names })
}

/// Splits `name=value`; `None` for a bare name.
fn split_assignment(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (arg, None),
    }
}

/// A value from `sysctl.conf`: surrounding quotes removed.
fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

/// The type name `-t` prints, as FreeBSD's sysctl names them.
fn type_name(kind: u32) -> &'static str {
    match kind & CTLTYPE {
        CTLTYPE_NODE => "node",
        CTLTYPE_INT => "integer",
        CTLTYPE_STRING => "string",
        CTLTYPE_S64 => "int64_t",
        CTLTYPE_OPAQUE => "opaque",
        CTLTYPE_UINT => "unsigned integer",
        CTLTYPE_LONG => "long integer",
        CTLTYPE_ULONG => "unsigned long",
        CTLTYPE_U64 => "uint64_t",
        _ => "unknown",
    }
}

/// `n` with thousands separators (`-h`).
fn human(n: i128) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

fn read_i32(b: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn read_i64(b: &[u8], at: usize) -> i64 {
    i64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

fn read_u64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

fn read_i16(b: &[u8], at: usize) -> i16 {
    i16::from_ne_bytes(b[at..at + 2].try_into().unwrap())
}

/// Seconds since the epoch as ctime(3) prints them, in UTC (no time zones yet: `TIMEZONE.md`).
fn ctime(t: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        d,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60,
        y
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A value as text, by its type and format; `None` for an opaque value of a structure this sysctl
/// doesn't know (FreeBSD skips those unless `-o`/`-x`).
fn format_value(kind: u32, fmt: &str, v: &[u8], f: &Flags) -> Option<String> {
    let num = |n: i128| if f.human { human(n) } else { n.to_string() };
    if f.all_hex && kind & CTLTYPE != CTLTYPE_STRING {
        return Some(format!("0x{}", hex(v)));
    }
    let text = match kind & CTLTYPE {
        CTLTYPE_STRING => {
            let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
            String::from_utf8_lossy(&v[..end]).into_owned()
        }
        CTLTYPE_INT => ints(v, 4, |b, at| read_i32(b, at) as i128, num),
        CTLTYPE_UINT => ints(v, 4, |b, at| read_u32(b, at) as i128, num),
        CTLTYPE_LONG | CTLTYPE_S64 => ints(v, 8, |b, at| read_i64(b, at) as i128, num),
        CTLTYPE_ULONG | CTLTYPE_U64 => ints(v, 8, |b, at| read_u64(b, at) as i128, num),
        CTLTYPE_OPAQUE => match (fmt, v.len()) {
            ("S,timeval", 16) => {
                let sec = read_i64(v, 0);
                format!("{{ sec = {}, usec = {} }} {}", sec, read_i64(v, 8), ctime(sec))
            }
            ("S,clockinfo", 20) => format!(
                "{{ hz = {}, tick = {}, profhz = {}, stathz = {} }}",
                read_i32(v, 0),
                read_i32(v, 4),
                read_i32(v, 16),
                read_i32(v, 12)
            ),
            ("S,loadavg", 24) => {
                let scale = read_i64(v, 16) as f64;
                format!(
                    "{{ {:.2} {:.2} {:.2} }}",
                    read_u32(v, 0) as f64 / scale,
                    read_u32(v, 4) as f64 / scale,
                    read_u32(v, 8) as f64 / scale
                )
            }
            ("S,vmtotal", 88) => vmtotal(v),
            _ if f.opaque_hex => format!("Format:{} Length:{} Dump:0x{}", fmt, v.len(), hex(v)),
            _ => return None,
        },
        _ => return None,
    };
    Some(text)
}

/// Integers of `width` bytes, space-separated (an array prints every element, as in FreeBSD).
fn ints(v: &[u8], width: usize, get: impl Fn(&[u8], usize) -> i128, num: impl Fn(i128) -> String) -> String {
    (0..v.len() / width).map(|i| num(get(v, i * width))).collect::<Vec<_>>().join(" ")
}

/// `vm.vmtotal` as FreeBSD's sysctl prints it: pages as kilobytes.
fn vmtotal(v: &[u8]) -> String {
    let kb = |i: usize| read_u64(v, i * 8) * 4;
    format!(
        "\nSystem wide totals computed every five seconds: (values in kilobytes)\n\
         ===============================================\n\
         Processes:\t\t(RUNQ: {} Disk Wait: {} Page Wait: {} Sleep: {})\n\
         Virtual Memory:\t\t(Total: {}K Active: {}K)\n\
         Real Memory:\t\t(Total: {}K Active: {}K)\n\
         Shared Virtual Memory:\t(Total: {}K Active: {}K)\n\
         Shared Real Memory:\t(Total: {}K Active: {}K)\n\
         Free Memory:\t{}K",
        read_i16(v, 72),
        read_i16(v, 74),
        read_i16(v, 76),
        read_i16(v, 78),
        kb(0),
        kb(1),
        kb(2),
        kb(3),
        kb(4),
        kb(5),
        kb(6),
        kb(7),
        kb(8)
    )
}

/// The bytes to write for `text` into a variable of `kind`: a string as is, numbers native-endian,
/// a comma-separated list for an array.
fn encode_value(kind: u32, text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let parse = |s: &str| -> Result<i128, String> {
        let s = s.trim();
        let (digits, radix) = match s.strip_prefix("0x") {
            Some(h) => (h, 16),
            None => (s, 10),
        };
        i128::from_str_radix(digits, radix).map_err(|_| format!("invalid integer '{s}'"))
    };
    match kind & CTLTYPE {
        CTLTYPE_STRING => return Ok(text.as_bytes().to_vec()),
        CTLTYPE_INT => {
            for s in text.split(',') {
                out.extend_from_slice(&i32::try_from(parse(s)?).map_err(|_| "value out of range")?.to_ne_bytes());
            }
        }
        CTLTYPE_UINT => {
            for s in text.split(',') {
                out.extend_from_slice(&u32::try_from(parse(s)?).map_err(|_| "value out of range")?.to_ne_bytes());
            }
        }
        CTLTYPE_LONG | CTLTYPE_S64 => {
            for s in text.split(',') {
                out.extend_from_slice(&i64::try_from(parse(s)?).map_err(|_| "value out of range")?.to_ne_bytes());
            }
        }
        CTLTYPE_ULONG | CTLTYPE_U64 => {
            for s in text.split(',') {
                out.extend_from_slice(&u64::try_from(parse(s)?).map_err(|_| "value out of range")?.to_ne_bytes());
            }
        }
        _ => return Err("setting a value of this type is not supported".into()),
    }
    Ok(out)
}

/// What `print_oid` writes for one variable, or `None` when it's skipped.
fn show(oid: &Oid, f: &Flags, explicit: bool) -> Option<String> {
    let name = mib::name(oid).ok()?;
    let (kind, fmt) = mib::format(oid).ok()?;
    if f.names_only {
        return Some(name);
    }
    let sep = if f.equals { "=" } else { ": " };
    if f.descr {
        let d = mib::description(oid).unwrap_or_default();
        return Some(if f.values_only { d } else { format!("{name}{sep}{d}") });
    }
    if f.types {
        let t = type_name(kind);
        return Some(if f.values_only { t.to_string() } else { format!("{name}{sep}{t}") });
    }
    let value = match mib::get(oid) {
        Ok(v) => v,
        Err(e) => {
            if explicit {
                eprintln!("sysctl: {name}: {e}");
            }
            return None;
        }
    };
    if f.binary {
        use std::io::Write;
        let _ = std::io::stdout().write_all(&value);
        return None;
    }
    let text = match format_value(kind, &fmt, &value, f) {
        Some(t) => t,
        // An unknown structure named explicitly is shown by its format, as FreeBSD does.
        None if explicit => format!("Format:{} Length:{}", fmt, value.len()),
        None => return None,
    };
    Some(if f.values_only { text } else { format!("{name}{sep}{text}") })
}

/// Prints `oid`, or every variable under it if it's a node.
fn print_tree(oid: &Oid, f: &Flags, explicit: bool) {
    let is_node = mib::format(oid).is_ok_and(|(k, _)| k & CTLTYPE == CTLTYPE_NODE);
    if !is_node {
        if let Some(line) = show(oid, f, explicit) {
            println!("{line}");
        }
        return;
    }
    let mut cur = oid.clone();
    while let Ok(next) = mib::next(&cur) {
        if !next.starts_with(oid) {
            break;
        }
        if let Some(line) = show(&next, f, false) {
            println!("{line}");
        }
        cur = next;
    }
}

/// Handles one command-line or file argument; `false` if it failed.
fn handle(arg: &str, f: &Flags, context: &str) -> bool {
    let (name, value) = split_assignment(arg);
    let oid = match mib::name_to_oid(name) {
        Ok(o) => o,
        Err(_) => {
            if !f.ignore_unknown && !f.quiet {
                eprintln!("sysctl: {context}unknown oid '{name}'");
            }
            return f.ignore_unknown;
        }
    };
    let Some(value) = value else {
        print_tree(&oid, f, true);
        return true;
    };
    let (kind, _) = match mib::format(&oid) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sysctl: {context}{name}: {e}");
            return false;
        }
    };
    if kind & CTLTYPE == CTLTYPE_NODE {
        eprintln!("sysctl: {context}oid '{name}' isn't a leaf node");
        return false;
    }
    if kind & CTLFLAG_WR == 0 {
        eprintln!("sysctl: {context}oid '{name}' is read only");
        return false;
    }
    let bytes = match encode_value(kind, value) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sysctl: {context}{name}: {e}");
            return false;
        }
    };
    let before = if f.quiet { None } else { show(&oid, &Flags { values_only: true, ..*f }, true) };
    if let Err(e) = mib::set(&oid, &bytes) {
        eprintln!("sysctl: {context}{name}={value}: {e}");
        return false;
    }
    if !f.quiet {
        let after = show(&oid, &Flags { values_only: true, ..*f }, true).unwrap_or_default();
        let before = before.unwrap_or_default();
        if f.values_only {
            println!("{after}");
        } else {
            println!("{name}: {before} -> {after}");
        }
    }
    true
}

/// `-f file`: `name=value` per line, `#` comments, blank lines skipped (`SYSCTL.md` §8).
fn parse_file(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = match line.find('#') {
            Some(at) => &line[..at],
            None => line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        let entry = match line.split_once('=') {
            Some((n, v)) => format!("{}={}", n.trim(), unquote(v)),
            None => line.to_string(),
        };
        out.push((i + 1, entry));
    }
    out
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", if e == USAGE { e } else { format!("sysctl: {e}\n{USAGE}") });
            return ExitCode::from(1);
        }
    };
    let f = args.flags;
    let mut ok = true;
    if let Some(path) = &args.file {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for (line, entry) in parse_file(&text) {
                    ok &= handle(&entry, &f, &format!("{path}:{line}: "));
                }
            }
            Err(e) => {
                eprintln!("sysctl: {path}: {e}");
                return ExitCode::from(1);
            }
        }
    }
    if f.all {
        let mut cur = Vec::new();
        while let Ok(next) = mib::next(&cur) {
            if let Some(line) = show(&next, &f, false) {
                println!("{line}");
            }
            cur = next;
        }
    }
    for arg in &args.names {
        ok &= handle(arg, &f, "");
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Result<Args, String> {
        parse_args(&s.iter().map(|x| x.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn options() {
        let a = args(&["-an"]).unwrap();
        assert!(a.flags.all && a.flags.values_only);
        let a = args(&["-f", "/etc/sysctl.conf", "-q"]).unwrap();
        assert_eq!(a.file.as_deref(), Some("/etc/sysctl.conf"));
        assert!(a.flags.quiet && a.names.is_empty(), "options go on after -f's argument");
        let a = args(&["kern.hz", "-q"]).unwrap();
        assert_eq!(a.names, ["kern.hz", "-q"], "options end at the first operand");
        let a = args(&["-f/x", "kern.hz"]).unwrap();
        assert_eq!(a.file.as_deref(), Some("/x"));
        assert_eq!(a.names, ["kern.hz"]);
        assert!(args(&[]).is_err());
        assert!(args(&["-z", "kern"]).is_err());
    }

    #[test]
    fn numbers_and_strings() {
        let f = Flags::default();
        assert_eq!(format_value(CTLTYPE_INT, "I", &100i32.to_ne_bytes(), &f).unwrap(), "100");
        assert_eq!(format_value(CTLTYPE_STRING, "A", b"OxideBSD\0", &f).unwrap(), "OxideBSD");
        let h = Flags { human: true, ..f };
        assert_eq!(format_value(CTLTYPE_ULONG, "LU", &8_589_934_592u64.to_ne_bytes(), &h).unwrap(), "8,589,934,592");
        assert_eq!(human(-1234), "-1,234");
        assert_eq!(human(999), "999");
    }

    #[test]
    fn structures() {
        let f = Flags::default();
        let mut tv = 1_790_000_000i64.to_ne_bytes().to_vec();
        tv.extend_from_slice(&5i64.to_ne_bytes());
        assert_eq!(
            format_value(CTLTYPE_OPAQUE, "S,timeval", &tv, &f).unwrap(),
            "{ sec = 1790000000, usec = 5 } Mon Sep 21 14:13:20 2026"
        );
        let ci: Vec<u8> = [100i32, 10000, 0, 128, 1024].iter().flat_map(|v| v.to_ne_bytes()).collect();
        assert_eq!(
            format_value(CTLTYPE_OPAQUE, "S,clockinfo", &ci, &f).unwrap(),
            "{ hz = 100, tick = 10000, profhz = 1024, stathz = 128 }"
        );
        let mut la: Vec<u8> = [2048u32, 1024, 0].iter().flat_map(|v| v.to_ne_bytes()).collect();
        la.extend_from_slice(&[0; 4]);
        la.extend_from_slice(&2048i64.to_ne_bytes());
        assert_eq!(format_value(CTLTYPE_OPAQUE, "S,loadavg", &la, &f).unwrap(), "{ 1.00 0.50 0.00 }");
        assert_eq!(format_value(CTLTYPE_OPAQUE, "S,mystery", &[1, 2], &f), None);
        let o = Flags { opaque_hex: true, ..f };
        assert_eq!(format_value(CTLTYPE_OPAQUE, "S,mystery", &[1, 2], &o).unwrap(), "Format:S,mystery Length:2 Dump:0x0102");
    }

    #[test]
    fn epoch() {
        assert_eq!(ctime(0), "Thu Jan  1 00:00:00 1970");
        assert_eq!(ctime(951_782_400), "Tue Feb 29 00:00:00 2000");
    }

    #[test]
    fn encoding() {
        assert_eq!(encode_value(CTLTYPE_INT, "7").unwrap(), 7i32.to_ne_bytes());
        assert_eq!(encode_value(CTLTYPE_INT, "0x10").unwrap(), 16i32.to_ne_bytes());
        assert_eq!(encode_value(CTLTYPE_INT, "1,2").unwrap().len(), 8);
        assert!(encode_value(CTLTYPE_UINT, "-1").is_err());
        assert!(encode_value(CTLTYPE_INT, "x").is_err());
        assert_eq!(encode_value(CTLTYPE_STRING, "host").unwrap(), b"host");
    }

    #[test]
    fn conf_file() {
        let text = "# comment\n\nkern.hostname = \"box\" # trailing\nvm.foo=1\n";
        assert_eq!(parse_file(text), vec![(3, "kern.hostname=box".to_string()), (4, "vm.foo=1".to_string())]);
    }
}
