//! Built-in utilities. The special built-ins (XCU 2.14) differ from the regular ones in that
//! assignments before them persist and their errors end a non-interactive shell.

use crate::exec::quote;
use crate::shell::{Exec, Flow, Options, Shell, Var};
use crate::sys;

pub type Builtin = fn(&mut Shell, &[String]) -> Exec;

const SPECIAL: &[(&str, Builtin)] = &[
    (":", colon),
    (".", dot),
    ("break", break_),
    ("continue", continue_),
    ("eval", eval),
    ("exec", exec),
    ("exit", exit),
    ("export", export),
    ("readonly", readonly),
    ("return", return_),
    ("set", set),
    ("shift", shift),
    ("times", times),
    ("trap", trap),
    ("unset", unset),
];

const REGULAR: &[(&str, Builtin)] = &[
    ("[", test),
    ("cd", cd),
    ("command", command),
    ("echo", echo),
    ("false", false_),
    ("getopts", getopts),
    ("hash", hash),
    ("kill", kill),
    ("local", local),
    ("printf", crate::printf::printf),
    ("pwd", pwd),
    ("read", read),
    ("test", test),
    ("true", colon),
    ("type", type_),
    ("umask", umask),
    ("wait", wait),
];

pub fn lookup_special(name: &str) -> Option<Builtin> {
    SPECIAL.iter().find(|(n, _)| *n == name).map(|&(_, b)| b)
}

pub fn lookup_regular(name: &str) -> Option<Builtin> {
    REGULAR.iter().find(|(n, _)| *n == name).map(|&(_, b)| b)
}

fn out(s: &str) {
    let _ = sys::write_all(1, s.as_bytes());
}

/// A special built-in's usage error: fatal (XCU 2.8.1).
fn fatal(sh: &Shell, msg: &str) -> Exec {
    sh.error(msg);
    Err(Flow::Exit(2))
}

fn colon(_: &mut Shell, _: &[String]) -> Exec {
    Ok(0)
}

fn false_(_: &mut Shell, _: &[String]) -> Exec {
    Ok(1)
}

fn hash(_: &mut Shell, _: &[String]) -> Exec {
    // Commands aren't cached, so there is nothing to remember or forget.
    Ok(0)
}

fn dot(sh: &mut Shell, args: &[String]) -> Exec {
    let Some(file) = args.get(1) else { return fatal(sh, ".: filename argument required") };
    let path = if file.contains('/') {
        file.clone()
    } else {
        let search = sh.get("PATH").unwrap_or_default();
        match search.split(':').map(|d| format!("{}/{file}", if d.is_empty() { "." } else { d })).find(|p| std::path::Path::new(p).is_file()) {
            Some(p) => p,
            None => return fatal(sh, &format!(".: {file}: not found")),
        }
    };
    let source = match std::fs::read(&path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return fatal(sh, &format!(".: cannot open {path}: {}", sys::strerror(&e))),
    };
    let list = match crate::parse(&source) {
        Ok(l) => l,
        Err(e) => return fatal(sh, &format!("{path}: {e}")),
    };
    let saved_pos = if args.len() > 2 { Some(std::mem::replace(&mut sh.positional, args[2..].to_vec())) } else { None };
    sh.return_depth += 1;
    let r = sh.run_list(&list);
    sh.return_depth -= 1;
    if let Some(p) = saved_pos {
        sh.positional = p;
    }
    match r {
        Err(Flow::Return(s)) => Ok(s),
        other => other,
    }
}

fn loop_count(sh: &Shell, args: &[String], what: &str) -> Result<usize, Flow> {
    match args.get(1) {
        None => Ok(1),
        Some(a) => match a.parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => {
                sh.error(&format!("{what}: illegal number: {a}"));
                Err(Flow::Exit(2))
            }
        },
    }
}

fn break_(sh: &mut Shell, args: &[String]) -> Exec {
    let n = loop_count(sh, args, "break")?;
    if sh.loop_depth == 0 {
        return Ok(0);
    }
    Err(Flow::Break(n.min(sh.loop_depth)))
}

fn continue_(sh: &mut Shell, args: &[String]) -> Exec {
    let n = loop_count(sh, args, "continue")?;
    if sh.loop_depth == 0 {
        return Ok(0);
    }
    Err(Flow::Continue(n.min(sh.loop_depth)))
}

fn eval(sh: &mut Shell, args: &[String]) -> Exec {
    let source = args[1..].join(" ");
    match crate::parse(&source) {
        Ok(list) => {
            sh.status = 0;
            sh.run_list(&list)
        }
        Err(e) => fatal(sh, &format!("eval: syntax error: {e}")),
    }
}

fn exec(sh: &mut Shell, args: &[String]) -> Exec {
    let fields = &args[1..];
    let Some(path) = sh.find_command(&fields[0]) else {
        sh.error(&format!("exec: {}: not found", fields[0]));
        return Err(Flow::Exit(127));
    };
    let env = sh.environment(&[]);
    let err = sys::execve(&path, fields, &env);
    sh.error(&format!("exec: {}: {}", fields[0], sys::strerror(&err)));
    Err(Flow::Exit(if err.raw_os_error() == Some(libc::ENOENT) { 127 } else { 126 }))
}

fn exit(sh: &mut Shell, args: &[String]) -> Exec {
    let status = match args.get(1) {
        None => sh.status,
        Some(a) => match a.parse::<i64>() {
            Ok(n) => (n & 0xff) as i32,
            Err(_) => return fatal(sh, &format!("exit: illegal number: {a}")),
        },
    };
    Err(Flow::Exit(status))
}

fn return_(sh: &mut Shell, args: &[String]) -> Exec {
    let status = match args.get(1) {
        None => sh.status,
        Some(a) => match a.parse::<i64>() {
            Ok(n) => (n & 0xff) as i32,
            Err(_) => return fatal(sh, &format!("return: illegal number: {a}")),
        },
    };
    Err(Flow::Return(status))
}

/// `export`/`readonly`: `name[=value]...` or `-p`.
fn export_like(sh: &mut Shell, args: &[String], cmd: &str, apply: fn(&mut Var)) -> Exec {
    let mut rest = &args[1..];
    if rest.first().is_some_and(|a| a == "--") {
        rest = &rest[1..];
    }
    if rest.is_empty() || (rest.len() == 1 && rest[0] == "-p") {
        let mut names: Vec<&String> = sh
            .vars
            .iter()
            .filter(|(_, v)| if cmd == "export" { v.exported } else { v.readonly })
            .map(|(k, _)| k)
            .collect();
        names.sort();
        let mut s = String::new();
        for n in names {
            match &sh.vars[n].value {
                Some(v) => s.push_str(&format!("{cmd} {n}={}\n", quote(v))),
                None => s.push_str(&format!("{cmd} {n}\n")),
            }
        }
        out(&s);
        return Ok(0);
    }
    for a in rest {
        let (name, value) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (a.as_str(), None),
        };
        if !crate::parse::is_name(name) {
            return fatal(sh, &format!("{cmd}: {name}: bad variable name"));
        }
        if let Some(v) = value
            && let Err(e) = sh.set(name, v)
        {
            return fatal(sh, &e);
        }
        apply(sh.vars.entry(name.to_string()).or_default());
    }
    Ok(0)
}

fn export(sh: &mut Shell, args: &[String]) -> Exec {
    export_like(sh, args, "export", |v| v.exported = true)
}

fn readonly(sh: &mut Shell, args: &[String]) -> Exec {
    export_like(sh, args, "readonly", |v| v.readonly = true)
}

fn set(sh: &mut Shell, args: &[String]) -> Exec {
    if args.len() == 1 {
        let mut names: Vec<(&String, &Var)> = sh.vars.iter().filter(|(_, v)| v.value.is_some()).collect();
        names.sort_by(|a, b| a.0.cmp(b.0));
        let s: String = names.iter().map(|(k, v)| format!("{k}={}\n", quote(v.value.as_deref().unwrap_or("")))).collect();
        out(&s);
        return Ok(0);
    }
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            sh.positional = args[i + 1..].to_vec();
            return Ok(0);
        }
        if a == "-" {
            sh.opts.xtrace = false;
            sh.opts.verbose = false;
            i += 1;
            break;
        }
        let (on, flags) = match (a.strip_prefix('-'), a.strip_prefix('+')) {
            (Some(f), _) if !f.is_empty() => (true, f),
            (_, Some(f)) if !f.is_empty() => (false, f),
            _ => break,
        };
        for c in flags.chars() {
            if c == 'o' {
                i += 1;
                match args.get(i) {
                    None => {
                        let mut s = String::new();
                        for &(l, name) in Options::LETTERS {
                            let mut o = sh.opts;
                            let v = o.flag_mut(l).is_some_and(|f| *f);
                            if on {
                                s.push_str(&format!("{name:<16}{}\n", if v { "on" } else { "off" }));
                            } else {
                                s.push_str(&format!("set {}o {name}\n", if v { '-' } else { '+' }));
                            }
                        }
                        out(&s);
                        return Ok(0);
                    }
                    Some(name) => match Options::letter_for(name).and_then(|l| sh.opts.flag_mut(l)) {
                        Some(f) => *f = on,
                        None => return fatal(sh, &format!("set: illegal option name: {name}")),
                    },
                }
            } else if let Some(f) = sh.opts.flag_mut(c) {
                *f = on;
            } else {
                return fatal(sh, &format!("set: illegal option -{c}"));
            }
        }
        i += 1;
    }
    if i < args.len() {
        sh.positional = args[i..].to_vec();
    }
    Ok(0)
}

fn shift(sh: &mut Shell, args: &[String]) -> Exec {
    let n = match args.get(1) {
        None => 1,
        Some(a) => match a.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return fatal(sh, &format!("shift: illegal number: {a}")),
        },
    };
    if n > sh.positional.len() {
        return fatal(sh, "shift: can't shift that many");
    }
    sh.positional.drain(..n);
    Ok(0)
}

fn times(_: &mut Shell, _: &[String]) -> Exec {
    let mut t: libc::tms = unsafe { std::mem::zeroed() };
    unsafe { libc::times(&mut t) };
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let f = |ticks: libc::clock_t| {
        let secs = ticks as f64 / hz;
        format!("{}m{:.6}s", (secs / 60.0) as u64, secs % 60.0)
    };
    out(&format!("{} {}\n{} {}\n", f(t.tms_utime), f(t.tms_stime), f(t.tms_cutime), f(t.tms_cstime)));
    Ok(0)
}

fn trap(sh: &mut Shell, args: &[String]) -> Exec {
    let mut rest = &args[1..];
    if rest.first().is_some_and(|a| a == "--") {
        rest = &rest[1..];
    }
    if rest.is_empty() || (rest.len() == 1 && rest[0] == "-p") {
        let mut sigs: Vec<(&i32, &String)> = sh.traps.iter().collect();
        sigs.sort();
        let s: String = sigs
            .iter()
            .map(|(sig, action)| {
                let name = if **sig == 0 { "EXIT".to_string() } else { sys::signal_name(**sig).map(String::from).unwrap_or_else(|| sig.to_string()) };
                format!("trap -- {} {name}\n", quote(action))
            })
            .collect();
        out(&s);
        return Ok(0);
    }
    // `trap sig...` with a numeric first operand resets those signals.
    let (action, sigs) = if rest[0].parse::<u32>().is_ok() { (None, rest) } else { (Some(rest[0].as_str()), &rest[1..]) };
    let mut status = 0;
    for s in sigs {
        let num = if s == "EXIT" || s == "0" { Some(0) } else { sys::signal_number(s) };
        let Some(num) = num.filter(|&n| n == 0 || (1..65).contains(&n) && n != libc::SIGKILL && n != libc::SIGSTOP) else {
            sh.error(&format!("trap: {s}: bad trap"));
            status = 1;
            continue;
        };
        match action {
            None | Some("-") => {
                sh.traps.remove(&num);
                if num != 0 {
                    unsafe { libc::signal(num, libc::SIG_DFL) };
                }
            }
            Some(a) => {
                sh.traps.insert(num, a.to_string());
                if num != 0 {
                    let handler = if a.is_empty() { libc::SIG_IGN } else { crate::shell::trap_handler as *const () as libc::sighandler_t };
                    unsafe { libc::signal(num, handler) };
                }
            }
        }
    }
    Ok(status)
}

fn unset(sh: &mut Shell, args: &[String]) -> Exec {
    let mut functions = false;
    let mut names = &args[1..];
    while let Some(a) = names.first() {
        match a.as_str() {
            "-f" => functions = true,
            "-v" => functions = false,
            "--" => {
                names = &names[1..];
                break;
            }
            _ => break,
        }
        names = &names[1..];
    }
    for n in names {
        if functions {
            sh.functions.remove(n);
        } else if let Err(e) = sh.unset(n) {
            return fatal(sh, &format!("unset: {e}"));
        }
    }
    Ok(0)
}

fn echo(_: &mut Shell, args: &[String]) -> Exec {
    // XSI echo, as dash and POSIX's XSI option have it: `-n` as the first operand, and
    // backslash escapes always interpreted.
    let (newline, words) = if args.get(1).is_some_and(|a| a == "-n") { (false, &args[2..]) } else { (true, &args[1..]) };
    let mut s = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        if crate::printf::push_escaped(&mut s, w, true) {
            let _ = sys::write_all(1, &crate::printf::to_bytes(&s));
            return Ok(0);
        }
    }
    if newline {
        s.push('\n');
    }
    let _ = sys::write_all(1, &crate::printf::to_bytes(&s));
    Ok(0)
}

fn cd(sh: &mut Shell, args: &[String]) -> Exec {
    let mut physical = false;
    let mut rest = &args[1..];
    while let Some(a) = rest.first() {
        match a.as_str() {
            "-P" => physical = true,
            "-L" => physical = false,
            "--" => {
                rest = &rest[1..];
                break;
            }
            _ => break,
        }
        rest = &rest[1..];
    }
    let mut print = false;
    let target = match rest.first().map(String::as_str) {
        None => match sh.get("HOME") {
            Some(h) if !h.is_empty() => h,
            _ => {
                sh.error("cd: HOME not set");
                return Ok(1);
            }
        },
        Some("-") => match sh.get("OLDPWD") {
            Some(o) => {
                print = true;
                o
            }
            None => {
                sh.error("cd: OLDPWD not set");
                return Ok(1);
            }
        },
        Some(d) => d.to_string(),
    };
    // CDPATH applies to a relative name that doesn't start with `.` or `..`.
    let mut candidates = Vec::new();
    let first = target.split('/').next().unwrap_or("");
    if !target.starts_with('/') && first != "." && first != ".." {
        if let Some(cdpath) = sh.get("CDPATH") {
            for d in cdpath.split(':') {
                if d.is_empty() {
                    candidates.push((target.clone(), false));
                } else {
                    candidates.push((format!("{}/{target}", d.trim_end_matches('/')), true));
                }
            }
        }
    }
    candidates.push((target.clone(), false));
    let old = sh.get("PWD").unwrap_or_default();
    for (dir, from_cdpath) in candidates {
        let logical = if physical { None } else { Some(logical_path(&old, &dir)) };
        let try_path = logical.clone().unwrap_or_else(|| dir.clone());
        if std::env::set_current_dir(&try_path).is_ok() {
            let new_pwd = match logical {
                Some(l) => l,
                None => std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)).unwrap_or(try_path),
            };
            let _ = sh.set("OLDPWD", &old);
            let _ = sh.set("PWD", &new_pwd);
            if print || from_cdpath {
                out(&format!("{new_pwd}\n"));
            }
            return Ok(0);
        }
    }
    let err = std::env::set_current_dir(&target).err().map(|e| sys::strerror(&e)).unwrap_or_default();
    sh.error(&format!("cd: can't cd to {target}: {err}"));
    Ok(2)
}

/// `cd -L`'s canonical path: `dir` resolved against `pwd` with `.` and `..` removed textually.
fn logical_path(pwd: &str, dir: &str) -> String {
    let full = if dir.starts_with('/') || pwd.is_empty() { dir.to_string() } else { format!("{pwd}/{dir}") };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn pwd(sh: &mut Shell, args: &[String]) -> Exec {
    let physical = args.iter().skip(1).any(|a| a == "-P");
    let logical = sh.get("PWD").filter(|p| p.starts_with('/'));
    let p = match (physical, logical) {
        (false, Some(l)) => l,
        _ => match std::env::current_dir() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                sh.error(&format!("pwd: {}", sys::strerror(&e)));
                return Ok(1);
            }
        },
    };
    out(&format!("{p}\n"));
    Ok(0)
}

fn command(sh: &mut Shell, args: &[String]) -> Exec {
    let mut i = 1;
    let mut verbose = None;
    let mut default_path = false;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-v" => verbose = Some(false),
            "-V" => verbose = Some(true),
            "-p" => default_path = true,
            "--" => {
                i += 1;
                break;
            }
            _ => break,
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.is_empty() {
        return Ok(0);
    }
    if let Some(v) = verbose {
        let mut status = 0;
        for name in rest {
            if describe(sh, name, v).is_none() {
                if v {
                    sh.error(&format!("{name}: not found"));
                }
                status = 127;
            }
        }
        return Ok(status);
    }
    if default_path {
        let saved = sh.vars.get("PATH").cloned();
        let _ = sh.set("PATH", "/bin:/usr/bin:/sbin:/usr/sbin");
        let r = sh.run_fields_no_functions(rest);
        match saved {
            Some(v) => {
                sh.vars.insert("PATH".into(), v);
            }
            None => {
                sh.vars.remove("PATH");
            }
        }
        return r;
    }
    sh.run_fields_no_functions(rest)
}

/// `command -v` (`verbose == false`) and `command -V`/`type` output for one name.
fn describe(sh: &Shell, name: &str, verbose: bool) -> Option<()> {
    let line = if let Some(kind) = sh.builtin_kind(name) {
        if verbose { format!("{name} is a {kind}") } else { name.to_string() }
    } else {
        let path = sh.find_command(name).filter(|p| !name.contains('/') || sys::is_executable_file(p))?;
        if verbose { format!("{name} is {path}") } else { path }
    };
    out(&format!("{line}\n"));
    Some(())
}

fn type_(sh: &mut Shell, args: &[String]) -> Exec {
    let mut status = 0;
    for name in &args[1..] {
        if describe(sh, name, true).is_none() {
            out(&format!("{name}: not found\n"));
            status = 127;
        }
    }
    Ok(status)
}

fn local(sh: &mut Shell, args: &[String]) -> Exec {
    if sh.local_frames.is_empty() {
        sh.error("local: not in a function");
        return Ok(1);
    }
    for a in &args[1..] {
        let (name, value) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (a.as_str(), None),
        };
        if !crate::parse::is_name(name) {
            sh.error(&format!("local: {name}: bad variable name"));
            return Ok(1);
        }
        let frame = sh.local_frames.last_mut().unwrap();
        if !frame.iter().any(|(n, _)| n == name) {
            frame.push((name.to_string(), sh.vars.get(name).cloned()));
        }
        if let Some(v) = value
            && let Err(e) = sh.set(name, v)
        {
            sh.error(&e);
            return Ok(1);
        }
    }
    Ok(0)
}

fn read(sh: &mut Shell, args: &[String]) -> Exec {
    let mut raw = false;
    let mut i = 1;
    while let Some(a) = args.get(i) {
        if a == "-r" {
            raw = true;
        } else if a == "--" {
            i += 1;
            break;
        } else {
            break;
        }
        i += 1;
    }
    let names = &args[i..];
    if names.is_empty() {
        sh.error("read: arg count");
        return Ok(2);
    }
    // One byte at a time: bytes past the newline belong to whoever reads the descriptor next.
    let mut bytes = Vec::new();
    // Positions (in the decoded line) of characters protected by a backslash.
    let mut escaped_at = Vec::new();
    let mut eof = false;
    loop {
        match sys::read_byte(0) {
            Ok(Some(b'\\')) if !raw => match sys::read_byte(0) {
                Ok(Some(b'\n')) => continue,
                Ok(Some(b)) => {
                    escaped_at.push(bytes.len());
                    bytes.push(b);
                }
                _ => {
                    eof = true;
                    break;
                }
            },
            Ok(Some(b'\n')) => break,
            Ok(Some(b)) => bytes.push(b),
            Ok(None) => {
                eof = true;
                break;
            }
            Err(e) => {
                sh.error(&format!("read: {}", sys::strerror(&e)));
                return Ok(2);
            }
        }
    }
    let line: Vec<(char, bool)> = bytes.iter().enumerate().map(|(i, &b)| (b as char, escaped_at.contains(&i))).collect();
    let line: Vec<(char, bool)> = if bytes.is_ascii() {
        line
    } else {
        // Non-ASCII input: decode as UTF-8 (escape positions are only meaningful for ASCII).
        String::from_utf8_lossy(&bytes).chars().map(|c| (c, false)).collect()
    };
    let ifs = sh.ifs();
    let fields = split_read(&line, &ifs, names.len());
    for (k, name) in names.iter().enumerate() {
        let v = fields.get(k).cloned().unwrap_or_default();
        if let Err(e) = sh.set(name, &v) {
            sh.error(&format!("read: {e}"));
            return Ok(2);
        }
    }
    Ok(if eof { 1 } else { 0 })
}

/// Field splitting for `read`: at most `n` fields; the last gets the remainder of the line with
/// leading and trailing IFS whitespace removed.
fn split_read(line: &[(char, bool)], ifs: &str, n: usize) -> Vec<String> {
    let is_ifs = |&(c, esc): &(char, bool)| !esc && ifs.contains(c);
    let is_ws = |&(c, esc): &(char, bool)| !esc && ifs.contains(c) && matches!(c, ' ' | '\t' | '\n');
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() && is_ws(&line[i]) {
        i += 1;
    }
    while i < line.len() {
        if out.len() + 1 == n {
            let mut end = line.len();
            while end > i && is_ws(&line[end - 1]) {
                end -= 1;
            }
            // A single trailing non-whitespace delimiter is also dropped, as in dash.
            let rest: Vec<(char, bool)> = line[i..end].to_vec();
            let mut s: String = rest.iter().map(|&(c, _)| c).collect();
            if let Some(&last) = rest.last()
                && is_ifs(&last)
                && !is_ws(&last)
                && !rest[..rest.len() - 1].iter().any(|x| is_ifs(x))
            {
                s.pop();
            }
            out.push(s);
            return out;
        }
        let start = i;
        while i < line.len() && !is_ifs(&line[i]) {
            i += 1;
        }
        out.push(line[start..i].iter().map(|&(c, _)| c).collect());
        // Skip one delimiter: surrounding whitespace plus at most one non-whitespace IFS char.
        while i < line.len() && is_ws(&line[i]) {
            i += 1;
        }
        if i < line.len() && is_ifs(&line[i]) && !is_ws(&line[i]) {
            i += 1;
            while i < line.len() && is_ws(&line[i]) {
                i += 1;
            }
        }
    }
    out
}

fn getopts(sh: &mut Shell, args: &[String]) -> Exec {
    if args.len() < 3 {
        sh.error("getopts: usage: getopts optstring var [arg...]");
        return Ok(2);
    }
    let optstring = args[1].as_str();
    let var = args[2].as_str();
    let params: Vec<String> = if args.len() > 3 { args[3..].to_vec() } else { sh.positional.clone() };
    let silent = optstring.starts_with(':');
    let spec = optstring.trim_start_matches(':');
    let optind: usize = sh.get("OPTIND").and_then(|v| v.parse().ok()).filter(|&n| n >= 1).unwrap_or(1);
    let mut char_pos = sh.getopts_char;

    let finish = |sh: &mut Shell, optind: usize, char_pos: usize, name: &str, arg: Option<&str>, status: i32| -> Exec {
        let _ = sh.set("OPTIND", &optind.to_string());
        sh.getopts_char = char_pos;
        match arg {
            Some(a) => {
                let _ = sh.set("OPTARG", a);
            }
            None => {
                let _ = sh.unset("OPTARG");
            }
        }
        if let Err(e) = sh.set(var, name) {
            sh.error(&e);
            return Ok(2);
        }
        Ok(status)
    };

    let Some(cur) = params.get(optind - 1) else { return finish(sh, optind, 0, "?", None, 1) };
    if char_pos == 0 {
        if cur == "--" {
            return finish(sh, optind + 1, 0, "?", None, 1);
        }
        if !cur.starts_with('-') || cur == "-" {
            return finish(sh, optind, 0, "?", None, 1);
        }
        char_pos = 1;
    }
    let chars: Vec<char> = cur.chars().collect();
    let c = chars[char_pos];
    char_pos += 1;
    let at_end = char_pos >= chars.len();
    let (next_ind, next_pos) = if at_end { (optind + 1, 0) } else { (optind, char_pos) };
    let known = spec.find(c).filter(|_| c != ':');
    let Some(idx) = known else {
        if silent {
            return finish(sh, next_ind, next_pos, "?", Some(&c.to_string()), 0);
        }
        sh.error(&format!("Illegal option -{c}"));
        return finish(sh, next_ind, next_pos, "?", None, 0);
    };
    if spec[idx + 1..].starts_with(':') {
        if !at_end {
            let optarg: String = chars[char_pos..].iter().collect();
            return finish(sh, optind + 1, 0, &c.to_string(), Some(&optarg), 0);
        }
        match params.get(optind) {
            Some(a) => {
                let a = a.clone();
                return finish(sh, optind + 2, 0, &c.to_string(), Some(&a), 0);
            }
            None => {
                if silent {
                    return finish(sh, optind + 1, 0, ":", Some(&c.to_string()), 0);
                }
                sh.error(&format!("No arg for -{c} option"));
                return finish(sh, optind + 1, 0, "?", None, 0);
            }
        }
    }
    finish(sh, next_ind, next_pos, &c.to_string(), None, 0)
}

fn umask(sh: &mut Shell, args: &[String]) -> Exec {
    let symbolic = args.get(1).is_some_and(|a| a == "-S");
    let operand = args.iter().skip(1).find(|a| *a != "-S");
    let current = sys::umask(0);
    sys::umask(current);
    let Some(op) = operand else {
        if symbolic {
            let perm = |shift: u32| {
                let bits = !current >> shift & 7;
                format!("{}{}{}", if bits & 4 != 0 { "r" } else { "" }, if bits & 2 != 0 { "w" } else { "" }, if bits & 1 != 0 { "x" } else { "" })
            };
            out(&format!("u={},g={},o={}\n", perm(6), perm(3), perm(0)));
        } else {
            out(&format!("{current:04o}\n"));
        }
        return Ok(0);
    };
    let new = if op.chars().all(|c| c.is_digit(8)) {
        u32::from_str_radix(op, 8).ok()
    } else {
        symbolic_umask(current, op)
    };
    match new {
        Some(m) if m <= 0o777 => {
            sys::umask(m);
            Ok(0)
        }
        _ => {
            sh.error(&format!("umask: illegal mode: {op}"));
            Ok(1)
        }
    }
}

/// Applies a chmod-style symbolic mode (`u=rwx,g+w,o-rx`) to the *permissions* a mask allows.
fn symbolic_umask(mask: u32, spec: &str) -> Option<u32> {
    let mut perms = !mask & 0o777;
    for clause in spec.split(',') {
        let who_end = clause.find(['+', '-', '=']).unwrap_or(clause.len());
        let (who, ops) = clause.split_at(who_end);
        let mut who_bits = 0;
        for c in who.chars() {
            who_bits |= match c {
                'u' => 0o700,
                'g' => 0o070,
                'o' => 0o007,
                'a' => 0o777,
                _ => return None,
            };
        }
        if who_bits == 0 {
            who_bits = 0o777;
        }
        let mut chars = ops.chars().peekable();
        if chars.peek().is_none() {
            return None;
        }
        while let Some(op) = chars.next() {
            let mut bits = 0;
            while let Some(&c) = chars.peek() {
                bits |= match c {
                    'r' => 0o444,
                    'w' => 0o222,
                    'x' => 0o111,
                    '+' | '-' | '=' => break,
                    _ => return None,
                };
                chars.next();
            }
            let bits = bits & who_bits;
            match op {
                '+' => perms |= bits,
                '-' => perms &= !bits,
                '=' => perms = (perms & !who_bits) | bits,
                _ => return None,
            }
        }
    }
    Some(!perms & 0o777)
}

fn kill(sh: &mut Shell, args: &[String]) -> Exec {
    let mut sig = libc::SIGTERM;
    let mut i = 1;
    match args.get(1).map(String::as_str) {
        None => {
            sh.error("kill: usage: kill [-s sigspec | -signum] pid...");
            return Ok(2);
        }
        Some("-l") => {
            if let Some(st) = args.get(2) {
                let n: i32 = st.parse().unwrap_or(0);
                let n = if n > 128 { n - 128 } else { n };
                match sys::signal_name(n) {
                    Some(name) => out(&format!("{name}\n")),
                    None => {
                        sh.error(&format!("kill: invalid signal number or exit status: {st}"));
                        return Ok(1);
                    }
                }
            } else {
                let s: Vec<&str> = sys::SIGNALS.iter().map(|(n, _)| *n).collect();
                out(&format!("{}\n", s.join(" ")));
            }
            return Ok(0);
        }
        Some("-s") => {
            let Some(n) = args.get(2).and_then(|s| sys::signal_number(s)) else {
                sh.error("kill: invalid signal");
                return Ok(2);
            };
            sig = n;
            i = 3;
        }
        Some("--") => i = 2,
        Some(a) if a.starts_with('-') && a.len() > 1 => {
            let Some(n) = sys::signal_number(&a[1..]) else {
                sh.error(&format!("kill: invalid signal {a}"));
                return Ok(2);
            };
            sig = n;
            i = 2;
        }
        _ => {}
    }
    let mut status = 0;
    for p in &args[i..] {
        let Ok(pid) = p.parse::<i32>() else {
            sh.error(&format!("kill: illegal pid: {p}"));
            status = 1;
            continue;
        };
        if let Err(e) = sys::kill(pid, sig) {
            sh.error(&format!("kill: {pid}: {}", sys::strerror(&e)));
            status = 1;
        }
    }
    Ok(status)
}

fn wait(sh: &mut Shell, args: &[String]) -> Exec {
    if args.len() == 1 {
        for pid in std::mem::take(&mut sh.bg_pids) {
            let _ = sys::wait_pid(pid);
        }
        sh.bg_done.clear();
        return Ok(0);
    }
    let mut status = 0;
    for a in &args[1..] {
        let Ok(pid) = a.parse::<i32>() else {
            sh.error(&format!("wait: illegal pid: {a}"));
            status = 2;
            continue;
        };
        if let Some(s) = sh.bg_done.remove(&pid) {
            status = s;
        } else if let Some(pos) = sh.bg_pids.iter().position(|&p| p == pid) {
            sh.bg_pids.remove(pos);
            status = sys::wait_pid(pid).unwrap_or(127);
        } else {
            status = 127;
        }
    }
    Ok(status)
}

fn test(sh: &mut Shell, args: &[String]) -> Exec {
    let mut a: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    if args[0] == "[" {
        if a.last() != Some(&"]") {
            sh.error("[: missing ]");
            return Ok(2);
        }
        a.pop();
    }
    match crate::test::eval(&a) {
        Ok(true) => Ok(0),
        Ok(false) => Ok(1),
        Err(e) => {
            sh.error(&format!("{}: {e}", args[0]));
            Ok(2)
        }
    }
}
