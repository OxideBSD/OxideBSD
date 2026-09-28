//! `man(1)`: finds manual pages by name and section, formats them with liboxdoc, and shows them
//! through the pager (MAN.md §8 in OxideBSD-doc).
//!
//! ```text
//! man [-acfhklw] [-C file] [-M path] [-m path] [-S subsection] [[-s] section] name ...
//! ```

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use liboxdoc::term::Styling;
use liboxdoc::{Device, Options};

const USAGE: &str = "usage: man [-acfhklw] [-C file] [-M path] [-m path] [-S subsection]\n\t   [[-s] section] name ...";
/// The order sections are searched in when none is given (MAN.md §8.2).
const SECTIONS: &[&str] = &["1", "8", "6", "2", "3", "5", "7", "4", "9"];
/// Exit status for a usage error or a page not found, as mandoc's man.
const NOT_FOUND: u8 = 5;

struct Args {
    all: bool,
    no_pager: bool,
    synopsis: bool,
    local: bool,
    where_only: bool,
    apropos: Option<&'static str>,
    conf: Option<String>,
    manpath: Option<String>,
    extra: Vec<String>,
    arch: Option<String>,
    section: Option<String>,
    names: Vec<String>,
    /// `-T`, `-O` and `-W`, passed to the formatter.
    formatter: Vec<(char, String)>,
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(NOT_FOUND)
}

fn parse_args() -> Result<Args, ()> {
    let mut a = Args { all: false, no_pager: false, synopsis: false, local: false, where_only: false, apropos: None, conf: None, manpath: None, extra: Vec::new(), arch: None, section: None, names: Vec::new(), formatter: Vec::new() };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "--" {
            a.names.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            a.names.push(arg.clone());
            i += 1;
            continue;
        }
        let flags: Vec<char> = arg[1..].chars().collect();
        let mut k = 0;
        while k < flags.len() {
            let f = flags[k];
            match f {
                'a' => a.all = true,
                'c' => a.no_pager = true,
                'f' => a.apropos = Some("whatis"),
                'k' => a.apropos = Some("apropos"),
                'h' => a.synopsis = true,
                'l' => a.local = true,
                'w' => a.where_only = true,
                'C' | 'M' | 'm' | 'S' | 's' | 'T' | 'O' | 'W' => {
                    let rest: String = flags[k + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        argv.get(i).cloned().ok_or(())?
                    };
                    match f {
                        'C' => a.conf = Some(value),
                        'M' => a.manpath = Some(value),
                        'm' => a.extra.push(value),
                        'S' => a.arch = Some(value),
                        's' => a.section = Some(value),
                        _ => a.formatter.push((f, value)),
                    }
                    k = flags.len();
                    continue;
                }
                _ => return Err(()),
            }
            k += 1;
        }
        i += 1;
    }
    // `man 8 reboot`: a first argument that is a section, with names after it.
    if a.section.is_none() && a.names.len() > 1 && !a.local && is_section(&a.names[0]) {
        a.section = Some(a.names.remove(0));
    }
    Ok(a)
}

fn is_section(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|d| d.is_ascii_digit() || d == 'n') && s.len() <= 4 || s == "n"
}

/// The manual path (MAN.md §8.2): `-M`, else `MANPATH`, else man.conf's `manpath` lines, else
/// the built-in default; then `-m` directories first.
fn manpath(a: &Args) -> Vec<String> {
    liboxdoc::manpath::resolve(a.conf.as_deref(), a.manpath.as_deref(), &a.extra)
}

/// The files for `name`: in each manual directory, each section in turn, the pages its index
/// (makewhatis(8)) lists under that name, then `manN/name.N*` and the architecture's
/// `manN/arch/name.N*`.
fn find(name: &str, dirs: &[String], a: &Args) -> Vec<PathBuf> {
    let sections: Vec<String> = match &a.section {
        Some(s) => vec![s.clone()],
        None => SECTIONS.iter().map(|s| s.to_string()).collect(),
    };
    let arch = a.arch.clone().unwrap_or_else(|| std::env::consts::ARCH.to_string());
    let mut found = Vec::new();
    for sec in &sections {
        for dir in dirs {
            // Any name of a page finds it through the index: `man getc` finds `fgetc.3`.
            for (file, secs, page_arch) in liboxdoc::apropos::lookup(dir, name) {
                let in_section = secs.split(", ").any(|s| s.starts_with(sec.as_str()));
                let for_arch = page_arch.is_empty() || page_arch.eq_ignore_ascii_case(&arch);
                let path = Path::new(dir).join(&file);
                if in_section && for_arch && path.is_file() && !found.contains(&path) {
                    found.push(path);
                }
            }
            if !a.all && !found.is_empty() {
                return found;
            }
            // The section's own directory is its first character: `3p` lives in `man3`.
            let first = sec.chars().next().unwrap_or('1');
            let mandir = Path::new(dir).join(format!("man{first}"));
            for d in [mandir.join(&arch), mandir.clone()] {
                let Ok(entries) = std::fs::read_dir(&d) else { continue };
                let mut hits: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        let f = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
                        f.strip_prefix(name).and_then(|r| r.strip_prefix('.')).is_some_and(|ext| ext.starts_with(sec.as_str()) && p.is_file())
                    })
                    .collect();
                hits.sort();
                for h in hits {
                    if !found.contains(&h) {
                        found.push(h);
                    }
                }
                if !a.all && !found.is_empty() {
                    return found;
                }
            }
        }
    }
    found
}

fn terminal_width() -> Option<usize> {
    // SAFETY: TIOCGWINSZ into a local winsize.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 { Some(ws.ws_col as usize) } else { None }
}

/// Today's date in the local time zone, for a page dated `$Mdocdate$`.
fn local_today() -> Option<String> {
    // SAFETY: time(NULL) and localtime_r into a local tm.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
        return None;
    }
    Some(liboxdoc::civil_date(tm.tm_year as i64 + 1900, tm.tm_mon as usize + 1, tm.tm_mday as u32))
}

fn main() -> ExitCode {
    let Ok(a) = parse_args() else { return usage() };
    if let Some(prog) = a.apropos {
        // `man -k` and `man -f` are apropos(1) and whatis(1), over the same trees.
        let mut args = Vec::new();
        for (flag, v) in [("-C", &a.conf), ("-M", &a.manpath), ("-S", &a.arch), ("-s", &a.section)] {
            if let Some(v) = v {
                args.push(flag.to_string());
                args.push(v.clone());
            }
        }
        for m in &a.extra {
            args.push("-m".to_string());
            args.push(m.clone());
        }
        args.extend(a.names.iter().cloned());
        return match liboxdoc::apropos::main(prog, &args) {
            0 => ExitCode::SUCCESS,
            _ => ExitCode::from(NOT_FOUND),
        };
    }
    if a.names.is_empty() {
        return usage();
    }
    let dirs = manpath(&a);
    let mut pages = Vec::new();
    let mut status = ExitCode::SUCCESS;
    for name in &a.names {
        if a.local || name.contains('/') {
            pages.push(PathBuf::from(name));
            continue;
        }
        let found = find(name, &dirs, &a);
        if found.is_empty() {
            match &a.section {
                Some(s) => eprintln!("man: No entry for {name} in section {s} of the manual."),
                None => eprintln!("man: No entry for {name} in the manual."),
            }
            status = ExitCode::from(NOT_FOUND);
        }
        pages.extend(found);
    }
    if a.where_only {
        for p in &pages {
            println!("{}", p.display());
        }
        return status;
    }

    let tty = std::io::stdout().is_terminal();
    let use_pager = tty && !a.no_pager;
    let mut opts = Options {
        styling: if tty { Styling::Sgr } else { Styling::Plain },
        width: terminal_width().map(|w| w.min(80).saturating_sub(2)).unwrap_or(78),
        synopsis_only: a.synopsis,
        today: local_today(),
        ..Options::default()
    };
    // UTF-8 output only when the locale asks for it, as mandoc does; otherwise ASCII.
    if !liboxdoc::locale_is_utf8() {
        opts.device = Device::Ascii;
    }
    for (f, v) in &a.formatter {
        match (f, v.as_str()) {
            ('T', "ascii") => opts.device = Device::Ascii,
            ('T', "utf8") | ('T', "locale") => opts.device = Device::Utf8,
            ('O', o) => {
                for o in o.split(',') {
                    if let Some(w) = o.strip_prefix("width=").and_then(|w| w.parse().ok()) {
                        opts.width = w;
                    } else if o == "overstrike" {
                        opts.styling = Styling::Overstrike;
                    }
                }
            }
            _ => {}
        }
    }

    let mut text = String::new();
    for p in &pages {
        match std::fs::read(p) {
            Ok(bytes) => {
                let input = String::from_utf8_lossy(&bytes);
                let (out, _) = liboxdoc::format(&input, &p.display().to_string(), &opts);
                if !text.is_empty() && !a.synopsis {
                    text.push('\n');
                }
                text.push_str(&out);
            }
            Err(e) => {
                eprintln!("man: {}: {e}", p.display());
                status = ExitCode::from(NOT_FOUND);
            }
        }
    }
    if text.is_empty() {
        return status;
    }
    if use_pager {
        let pager = std::env::var("MANPAGER").or_else(|_| std::env::var("PAGER")).ok().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "/usr/bin/more -s".to_string());
        match Command::new("/bin/sh").arg("-c").arg(&pager).stdin(Stdio::piped()).spawn() {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return status;
            }
            Err(e) => eprintln!("man: {pager}: {e}"),
        }
    }
    let _ = std::io::stdout().write_all(text.as_bytes());
    status
}
