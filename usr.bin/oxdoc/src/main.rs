//! `oxdoc(1)`: formats or checks manual pages (MAN.md §2 in OxideBSD-doc).
//!
//! ```text
//! oxdoc [-T device] [-O option[,...]] [-W level] [file ...]
//! ```
//!
//! Reads each file, or standard input, and writes it formatted for `device` (`utf8` by default,
//! `ascii`, `lint`, `tree`). Diagnostics at `level` and above go to standard error; the exit
//! status is 1 if any at `warning` or above were reported, 2 on a usage or file error.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use liboxdoc::diag::Level;
use liboxdoc::term::Styling;
use liboxdoc::{Device, Options};

const USAGE: &str = "usage: oxdoc [-T device] [-O option[,...]] [-W level] [file ...]";

/// The terminal's width, when standard output is one.
fn terminal_width() -> Option<usize> {
    // SAFETY: TIOCGWINSZ into a local winsize.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        Some(ws.ws_col as usize)
    } else {
        None
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tty = std::io::stdout().is_terminal();
    // MAN.md §5.1-5.2: styles when writing to a terminal, the terminal's width (at most 80)
    // less two, 78 otherwise.
    let mut opts = Options {
        styling: if tty { Styling::Sgr } else { Styling::Plain },
        width: terminal_width().map(|w| w.min(80).saturating_sub(2)).unwrap_or(78),
        ..Options::default()
    };
    // UTF-8 output only when the locale asks for it, as mandoc does; otherwise ASCII.
    if !liboxdoc::locale_is_utf8() {
        opts.device = Device::Ascii;
    }
    let mut min = None;
    let mut stop = false;
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.as_str() {
            s if s.starts_with("-T") || s.starts_with("-O") || s.starts_with("-W") => (&s[..2], &s[2..]),
            "--" => {
                files.extend(it.by_ref().cloned());
                break;
            }
            s if s.starts_with('-') && s.len() > 1 => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            s => {
                files.push(s.to_string());
                continue;
            }
        };
        let value = if inline.is_empty() {
            match it.next() {
                Some(v) => v.clone(),
                None => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            }
        } else {
            inline.to_string()
        };
        match flag {
            "-T" => {
                opts.device = match value.as_str() {
                    "utf8" | "locale" => Device::Utf8,
                    "ascii" => Device::Ascii,
                    "lint" => Device::Lint,
                    "tree" => Device::Tree,
                    d => {
                        eprintln!("oxdoc: -T {d}: unknown output device");
                        return ExitCode::from(2);
                    }
                };
                if value == "lint" && min.is_none() {
                    min = Some(Level::Style);
                }
            }
            "-O" => {
                for o in value.split(',') {
                    match o.split_once('=') {
                        Some(("width", w)) => match w.parse() {
                            Ok(w) => opts.width = w,
                            Err(_) => eprintln!("oxdoc: -O width={w}: not a number"),
                        },
                        Some(("os", os)) => opts.os = Some(os.to_string()),
                        None if o == "overstrike" => opts.styling = Styling::Overstrike,
                        None if o == "plain" => opts.styling = Styling::Plain,
                        _ => eprintln!("oxdoc: -O {o}: unknown option"),
                    }
                }
            }
            _ => {
                if value == "stop" {
                    stop = true;
                } else if value == "all" {
                    min = Some(Level::Style);
                } else {
                    match Level::parse(&value) {
                        Some(l) => min = Some(l),
                        None => {
                            eprintln!("oxdoc: -W {value}: unknown level");
                            return ExitCode::from(2);
                        }
                    }
                }
            }
        }
    }
    let min = min.unwrap_or(Level::Warning);
    if files.is_empty() {
        files.push("-".to_string());
    }
    let mut worst = None;
    let mut out = std::io::stdout().lock();
    for f in &files {
        let mut input = String::new();
        let read = if f == "-" {
            std::io::stdin().read_to_string(&mut input).map(|_| ())
        } else {
            std::fs::read(f).map(|b| input = String::from_utf8_lossy(&b).into_owned())
        };
        if let Err(e) = read {
            eprintln!("oxdoc: {f}: {e}");
            return ExitCode::from(2);
        }
        let name = if f == "-" { "<stdin>" } else { f.as_str() };
        let (text, diag) = liboxdoc::format(&input, name, &opts);
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
        eprint!("{}", diag.format(min));
        worst = worst.max(diag.worst());
        if stop && diag.worst().is_some_and(|w| w >= min) {
            break;
        }
    }
    if worst.is_some_and(|w| w >= Level::Warning) { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
