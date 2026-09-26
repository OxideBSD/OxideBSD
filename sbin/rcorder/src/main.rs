//! `/sbin/rcorder [-gp] [-k keep] [-s skip] file ...` -- see rcorder(8) and the library crate.

use std::io::Write;
use std::process::ExitCode;

use rcorder::{Filter, Script, order, render_graph, render_list, render_parallel};

const USAGE: &str = "usage: rcorder [-gp] [-k keep] [-s skip] file ...";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    let (mut graph, mut parallel) = (false, false);
    let mut filter = Filter::default();
    while let Some(arg) = args.next_if(|a| a.starts_with('-') && a.len() > 1) {
        if arg == "--" {
            break;
        }
        let mut flags = arg[1..].chars();
        while let Some(c) = flags.next() {
            match c {
                'g' => graph = true,
                'p' => parallel = true,
                'k' | 's' => {
                    // The value is the rest of this argument, or else the next one.
                    let rest: String = flags.by_ref().collect();
                    let Some(value) = (if rest.is_empty() { args.next() } else { Some(rest) }) else {
                        eprintln!("rcorder: option requires an argument -- {c}\n{USAGE}");
                        return ExitCode::FAILURE;
                    };
                    if c == 'k' { &mut filter.keep } else { &mut filter.skip }.push(value);
                }
                _ => {
                    eprintln!("rcorder: illegal option -- {c}\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    let files: Vec<String> = args.collect();
    if files.is_empty() || (graph && parallel) {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }

    let mut failed = false;
    let mut scripts = Vec::new();
    for path in files {
        match std::fs::read(&path) {
            Ok(bytes) => match Script::from_text(&path, &String::from_utf8_lossy(&bytes)) {
                Ok(s) => scripts.push(s),
                Err(e) => {
                    // Still ordered, as declaring nothing: init_sh reports the error again
                    // when it runs the script.
                    eprintln!("rcorder: {e}");
                    scripts.push(Script { path, ..Script::default() });
                }
            },
            Err(e) => {
                eprintln!("rcorder: could not open {path}: {e}");
                failed = true;
            }
        }
    }

    let o = order(&scripts);
    for w in &o.warnings {
        eprintln!("rcorder: {w}");
    }
    let out = if graph {
        render_graph(&scripts, &o, &filter)
    } else if parallel {
        render_parallel(&scripts, &o, &filter)
    } else {
        render_list(&scripts, &o, &filter)
    };
    let _ = std::io::stdout().write_all(out.as_bytes());
    if failed || o.cycle { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
