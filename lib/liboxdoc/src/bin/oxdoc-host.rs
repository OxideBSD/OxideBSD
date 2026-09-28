//! A host-side driver for testing: `oxdoc-host [-T device] [-O option] [-W level] file`.

use liboxdoc::diag::Level;
use liboxdoc::term::Styling;
use liboxdoc::{Device, Options};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Today in the local time zone, as mandoc prints a bare `$Mdocdate$`.
    let today = std::process::Command::new("date").arg("+%B %-d, %Y").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let mut opts = Options { styling: Styling::Overstrike, today, ..Options::default() };
    let mut min = Level::Warning;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-T" => {
                i += 1;
                opts.device = match args[i].as_str() {
                    "ascii" => Device::Ascii,
                    "utf8" => Device::Utf8,
                    "lint" => Device::Lint,
                    "tree" => Device::Tree,
                    d => panic!("unknown device {d}"),
                };
            }
            "-O" => {
                i += 1;
                for o in args[i].split(',') {
                    if let Some(w) = o.strip_prefix("width=") {
                        opts.width = w.parse().unwrap();
                    } else if o == "sgr" {
                        opts.styling = Styling::Sgr;
                    }
                }
            }
            "-W" => {
                i += 1;
                min = Level::parse(&args[i]).unwrap_or(Level::Warning);
            }
            f => files.push(f.to_string()),
        }
        i += 1;
    }
    for f in files {
        let input = std::fs::read_to_string(&f).expect("read");
        let (out, diag) = liboxdoc::format(&input, &f, &opts);
        print!("{out}");
        eprint!("{}", diag.format(min));
    }
}
