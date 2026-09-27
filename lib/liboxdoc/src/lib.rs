//! liboxdoc: OxideBSD's roff formatter (MAN.md in OxideBSD-doc).
//!
//! [`format`] runs a page through all four stages: roff, the language parser, validation, and
//! an output device.

pub mod chars;
pub mod diag;
pub mod mdoc;
pub mod mdoc_term;
pub mod roff;
pub mod standards;
pub mod term;
pub mod tree;

use diag::Diagnostics;
use term::{Encoding, Styling, Term};
use tree::{Document, Language};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Ascii,
    Utf8,
    Lint,
    Tree,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub device: Device,
    /// Line length in columns (MAN.md §5.2).
    pub width: usize,
    pub styling: Styling,
    /// The operating system name for a page with an empty `.Os`.
    pub os: Option<String>,
}

impl Default for Options {
    fn default() -> Options {
        Options { device: Device::Utf8, width: 78, styling: Styling::Sgr, os: None }
    }
}

/// Parses a page: roff, then the language the page is written in.
pub fn parse(input: &str, diag: &mut Diagnostics) -> Document {
    let lines = roff::Roff::new(diag).run(input);
    let language = detect(&lines);
    match language {
        Language::Mdoc | Language::Man => mdoc::parse(lines, diag),
    }
}

/// `.Dd` first means mdoc (MAN.md §3.2).
fn detect(lines: &[roff::Line]) -> Language {
    for l in lines {
        if let roff::Line::Macro { name, .. } = l {
            return if name == "Dd" { Language::Mdoc } else { Language::Man };
        }
    }
    Language::Mdoc
}

/// Formats a page for `opts.device`. Returns the output and the diagnostics.
pub fn format(input: &str, file: &str, opts: &Options) -> (String, Diagnostics) {
    let mut diag = Diagnostics::new(file);
    let mut doc = parse(input, &mut diag);
    if let Some(os) = &opts.os
        && doc.meta.os.is_empty()
    {
        doc.meta.os = os.clone();
    }
    let out = match opts.device {
        Device::Ascii | Device::Utf8 => {
            let enc = if opts.device == Device::Ascii { Encoding::Ascii } else { Encoding::Utf8 };
            mdoc_term::render(&doc, Term::new(opts.width, enc, opts.styling))
        }
        Device::Lint => String::new(),
        Device::Tree => {
            let mut s = String::new();
            doc.root.dump(0, &mut s);
            s
        }
    };
    (out, diag)
}

/// The operating system name printed for an empty `.Os`: `uname`'s name and release.
pub fn default_os() -> String {
    std::fs::read_to_string("/proc/sys/kernel/ostype")
        .ok()
        .map(|s| s.trim().to_string())
        .and_then(|name| std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|r| format!("{name} {}", r.trim())))
        .unwrap_or_else(|| "OxideBSD".to_string())
}

/// `.Dd`'s date as printed: `$Mdocdate: ... $` unwrapped, anything else as given.
pub fn format_date(date: &str) -> String {
    let d = date.trim();
    if let Some(inner) = d.strip_prefix("$Mdocdate:").and_then(|r| r.strip_suffix('$')) {
        return inner.trim().to_string();
    }
    d.to_string()
}
