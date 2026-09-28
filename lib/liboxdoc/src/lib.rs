//! liboxdoc: OxideBSD's roff formatter (MAN.md in OxideBSD-doc).
//!
//! [`format`] runs a page through all four stages: roff, the language parser, validation, and
//! an output device.

pub mod chars;
pub mod diag;
pub mod libraries;
pub mod man;
pub mod man_term;
pub mod mdoc;
pub mod mdoc_term;
pub mod roff;
pub mod standards;
pub mod term;
pub mod tree;
pub mod unicode;
pub mod lint;
pub mod tbl;
pub mod tbl_term;
pub mod regex;
pub mod keys;
pub mod db;
pub mod manpath;
pub mod makewhatis;
pub mod apropos;

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
    /// Only the SYNOPSIS section, without heading, header or footer (`man -h`).
    pub synopsis_only: bool,
    /// Today's date in the local time zone, `Month D, YYYY`, for a `$Mdocdate$` with no date;
    /// without it, today in UTC. (This library doesn't read the time zone itself.)
    pub today: Option<String>,
}

impl Default for Options {
    fn default() -> Options {
        Options { device: Device::Utf8, width: 78, styling: Styling::Sgr, os: None, synopsis_only: false, today: None }
    }
}

/// Parses a page: roff, then the language the page is written in.
pub fn parse(input: &str, diag: &mut Diagnostics) -> Document {
    let lines = roff::Roff::new(diag).run(input);
    let language = detect(&lines);
    match language {
        Language::Mdoc => mdoc::parse(lines, diag),
        Language::Man => man::parse(lines, diag),
    }
}

/// `.Dd` first means mdoc (MAN.md §3.2).
fn detect(lines: &[roff::Line]) -> Language {
    for l in lines {
        if let roff::Line::Macro { name, .. } = l {
            // (A page starting with `.Dt`, prologue out of order, is still mdoc.)
            return if name == "Dd" || name == "Dt" { Language::Mdoc } else { Language::Man };
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
    if let Some(today) = &opts.today
        && doc.meta.date.trim().trim_start_matches("$Mdocdate").trim_matches([':', '$', ' ']).is_empty()
        && doc.meta.date.trim().starts_with("$Mdocdate")
    {
        doc.meta.date = today.clone();
    }
    let out = match opts.device {
        Device::Ascii | Device::Utf8 => {
            let enc = if opts.device == Device::Ascii { Encoding::Ascii } else { Encoding::Utf8 };
            let t = Term::new(opts.width, enc, opts.styling);
            match doc.language {
                Language::Mdoc => mdoc_term::render(&doc, t, opts.synopsis_only),
                Language::Man => man_term::render(&doc, t, opts.synopsis_only),
            }
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

/// Whether the locale (`LC_ALL`, else `LC_CTYPE`, else `LANG`) names UTF-8.
pub fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .is_some_and(|l| {
            let l = l.to_uppercase();
            l.contains("UTF-8") || l.contains("UTF8")
        })
}

/// The operating system name printed for an empty `.Os`: `uname`'s name and release.
pub fn default_os() -> String {
    std::fs::read_to_string("/proc/sys/kernel/ostype")
        .ok()
        .map(|s| s.trim().to_string())
        .and_then(|name| std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|r| format!("{name} {}", r.trim())))
        .unwrap_or_else(|| "OxideBSD".to_string())
}

const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/// `.Dd`'s date as printed, following mandoc: `Month D, YYYY` (the month in full or its first
/// three letters) and `$Mdocdate: Month D YYYY $` are printed as `Month D, YYYY`; a bare
/// `$Mdocdate$` is today; anything else is printed as given.
pub fn format_date(date: &str) -> String {
    let d = date.trim();
    if let Some(inner) = d.strip_prefix("$Mdocdate").map(|r| r.trim_start_matches(':').trim()) {
        let inner = inner.trim_end_matches('$').trim();
        if inner.is_empty() {
            return today();
        }
        return parse_date(inner, false).unwrap_or_else(|| inner.to_string());
    }
    parse_date(d, true).unwrap_or_else(|| d.to_string())
}

/// `Month D, YYYY` (with the comma) or `Month D YYYY` (without) in canonical form.
fn parse_date(s: &str, comma: bool) -> Option<String> {
    let mut it = s.split_whitespace();
    let month = it.next()?;
    let day = it.next()?;
    let year = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let day = if comma { day.strip_suffix(',')? } else { day };
    let m = MONTHS.iter().find(|m| month == **m || (month.len() == 3 && m.starts_with(month)))?;
    let day: u32 = day.parse().ok().filter(|d| (1..=31).contains(d))?;
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("{m} {day}, {year}"))
}

/// A date as `.Dd` writes it, `Month D, YYYY`, from a month 1-12.
pub fn civil_date(year: i64, month: usize, day: u32) -> String {
    format!("{} {day}, {year}", MONTHS[month.clamp(1, 12) - 1])
}

/// Today's date, `Month D, YYYY`, in UTC.
fn today() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{} {d}, {y}", MONTHS[(m - 1) as usize])
}
