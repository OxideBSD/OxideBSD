//! Diagnostics (MAN.md §6): mandoc's four levels, collected per file and printed as
//! `oxdoc: file:line:column: LEVEL: message: detail`.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Style,
    Warning,
    Error,
    Unsupported,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "style" => Level::Style,
            "warning" => Level::Warning,
            "error" => Level::Error,
            "unsupp" | "unsupported" => Level::Unsupported,
            _ => return None,
        })
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Level::Style => "STYLE",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
            Level::Unsupported => "UNSUPP",
        })
    }
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub level: Level,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct Diagnostics {
    pub file: String,
    pub list: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new(file: &str) -> Diagnostics {
        Diagnostics { file: file.to_string(), list: Vec::new() }
    }

    pub fn report(&mut self, level: Level, line: usize, column: usize, message: &str, detail: &str) {
        self.list.push(Diagnostic { level, line, column, message: message.to_string(), detail: detail.to_string() });
    }

    /// The worst level reported, if any.
    pub fn worst(&self) -> Option<Level> {
        self.list.iter().map(|d| d.level).max()
    }

    /// The diagnostics at `min` and above, formatted one per line.
    pub fn format(&self, min: Level) -> String {
        let mut out = String::new();
        for d in self.list.iter().filter(|d| d.level >= min) {
            out.push_str(&format!("oxdoc: {}:{}:{}: {}: {}", self.file, d.line, d.column, d.level, d.message));
            if !d.detail.is_empty() {
                out.push_str(": ");
                out.push_str(&d.detail);
            }
            out.push('\n');
        }
        out
    }
}
