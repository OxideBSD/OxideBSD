//! `/etc/ttys` (ttys(5)): the terminals init runs login sessions on (INIT.md §5), in FreeBSD's
//! format -- one line per terminal:
//!
//! ```text
//! # name   getty                  type    status  flags
//! console  "/usr/libexec/getty"   linux   on      insecure
//! ```
//!
//! `getty` is a command (quoted if it has arguments) or `none`; `status` is `on`, `off`,
//! `onifexists` or `onifconsole`; the remaining words are flags: `secure` / `insecure`,
//! `window="command"`, `group=name`. `#` starts a comment.

use std::io;

pub const PATH: &str = "/etc/ttys";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    On,
    Off,
    /// On if the device node exists.
    OnIfExists,
    /// On if this terminal is the system console.
    OnIfConsole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TtyEnt {
    pub name: String,
    /// The command init runs on the terminal; `None` for `none`.
    pub getty: Option<String>,
    pub term: String,
    pub status: Status,
    /// Root may log in here, and single-user mode doesn't ask for root's password.
    pub secure: bool,
    pub window: Option<String>,
    pub group: Option<String>,
}

/// Splits a line into words, keeping `"quoted strings"` (and `key="value"`) together.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut any) = (false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            '#' if !quoted => break,
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Parses `/etc/ttys` text. Malformed lines are returned as errors with their line numbers,
/// alongside every entry that did parse.
pub fn parse(text: &str) -> (Vec<TtyEnt>, Vec<String>) {
    let (mut entries, mut errors) = (Vec::new(), Vec::new());
    for (i, line) in text.lines().enumerate() {
        let w = words(line);
        if w.is_empty() {
            continue;
        }
        if w.len() < 4 {
            errors.push(format!("line {}: expected name, getty, type and status", i + 1));
            continue;
        }
        let status = match w[3].as_str() {
            "on" => Status::On,
            "off" => Status::Off,
            "onifexists" => Status::OnIfExists,
            "onifconsole" => Status::OnIfConsole,
            s => {
                errors.push(format!("line {}: unknown status `{s}'", i + 1));
                continue;
            }
        };
        let mut e = TtyEnt {
            name: w[0].clone(),
            getty: (w[1] != "none").then(|| w[1].clone()),
            term: w[2].clone(),
            status,
            secure: false,
            window: None,
            group: None,
        };
        for flag in &w[4..] {
            match flag.split_once('=') {
                None if flag == "secure" => e.secure = true,
                None if flag == "insecure" => e.secure = false,
                Some(("window", v)) => e.window = Some(v.into()),
                Some(("group", v)) => e.group = Some(v.into()),
                _ => errors.push(format!("line {}: unknown flag `{flag}'", i + 1)),
            }
        }
        entries.push(e);
    }
    (entries, errors)
}

/// Reads `/etc/ttys`, ignoring malformed lines.
pub fn read() -> io::Result<Vec<TtyEnt>> {
    Ok(parse(&std::fs::read_to_string(PATH)?).0)
}

/// Whether `/etc/ttys` marks this terminal `secure`. A terminal that isn't listed, or no
/// `/etc/ttys` at all, is insecure.
pub fn is_secure(name: &str) -> bool {
    read().ok().and_then(|es| es.into_iter().find(|e| e.name == name)).is_some_and(|e| e.secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freebsd_style_lines() {
        let text = "# name getty type status comments\n\
                    console none unknown off secure\n\
                    ttyv0 \"/usr/libexec/getty Pc\" xterm onifexists secure window=\"/x -f\" group=wheel # a comment\n\
                    \n\
                    ttyu0 \"/usr/libexec/getty 3wire\" vt100 onifconsole insecure\n";
        let (es, errs) = parse(text);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(es.len(), 3);
        assert_eq!(es[0].getty, None);
        assert!(es[0].secure && es[0].status == Status::Off);
        assert_eq!(es[1].getty.as_deref(), Some("/usr/libexec/getty Pc"));
        assert_eq!(es[1].window.as_deref(), Some("/x -f"));
        assert_eq!(es[1].group.as_deref(), Some("wheel"));
        assert_eq!(es[1].status, Status::OnIfExists);
        assert!(!es[2].secure);
    }

    #[test]
    fn errors_name_the_line() {
        let (es, errs) = parse("console none\nttyv0 none xterm maybe\nttyv1 none xterm on shiny\n");
        assert_eq!(es.len(), 1);
        assert_eq!(errs, ["line 1: expected name, getty, type and status", "line 2: unknown status `maybe'", "line 3: unknown flag `shiny'"]);
    }
}
