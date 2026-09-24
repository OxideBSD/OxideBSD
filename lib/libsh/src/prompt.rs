//! Prompt strings (`PS1`, `PS2`): FreeBSD `sh`'s backslash escapes, then parameter expansion.
//!
//! Escapes: `\u` user, `\h` host up to the first `.`, `\H` full host, `\w` working directory with
//! `$HOME` shown as `~`, `\W` its last component, `\$` `#` for root and `$` otherwise, `\\`, and
//! `\[ … \]` around text that takes no room on screen (colour sequences). Also `\e` (escape),
//! `\a`, `\n` and `\nnn` octal, as in bash, which the colour sequences in a typical `PS1` need.

use crate::sys;

/// Marks the start and end of a `\[ … \]` region in an expanded prompt, for the line editor.
pub const INVISIBLE_START: char = '\u{1}';
pub const INVISIBLE_END: char = '\u{2}';

impl crate::shell::Shell {
    pub fn expand_prompt(&mut self, var: &str, default: &str) -> String {
        let raw = self.get(var).unwrap_or_else(|| default.to_string());
        let escaped = self.prompt_escapes(&raw);
        // Parameter expansion (and command substitution) over the result, as a here-document
        // body would be expanded: no field splitting, no quote removal.
        match crate::parse::parse_heredoc_body(&escaped) {
            Ok(word) => {
                let saved = self.status;
                let r = self.expand_string(&word).unwrap_or(escaped);
                self.status = saved;
                r
            }
            Err(_) => escaped,
        }
    }

    fn prompt_escapes(&self, raw: &str) -> String {
        // Substituted values are escaped so the expansion pass leaves them alone.
        let lit = |s: &str| s.chars().fold(String::new(), |mut o, c| {
            if matches!(c, '$' | '`' | '\\') {
                o.push('\\');
            }
            o.push(c);
            o
        });
        let chars: Vec<char> = raw.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            i += 1;
            if c != '\\' || i >= chars.len() {
                out.push(c);
                continue;
            }
            let e = chars[i];
            i += 1;
            match e {
                'u' => out.push_str(&lit(&sys::user_name(sys::geteuid()).unwrap_or_default())),
                'h' => {
                    let h = sys::hostname();
                    out.push_str(&lit(h.split('.').next().unwrap_or("")));
                }
                'H' => out.push_str(&lit(&sys::hostname())),
                'w' => out.push_str(&lit(&self.prompt_cwd(false))),
                'W' => out.push_str(&lit(&self.prompt_cwd(true))),
                '$' => out.push(if sys::geteuid() == 0 { '#' } else { '$' }),
                '\\' => out.push_str("\\\\"),
                '[' => out.push(INVISIBLE_START),
                ']' => out.push(INVISIBLE_END),
                'e' => out.push('\x1b'),
                'a' => out.push('\x07'),
                'n' => out.push('\n'),
                '0'..='7' => {
                    let mut v = e.to_digit(8).unwrap();
                    let mut n = 1;
                    while n < 3 && i < chars.len() && chars[i].is_digit(8) {
                        v = v * 8 + chars[i].to_digit(8).unwrap();
                        i += 1;
                        n += 1;
                    }
                    out.push(char::from_u32(v & 0xff).unwrap_or('?'));
                }
                // Anything else is left for the expansion pass (`\$` meaning a literal `$` etc.).
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
        }
        out
    }

    fn prompt_cwd(&self, last_only: bool) -> String {
        let pwd = self
            .get("PWD")
            .filter(|p| p.starts_with('/'))
            .or_else(|| std::env::current_dir().ok().and_then(|p| p.to_str().map(String::from)))
            .unwrap_or_default();
        let home = self.get("HOME").filter(|h| h.len() > 1).map(|h| h.trim_end_matches('/').to_string());
        let shown = match &home {
            Some(h) if pwd == *h => "~".to_string(),
            Some(h) if pwd.starts_with(&format!("{h}/")) => format!("~{}", &pwd[h.len()..]),
            _ => pwd,
        };
        if last_only && shown != "/" && shown != "~" { shown.rsplit('/').next().unwrap_or("").to_string() } else { shown }
    }
}

/// The on-screen width of an expanded prompt: its last line, minus `\[ … \]` regions.
pub fn visible_width(prompt: &str) -> usize {
    let last = prompt.rsplit('\n').next().unwrap_or("");
    let mut width = 0;
    let mut hidden = false;
    for c in last.chars() {
        match c {
            INVISIBLE_START => hidden = true,
            INVISIBLE_END => hidden = false,
            _ if !hidden => width += 1,
            _ => {}
        }
    }
    width
}

/// The prompt as written to the terminal: without the `\[ \]` markers.
pub fn printable(prompt: &str) -> String {
    prompt.chars().filter(|&c| c != INVISIBLE_START && c != INVISIBLE_END).collect()
}
