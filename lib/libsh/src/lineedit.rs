//! The interactive line editor: raw terminal input, emacs-style editing keys, history (kept in
//! `$HISTFILE`), Tab completion and Ctrl+R reverse search.
//!
//! OxideBSD's console has no line discipline of its own (`ICANON` is recorded, not acted on), so
//! everything a cooked-mode terminal would do for a line -- echo, erase, cursor movement -- is
//! done here, with ECMA-48 sequences the console implements (`CUU`, `CUF`, `ED`).
//!
//! Every keystroke redraws the whole edited line from its first row: simple, correct when the
//! line wraps, and one `write` per keystroke.

use crate::prompt;
use crate::shell::Shell;
use crate::sys::{self, Fd};

pub enum ReadResult {
    Line(String),
    /// Ctrl+D on an empty line, or the terminal went away.
    Eof,
    /// Ctrl+C: the line was abandoned.
    Interrupted,
}

pub struct Editor {
    /// Keys come from here; terminal modes are set here.
    tty: Fd,
    /// Prompts and echo go here.
    out: Fd,
    pub history: Vec<String>,
    hist_file: Option<String>,
    hist_max: usize,
    kill_buffer: Vec<char>,
}

/// One line being edited.
struct Line<'p> {
    /// The prompt's last line (earlier lines are printed once, above).
    prompt: &'p str,
    buf: Vec<char>,
    pos: usize,
    /// Rows between the line's first row and the cursor's, as last drawn.
    cursor_row: usize,
}

enum Key {
    Char(char),
    Ctrl(u8),
    Up,
    Down,
    Left,
    Right,
    WordLeft,
    WordRight,
    Home,
    End,
    Delete,
    Backspace,
    Enter,
    Tab,
    Ignore,
    Eof,
}

impl Editor {
    pub fn new(tty: Fd, out: Fd, hist_file: Option<String>, hist_max: usize) -> Self {
        let mut e = Editor { tty, out, history: Vec::new(), hist_file, hist_max: hist_max.max(1), kill_buffer: Vec::new() };
        e.load_history();
        e
    }

    // --- history ------------------------------------------------------------------------------

    fn load_history(&mut self) {
        let Some(path) = &self.hist_file else { return };
        let Ok(text) = std::fs::read_to_string(path) else { return };
        self.history = text.lines().filter(|l| !l.is_empty()).map(unescape_entry).collect();
        let excess = self.history.len().saturating_sub(self.hist_max);
        self.history.drain(..excess);
    }

    /// Records a command line (not blank, not a repeat of the one before), appending it to the
    /// history file straight away so a crash doesn't lose it.
    pub fn add_history(&mut self, entry: &str) {
        let entry = entry.trim_end_matches('\n');
        if entry.trim().is_empty() || self.history.last().is_some_and(|l| l == entry) {
            return;
        }
        self.history.push(entry.to_string());
        if self.history.len() > self.hist_max {
            self.history.remove(0);
        }
        if let Some(path) = &self.hist_file {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, "{}", escape_entry(entry));
            }
        }
    }

    /// Rewrites the history file trimmed to `$HISTSIZE` (appending alone would grow it forever).
    pub fn save_history(&self) {
        let Some(path) = &self.hist_file else { return };
        let text: String = self.history.iter().map(|e| format!("{}\n", escape_entry(e))).collect();
        let _ = std::fs::write(path, text);
    }

    // --- terminal -----------------------------------------------------------------------------

    fn write(&self, s: &str) {
        let _ = sys::write_all(self.out, s.as_bytes());
    }

    fn read_byte(&self) -> Option<u8> {
        sys::read_byte(self.tty).ok().flatten()
    }

    fn read_key(&self) -> Key {
        let Some(b) = self.read_byte() else { return Key::Eof };
        match b {
            b'\r' | b'\n' => Key::Enter,
            b'\t' => Key::Tab,
            0x7f | 0x08 => Key::Backspace,
            0x1b => self.read_escape(),
            0..=0x1f => Key::Ctrl(b),
            0x80.. => {
                // A UTF-8 sequence: collect its continuation bytes.
                let len = if b >= 0xf0 {
                    4
                } else if b >= 0xe0 {
                    3
                } else {
                    2
                };
                let mut bytes = vec![b];
                for _ in 1..len {
                    match self.read_byte() {
                        Some(c) => bytes.push(c),
                        None => break,
                    }
                }
                String::from_utf8(bytes).ok().and_then(|s| s.chars().next()).map(Key::Char).unwrap_or(Key::Ignore)
            }
            _ => Key::Char(b as char),
        }
    }

    /// After ESC: `ESC [ params final`, `ESC O x`, or `ESC b`/`ESC f` (Alt+b/f).
    fn read_escape(&self) -> Key {
        match self.read_byte() {
            Some(b'[') => {
                let mut params = String::new();
                let fin = loop {
                    match self.read_byte() {
                        Some(c @ 0x40..=0x7e) => break c,
                        Some(c) => params.push(c as char),
                        None => return Key::Eof,
                    }
                };
                let modified = params.contains(";5") || params.contains(";3");
                match (fin, params.split(';').next().unwrap_or("")) {
                    (b'A', _) => Key::Up,
                    (b'B', _) => Key::Down,
                    (b'C', _) if modified => Key::WordRight,
                    (b'D', _) if modified => Key::WordLeft,
                    (b'C', _) => Key::Right,
                    (b'D', _) => Key::Left,
                    (b'H', _) => Key::Home,
                    (b'F', _) => Key::End,
                    (b'~', "1" | "7") => Key::Home,
                    (b'~', "4" | "8") => Key::End,
                    (b'~', "3") => Key::Delete,
                    _ => Key::Ignore,
                }
            }
            Some(b'O') => match self.read_byte() {
                Some(b'A') => Key::Up,
                Some(b'B') => Key::Down,
                Some(b'C') => Key::Right,
                Some(b'D') => Key::Left,
                Some(b'H') => Key::Home,
                Some(b'F') => Key::End,
                _ => Key::Ignore,
            },
            Some(b'b') => Key::WordLeft,
            Some(b'f') => Key::WordRight,
            Some(0x7f) => Key::Ctrl(0x17),
            _ => Key::Ignore,
        }
    }

    /// Raw mode for the duration of one line: no echo, no line buffering, and Ctrl+C/Ctrl+Z
    /// arrive as bytes instead of signals.
    fn raw_mode(&self) -> Option<libc::termios> {
        let orig = sys::tcgetattr(self.tty).ok()?;
        let mut raw = orig;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::ICRNL | libc::INLCR | libc::IXON);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        let _ = sys::tcsetattr(self.tty, &raw);
        Some(orig)
    }

    // --- drawing ------------------------------------------------------------------------------

    fn columns(&self) -> usize {
        sys::term_columns(self.out).or_else(|| sys::term_columns(self.tty)).unwrap_or(80).max(10)
    }

    /// Redraws `line` from its first row and leaves the cursor at `line.pos`.
    fn refresh(&self, line: &mut Line) {
        let cols = self.columns();
        let plen = prompt::visible_width(line.prompt);
        let total = plen + display_width(&line.buf);
        let cur = plen + display_width(&line.buf[..line.pos]);
        let mut out = String::new();
        if line.cursor_row > 0 {
            out.push_str(&format!("\x1b[{}A", line.cursor_row));
        }
        out.push_str("\r\x1b[J");
        out.push_str(&prompt::printable(line.prompt));
        for &c in &line.buf {
            push_display(&mut out, c);
        }
        let mut end_row = if total == 0 { 0 } else { (total - 1) / cols };
        // The console wraps lazily: after exactly filling a row the cursor still sits on it. A
        // cursor that belongs at the start of the next row has to be put there explicitly.
        if cur == total && total > 0 && total % cols == 0 {
            out.push_str("\r\n");
            end_row += 1;
        }
        let (row, col) = (cur / cols, cur % cols);
        out.push('\r');
        if end_row > row {
            out.push_str(&format!("\x1b[{}A", end_row - row));
        }
        if col > 0 {
            out.push_str(&format!("\x1b[{col}C"));
        }
        line.cursor_row = row;
        self.write(&out);
    }

    /// Moves the cursor below the edited line, ready for output.
    fn finish_line(&self, line: &mut Line) {
        line.pos = line.buf.len();
        self.refresh(line);
        self.write("\r\n");
    }

    // --- reading ------------------------------------------------------------------------------

    /// Reads one line with editing. `prompt` is the expanded prompt, `\[ \]` markers included.
    pub fn read_line(&mut self, sh: &Shell, full_prompt: &str) -> ReadResult {
        // Lines of a multi-line prompt before the last are printed once; only the last one is
        // redrawn with the line.
        let (above, last) = match full_prompt.rfind('\n') {
            Some(i) => (&full_prompt[..=i], &full_prompt[i + 1..]),
            None => ("", full_prompt),
        };
        if !above.is_empty() {
            self.write(&prompt::printable(above).replace('\n', "\r\n"));
        }
        let orig = self.raw_mode();
        let r = self.edit(sh, last);
        if let Some(t) = orig {
            let _ = sys::tcsetattr(self.tty, &t);
        }
        r
    }

    fn edit(&mut self, sh: &Shell, prompt: &str) -> ReadResult {
        let mut line = Line { prompt, buf: Vec::new(), pos: 0, cursor_row: 0 };
        let mut hist_idx = self.history.len();
        let mut saved_new: Vec<char> = Vec::new();
        let mut tabs = 0;
        self.refresh(&mut line);
        loop {
            let key = self.read_key();
            if !matches!(key, Key::Tab) {
                tabs = 0;
            }
            match key {
                Key::Enter => {
                    self.finish_line(&mut line);
                    return ReadResult::Line(line.buf.iter().collect());
                }
                Key::Eof => {
                    self.finish_line(&mut line);
                    return ReadResult::Eof;
                }
                Key::Char(c) => {
                    line.buf.insert(line.pos, c);
                    line.pos += 1;
                }
                Key::Backspace => {
                    if line.pos > 0 {
                        line.pos -= 1;
                        line.buf.remove(line.pos);
                    }
                }
                Key::Delete => {
                    if line.pos < line.buf.len() {
                        line.buf.remove(line.pos);
                    }
                }
                Key::Left => line.pos = line.pos.saturating_sub(1),
                Key::Right => line.pos = (line.pos + 1).min(line.buf.len()),
                Key::Home => line.pos = 0,
                Key::End => line.pos = line.buf.len(),
                Key::WordLeft => line.pos = word_start(&line.buf, line.pos),
                Key::WordRight => line.pos = word_end(&line.buf, line.pos),
                Key::Up | Key::Ctrl(0x10) => {
                    if hist_idx > 0 {
                        if hist_idx == self.history.len() {
                            saved_new = line.buf.clone();
                        }
                        hist_idx -= 1;
                        line.buf = self.history[hist_idx].chars().collect();
                        line.pos = line.buf.len();
                    }
                }
                Key::Down | Key::Ctrl(0x0e) => {
                    if hist_idx < self.history.len() {
                        hist_idx += 1;
                        line.buf = if hist_idx == self.history.len() { saved_new.clone() } else { self.history[hist_idx].chars().collect() };
                        line.pos = line.buf.len();
                    }
                }
                Key::Tab => {
                    tabs += 1;
                    self.complete(sh, &mut line, tabs);
                }
                Key::Ctrl(c) => match c {
                    0x01 => line.pos = 0,
                    0x05 => line.pos = line.buf.len(),
                    0x02 => line.pos = line.pos.saturating_sub(1),
                    0x06 => line.pos = (line.pos + 1).min(line.buf.len()),
                    0x03 => {
                        line.pos = line.buf.len();
                        self.refresh(&mut line);
                        self.write("^C\r\n");
                        return ReadResult::Interrupted;
                    }
                    0x04 => {
                        if line.buf.is_empty() {
                            self.write("\r\n");
                            return ReadResult::Eof;
                        }
                        if line.pos < line.buf.len() {
                            line.buf.remove(line.pos);
                        }
                    }
                    0x0b => self.kill_buffer = line.buf.drain(line.pos..).collect(),
                    0x15 => {
                        self.kill_buffer = line.buf.drain(..line.pos).collect();
                        line.pos = 0;
                    }
                    0x17 => {
                        let start = word_start(&line.buf, line.pos);
                        self.kill_buffer = line.buf.drain(start..line.pos).collect();
                        line.pos = start;
                    }
                    0x19 => {
                        let k = self.kill_buffer.clone();
                        let n = k.len();
                        line.buf.splice(line.pos..line.pos, k);
                        line.pos += n;
                    }
                    0x14 => {
                        // Ctrl+T: swap the two characters before the cursor (at the end), or
                        // around it.
                        if line.buf.len() >= 2 && line.pos > 0 {
                            let p = if line.pos == line.buf.len() { line.pos - 1 } else { line.pos };
                            line.buf.swap(p - 1, p);
                            line.pos = (p + 1).min(line.buf.len());
                        }
                    }
                    0x0c => {
                        self.write("\x1b[H\x1b[J");
                        line.cursor_row = 0;
                    }
                    0x12 => {
                        if let Some(done) = self.reverse_search(&mut line) {
                            return done;
                        }
                    }
                    _ => {}
                },
                Key::Ignore => {}
            }
            self.refresh(&mut line);
        }
    }

    // --- reverse search -----------------------------------------------------------------------

    /// Ctrl+R. Returns `Some` if the search ended the line (Enter, or Ctrl+C), `None` if it left
    /// a match in `line` to keep editing.
    fn reverse_search(&mut self, line: &mut Line) -> Option<ReadResult> {
        let original = (line.buf.clone(), line.pos);
        let real_prompt = line.prompt;
        let mut query = String::new();
        let mut at = self.history.len();
        let mut failed = false;
        loop {
            let label = format!("({}reverse-i-search)`{query}': ", if failed { "failed " } else { "" });
            // Draw through a temporary prompt; `Line` borrows it only for the redraw.
            let mut tmp = Line { prompt: &label, buf: line.buf.clone(), pos: line.pos, cursor_row: line.cursor_row };
            self.refresh(&mut tmp);
            line.cursor_row = tmp.cursor_row;
            let key = self.read_key();
            let search_from = match key {
                Key::Char(c) => {
                    query.push(c);
                    Some(at.min(self.history.len().saturating_sub(1)) + 1)
                }
                Key::Backspace => {
                    query.pop();
                    Some(self.history.len())
                }
                Key::Ctrl(0x12) => Some(at),
                Key::Ctrl(0x03) | Key::Ctrl(0x07) => {
                    line.buf = original.0.clone();
                    line.pos = original.1;
                    if matches!(key, Key::Ctrl(0x03)) {
                        let mut l = Line { prompt: real_prompt, buf: line.buf.clone(), pos: line.buf.len(), cursor_row: line.cursor_row };
                        self.refresh(&mut l);
                        self.write("^C\r\n");
                        return Some(ReadResult::Interrupted);
                    }
                    return None;
                }
                Key::Enter => {
                    let mut l = Line { prompt: real_prompt, buf: line.buf.clone(), pos: line.pos, cursor_row: line.cursor_row };
                    self.finish_line(&mut l);
                    return Some(ReadResult::Line(line.buf.iter().collect()));
                }
                // Anything else accepts the match and goes back to normal editing.
                _ => return None,
            };
            if let Some(from) = search_from {
                if query.is_empty() {
                    failed = false;
                    continue;
                }
                match (0..from.min(self.history.len())).rev().find(|&i| self.history[i].contains(&query)) {
                    Some(i) => {
                        at = i;
                        failed = false;
                        line.buf = self.history[i].chars().collect();
                        let byte = self.history[i].find(&query).unwrap_or(0);
                        line.pos = self.history[i][..byte].chars().count();
                    }
                    None => failed = true,
                }
            }
        }
    }

    // --- completion ---------------------------------------------------------------------------

    fn complete(&mut self, sh: &Shell, line: &mut Line, tabs: usize) {
        let start = completion_start(&line.buf, line.pos);
        let raw: String = line.buf[start..line.pos].iter().collect();
        let word = unescape_word(&raw);
        let before: String = line.buf[..start].iter().collect();
        let command_position = is_command_position(&before);
        let mut cands = if command_position && !word.contains('/') { command_candidates(sh, &word) } else { path_candidates(sh, &word) };
        cands.sort();
        cands.dedup();
        if cands.is_empty() {
            self.write("\x07");
            return;
        }
        let replace = |line: &mut Line, text: &str| {
            let new: Vec<char> = text.chars().collect();
            let n = new.len();
            line.buf.splice(start..line.pos, new);
            line.pos = start + n;
        };
        if cands.len() == 1 {
            let c = &cands[0];
            let mut text = escape_word(c);
            if !c.ends_with('/') {
                text.push(' ');
            }
            replace(line, &text);
            return;
        }
        let common = common_prefix(&cands);
        if common.chars().count() > word.chars().count() {
            replace(line, &escape_word(&common));
            return;
        }
        if tabs < 2 {
            self.write("\x07");
            return;
        }
        // Second Tab with nothing more to add: list the candidates under the line, in columns.
        let shown: Vec<&str> = cands.iter().map(|c| display_name(c)).collect();
        let cols = self.columns();
        let width = shown.iter().map(|s| s.chars().count()).max().unwrap_or(0) + 2;
        let per_row = (cols / width).max(1);
        let rows = shown.len().div_ceil(per_row);
        let mut out = String::new();
        let saved_pos = line.pos;
        line.pos = line.buf.len();
        self.refresh(line);
        out.push_str("\r\n");
        for r in 0..rows {
            for c in 0..per_row {
                let Some(s) = shown.get(c * rows + r) else { continue };
                out.push_str(s);
                if c + 1 < per_row {
                    out.push_str(&" ".repeat(width - s.chars().count()));
                }
            }
            out.push_str("\r\n");
        }
        self.write(&out);
        line.pos = saved_pos;
        line.cursor_row = 0;
    }
}

// --- helpers -----------------------------------------------------------------------------------

fn char_width(c: char) -> usize {
    if (c as u32) < 0x20 || c == '\x7f' { 2 } else { 1 }
}

fn display_width(s: &[char]) -> usize {
    s.iter().map(|&c| char_width(c)).sum()
}

/// Control characters (a newline in a recalled multi-line command, say) show as `^X`.
fn push_display(out: &mut String, c: char) {
    if (c as u32) < 0x20 {
        out.push('^');
        out.push((c as u8 + b'@') as char);
    } else if c == '\x7f' {
        out.push_str("^?");
    } else {
        out.push(c);
    }
}

fn word_start(buf: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 && !buf[i - 1].is_alphanumeric() {
        i -= 1;
    }
    while i > 0 && buf[i - 1].is_alphanumeric() {
        i -= 1;
    }
    i
}

fn word_end(buf: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i < buf.len() && !buf[i].is_alphanumeric() {
        i += 1;
    }
    while i < buf.len() && buf[i].is_alphanumeric() {
        i += 1;
    }
    i
}

/// History file entries are one per line; a multi-line command's newlines (and backslashes) are
/// escaped.
fn escape_entry(e: &str) -> String {
    e.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape_entry(e: &str) -> String {
    let mut out = String::new();
    let mut chars = e.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Where the word being completed starts: after the last unescaped blank or operator character.
fn completion_start(buf: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 {
        let c = buf[i - 1];
        let escaped = i >= 2 && buf[i - 2] == '\\';
        if !escaped && (c.is_whitespace() || ";|&()<>`\"'".contains(c)) {
            break;
        }
        i -= 1;
    }
    i
}

fn is_command_position(before: &str) -> bool {
    let t = before.trim_end();
    if t.is_empty() || t.ends_with([';', '|', '&', '(', '`', '{']) || t.ends_with("$(") {
        return true;
    }
    let last = t.rsplit(|c: char| c.is_whitespace()).next().unwrap_or("");
    matches!(last, "then" | "do" | "else" | "elif" | "if" | "while" | "until" | "!" | "time" | "exec" | "command" | "nohup" | "env")
}

fn unescape_word(w: &str) -> String {
    let mut out = String::new();
    let mut chars = w.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_word(w: &str) -> String {
    let mut out = String::new();
    for c in w.chars() {
        if " \t'\"\\$`|&;<>()*?[#=!{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn common_prefix(c: &[String]) -> String {
    let mut prefix: Vec<char> = c[0].chars().collect();
    for s in &c[1..] {
        let n = prefix.iter().zip(s.chars()).take_while(|(a, b)| **a == *b).count();
        prefix.truncate(n);
    }
    prefix.into_iter().collect()
}

/// How a candidate is listed: just its last path component (`dir/` for a directory).
fn display_name(c: &str) -> &str {
    let trimmed = c.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(i) => &c[i + 1..],
        None => c,
    }
}

fn command_candidates(sh: &Shell, prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = crate::builtins::names().into_iter().filter(|n| n.starts_with(prefix)).map(String::from).collect();
    out.extend(sh.functions.keys().filter(|n| n.starts_with(prefix)).cloned());
    for kw in ["if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in"] {
        if kw.starts_with(prefix) && !prefix.is_empty() {
            out.push(kw.to_string());
        }
    }
    let path = sh.get("PATH").unwrap_or_default();
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let Some(name) = e.file_name().to_str().map(String::from) else { continue };
            if name.starts_with(prefix) && sys::is_executable_file(&format!("{dir}/{name}")) {
                out.push(name);
            }
        }
    }
    out
}

fn path_candidates(sh: &Shell, word: &str) -> Vec<String> {
    let (dir_part, prefix) = match word.rfind('/') {
        Some(i) => (&word[..=i], &word[i + 1..]),
        None => ("", word),
    };
    // `~/` and `~user/` are listed from the home directory but kept as typed.
    let listed_dir = if let Some(rest) = dir_part.strip_prefix('~') {
        let (user, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let home = if user.is_empty() { sh.get("HOME") } else { sys::home_of(user) };
        match home {
            Some(h) => format!("{}{tail}", h.trim_end_matches('/')),
            None => return Vec::new(),
        }
    } else if dir_part.is_empty() {
        ".".to_string()
    } else {
        dir_part.to_string()
    };
    let Ok(entries) = std::fs::read_dir(&listed_dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(String::from) else { continue };
        if !name.starts_with(prefix) || (name.starts_with('.') && !prefix.starts_with('.')) {
            continue;
        }
        let is_dir = std::fs::metadata(format!("{listed_dir}/{name}")).is_ok_and(|m| m.is_dir());
        out.push(format!("{dir_part}{name}{}", if is_dir { "/" } else { "" }));
    }
    out
}
