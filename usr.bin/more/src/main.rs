//! `more(1)`, also `less(1)`: a pager (MAN.md §8.6 in OxideBSD-doc).
//!
//! ```text
//! more [-ceFisu] [-n number] [-p command] [+command] [file ...]
//! ```
//!
//! POSIX `more` with less's backward movement and searching. Bold and underline arrive as SGR
//! sequences or as backspace overstrike (`c\bc`, `_\bc`); both are shown as SGR. When standard
//! output isn't a terminal, the input is copied through unchanged.

use std::io::{IsTerminal, Read, Write};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Attr {
    bold: bool,
    under: bool,
    reverse: bool,
}

impl Attr {
    fn sgr(self) -> String {
        let mut s = String::from("\x1b[0");
        if self.bold {
            s.push_str(";1");
        }
        if self.under {
            s.push_str(";4");
        }
        if self.reverse {
            s.push_str(";7");
        }
        s.push('m');
        s
    }
}

type Cell = (char, Attr);

struct Opts {
    exit_at_eof: bool,
    quit_if_one_screen: bool,
    ignore_case: bool,
    squeeze: bool,
    no_styles: bool,
    lines: Option<usize>,
    initial: Option<String>,
}

/// One input line as display cells: SGR sequences and overstrikes become attributes, tabs
/// become spaces to the next multiple of 8, other control characters are shown as `^X`.
fn cells(line: &str, no_styles: bool) -> Vec<Cell> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<Cell> = Vec::new();
    let mut attr = Attr::default();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\x1b' && chars.get(i + 1) == Some(&'[') {
            // An SGR sequence: parameters up to `m`.
            let mut j = i + 2;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == ';') {
                j += 1;
            }
            if chars.get(j) == Some(&'m') {
                let params: String = chars[i + 2..j].iter().collect();
                for p in params.split(';') {
                    match p {
                        "" | "0" => attr = Attr::default(),
                        "1" => attr.bold = true,
                        "4" => attr.under = true,
                        "7" => attr.reverse = true,
                        "22" => attr.bold = false,
                        "24" => attr.under = false,
                        "27" => attr.reverse = false,
                        _ => {}
                    }
                }
                i = j + 1;
                continue;
            }
        }
        if chars.get(i + 1) == Some(&'\x08') && i + 2 < chars.len() && !no_styles {
            // Overstrike: `_\bc` underlines, `c\bc` emboldens; chains stack.
            let mut a = attr;
            let mut base = c;
            let mut j = i;
            while chars.get(j + 1) == Some(&'\x08') && j + 2 < chars.len() {
                let next = chars[j + 2];
                if base == '_' && next != '_' {
                    a.under = true;
                    base = next;
                } else if next == '_' && base != '_' {
                    a.under = true;
                } else if next == base {
                    a.bold = true;
                } else {
                    base = next;
                }
                j += 2;
            }
            out.push((base, a));
            i = j + 1;
            continue;
        }
        match c {
            '\t' => {
                let n = 8 - out.len() % 8;
                out.extend(std::iter::repeat_n((' ', attr), n));
            }
            '\x08' => {
                out.pop();
            }
            c if (c as u32) < 32 || c == '\x7f' => {
                out.push(('^', attr));
                out.push((((c as u8) ^ 0x40) as char, attr));
            }
            c => out.push((c, attr)),
        }
        i += 1;
    }
    out
}

/// The terminal: the controlling tty for keys, standard output for display.
struct Tty {
    fd: i32,
    saved: libc::termios,
    rows: usize,
    cols: usize,
}

static mut SAVED: Option<(i32, libc::termios)> = None;

extern "C" fn on_signal(sig: libc::c_int) {
    // SAFETY: restoring the terminal from a signal handler: tcsetattr and write are
    // async-signal-safe.
    unsafe {
        if let Some((fd, t)) = SAVED {
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
        let msg = b"\x1b[0m\x1b[?1049l";
        libc::write(1, msg.as_ptr().cast(), msg.len());
        libc::_exit(128 + sig);
    }
}

impl Tty {
    fn open() -> Option<Tty> {
        let fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDONLY) };
        let fd = if fd >= 0 { fd } else if std::io::stdin().is_terminal() { 0 } else { return None };
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
            SAVED = Some((fd, saved));
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
        }
        let mut t = Tty { fd, saved, rows: 24, cols: 80 };
        t.size();
        Some(t)
    }

    fn size(&mut self) {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 1 && ws.ws_col > 0 {
            self.rows = ws.ws_row as usize;
            self.cols = ws.ws_col as usize;
        }
    }

    fn key(&self) -> Option<u8> {
        let mut b = [0u8; 1];
        loop {
            let n = unsafe { libc::read(self.fd, b.as_mut_ptr().cast(), 1) };
            if n == 1 {
                return Some(b[0]);
            }
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

struct File {
    name: String,
    /// Screen rows: input lines folded at the terminal width.
    rows: Vec<Vec<Cell>>,
    /// The first row on the screen.
    top: usize,
}

struct Pager {
    tty: Tty,
    files: Vec<File>,
    cur: usize,
    opts: Opts,
    pattern: Option<(String, bool)>,
    message: Option<String>,
    out: std::io::StdoutLock<'static>,
}

fn load(name: &str, text: &str, cols: usize, opts: &Opts) -> File {
    let mut rows = Vec::new();
    let mut blank_run = false;
    for line in text.split_inclusive('\n') {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let c = cells(line, opts.no_styles);
        let blank = c.iter().all(|(ch, _)| *ch == ' ');
        if opts.squeeze && blank && blank_run {
            continue;
        }
        blank_run = blank;
        if c.is_empty() {
            rows.push(Vec::new());
            continue;
        }
        for chunk in c.chunks(cols.max(1)) {
            rows.push(chunk.to_vec());
        }
    }
    File { name: name.to_string(), rows, top: 0 }
}

impl Pager {
    fn page(&self) -> usize {
        self.opts.lines.unwrap_or(self.tty.rows.saturating_sub(1)).max(1)
    }

    fn file(&self) -> &File {
        &self.files[self.cur]
    }

    fn max_top(&self) -> usize {
        self.file().rows.len().saturating_sub(self.page())
    }

    fn at_end(&self) -> bool {
        self.file().top + self.page() >= self.file().rows.len()
    }

    fn scroll(&mut self, delta: isize) {
        let max = self.max_top() as isize;
        let f = &mut self.files[self.cur];
        f.top = (f.top as isize + delta).clamp(0, max.max(0)) as usize;
    }

    fn row_matches(&self, row: &[Cell], pat: &str) -> Vec<(usize, usize)> {
        let text: String = row.iter().map(|(c, _)| *c).collect();
        let (hay, needle) = if self.opts.ignore_case { (text.to_lowercase(), pat.to_lowercase()) } else { (text.clone(), pat.to_string()) };
        let mut hits = Vec::new();
        if needle.is_empty() {
            return hits;
        }
        let mut from = 0;
        while let Some(pos) = hay[from..].find(&needle) {
            let start = hay[..from + pos].chars().count();
            hits.push((start, start + needle.chars().count()));
            from += pos + needle.len().max(1);
        }
        hits
    }

    fn draw(&mut self) {
        let page = self.page();
        let cols = self.tty.cols;
        let f = &self.files[self.cur];
        let mut s = String::from("\x1b[H");
        for r in 0..page {
            let row = f.rows.get(f.top + r);
            let hits = match (&self.pattern, row) {
                (Some((p, _)), Some(row)) => self.row_matches(row, p),
                _ => Vec::new(),
            };
            let mut cur = Attr::default();
            if let Some(row) = row {
                for (k, (ch, a)) in row.iter().take(cols).enumerate() {
                    let mut a = *a;
                    if hits.iter().any(|(s, e)| (*s..*e).contains(&k)) {
                        a.reverse = true;
                    }
                    if a != cur {
                        s.push_str(&a.sgr());
                        cur = a;
                    }
                    s.push(*ch);
                }
            } else {
                s.push('~');
            }
            if cur != Attr::default() {
                s.push_str("\x1b[0m");
            }
            s.push_str("\x1b[K\r\n");
        }
        let status = if let Some(m) = self.message.take() {
            m
        } else if self.at_end() {
            if self.files.len() > 1 && self.cur + 1 < self.files.len() {
                format!("(END) - Next: {}", self.files[self.cur + 1].name)
            } else {
                "(END)".to_string()
            }
        } else {
            let pct = ((f.top + page) * 100 / f.rows.len().max(1)).min(100);
            if f.name.is_empty() { format!("--More--({pct}%)") } else { format!("{} ({pct}%)", f.name) }
        };
        s.push_str("\x1b[7m");
        s.push_str(&status.chars().take(cols.saturating_sub(1)).collect::<String>());
        s.push_str("\x1b[0m\x1b[K");
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    /// Reads a line on the status line (a search pattern or a `:` command).
    fn prompt(&mut self, lead: char) -> Option<String> {
        let rows = self.page() + 1;
        let _ = write!(self.out, "\x1b[{rows};1H\x1b[K{lead}");
        let _ = self.out.flush();
        let mut buf = String::new();
        loop {
            let k = self.tty.key()?;
            match k {
                b'\r' | b'\n' => return Some(buf),
                0x1b | 0x03 | 0x07 => return None,
                0x7f | 0x08 => {
                    if buf.pop().is_none() {
                        return None;
                    }
                    let _ = write!(self.out, "\x08 \x08");
                }
                0x15 => {
                    for _ in 0..buf.chars().count() {
                        let _ = write!(self.out, "\x08 \x08");
                    }
                    buf.clear();
                }
                c if c >= 0x20 => {
                    buf.push(c as char);
                    let _ = self.out.write_all(&[c]);
                }
                _ => {}
            }
            let _ = self.out.flush();
        }
    }

    fn search(&mut self, forward: bool, again: bool) {
        let Some((pat, dir)) = self.pattern.clone() else {
            self.message = Some("No previous search pattern".into());
            return;
        };
        let forward = if again { forward == dir } else { forward };
        let f = &self.files[self.cur];
        let start = f.top;
        let found = if forward {
            (start + 1..f.rows.len()).find(|&r| !self.row_matches(&f.rows[r], &pat).is_empty())
        } else {
            (0..start).rev().find(|&r| !self.row_matches(&f.rows[r], &pat).is_empty())
        };
        match found {
            Some(r) => {
                let max = self.max_top();
                self.files[self.cur].top = r.min(max);
            }
            None => self.message = Some("Pattern not found".into()),
        }
    }

    fn command(&mut self, cmd: &str) {
        // `+/pattern`, `+G`, `+number`.
        if let Some(p) = cmd.strip_prefix('/') {
            self.pattern = Some((p.to_string(), true));
            self.files[self.cur].top = 0;
            if !self.file().rows.first().is_some_and(|r| !self.row_matches(r, p).is_empty()) {
                self.search(true, false);
            }
        } else if cmd == "G" {
            self.files[self.cur].top = self.max_top();
        } else if let Ok(n) = cmd.parse::<usize>() {
            self.files[self.cur].top = n.saturating_sub(1).min(self.max_top());
        }
    }

    fn help(&mut self) {
        let text = "\
  SUMMARY OF COMMANDS (N is an optional count)\n\n\
  SPACE f ^F ^V   Forward one screen (N screens)\n\
  b ^B            Backward one screen\n\
  RETURN j e ^N   Forward one line (N lines)\n\
  k y ^Y ^P       Backward one line\n\
  d ^D / u ^U     Forward / backward half a screen\n\
  g <             Go to the first line (line N)\n\
  G >             Go to the last line (line N)\n\
  /pattern        Search forward\n\
  ?pattern        Search backward\n\
  n / N           Repeat the search / in reverse\n\
  :n / :p         Next / previous file\n\
  = ^G            Show position\n\
  r ^L            Redraw\n\
  h               This summary\n\
  q Q ZZ          Quit\n\n\
  Press any key to return.";
        let _ = write!(self.out, "\x1b[H\x1b[2J{}", text.replace('\n', "\r\n"));
        let _ = self.out.flush();
        self.tty.key();
    }

    fn run(&mut self) {
        let _ = write!(self.out, "\x1b[?1049h\x1b[H\x1b[2J");
        if let Some(cmd) = self.opts.initial.clone() {
            self.command(&cmd);
        }
        if self.opts.quit_if_one_screen && self.files.len() == 1 && self.file().rows.len() <= self.page() {
            let _ = write!(self.out, "\x1b[?1049l");
            self.dump_current();
            return;
        }
        let mut count: Option<usize> = None;
        let mut prev_z = false;
        loop {
            self.draw();
            if self.opts.exit_at_eof && self.at_end() && self.cur + 1 >= self.files.len() {
                break;
            }
            let Some(k) = self.tty.key() else { break };
            let n = count.take();
            let page = self.page() as isize;
            match k {
                b'0'..=b'9' => {
                    count = Some(n.unwrap_or(0) * 10 + (k - b'0') as usize);
                    continue;
                }
                b' ' | b'f' | 0x06 | 0x16 => {
                    if self.at_end() && self.cur + 1 < self.files.len() {
                        self.cur += 1;
                    } else {
                        self.scroll(page * n.unwrap_or(1) as isize);
                    }
                }
                b'b' | 0x02 => self.scroll(-page * n.unwrap_or(1) as isize),
                b'\r' | b'\n' | b'j' | b'e' | 0x0e | 0x05 => self.scroll(n.unwrap_or(1) as isize),
                b'k' | b'y' | 0x19 | 0x10 | 0x0b => self.scroll(-(n.unwrap_or(1) as isize)),
                b'd' | 0x04 => self.scroll(page / 2),
                b'u' | 0x15 => self.scroll(-page / 2),
                b'g' | b'<' => self.files[self.cur].top = n.map(|l| l.saturating_sub(1)).unwrap_or(0).min(self.max_top()),
                b'G' | b'>' => self.files[self.cur].top = n.map(|l| l.saturating_sub(1)).unwrap_or(usize::MAX).min(self.max_top()),
                b'/' | b'?' => {
                    if let Some(p) = self.prompt(k as char) {
                        if !p.is_empty() {
                            self.pattern = Some((p, k == b'/'));
                        }
                        self.search(k == b'/', false);
                    }
                }
                b'n' => self.search(true, true),
                b'N' => self.search(false, true),
                b':' => match self.prompt(':').as_deref() {
                    Some("n") if self.cur + 1 < self.files.len() => self.cur += 1,
                    Some("p") if self.cur > 0 => self.cur -= 1,
                    Some("q") => break,
                    _ => {}
                },
                b'=' | 0x07 => {
                    let f = self.file();
                    self.message = Some(format!("{} lines {}-{}/{}", if f.name.is_empty() { "standard input" } else { f.name.as_str() }, f.top + 1, (f.top + self.page()).min(f.rows.len()), f.rows.len()));
                }
                b'h' | b'H' => self.help(),
                b'r' | 0x0c => {
                    let _ = write!(self.out, "\x1b[2J");
                }
                b'q' | b'Q' => break,
                b'Z' => {
                    if prev_z {
                        break;
                    }
                    prev_z = true;
                    continue;
                }
                0x1b => {
                    // Arrow keys and paging keys: ESC [ A/B, ESC [ 5~ / 6~.
                    if self.tty.key() == Some(b'[') {
                        match self.tty.key() {
                            Some(b'A') => self.scroll(-1),
                            Some(b'B') => self.scroll(1),
                            Some(b'5') => {
                                self.tty.key();
                                self.scroll(-page);
                            }
                            Some(b'6') => {
                                self.tty.key();
                                self.scroll(page);
                            }
                            Some(b'H') | Some(b'1') => self.files[self.cur].top = 0,
                            Some(b'F') | Some(b'4') => self.files[self.cur].top = self.max_top(),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            prev_z = false;
        }
        let _ = write!(self.out, "\x1b[0m\x1b[?1049l");
        let _ = self.out.flush();
    }

    fn dump_current(&mut self) {
        let rows = self.file().rows.clone();
        for row in rows {
            let mut cur = Attr::default();
            let mut s = String::new();
            for (ch, a) in row {
                if a != cur {
                    s.push_str(&a.sgr());
                    cur = a;
                }
                s.push(ch);
            }
            if cur != Attr::default() {
                s.push_str("\x1b[0m");
            }
            s.push('\n');
            let _ = self.out.write_all(s.as_bytes());
        }
        let _ = self.out.flush();
    }
}

fn usage() -> ! {
    eprintln!("usage: more [-ceFisu] [-n number] [-p command] [+command] [file ...]");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Opts { exit_at_eof: false, quit_if_one_screen: false, ignore_case: false, squeeze: false, no_styles: false, lines: None, initial: None };
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(cmd) = a.strip_prefix('+') {
            opts.initial = Some(cmd.to_string());
        } else if a == "--" {
            files.extend(args[i + 1..].iter().cloned());
            break;
        } else if a.starts_with('-') && a.len() > 1 {
            let flags: Vec<char> = a[1..].chars().collect();
            let mut k = 0;
            while k < flags.len() {
                match flags[k] {
                    'c' | 'R' | 'r' | 'X' | 'K' => {}
                    'e' | 'E' => opts.exit_at_eof = true,
                    'F' => opts.quit_if_one_screen = true,
                    'i' | 'I' => opts.ignore_case = true,
                    's' => opts.squeeze = true,
                    'u' => opts.no_styles = true,
                    'n' | 'p' | 't' => {
                        let rest: String = flags[k + 1..].iter().collect();
                        let v = if rest.is_empty() {
                            i += 1;
                            args.get(i).cloned().unwrap_or_else(|| usage())
                        } else {
                            rest
                        };
                        match flags[k] {
                            'n' => opts.lines = Some(v.parse().unwrap_or_else(|_| usage())),
                            'p' => opts.initial = Some(v),
                            _ => opts.initial = Some(format!("/{v}")),
                        }
                        k = flags.len();
                        continue;
                    }
                    _ => usage(),
                }
                k += 1;
            }
        } else {
            files.push(a.clone());
        }
        i += 1;
    }

    // Read everything first: files, or standard input.
    let mut inputs: Vec<(String, String)> = Vec::new();
    if files.is_empty() {
        let mut buf = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut buf);
        inputs.push((String::new(), String::from_utf8_lossy(&buf).into_owned()));
    } else {
        for f in &files {
            match std::fs::read(f) {
                Ok(b) => inputs.push((f.clone(), String::from_utf8_lossy(&b).into_owned())),
                Err(e) => eprintln!("more: {f}: {e}"),
            }
        }
    }

    let stdout = std::io::stdout();
    if !stdout.is_terminal() {
        let mut out = stdout.lock();
        for (_, text) in &inputs {
            let _ = out.write_all(text.as_bytes());
        }
        return;
    }
    let Some(tty) = Tty::open() else {
        let mut out = stdout.lock();
        for (_, text) in &inputs {
            let _ = out.write_all(text.as_bytes());
        }
        return;
    };
    let cols = tty.cols;
    let files = inputs.iter().map(|(n, t)| load(n, t, cols, &opts)).collect();
    let mut p = Pager { tty, files, cur: 0, opts, pattern: None, message: None, out: stdout.lock() };
    if p.files.is_empty() {
        std::process::exit(1);
    }
    p.run();
}
