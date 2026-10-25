//! The installer's dialogs (OxideBSD-doc `INSTALLER.md` §9.7): bsdinstall's and sysinst's boxes --
//! a title, text, a list or fields, buttons -- over a screen naming the step, in the rust palette
//! (`curses`). The keys are `dialog(1)`'s: the arrows (and `j`/`k`) move in a list, Tab and
//! Shift-Tab between the list or fields and the buttons, Enter takes the highlighted button (in a
//! list, its item), Space ticks a checklist's item, Esc goes back; F1 shows the screen's help and
//! F10 a shell on the install medium, from any dialog.

use std::os::unix::process::CommandExt;

use crate::curses::{
    A_BOLD, KEY_BACKSPACE, KEY_BTAB, KEY_DC, KEY_DOWN, KEY_END, KEY_ENTER, KEY_F0, KEY_HOME, KEY_LEFT, KEY_NPAGE, KEY_PPAGE,
    KEY_RIGHT, KEY_UP, Pair, Screen,
};

const ESC: i32 = 0x1b;
const TAB: i32 = 0x09;

fn is_enter(k: i32) -> bool {
    matches!(k, KEY_ENTER | 0x0a | 0x0d)
}

/// `text`'s words in lines of at most `width` columns; a blank line stays one.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            let len = line.chars().count();
            if len > 0 && len + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        out.push(line);
    }
    out
}

fn width_of(s: &str) -> i32 {
    s.chars().count() as i32
}

/// What one dialog says: its title, its text (wrapped to fit), and its F1 help.
pub struct Dialog<'a> {
    pub title: &'a str,
    pub text: &'a str,
    pub help: &'a str,
}

impl<'a> Dialog<'a> {
    pub fn new(title: &'a str, text: &'a str, help: &'a str) -> Dialog<'a> {
        Dialog { title, text, help }
    }
}

/// One text field of a form.
pub struct Field {
    pub label: String,
    pub value: String,
    /// A password: shown as `*`.
    pub secret: bool,
}

impl Field {
    pub fn new(label: &str, value: &str) -> Field {
        Field { label: label.into(), value: value.into(), secret: false }
    }

    pub fn secret(label: &str) -> Field {
        Field { label: label.into(), value: String::new(), secret: true }
    }
}

/// One item of a checklist: its name, what it is, whether it's ticked, and whether it must stay
/// so (the base set).
pub struct Check {
    pub name: String,
    pub what: String,
    pub on: bool,
    pub fixed: bool,
}

/// A dialog's place on the screen, once drawn: its box, and where its inside starts.
struct Placed {
    y: i32,
    x: i32,
    h: i32,
    w: i32,
    /// The first row below the text.
    body: i32,
}

/// The screen the dialogs are drawn on, and the step they belong to.
pub struct Ui {
    pub screen: Screen,
    /// `OxideBSD 0.3.0 installer`.
    pub title: String,
    /// `Step 2 of 8: Disks`, at the top right.
    pub step: String,
    /// The dialog last drawn (its title and text): a new one repaints the whole screen.
    last: std::cell::RefCell<(String, String)>,
}

impl Ui {
    pub fn new(screen: Screen, title: String) -> Ui {
        Ui { screen, title, step: String::new(), last: Default::default() }
    }

    /// The screen behind the dialogs: the title, the step, a rule, and the keys at the bottom.
    fn backdrop(&self, keys: &str) {
        let s = &self.screen;
        let (rows, cols) = s.size();
        s.clear();
        let blank = " ".repeat(cols as usize);
        for y in 0..rows {
            s.put(y, 0, &blank, Pair::Screen.attr());
        }
        s.put(0, 1, &self.title, Pair::Screen.attr() | A_BOLD);
        s.put(0, cols - 1 - width_of(&self.step), &self.step, Pair::Screen.attr());
        s.put(1, 1, &"═".repeat(cols as usize - 2), Pair::Screen.attr());
        s.put(rows - 1, 1, keys, Pair::Screen.attr());
    }

    /// Draws a dialog of `inner` rows below its text, at least `min_w` wide, with its shadow,
    /// frame, title and text, in the middle of the screen.
    fn place(&self, d: &Dialog, inner: i32, min_w: i32) -> Placed {
        let s = &self.screen;
        let this = (d.title.to_string(), d.text.to_string());
        if *self.last.borrow() != this {
            s.repaint();
            *self.last.borrow_mut() = this;
        }
        let (rows, cols) = s.size();
        let w = min_w.max(width_of(d.title) + 8).max(52).min(cols - 4);
        let text = if d.text.is_empty() { Vec::new() } else { wrap(d.text, (w - 6) as usize) };
        let h = (text.len() as i32 + inner + 4 + if text.is_empty() { 0 } else { 1 }).min(rows - 4);
        let y = ((rows - h) / 2).max(2);
        let x = (cols - w) / 2;
        for r in y + 1..=y + h {
            s.put(r, x + w, "  ", Pair::Shadow.attr());
        }
        s.put(y + h, x + 2, &" ".repeat(w as usize), Pair::Shadow.attr());
        let fill = " ".repeat(w as usize);
        for r in y..y + h {
            s.put(r, x, &fill, Pair::Box.attr());
        }
        self.frame(y, x, h, w);
        let t = format!(" {} ", d.title);
        s.put(y, x + (w - width_of(&t)) / 2, &t, Pair::Title.attr() | A_BOLD);
        for (i, l) in text.iter().enumerate() {
            s.put(y + 2 + i as i32, x + 3, l, Pair::Box.attr());
        }
        let body = y + 2 + text.len() as i32 + if text.is_empty() { 0 } else { 1 };
        Placed { y, x, h, w, body }
    }

    fn frame(&self, y: i32, x: i32, h: i32, w: i32) {
        let s = &self.screen;
        let a = Pair::Frame.attr();
        let line = "─".repeat(w as usize - 2);
        s.put(y, x, &format!("┌{line}┐"), a);
        for r in y + 1..y + h - 1 {
            s.put(r, x, "│", a);
            s.put(r, x + w - 1, "│", a);
        }
        s.put(y + h - 1, x, &format!("└{line}┘"), a);
    }

    /// The buttons along a dialog's bottom, `at` highlighted when `focused`.
    fn buttons(&self, p: &Placed, labels: &[&str], at: usize, focused: bool) {
        let s = &self.screen;
        let cells: Vec<String> = labels.iter().map(|l| format!("<{l:^8}>")).collect();
        let total: i32 = cells.iter().map(|c| width_of(c)).sum::<i32>() + 4 * (cells.len() as i32 - 1);
        let mut x = p.x + (p.w - total) / 2;
        for (i, c) in cells.iter().enumerate() {
            let sel = focused && i == at;
            let a = if sel { Pair::Sel.attr() | A_BOLD } else { Pair::Box.attr() };
            s.put(p.y + p.h - 2, x, c, a);
            // The shortcut letter, as dialog(1) draws it.
            if let Some((off, ch)) = c.char_indices().find(|(_, ch)| ch.is_alphanumeric()) {
                let col = x + c[..off].chars().count() as i32;
                s.put(p.y + p.h - 2, col, &ch.to_string(), if sel { a } else { Pair::Key.attr() | A_BOLD });
            }
            x += width_of(c) + 4;
        }
    }

    /// The next key, the screen-wide ones taken care of: F1 shows `help` and F10 a shell, both
    /// asking the caller to draw again (`None`).
    fn key(&self, help: &str) -> Option<i32> {
        let k = self.screen.key().unwrap_or(ESC);
        match k {
            k if k == KEY_F0 + 1 => {
                self.help(help);
                None
            }
            k if k == KEY_F0 + 10 => {
                self.shell();
                None
            }
            k => Some(k),
        }
    }

    fn help(&self, help: &str) {
        let text = if help.is_empty() { "There is no help for this screen." } else { help };
        self.backdrop("Any key goes back");
        let d = Dialog { title: "Help", text, help: "" };
        let p = self.place(&d, 0, 64);
        self.buttons(&p, &["OK"], 0, true);
        self.screen.show();
        self.screen.key();
    }

    /// A shell on the install medium, the installer back when it exits.
    pub fn shell(&self) {
        self.screen.suspend(|| {
            println!("\nThe install medium's shell; `exit` returns to the installer.\n");
            let _ = std::process::Command::new("/bin/sh").arg0("-sh").status();
            take_foreground();
        });
    }

    /// A message and an OK button.
    pub fn message(&self, d: &Dialog) {
        loop {
            self.backdrop("Enter goes   F1 help   F10 shell");
            let p = self.place(d, 0, 0);
            self.buttons(&p, &["OK"], 0, true);
            self.screen.show();
            match self.key(d.help) {
                Some(k) if is_enter(k) || k == ESC || k == b' ' as i32 => return,
                _ => {}
            }
        }
    }

    /// Two buttons; `Some(true)` for the first, `None` for Esc.
    pub fn yesno(&self, d: &Dialog, yes: &str, no: &str) -> Option<bool> {
        let mut at = 0;
        loop {
            self.backdrop("←→ choose   Enter goes   Esc back   F1 help");
            let p = self.place(d, 0, 0);
            self.buttons(&p, &[yes, no], at, true);
            self.screen.show();
            match self.key(d.help) {
                Some(KEY_LEFT | KEY_RIGHT | TAB | KEY_BTAB) => at ^= 1,
                Some(k) if is_enter(k) => return Some(at == 0),
                Some(ESC) => return None,
                Some(k) if first_letter(yes) == Some(k) => return Some(true),
                Some(k) if first_letter(no) == Some(k) => return Some(false),
                _ => {}
            }
        }
    }

    /// A list of `(name, what)` items, one chosen; its index, or `None` to go back. `at` is the
    /// item first highlighted.
    pub fn menu(&self, d: &Dialog, items: &[(String, String)], at: usize) -> Option<usize> {
        self.menu_keys(d, items, at, "↑↓ choose   Tab to the buttons   Enter goes   Esc back   F1 help   F10 shell")
    }

    /// `menu`, with `keys` on the screen's bottom line.
    pub fn menu_keys(&self, d: &Dialog, items: &[(String, String)], at: usize, keys: &str) -> Option<usize> {
        match self.menu_buttons(d, items, at, &["OK", "Back"], keys, true)? {
            (_, 1) => None,
            (_, _) if items.is_empty() => None,
            (i, _) => Some(i),
        }
    }

    /// A list of `(name, what)` items and a row of `buttons`: Enter gives the highlighted item
    /// and button, `None` is Esc. With `jump`, a letter goes to the next item starting with it;
    /// without, to the button starting with it, as if pressed.
    pub fn menu_buttons(&self, d: &Dialog, items: &[(String, String)], at: usize, buttons: &[&str], keys: &str, jump: bool) -> Option<(usize, usize)> {
        let mut at = at.min(items.len().saturating_sub(1));
        let mut btn = 0usize;
        let name_w = items.iter().map(|(n, _)| width_of(n)).max().unwrap_or(0) + 2;
        let line_w = items.iter().map(|(_, w)| name_w + width_of(w)).max().unwrap_or(0);
        let buttons_w = buttons.len() as i32 * 14;
        let mut top = 0usize;
        loop {
            self.backdrop(keys);
            let (rows, _) = self.screen.size();
            let shown = (items.len() as i32).min(rows - 14).max(3) as usize;
            let p = self.place(d, shown as i32 + 3, (line_w + 12).max(buttons_w));
            let lx = p.x + 3;
            let lw = p.w - 6;
            self.frame(p.body, lx, shown as i32 + 2, lw);
            if at < top {
                top = at;
            } else if at >= top + shown {
                top = at + 1 - shown;
            }
            for (row, i) in (top..items.len().min(top + shown)).enumerate() {
                let (n, w) = &items[i];
                let sel = i == at;
                let y = p.body + 1 + row as i32;
                let a = if sel { Pair::Sel.attr() } else { Pair::Box.attr() };
                self.screen.put(y, lx + 1, &" ".repeat(lw as usize - 2), a);
                self.screen.put(y, lx + 2, n, if sel { a | A_BOLD } else { Pair::Key.attr() | A_BOLD });
                let room = (lw - 4 - name_w).max(0) as usize;
                self.screen.put(y, lx + 2 + name_w, &w.chars().take(room).collect::<String>(), a);
            }
            if top > 0 {
                self.screen.put(p.body, lx + lw - 4, "↑", Pair::Frame.attr());
            }
            if top + shown < items.len() {
                self.screen.put(p.body + shown as i32 + 1, lx + lw - 4, "↓", Pair::Frame.attr());
            }
            self.buttons(&p, buttons, btn, true);
            self.screen.show();
            let Some(k) = self.key(d.help) else { continue };
            let n = buttons.len();
            match k {
                KEY_UP | 0x6b if jump && !items.is_empty() => at = at.checked_sub(1).unwrap_or(items.len() - 1),
                KEY_DOWN | 0x6a if jump && !items.is_empty() => at = (at + 1) % items.len(),
                KEY_UP if !items.is_empty() => at = at.checked_sub(1).unwrap_or(items.len() - 1),
                KEY_DOWN if !items.is_empty() => at = (at + 1) % items.len(),
                KEY_PPAGE => at = at.saturating_sub(shown),
                KEY_NPAGE => at = (at + shown).min(items.len().saturating_sub(1)),
                KEY_HOME => at = 0,
                KEY_END => at = items.len().saturating_sub(1),
                TAB | KEY_RIGHT => btn = (btn + 1) % n,
                KEY_BTAB | KEY_LEFT => btn = (btn + n - 1) % n,
                ESC => return None,
                k if is_enter(k) => return Some((at, btn)),
                k if !jump => {
                    if let Some(b) = buttons.iter().position(|b| first_letter(b) == Some(k)) {
                        return Some((at, b));
                    }
                }
                k => {
                    // The first item after this one whose name starts with the letter.
                    if let Some(c) = char::from_u32(k as u32).filter(|c| c.is_ascii_alphanumeric()) {
                        let n = items.len();
                        if let Some(i) = (1..=n).map(|o| (at + o) % n).find(|&i| items[i].0.to_ascii_lowercase().starts_with(c.to_ascii_lowercase())) {
                            at = i;
                        }
                    }
                }
            }
        }
    }

    /// A form: each field edited in turn; `true` for OK (with every field's new value), `false`
    /// to go back.
    pub fn form(&self, d: &Dialog, fields: &mut [Field]) -> bool {
        let label_w = fields.iter().map(|f| width_of(&f.label)).max().unwrap_or(0) + 2;
        // The field focused, or the buttons (`fields.len()`, then +1 for Back).
        let mut at = 0usize;
        let mut cursor: Vec<usize> = fields.iter().map(|f| f.value.chars().count()).collect();
        let field_w = 30i32;
        let mut utf8 = Utf8::default();
        loop {
            self.backdrop("Tab next   Enter goes   Esc back   F1 help   F10 shell");
            let p = self.place(d, fields.len() as i32 * 2 + 1, label_w + field_w + 10);
            let fx = p.x + 3 + label_w;
            let fw = (p.w - 6 - label_w).min(field_w + 10);
            let mut cur = None;
            for (i, f) in fields.iter().enumerate() {
                let y = p.body + 2 * i as i32;
                self.screen.put(y, p.x + 3, &f.label, Pair::Box.attr() | if i == at { A_BOLD } else { 0 });
                let shown: String = if f.secret { "*".repeat(f.value.chars().count()) } else { f.value.clone() };
                // The part of a long value around the cursor.
                let skip = cursor[i].saturating_sub(fw as usize - 1);
                let vis: String = shown.chars().skip(skip).take(fw as usize).collect();
                self.screen.put(y, fx, &format!("{vis:<width$}", width = fw as usize), Pair::Field.attr());
                if i == at {
                    cur = Some((y, fx + (cursor[i] - skip) as i32));
                }
            }
            let on_buttons = at >= fields.len();
            self.buttons(&p, &["OK", "Back"], at.saturating_sub(fields.len()), on_buttons);
            self.screen.cursor(cur);
            self.screen.show();
            let Some(k) = self.key(d.help) else { continue };
            self.screen.cursor(None);
            let n = fields.len() + 2;
            match k {
                TAB | KEY_DOWN => at = (at + 1) % n,
                KEY_BTAB | KEY_UP => at = (at + n - 1) % n,
                ESC => return false,
                k if is_enter(k) => match at {
                    a if a < fields.len() - 1 => at += 1,
                    a if a == fields.len() + 1 => return false,
                    _ => return true,
                },
                _ if on_buttons => {
                    if matches!(k, KEY_LEFT | KEY_RIGHT) {
                        at = if at == fields.len() { fields.len() + 1 } else { fields.len() };
                    }
                }
                k => {
                    if let Some(t) = utf8.take(k) {
                        edit(&mut fields[at].value, &mut cursor[at], t);
                    }
                }
            }
        }
    }

    /// A checklist: Space ticks an item (not a fixed one); `true` for OK.
    pub fn checklist(&self, d: &Dialog, items: &mut [Check]) -> bool {
        let mut at = 0usize;
        let mut on_buttons = None::<usize>;
        let name_w = items.iter().map(|c| width_of(&c.name)).max().unwrap_or(0) + 2;
        loop {
            self.backdrop("↑↓ choose   Space ticks   Tab to the buttons   Enter goes   Esc back   F1 help");
            let line_w = items.iter().map(|c| 6 + name_w + width_of(&c.what)).max().unwrap_or(0);
            let p = self.place(d, items.len() as i32 + 3, line_w + 12);
            let lx = p.x + 3;
            let lw = p.w - 6;
            self.frame(p.body, lx, items.len() as i32 + 2, lw);
            for (i, c) in items.iter().enumerate() {
                let sel = on_buttons.is_none() && i == at;
                let y = p.body + 1 + i as i32;
                let a = if sel { Pair::Sel.attr() } else { Pair::Box.attr() };
                self.screen.put(y, lx + 1, &" ".repeat(lw as usize - 2), a);
                let mark = if c.on { "[X]" } else { "[ ]" };
                self.screen.put(y, lx + 2, mark, if c.fixed && !sel { Pair::Dim.attr() } else { a });
                self.screen.put(y, lx + 6, &c.name, if sel { a | A_BOLD } else { Pair::Key.attr() | A_BOLD });
                let room = (lw - 8 - name_w).max(0) as usize;
                self.screen.put(y, lx + 6 + name_w, &c.what.chars().take(room).collect::<String>(), a);
            }
            self.buttons(&p, &["OK", "Back"], on_buttons.unwrap_or(0), true);
            self.screen.show();
            let Some(k) = self.key(d.help) else { continue };
            match k {
                KEY_UP | 0x6b => at = at.checked_sub(1).unwrap_or(items.len() - 1),
                KEY_DOWN | 0x6a => at = (at + 1) % items.len(),
                0x20 => {
                    if !items[at].fixed {
                        items[at].on = !items[at].on;
                    }
                }
                TAB | KEY_RIGHT | KEY_BTAB | KEY_LEFT => on_buttons = Some(on_buttons.map_or(1, |b| (b + 1) % 2)),
                ESC => return false,
                k if is_enter(k) => return on_buttons != Some(1),
                _ => {}
            }
        }
    }

    /// `lines` to read, scrolled with the arrows, and two buttons; `true` for the first.
    pub fn review(&self, d: &Dialog, lines: &[String], yes: &str, no: &str) -> bool {
        let mut top = 0usize;
        let mut at = 1usize;
        loop {
            self.backdrop("↑↓ scroll   ←→ choose   Enter goes   Esc back   F1 help");
            let (rows, _) = self.screen.size();
            let shown = (lines.len() as i32).min(rows - 14).max(3) as usize;
            let w = lines.iter().map(|l| width_of(l)).max().unwrap_or(0) + 10;
            let p = self.place(d, shown as i32 + 3, w);
            let lx = p.x + 3;
            let lw = p.w - 6;
            self.frame(p.body, lx, shown as i32 + 2, lw);
            top = top.min(lines.len().saturating_sub(shown));
            for (row, l) in lines.iter().skip(top).take(shown).enumerate() {
                let room = (lw - 4).max(0) as usize;
                // A line starting with `!` says what's erased: it stands out.
                let (text, a) = match l.strip_prefix('!') {
                    Some(t) => (t, Pair::Title.attr() | A_BOLD),
                    None => (l.as_str(), Pair::Box.attr()),
                };
                self.screen.put(p.body + 1 + row as i32, lx + 2, &text.chars().take(room).collect::<String>(), a);
            }
            if top > 0 {
                self.screen.put(p.body, lx + lw - 4, "↑", Pair::Frame.attr());
            }
            if top + shown < lines.len() {
                self.screen.put(p.body + shown as i32 + 1, lx + lw - 4, "↓", Pair::Frame.attr());
            }
            self.buttons(&p, &[yes, no], at, true);
            self.screen.show();
            match self.key(d.help) {
                Some(KEY_UP | 0x6b) => top = top.saturating_sub(1),
                Some(KEY_DOWN | 0x6a) => top += 1,
                Some(KEY_PPAGE) => top = top.saturating_sub(shown),
                Some(KEY_NPAGE) => top += shown,
                Some(KEY_LEFT | KEY_RIGHT | TAB | KEY_BTAB) => at ^= 1,
                Some(ESC) => return false,
                Some(k) if is_enter(k) => return at == 0,
                _ => {}
            }
        }
    }

    /// A progress bar, `done` of 100, under `text`; drawn and left (no keys).
    pub fn gauge(&self, title: &str, text: &str, done: u32) {
        self.backdrop("Installing: please wait");
        let d = Dialog { title, text, help: "" };
        let p = self.place(&d, 1, 60);
        let bw = (p.w - 8) as usize;
        let filled = bw * done.min(100) as usize / 100;
        let pct = format!("{done:>3}%");
        let bar: String = "█".repeat(filled) + &"░".repeat(bw - filled);
        self.screen.put(p.body, p.x + 4, &bar, Pair::Title.attr());
        self.screen.put(p.body, p.x + 4 + (bw as i32 - 4) / 2, &pct, Pair::Box.attr() | A_BOLD);
        self.screen.show();
    }
}

/// The terminal's foreground back for the installer's process group. An interactive shell makes
/// its own group the foreground and leaves it so when it exits: the installer, then in the
/// background, would be stopped (SIGTTOU) at curses' next terminal setting. Asking for it back is
/// itself such a call, so SIGTTOU is ignored while it's made.
fn take_foreground() {
    // SAFETY: plain system calls on the standard input, the terminal.
    unsafe {
        let old = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::tcsetpgrp(0, libc::getpgrp());
        libc::signal(libc::SIGTTOU, old);
    }
}

/// A button's shortcut: its label's first letter, lower case.
fn first_letter(label: &str) -> Option<i32> {
    label.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_ascii_lowercase() as i32)
}

/// One key's edit of a field's `value`, the cursor at character `at`: a character typed,
/// Backspace, Delete, Ctrl-U, the arrows, Home and End.
fn edit(value: &mut String, at: &mut usize, k: Typed) {
    let mut chars: Vec<char> = value.chars().collect();
    match k {
        Typed::Char(c) => {
            chars.insert(*at, c);
            *at += 1;
        }
        Typed::Key(KEY_LEFT) => *at = at.saturating_sub(1),
        Typed::Key(KEY_RIGHT) => *at = (*at + 1).min(chars.len()),
        Typed::Key(KEY_HOME | 0x01) => *at = 0,
        Typed::Key(KEY_END | 0x05) => *at = chars.len(),
        Typed::Key(KEY_BACKSPACE | 0x7f | 0x08) => {
            if *at > 0 {
                chars.remove(*at - 1);
                *at -= 1;
            }
        }
        Typed::Key(KEY_DC) => {
            if *at < chars.len() {
                chars.remove(*at);
            }
        }
        Typed::Key(0x15) => {
            chars.clear();
            *at = 0;
        }
        Typed::Key(_) => {}
    }
    *value = chars.into_iter().collect();
}

/// A key as a field takes it: a character (its UTF-8 bytes, which come a key each, put
/// together by `Utf8`), or any other key.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Typed {
    Char(char),
    Key(i32),
}

/// Puts a character's UTF-8 bytes back together, as `getch` hands them over one by one.
#[derive(Default)]
struct Utf8(Vec<u8>);

impl Utf8 {
    /// Key `k` as typed: `None` while a character's bytes are still coming.
    fn take(&mut self, k: i32) -> Option<Typed> {
        match k {
            // DEL (0x7f) is what Backspace sends: a key, not a character.
            0x20..=0x7e => Some(Typed::Char(k as u8 as char)),
            0x80..0x100 => {
                self.0.push(k as u8);
                match std::str::from_utf8(&self.0) {
                    Ok(s) => {
                        let c = s.chars().next();
                        self.0.clear();
                        c.map(Typed::Char)
                    }
                    // Not UTF-8 after all: dropped.
                    Err(e) if e.error_len().is_some() => {
                        self.0.clear();
                        None
                    }
                    Err(_) => None,
                }
            }
            k => Some(Typed::Key(k)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping() {
        assert_eq!(wrap("one two three four", 9), ["one two", "three", "four"]);
        assert_eq!(wrap("a\n\nb", 10), ["a", "", "b"]);
    }

    #[test]
    fn editing() {
        let (mut v, mut at) = (String::from("ab"), 2);
        let mut u = Utf8::default();
        for k in [b'c' as i32, KEY_LEFT, KEY_BACKSPACE] {
            edit(&mut v, &mut at, u.take(k).unwrap());
        }
        assert_eq!((v.as_str(), at), ("ac", 1));
        // ü and € typed as their UTF-8 bytes, a key each.
        let (mut v, mut at) = (String::new(), 0);
        for b in "ü€".bytes() {
            if let Some(t) = u.take(b as i32) {
                edit(&mut v, &mut at, t);
            }
        }
        assert_eq!((v.as_str(), at), ("ü€", 2));
        assert_eq!(u.take(0xff), None);
        assert_eq!(u.take(b'x' as i32), Some(Typed::Char('x')));
    }
}
