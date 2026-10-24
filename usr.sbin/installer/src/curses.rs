//! The few ncurses calls the installer draws with (`INSTALLER.md` §9.1: the in-tree ncurses,
//! through FFI), wrapped so the rest of the program needn't touch raw pointers.
//!
//! Text goes out as UTF-8 (the console draws box lines and shades from its CP437 font), in eight
//! colour pairs' worth of the `linux` terminfo's eight colours, which `Screen::start` redefines to
//! the installer's rust palette with the console's `ESC ] P` (`INSTALLER.md` §13) and `Drop` and
//! `suspend` give back with `ESC ] R`. A terminal without the escape shows the stock colours the
//! palette was laid out over: reds, browns and white.

use std::ffi::{CString, c_char, c_int, c_short, c_void};
use std::io::Write;

type Window = c_void;

#[link(name = "ncursesw")]
unsafe extern "C" {
    static mut stdscr: *mut Window;
    static LINES: c_int;
    static COLS: c_int;
    fn initscr() -> *mut Window;
    fn endwin() -> c_int;
    fn cbreak() -> c_int;
    fn noecho() -> c_int;
    fn keypad(win: *mut Window, on: bool) -> c_int;
    fn curs_set(visibility: c_int) -> c_int;
    fn set_escdelay(ms: c_int) -> c_int;
    fn wgetch(win: *mut Window) -> c_int;
    fn erase() -> c_int;
    fn refresh() -> c_int;
    fn clearok(win: *mut Window, on: bool) -> c_int;
    fn wmove(win: *mut Window, y: c_int, x: c_int) -> c_int;
    fn mvaddstr(y: c_int, x: c_int, s: *const c_char) -> c_int;
    fn attron(attrs: c_int) -> c_int;
    fn attroff(attrs: c_int) -> c_int;
    fn has_colors() -> bool;
    fn start_color() -> c_int;
    fn init_pair(pair: c_short, fg: c_short, bg: c_short) -> c_int;
}

/// ncurses' bold attribute (`NCURSES_BITS(1, 13)`).
pub const A_BOLD: c_int = 1 << 21;

/// The keys `getch` returns (`<curses.h>`).
pub const KEY_DOWN: i32 = 0o402;
pub const KEY_UP: i32 = 0o403;
pub const KEY_LEFT: i32 = 0o404;
pub const KEY_RIGHT: i32 = 0o405;
pub const KEY_HOME: i32 = 0o406;
pub const KEY_BACKSPACE: i32 = 0o407;
/// `KEY_F(n)`.
pub const KEY_F0: i32 = 0o410;
pub const KEY_DC: i32 = 0o512;
pub const KEY_NPAGE: i32 = 0o522;
pub const KEY_PPAGE: i32 = 0o523;
pub const KEY_ENTER: i32 = 0o527;
pub const KEY_BTAB: i32 = 0o541;
pub const KEY_END: i32 = 0o550;

/// The palette's eight colours, by the `linux` terminfo's colour numbers, each over the stock
/// colour it stands in for: 0 black, dark brown (text, shadows); 1 red, iron oxide (the screen);
/// 2 green, a dim brown (frames, notes); 3 yellow (brown), copper (titles, keys); 4 blue, steel
/// blue (other systems); 5 magenta, burnt orange (the selection); 6 cyan, peach (the screen's
/// text, fields); 7 white, cream (dialogs).
const PALETTE: [&str; 8] = ["2A1A12", "6E2A12", "7A4A30", "9A3B14", "2F5D7A", "B4471B", "F3C9A2", "EFE3CF"];

/// The colour pairs (`init_pair`), as attributes for `put`.
#[derive(Clone, Copy, PartialEq)]
#[repr(i16)]
pub enum Pair {
    /// The screen behind the dialogs, and the help line on it.
    Screen = 1,
    /// A dialog's text.
    Box,
    Title,
    Frame,
    /// The highlighted item or button.
    Sel,
    /// A shortcut letter, a column heading.
    Key,
    Shadow,
    Dim,
    /// Another system's partitions.
    Other,
    /// A text field.
    Field,
}

const PAIRS: [(Pair, c_short, c_short); 10] = [
    (Pair::Screen, 6, 1),
    (Pair::Box, 0, 7),
    (Pair::Title, 3, 7),
    (Pair::Frame, 2, 7),
    (Pair::Sel, 7, 5),
    (Pair::Key, 3, 7),
    (Pair::Shadow, 0, 0),
    (Pair::Dim, 2, 7),
    (Pair::Other, 4, 7),
    (Pair::Field, 0, 6),
];

impl Pair {
    /// `COLOR_PAIR(n)`.
    pub fn attr(self) -> c_int {
        (self as c_int) << 8
    }
}

fn palette(on: bool) {
    let mut out = std::io::stdout();
    if on {
        // Bold is drawn in the bright colours, 8 to 15: the same eight, as the mockup has them.
        for i in 0..16 {
            let _ = write!(out, "\x1b]P{i:x}{}", PALETTE[i % 8]);
        }
    } else {
        let _ = write!(out, "\x1b]R");
    }
    let _ = out.flush();
}

/// The terminal in curses mode, until dropped (or `suspend`ed).
pub struct Screen;

impl Screen {
    pub fn start() -> Screen {
        // SAFETY: setlocale, then ncurses' own setup, once, from one thread.
        unsafe {
            libc::setlocale(libc::LC_CTYPE, c"C.UTF-8".as_ptr());
            initscr();
            cbreak();
            noecho();
            keypad(stdscr, true);
            curs_set(0);
            // Esc alone is Back: a key sequence's bytes come together, so a short wait tells them.
            set_escdelay(150);
            if has_colors() {
                start_color();
                for (p, fg, bg) in PAIRS {
                    init_pair(p as c_short, fg, bg);
                }
            }
        }
        // After start_color, which may send the terminal's colour reset.
        palette(true);
        Screen
    }

    /// The screen's size, `(rows, columns)`.
    pub fn size(&self) -> (i32, i32) {
        // SAFETY: plain reads of ncurses' globals, set by initscr.
        unsafe { (LINES, COLS) }
    }

    pub fn clear(&self) {
        // SAFETY: ncurses is set up.
        unsafe { erase() };
    }

    /// Writes `text` at row `y`, column `x`, with `attrs` (0 for none; a `Pair::attr`, maybe with
    /// `A_BOLD`); off-screen text is cut.
    pub fn put(&self, y: i32, x: i32, text: &str, attrs: c_int) {
        let text = CString::new(text.replace('\0', "?")).unwrap_or_default();
        // SAFETY: ncurses is set up; a NUL-terminated string.
        unsafe {
            if attrs != 0 {
                attron(attrs);
            }
            mvaddstr(y, x, text.as_ptr());
            if attrs != 0 {
                attroff(attrs);
            }
        }
    }

    /// Shows the cursor at `(y, x)` (a text field's), or hides it.
    pub fn cursor(&self, at: Option<(i32, i32)>) {
        // SAFETY: ncurses is set up.
        unsafe {
            match at {
                Some((y, x)) => {
                    wmove(stdscr, y, x);
                    curs_set(1);
                }
                None => {
                    curs_set(0);
                }
            }
        }
    }

    /// The next `show` draws the whole screen afresh, not only what changed: anything written
    /// around curses (the kernel's messages on the console) goes.
    pub fn repaint(&self) {
        // SAFETY: ncurses is set up.
        unsafe { clearok(stdscr, true) };
    }

    pub fn show(&self) {
        // SAFETY: ncurses is set up.
        unsafe { refresh() };
    }

    /// The next key; `None` at the terminal's end.
    pub fn key(&self) -> Option<i32> {
        // SAFETY: ncurses is set up.
        let k = unsafe { wgetch(stdscr) };
        (k >= 0).then_some(k)
    }

    /// Leaves curses mode for `f` (a shell, say), the console's own colours back, then comes back.
    pub fn suspend<T>(&self, f: impl FnOnce() -> T) -> T {
        // SAFETY: ncurses is set up; refresh after endwin resumes it.
        unsafe { endwin() };
        palette(false);
        let r = f();
        palette(true);
        self.show();
        r
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        // SAFETY: ncurses is set up.
        unsafe { endwin() };
        palette(false);
    }
}
