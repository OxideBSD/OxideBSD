//! The few ncurses calls the installer draws with (`INSTALLER.md` §9.1: the in-tree ncurses,
//! through FFI), wrapped so the rest of the program needn't touch raw pointers.

use std::ffi::{CString, c_char, c_int, c_void};

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
    fn wgetch(win: *mut Window) -> c_int;
    fn erase() -> c_int;
    fn refresh() -> c_int;
    fn mvaddstr(y: c_int, x: c_int, s: *const c_char) -> c_int;
    fn attron(attrs: c_int) -> c_int;
    fn attroff(attrs: c_int) -> c_int;
}

/// ncurses' attribute bits (`NCURSES_BITS(1, 10)` and `(1, 13)`).
pub const A_REVERSE: c_int = 1 << 18;
pub const A_BOLD: c_int = 1 << 21;

/// The keys `getch` returns for the arrows and Enter (`<curses.h>`).
pub const KEY_DOWN: i32 = 0o402;
pub const KEY_UP: i32 = 0o403;
pub const KEY_ENTER: i32 = 0o527;

/// The terminal in curses mode, until dropped (or `suspend`ed).
pub struct Screen;

impl Screen {
    pub fn start() -> Screen {
        // SAFETY: ncurses' own setup, once, from one thread.
        unsafe {
            initscr();
            cbreak();
            noecho();
            keypad(stdscr, true);
            curs_set(0);
        }
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

    /// Writes `text` at row `y`, column `x`, with `attrs` (0 for none); off-screen text is cut.
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

    /// Leaves curses mode for `f` (a shell, say), then comes back.
    pub fn suspend<T>(&self, f: impl FnOnce() -> T) -> T {
        // SAFETY: ncurses is set up; refresh after endwin resumes it.
        unsafe { endwin() };
        let r = f();
        self.show();
        r
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        // SAFETY: ncurses is set up.
        unsafe { endwin() };
    }
}
