//! `ttyv0`, the framebuffer console (TTY.md §2.2, §7): keyboard input, and output through the
//! ANSI engine (`console::vga`) and framebuffer. Its output is also copied to COM1, before output
//! processing, so the serial log reads as the program wrote it (§2.5).

use core::sync::atomic::{AtomicBool, Ordering};

use super::{B38400, Driver, TTYV0, TtyId, Winsize};

struct Console;

/// Where the console's output goes (§2.5), set from the boot flags: the screen by default, the
/// screen and COM1 with `-D` (dual console), COM1 alone with `-h` (serial console), as in
/// FreeBSD. Each byte to COM1 is a port write, an exit to the hypervisor under a VM, so copying
/// is opt-in. Kernel messages go to COM1 regardless. Input is always the keyboard for now; the
/// kernel doesn't read the serial port yet.
static TO_SCREEN: AtomicBool = AtomicBool::new(true);
static TO_SERIAL: AtomicBool = AtomicBool::new(false);

pub fn set_outputs(screen: bool, serial: bool) {
    TO_SCREEN.store(screen, Ordering::Relaxed);
    TO_SERIAL.store(serial, Ordering::Relaxed);
}

impl Driver for Console {
    fn output(&self, raw: &[u8], cooked: &[u8]) {
        if TO_SERIAL.load(Ordering::Relaxed) {
            crate::console::serial::write_bytes(raw);
        }
        if TO_SCREEN.load(Ordering::Relaxed) {
            crate::console::vga::write_bytes(cooked);
            crate::console::framebuffer::redraw();
        }
        // A cursor-position query answers through the input (§7.3); the writer queues the
        // reply rather than feeding it in while it holds its own lock.
        let reply = crate::console::vga::take_replies();
        if !reply.is_empty() {
            super::input(TTYV0, &reply);
        }
    }
}

static CONSOLE: Console = Console;

/// Registers `ttyv0`, once; it is always the first terminal.
pub fn init() {
    if !super::TTYS.lock().is_empty() {
        return;
    }
    let ws = Winsize {
        ws_row: crate::console::vga::height() as u16,
        ws_col: crate::console::vga::width() as u16,
        ..Winsize::default()
    };
    let id: TtyId = super::register("ttyv0", 4, 0, B38400, ws, &CONSOLE);
    assert_eq!(id, TTYV0, "ttyv0 must be the first terminal");
}

/// Set while a process that mapped `/dev/fb0` owns the keyboard (§7.2): keys then go only to
/// its raw key-event queue (`console::keyevents`), not to `ttyv0`, except the signal characters.
static RAW_KEYBOARD_OWNED: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_raw_keyboard_owned(owned: bool) {
    RAW_KEYBOARD_OWNED.store(owned, Ordering::Relaxed);
}

pub(crate) fn raw_keyboard_owned() -> bool {
    RAW_KEYBOARD_OWNED.load(Ordering::Relaxed)
}

/// Keyboard bytes. Returns whether a signal character stopped or killed the current process,
/// so that the interrupt handler, if it interrupted that process in user mode, reschedules.
pub fn keyboard(bytes: &[u8]) -> bool {
    let cur = crate::process::scheduler::current_pid();
    let signaled = if raw_keyboard_owned() {
        // The screen's owner still gets ^C and ^Z.
        bytes.iter().fold(false, |any, &b| super::signal_character(TTYV0, b) || any)
    } else {
        super::input(TTYV0, bytes)
    };
    signaled
        && cur != 0
        && !matches!(
            crate::process::table().lock().get(&cur).map(|p| p.state),
            Some(crate::process::ProcState::Running)
        )
}
