//! `ttyv0`, the framebuffer console (TTY.md §2.2, §7): keyboard input, and output through the
//! ANSI engine (`console::vga`) and framebuffer. With a serial console (`-h`, `-D`) its output is
//! also copied to COM1, before output processing, so the serial log reads as the program wrote
//! it, and what COM1 receives is input too (§2.5).

use core::sync::atomic::{AtomicBool, Ordering};

use super::{B38400, Driver, TTYV0, TtyId, Winsize};

struct Console;

/// Where the console's output goes (§2.5), set from the boot flags: the screen by default, the
/// screen and COM1 with `-D` (dual console), COM1 alone with `-h` (serial console), as in
/// FreeBSD. Each byte to COM1 is a port write, an exit to the hypervisor under a VM, so copying
/// is opt-in. Kernel messages go to COM1 regardless. Input is the keyboard's, and with COM1 in
/// use COM1's too (`serial_interrupt`), as in FreeBSD: one terminal, two keyboards.
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
    // /dev/tty reaches only the opener's own controlling terminal, so it's open to all.
    let (ctty, console) = (super::CTTY_DEVICE, super::CONSOLE_DEVICE);
    let _ = crate::fs::devfs::make_dev("tty", ctty.0, ctty.1, 0, 0, 0o666, super::dev_open);
    let _ = crate::fs::devfs::make_dev("console", console.0, console.1, 0, 0, 0o600, super::dev_open);
    super::pty::init();
    // The serial console's input, now that ttyv0 can take it (§2.5).
    if TO_SERIAL.load(Ordering::Relaxed) {
        crate::cpu::interrupts::register_irq_handler(COM1_IRQ, serial_interrupt);
        // SAFETY: IRQ 4 has its handler, registered just above.
        unsafe { crate::cpu::pic::unmask_irq(COM1_IRQ) };
    }
}

/// COM1's interrupt line on a PC.
const COM1_IRQ: u8 = 4;

/// IRQ 4: COM1 received bytes, the serial console's typing (§2.5). They go where the keyboard's
/// go (`keyboard`); a signal character that stops or kills the current process reschedules at
/// the next tick (`request_reschedule`), since this handler has no frame to tell whether it
/// interrupted user code.
fn serial_interrupt() {
    let mut buf = [0u8; 16];
    loop {
        let n = crate::console::serial::receive(&mut buf);
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            crate::random::mix_entropy(b as u64);
        }
        if keyboard(&buf[..n]) {
            crate::cpu::interrupts::request_reschedule();
        }
    }
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

/// Bytes typed at the console: the keyboard's, or the serial console's (`serial_interrupt`).
/// Returns whether a signal character stopped or killed the current process, so that the
/// interrupt handler, if it interrupted that process in user mode, reschedules.
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
