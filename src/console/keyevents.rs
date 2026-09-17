//! A minimal, general-purpose raw keyboard-event source: real press/release pairs in a small,
//! kernel-owned keycode space, feeding `syscall::sys_get_keyevent` (`SYS_GET_KEYEVENT`). This is
//! deliberately separate infrastructure from `console::stdin`'s decoded-ASCII byte stream, and
//! deliberately general (not game-specific) -- it's the first real input-event primitive future
//! consumers beyond a single game (a future window system, say) can also build on.
//!
//! **Why this has to exist at all, separate from `stdin`'s stream**: `pc_keyboard::
//! EventDecoder::process_keyevent` (the `KEYBOARD.process_keyevent` call both
//! `interrupts::keyboard_interrupt_handler` and `interrupts::feed_synthetic_scancode` already
//! make) discards release information for nearly every key -- it returns `None` for essentially
//! every `KeyState::Up`, including modifier releases. A consumer that needs real held-key state
//! (is this key still down this tic) can never recover that from the ASCII-decoded stream even in
//! principle. The raw `KeyEvent{code, state}` produced one step earlier, by `KEYBOARD.add_byte`,
//! still carries full make/break -- this module captures *that*, before `process_keyevent` ever
//! discards anything, translates it into a small stable keycode space of this kernel's own
//! choosing (not `pc_keyboard::KeyCode` -- not a stable type to expose across the syscall ABI),
//! and buffers it here.
//!
//! **Deliberately non-blocking, unlike `stdin`'s ring buffer**: a caller polling for held-key
//! state (a game loop, once per tic) must never block waiting for a keystroke that may never
//! come. `pop_event` returns `None` immediately on an empty buffer -- no `BlockReason`, no
//! `scheduler::schedule()` involved anywhere in this module.

use pc_keyboard::{KeyCode, KeyEvent, KeyState};
use spin::Mutex;

const CAPACITY: usize = 64;

/// The wire format `syscall::sys_get_keyevent` copies out to a caller's pointer -- `#[repr(C)]`,
/// same "cast a raw pointer straight to a plain-old-data struct" discipline `RawTermios`/
/// `RawWinsize` already use elsewhere in this codebase.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawKeyEvent {
    pub keycode: u8,
    /// `1` = pressed, `0` = released.
    pub pressed: u8,
}

/// This kernel's own small, stable keycode space. ASCII passthrough covers every printable key
/// (letters, digits, space, common punctuation); values `>= 0x80` cover keys with no ASCII
/// representation. Chosen so a userland consumer's own translation table (e.g. to a game engine's
/// internal keycode space) stays a small, direct match, not a re-implementation of a scancode
/// table.
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_ENTER: u8 = 0x84;
pub const KEY_ESCAPE: u8 = 0x85;
pub const KEY_TAB: u8 = 0x86;
pub const KEY_BACKSPACE: u8 = 0x87;
pub const KEY_LCTRL: u8 = 0x88;
pub const KEY_RCTRL: u8 = 0x89;
pub const KEY_LALT: u8 = 0x8a;
pub const KEY_RALT: u8 = 0x8b;
pub const KEY_LSHIFT: u8 = 0x8c;
pub const KEY_RSHIFT: u8 = 0x8d;

/// Translates a raw `pc_keyboard::KeyCode` into this module's own stable keycode space (see the
/// constants above). Returns `None` for anything with no meaningful representation here (function
/// keys, numpad, media keys, lock keys, ...) -- silently dropped, same "not every key matters"
/// precedent `interrupts::handle_decoded_key`'s own `DecodedKey::RawKey(_) => {}` arm already sets
/// for the ASCII-decoded path.
fn translate(code: KeyCode) -> Option<u8> {
    use KeyCode::*;
    Some(match code {
        A => b'a',
        B => b'b',
        C => b'c',
        D => b'd',
        E => b'e',
        F => b'f',
        G => b'g',
        H => b'h',
        I => b'i',
        J => b'j',
        K => b'k',
        L => b'l',
        M => b'm',
        N => b'n',
        O => b'o',
        P => b'p',
        Q => b'q',
        R => b'r',
        S => b's',
        T => b't',
        U => b'u',
        V => b'v',
        W => b'w',
        X => b'x',
        Y => b'y',
        Z => b'z',
        Key0 => b'0',
        Key1 => b'1',
        Key2 => b'2',
        Key3 => b'3',
        Key4 => b'4',
        Key5 => b'5',
        Key6 => b'6',
        Key7 => b'7',
        Key8 => b'8',
        Key9 => b'9',
        Spacebar => b' ',
        ArrowUp => KEY_UP,
        ArrowDown => KEY_DOWN,
        ArrowLeft => KEY_LEFT,
        ArrowRight => KEY_RIGHT,
        Return => KEY_ENTER,
        Escape => KEY_ESCAPE,
        Tab => KEY_TAB,
        Backspace => KEY_BACKSPACE,
        LControl => KEY_LCTRL,
        RControl => KEY_RCTRL,
        LAlt => KEY_LALT,
        RAltGr => KEY_RALT,
        LShift => KEY_LSHIFT,
        RShift => KEY_RSHIFT,
        _ => return None,
    })
}

struct RingBuffer {
    data: [RawKeyEvent; CAPACITY],
    head: usize,
    len: usize,
}

impl RingBuffer {
    const fn new() -> Self {
        RingBuffer {
            data: [RawKeyEvent {
                keycode: 0,
                pressed: 0,
            }; CAPACITY],
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, ev: RawKeyEvent) {
        if self.len == CAPACITY {
            // Drop the OLDEST event, not the newest -- unlike stdin's byte stream (a FIFO text
            // reader, where dropping the newest keeps order sane), a held-key consumer cares most
            // about current state. Dropping the newest event here could drop a release and leave
            // a phantom stuck "held" key; dropping the oldest never loses the most recent
            // transition for any given key.
            self.head = (self.head + 1) % CAPACITY;
            self.len -= 1;
        }
        let tail = (self.head + self.len) % CAPACITY;
        self.data[tail] = ev;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<RawKeyEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.data[self.head];
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        Some(ev)
    }
}

static BUFFER: Mutex<RingBuffer> = Mutex::new(RingBuffer::new());

/// Called from both `interrupts::keyboard_interrupt_handler` (real PS/2 IRQ) and
/// `interrupts::feed_synthetic_scancode` (USB HID, via `drivers::usb::hid_keyboard`) with the raw
/// `KeyEvent` `KEYBOARD.add_byte` just produced -- before `process_keyevent` gets a chance to
/// discard release information. `KeyState::SingleShot` (an atomic press+release with no separate
/// `Up`, e.g. a power-on self test event) is recorded as a single `pressed` event with no matching
/// release -- rare enough, and meaningless enough for held-key state, that a phantom "still held"
/// bit for one of these has no real consumer to affect.
pub fn record_raw_key_event(event: &KeyEvent) {
    let Some(keycode) = translate(event.code) else {
        return;
    };
    let pressed = match event.state {
        KeyState::Down | KeyState::SingleShot => 1,
        KeyState::Up => 0,
    };
    BUFFER.lock().push(RawKeyEvent { keycode, pressed });
}

/// Non-blocking pop -- `syscall::sys_get_keyevent`'s only caller. `None` means no event is
/// currently buffered; never blocks, never returns a synthesized/default event.
pub fn pop_event() -> Option<RawKeyEvent> {
    BUFFER.lock().pop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_translate_known_keys() {
        assert_eq!(translate(KeyCode::A), Some(b'a'));
        assert_eq!(translate(KeyCode::ArrowUp), Some(KEY_UP));
        assert_eq!(translate(KeyCode::F1), None);
    }

    #[test_case]
    fn test_ring_buffer_fifo_and_drop_oldest() {
        let mut buffer = RingBuffer::new();
        for i in 0..CAPACITY {
            buffer.push(RawKeyEvent {
                keycode: i as u8,
                pressed: 1,
            });
        }
        // Buffer is now full (oldest is keycode 0); one more push should drop keycode 0, not the
        // just-pushed newest event.
        buffer.push(RawKeyEvent {
            keycode: 0xff,
            pressed: 1,
        });
        assert_eq!(buffer.pop().unwrap().keycode, 1);
    }

    #[test_case]
    fn test_record_and_pop_roundtrip() {
        record_raw_key_event(&KeyEvent {
            code: KeyCode::ArrowLeft,
            state: KeyState::Down,
        });
        let ev = pop_event().expect("expected a buffered event");
        assert_eq!(ev.keycode, KEY_LEFT);
        assert_eq!(ev.pressed, 1);
    }
}
