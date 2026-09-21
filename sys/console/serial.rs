use core::fmt;
use core::fmt::Write;

use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts;
use x86_64::instructions::port::Port;

/// Line status register bit: set when the transmit holding register is empty and ready to
/// accept another byte.
const LSR_TRANSMIT_EMPTY: u8 = 1 << 5;

/// A minimal driver for a 16550-compatible UART accessed via port I/O, write-only (this kernel
/// never reads from the serial port). See <https://wiki.osdev.org/Serial_Ports>.
struct SerialPort {
    data: Port<u8>,
    interrupt_enable: Port<u8>,
    fifo_control: Port<u8>,
    line_control: Port<u8>,
    modem_control: Port<u8>,
    line_status: Port<u8>,
}

impl SerialPort {
    /// # Safety
    ///
    /// `base` must be the I/O base port of a real 16550-compatible UART.
    const unsafe fn new(base: u16) -> Self {
        SerialPort {
            data: Port::new(base),
            interrupt_enable: Port::new(base + 1),
            fifo_control: Port::new(base + 2),
            line_control: Port::new(base + 3),
            modem_control: Port::new(base + 4),
            line_status: Port::new(base + 5),
        }
    }

    fn init(&mut self) {
        unsafe {
            self.interrupt_enable.write(0x00); // disable interrupts
            self.line_control.write(0x80); // enable DLAB to set the baud rate divisor
            self.data.write(0x03); // divisor low byte: 38400 baud
            self.interrupt_enable.write(0x00); // divisor high byte
            self.line_control.write(0x03); // disable DLAB; 8 data bits, no parity, 1 stop bit
            self.fifo_control.write(0xc7); // enable FIFO, clear queues, 14-byte threshold
            self.modem_control.write(0x0b); // DTR + RTS + enable the UART's IRQ output line
            self.interrupt_enable.write(0x01); // re-enable interrupts
        }
    }

    fn send(&mut self, byte: u8) {
        match byte {
            // Backspace/DEL: move back, blank the character, move back again.
            0x08 | 0x7f => {
                self.send_raw(0x08);
                self.send_raw(b' ');
                self.send_raw(0x08);
            }
            byte => self.send_raw(byte),
        }
    }

    fn send_raw(&mut self, byte: u8) {
        unsafe {
            while self.line_status.read() & LSR_TRANSMIT_EMPTY == 0 {}
            self.data.write(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

static SERIAL1: Lazy<Mutex<SerialPort>> = Lazy::new(|| {
    // SAFETY: 0x3F8 is the standard I/O base for COM1 on x86 PCs (and QEMU's default).
    let mut serial_port = unsafe { SerialPort::new(0x3F8) };
    serial_port.init();
    Mutex::new(serial_port)
});

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    interrupts::without_interrupts(|| {
        SERIAL1
            .lock()
            .write_fmt(args)
            .expect("printing to serial port failed");
    });
    crate::console::vga::_print(args);
    // Rasterizes whatever `vga::_print` just applied to its own real ANSI-aware buffer -- see
    // `console::framebuffer`'s own module doc comment. Takes no args of its own: it reads
    // `vga`'s buffer directly rather than re-parsing the same bytes a second time.
    crate::console::framebuffer::redraw();
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::console::serial::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (
        $crate::serial_print!(concat!($fmt, "\n"), $($arg)*)
    );
}
