//! xHCI + USB HID boot-protocol keyboard support -- this kernel's only input path on hardware
//! with no PS/2 controller at all (a Surface Pro, the actual real-hardware target this exists
//! for). See `xhci`'s own module doc comment for the host-controller driver itself and
//! `hid_keyboard`'s for the keyboard device on top of it.
//!
//! **Polled, not IRQ-driven, deliberately**: `poll()` is called once per timer tick (100 Hz, see
//! `cpu::interrupts::timer_interrupt_handler`) rather than registering a PCI IRQ handler the way
//! `net::rtl8139` does. This kernel has no IOAPIC/MSI support, and this is its first real-hardware
//! (not just QEMU) boot target -- legacy PCI `INTx` routing on a modern UEFI-only chipset is a
//! real, unquantified risk not worth taking just to shave a few milliseconds of keystroke latency
//! a human typist will never notice. Matches `drivers::ata`'s own established polling-only
//! precedent for exactly this class of "first real-hardware driver" concern.
//!
//! One keyboard device for v1: the first HID boot-keyboard endpoint found during the one-time
//! port scan in `init` wins; no hot-plug (attach/detach after boot). Mouse/pointer input is out of
//! scope entirely -- this kernel has no GUI or pointer concept anywhere to consume it.

mod hid_keyboard;
mod xhci;

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use crate::serial_println;

struct UsbState {
    controller: xhci::Xhci,
    keyboard: Option<hid_keyboard::KeyboardDevice>,
}

/// `None` until `init` has found and brought up a real xHCI controller; stays `None` for the rest
/// of the boot if none was found, or if one was found but no HID boot keyboard ever showed up on
/// any of its ports -- `poll()` is a no-op either way.
static STATE: Mutex<Option<UsbState>> = Mutex::new(None);

/// Finds an xHCI controller via PCI, brings it up, scans its root ports once, and initializes the
/// first HID boot-keyboard device found. Not fatal either way -- logged and skipped on any
/// failure, exactly `net::rtl8139::init`'s own "no supported hardware found" precedent. Call once,
/// at boot, before module loading (same ordering `net::rtl8139::init` already uses) so a USB
/// keyboard is live before `hush` is spawned.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    let Some(mut controller) = xhci::Xhci::init(frame_allocator, mapper, phys_mem_offset) else {
        serial_println!("[usb] no xHCI controller found -- USB input unavailable this boot");
        return;
    };

    let mut keyboard = None;
    for port in 1..=controller.max_ports() {
        let Some(speed) = controller.reset_port(port) else {
            continue;
        };
        serial_println!(
            "[usb] device connected on port {} (speed id {})",
            port,
            speed
        );
        match hid_keyboard::bring_up(
            &mut controller,
            frame_allocator,
            phys_mem_offset,
            port,
            speed,
        ) {
            Some(kb) => {
                serial_println!("[usb] USB HID keyboard ready on port {}", port);
                keyboard = Some(kb);
                break;
            }
            None => {
                serial_println!(
                    "[usb] port {}: device didn't come up as a HID boot keyboard -- skipping",
                    port
                );
            }
        }
    }
    if keyboard.is_none() {
        serial_println!("[usb] xHCI controller up, but no HID boot keyboard found on any port");
    }

    *STATE.lock() = Some(UsbState {
        controller,
        keyboard,
    });
}

/// Drains and processes any pending USB keyboard input. Called once per timer tick -- see this
/// module's own doc comment for why polling, not an IRQ handler. A no-op (a single `try_lock` plus
/// two `Option` checks) until `init` has actually found a working keyboard.
pub fn poll() {
    let Some(mut guard) = STATE.try_lock() else {
        // Never expected to actually contend (this driver has no other caller), but a timer tick
        // firing while `init` itself is still mid-setup is possible early at boot -- skip this
        // tick rather than spin-waiting inside a timer IRQ.
        return;
    };
    let Some(state) = guard.as_mut() else {
        return;
    };
    let Some(keyboard) = state.keyboard.as_mut() else {
        return;
    };
    keyboard.poll(&mut state.controller);
}
