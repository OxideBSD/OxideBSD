//! xHCI + USB HID boot-protocol keyboard support -- this kernel's only input path on hardware
//! with no PS/2 controller at all (a Surface Pro, the actual real-hardware target this exists
//! for). See `xhci`'s own module doc comment for the host-controller driver itself and
//! `hid_keyboard`'s for the keyboard device on top of it.
//!
//! **MSI-X when the local APIC is up, with a polling safety net.** `init` arms the controller for
//! MSI-X (`cpu::apic`) once boot enumeration is done, so completions arrive as interrupts
//! (`msi_handler`) -- the keyboard's reports, and the bulk transfers of USB mass storage, where
//! waiting on the 100 Hz tick would make disk I/O crawl. The tick-driven `poll` stays as a safety
//! net (it drains anything an interrupt missed on lock contention) and as the sole path when
//! there's no LAPIC or no MSI-X capability. Legacy `INTx` is deliberately not used: on the
//! real-hardware target (a UEFI-only PCIe chipset) its routing is an unquantified risk, which is
//! the whole reason `cpu::apic` exists. Auto-repeat is driven from `poll` either way, being a
//! function of the clock, not of report arrival.
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
    /// Whether the controller delivers completions as MSI-X (`msi_handler`) rather than relying on
    /// the tick-driven `poll` fallback. Either way `poll` still drains the ring as a safety net
    /// and drives keyboard auto-repeat.
    msi_armed: bool,
}

/// `None` until `init` has found and brought up a real xHCI controller; stays `None` for the rest
/// of the boot if none was found, or if one was found but no HID boot keyboard ever showed up on
/// any of its ports -- `poll()` is a no-op either way.
static STATE: Mutex<Option<UsbState>> = Mutex::new(None);

/// Finds an xHCI controller via PCI, brings it up, scans its root ports once, and initializes the
/// first HID boot-keyboard device found. Not fatal either way -- logged and skipped on any
/// failure, exactly `drivers::rtl8139::init`'s own "no supported hardware found" precedent. Call once,
/// at boot, before module loading (same ordering `drivers::rtl8139::init` already uses) so a USB
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

    // Boot-time enumeration is done (it spin-polled the Event Ring synchronously), so it's now
    // safe to hand the ring to the MSI handler. Store the state first, then arm MSI-X holding the
    // state lock -- so if the very first completion interrupts mid-arm, `msi_handler` simply bails
    // (lock held) and the tick `poll` drains it a moment later.
    *STATE.lock() = Some(UsbState {
        controller,
        keyboard,
        msi_armed: false,
    });
    if let Some(vector) = crate::cpu::apic::register_msi(msi_handler) {
        let mut guard = STATE.lock();
        let state = guard.as_mut().unwrap();
        if state
            .controller
            .arm_msix(mapper, frame_allocator, phys_mem_offset, vector)
        {
            state.msi_armed = true;
            serial_println!("[usb] xHCI completions via MSI-X (vector {})", vector);
        }
    }
}

/// Drains the Event Ring and dispatches each event to its owner (the keyboard today; a future
/// mass-storage completion wakes its waiter here). The sole consumer of the ring once MSI is
/// armed, and the polling fallback's drain otherwise -- both call it holding `STATE`, so the two
/// never race on the ring's dequeue pointer. Acknowledges interrupter 0 at the end so the next
/// completion can raise a fresh MSI.
fn service(state: &mut UsbState) {
    while let Some(evt) = state.controller.poll_event() {
        if let Some(keyboard) = state.keyboard.as_mut()
            && keyboard.handle_transfer_event(&mut state.controller, evt)
        {
            continue;
        }
        // Unclaimed: dropped, same as the driver has always done with a stray event.
    }
    if state.msi_armed {
        state.controller.ack_interrupter();
    }
}

/// The MSI-X interrupt handler: drains and dispatches completions. Bails on lock contention (the
/// tick `poll`, or `init`'s arming, holds `STATE`) -- the tick drains what it missed within one
/// tick. `cpu::apic::dispatch_msi` sends the LAPIC EOI after this returns.
fn msi_handler() {
    if let Some(mut guard) = STATE.try_lock()
        && let Some(state) = guard.as_mut()
    {
        service(state);
    }
}

/// Called once per timer tick. Drains the Event Ring as a safety net (when MSI is armed the
/// handler normally does this first; this catches anything it skipped on lock contention, and is
/// the only drain when MSI isn't armed), then drives keyboard auto-repeat (inherently clock-, not
/// event-driven). A near-no-op until `init` has found a working controller.
pub fn poll() {
    let Some(mut guard) = STATE.try_lock() else {
        // A timer tick firing while `init` is mid-setup, or during an MSI drain -- skip this tick
        // rather than spin-waiting inside a timer IRQ.
        return;
    };
    let Some(state) = guard.as_mut() else {
        return;
    };
    service(state);
    if let Some(keyboard) = state.keyboard.as_mut() {
        keyboard.poll_repeat();
    }
}
