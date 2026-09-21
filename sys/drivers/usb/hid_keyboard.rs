//! A USB HID **Boot Protocol** keyboard driver, built on `super::xhci`'s real xHCI primitives.
//! Boot Protocol (USB HID spec Appendix B) is the fixed, simple 8-byte report every real keyboard
//! supports (BIOS/UEFI depend on it) -- byte 0 is a modifier bitmask, byte 1 is reserved, bytes
//! 2-7 are up to six simultaneously-pressed key usage IDs. No general HID Report Descriptor
//! parsing here; deliberately out of scope for v1 (see `super`'s own module doc comment).
//!
//! **Reuses `cpu::interrupts`'s existing PS/2 decode pipeline wholesale**: each report is diffed
//! against the previous one to find newly-pressed/newly-released keys, each of which is
//! translated to a PS/2 Scan Code Set 1 make/break byte sequence and fed through
//! `interrupts::feed_synthetic_scancode` -- the exact same `KEYBOARD: Mutex<PS2Keyboard<...>>`
//! decode a real PS/2 IRQ uses. Shift state, Caps Lock, Ctrl+C/Ctrl+Z interception, and echo all
//! come along for free; this file only has to get the raw scancode bytes right.
//!
//! **US 104-key layout only** (matches this kernel's existing PS/2 `Us104Key` assumption). A
//! small number of ISO/international keys (Non-US `#`/`\`) and PrintScreen/Pause (which use
//! irregular, multi-byte Set 1 sequences) aren't mapped -- a real, narrow, deliberate gap, not
//! something a Surface Pro's own keyboard/most USB keyboards would ever send anyway.

use x86_64::structures::paging::{FrameAllocator, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::xhci::{
    EndpointType, TrbRing, Xhci, alloc_zeroed_page, endpoint_dci, enqueue_normal_in,
    write_endpoint_context, write_input_control_context, write_slot_context,
};
use crate::serial_println;

const REQ_GET_DESCRIPTOR: u8 = 0x06;
const REQ_SET_CONFIGURATION: u8 = 0x09;
const DESC_TYPE_DEVICE: u16 = 1 << 8;
const DESC_TYPE_CONFIGURATION: u16 = 2 << 8;
const HID_REQ_SET_IDLE: u8 = 0x0A;
const HID_REQ_SET_PROTOCOL: u8 = 0x0B;
const HID_BOOT_PROTOCOL: u16 = 0;
const BM_STD_DEV_TO_HOST: u8 = 0x80;
const BM_STD_HOST_TO_DEV: u8 = 0x00;
const BM_CLASS_INTERFACE_HOST_TO_DEV: u8 = 0x21;

/// Ticks (at the 100 Hz timer rate every other duration constant in this codebase assumes -- see
/// `cpu::pit`) before a newly-pressed, still-held key starts auto-repeating, and the interval
/// between repeats thereafter -- real desktop-OS-typical values (~500ms initial delay, ~40ms/25cps
/// repeat rate). **Not something the HID device itself provides**: a real USB HID boot-keyboard
/// device reports a key exactly once per real state change (press, then nothing more until
/// release) -- unlike a PS/2 keyboard, whose own firmware autonomously resends the make code while
/// a key is held, entirely transparent to this kernel's decode pipeline. Typematic repeat for a
/// USB keyboard is universally an OS-side responsibility (every real desktop OS implements it in
/// software), so `KeyboardDevice::poll` has to synthesize it here, driven by `cpu::interrupts::
/// ticks()` rather than by report arrival (a held key generates no further xHCI Transfer Events at
/// all once the device stops seeing a change).
const REPEAT_INITIAL_DELAY_TICKS: u64 = 50;
const REPEAT_INTERVAL_TICKS: u64 = 4;

/// A live, configured HID boot-keyboard device. Owns the one endpoint (the control endpoint's own
/// transfer ring is only needed during bring-up, so it isn't kept) this driver ever talks to after
/// setup: the interrupt-IN endpoint reports arrive on.
pub(crate) struct KeyboardDevice {
    slot_id: u8,
    interrupt_ep_dci: u8,
    interrupt_ring: TrbRing,
    report_buf_virt: VirtAddr,
    report_buf_phys: PhysAddr,
    prev_report: [u8; 8],
    /// The one key currently auto-repeating (real desktop-OS convention: only the most recently
    /// pressed still-held key repeats, not every held key at once), and the `ticks()` deadline for
    /// its next repeat. `None` whenever nothing's held, or the repeating key was just released.
    repeat_usage: Option<u8>,
    repeat_next_tick: u64,
}

impl KeyboardDevice {
    /// Drains every pending Transfer Event for this device's interrupt endpoint from the shared
    /// Event Ring, diffs each completed 8-byte report against the previous one, and feeds the
    /// resulting make/break scancodes into `interrupts::feed_synthetic_scancode`. Called once per
    /// timer tick (see `super::poll`) -- any other event type on the shared ring (there shouldn't
    /// be any once bring-up has finished) is simply dropped.
    pub(crate) fn poll(&mut self, controller: &mut Xhci) {
        while let Some(evt) = controller.poll_event() {
            if !evt.is_transfer_event()
                || evt.slot_id() != self.slot_id
                || evt.endpoint_id() != self.interrupt_ep_dci
            {
                continue;
            }
            if evt.is_success() {
                let mut report = [0u8; 8];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.report_buf_virt.as_ptr::<u8>(),
                        report.as_mut_ptr(),
                        8,
                    );
                }
                self.handle_report(report);
            }
            // Re-arm regardless of completion code -- a stalled/short-packet report shouldn't
            // stop future polling.
            enqueue_normal_in(&mut self.interrupt_ring, self.report_buf_phys, 8);
            controller.ring_endpoint_doorbell(self.slot_id, self.interrupt_ep_dci);
        }

        // Auto-repeat: driven by the clock, not by report arrival -- see `REPEAT_INITIAL_DELAY_
        // TICKS`'s own doc comment for why a held key generates no further events to react to here.
        if let Some(usage) = self.repeat_usage {
            let now = crate::cpu::interrupts::ticks();
            if now >= self.repeat_next_tick {
                if let Some((code, extended)) = hid_usage_to_scancode(usage) {
                    feed_key(code, extended, true);
                }
                self.repeat_next_tick = now + REPEAT_INTERVAL_TICKS;
            }
        }
    }

    fn handle_report(&mut self, report: [u8; 8]) {
        // ErrorRollOver (usage 0x01) in any key slot -- more keys are down than the device can
        // report, or a "phantom state" -- the real, spec-mandated signal to ignore the whole
        // report rather than treat 0x01 as a real key.
        if report[2..8].contains(&1) {
            return;
        }

        let old = self.prev_report;
        for bit in 0..8u8 {
            let now = report[0] & (1 << bit) != 0;
            let before = old[0] & (1 << bit) != 0;
            if now != before
                && let Some((code, extended)) = modifier_scancode(bit)
            {
                feed_key(code, extended, now);
            }
        }
        for &usage in &old[2..8] {
            if usage != 0
                && !report[2..8].contains(&usage)
                && let Some((code, extended)) = hid_usage_to_scancode(usage)
            {
                feed_key(code, extended, false);
                if self.repeat_usage == Some(usage) {
                    self.repeat_usage = None;
                }
            }
        }
        for &usage in &report[2..8] {
            if usage != 0
                && !old[2..8].contains(&usage)
                && let Some((code, extended)) = hid_usage_to_scancode(usage)
            {
                feed_key(code, extended, true);
                self.repeat_usage = Some(usage);
                self.repeat_next_tick =
                    crate::cpu::interrupts::ticks() + REPEAT_INITIAL_DELAY_TICKS;
            }
        }
        self.prev_report = report;
    }
}

fn feed_key(code: u8, extended: bool, make: bool) {
    if extended {
        crate::cpu::interrupts::feed_synthetic_scancode(0xE0);
    }
    crate::cpu::interrupts::feed_synthetic_scancode(if make { code } else { code | 0x80 });
}

/// PS/2 Scan Code Set 1 for each of the 8 HID boot-report modifier bits (byte 0), and whether it's
/// an `0xE0`-extended code.
fn modifier_scancode(bit: u8) -> Option<(u8, bool)> {
    Some(match bit {
        0 => (0x1D, false), // LCtrl
        1 => (0x2A, false), // LShift
        2 => (0x38, false), // LAlt
        3 => (0x5B, true),  // LGui
        4 => (0x1D, true),  // RCtrl
        5 => (0x36, false), // RShift
        6 => (0x38, true),  // RAlt
        7 => (0x5C, true),  // RGui
        _ => return None,
    })
}

/// PS/2 Scan Code Set 1 for a HID Keyboard/Keypad usage ID (HID Usage Tables page `0x07`), and
/// whether it's an `0xE0`-extended code. `None` for a usage this driver doesn't map -- see this
/// module's own doc comment.
fn hid_usage_to_scancode(usage: u8) -> Option<(u8, bool)> {
    Some(match usage {
        0x04 => (0x1E, false), // A
        0x05 => (0x30, false), // B
        0x06 => (0x2E, false), // C
        0x07 => (0x20, false), // D
        0x08 => (0x12, false), // E
        0x09 => (0x21, false), // F
        0x0A => (0x22, false), // G
        0x0B => (0x23, false), // H
        0x0C => (0x17, false), // I
        0x0D => (0x24, false), // J
        0x0E => (0x25, false), // K
        0x0F => (0x26, false), // L
        0x10 => (0x32, false), // M
        0x11 => (0x31, false), // N
        0x12 => (0x18, false), // O
        0x13 => (0x19, false), // P
        0x14 => (0x10, false), // Q
        0x15 => (0x13, false), // R
        0x16 => (0x1F, false), // S
        0x17 => (0x14, false), // T
        0x18 => (0x16, false), // U
        0x19 => (0x2F, false), // V
        0x1A => (0x11, false), // W
        0x1B => (0x2D, false), // X
        0x1C => (0x15, false), // Y
        0x1D => (0x2C, false), // Z
        0x1E => (0x02, false), // 1
        0x1F => (0x03, false), // 2
        0x20 => (0x04, false), // 3
        0x21 => (0x05, false), // 4
        0x22 => (0x06, false), // 5
        0x23 => (0x07, false), // 6
        0x24 => (0x08, false), // 7
        0x25 => (0x09, false), // 8
        0x26 => (0x0A, false), // 9
        0x27 => (0x0B, false), // 0
        0x28 => (0x1C, false), // Enter
        0x29 => (0x01, false), // Escape
        0x2A => (0x0E, false), // Backspace
        0x2B => (0x0F, false), // Tab
        0x2C => (0x39, false), // Space
        0x2D => (0x0C, false), // -
        0x2E => (0x0D, false), // =
        0x2F => (0x1A, false), // [
        0x30 => (0x1B, false), // ]
        0x31 => (0x2B, false), // backslash
        0x33 => (0x27, false), // ;
        0x34 => (0x28, false), // '
        0x35 => (0x29, false), // `
        0x36 => (0x33, false), // ,
        0x37 => (0x34, false), // .
        0x38 => (0x35, false), // /
        0x39 => (0x3A, false), // CapsLock
        0x3A => (0x3B, false), // F1
        0x3B => (0x3C, false), // F2
        0x3C => (0x3D, false), // F3
        0x3D => (0x3E, false), // F4
        0x3E => (0x3F, false), // F5
        0x3F => (0x40, false), // F6
        0x40 => (0x41, false), // F7
        0x41 => (0x42, false), // F8
        0x42 => (0x43, false), // F9
        0x43 => (0x44, false), // F10
        0x44 => (0x57, false), // F11
        0x45 => (0x58, false), // F12
        0x47 => (0x46, false), // ScrollLock
        0x49 => (0x52, true),  // Insert
        0x4A => (0x47, true),  // Home
        0x4B => (0x49, true),  // PageUp
        0x4C => (0x53, true),  // Delete
        0x4D => (0x4F, true),  // End
        0x4E => (0x51, true),  // PageDown
        0x4F => (0x4D, true),  // Right
        0x50 => (0x4B, true),  // Left
        0x51 => (0x50, true),  // Down
        0x52 => (0x48, true),  // Up
        0x53 => (0x45, false), // NumLock
        0x54 => (0x35, true),  // KP /
        0x55 => (0x37, false), // KP *
        0x56 => (0x4A, false), // KP -
        0x57 => (0x4E, false), // KP +
        0x58 => (0x1C, true),  // KP Enter
        0x59 => (0x4F, false), // KP 1
        0x5A => (0x50, false), // KP 2
        0x5B => (0x51, false), // KP 3
        0x5C => (0x4B, false), // KP 4
        0x5D => (0x4C, false), // KP 5
        0x5E => (0x4D, false), // KP 6
        0x5F => (0x47, false), // KP 7
        0x60 => (0x48, false), // KP 8
        0x61 => (0x49, false), // KP 9
        0x62 => (0x52, false), // KP 0
        0x63 => (0x53, false), // KP .
        0x65 => (0x5D, true),  // Application/Menu
        _ => return None,
    })
}

/// EP0's initial `bMaxPacketSize0` guess by Port Speed ID (xHCI spec Table 5-12). Low/High/Super
/// Speed values are spec-fixed; Full Speed's real value (8/16/32/64) is read from the device's own
/// descriptor and applied via a real Evaluate Context command once known -- see `bring_up`.
fn initial_ep0_max_packet(speed: u8) -> u16 {
    match speed {
        2 => 8,   // Low Speed -- always exactly 8.
        3 => 64,  // High Speed -- always exactly 64.
        1 => 8,   // Full Speed -- refined below once the real descriptor is read.
        _ => 512, // SuperSpeed(+) and anything unrecognized.
    }
}

fn log2_ceil_u32(n: u32) -> u8 {
    if n <= 1 {
        return 0;
    }
    (32 - (n - 1).leading_zeros()) as u8
}

/// Converts a USB endpoint descriptor's `bInterval` into xHCI's own Endpoint Context `Interval`
/// field, which is always expressed as `2^Interval * 125us` regardless of speed -- but `bInterval`
/// itself means different things at different speeds (USB 2.0 spec 9.6.6): a raw millisecond count
/// (1-255) for Low/Full Speed, already a `125us`-unit power-of-two exponent (1-16) for High Speed
/// and above.
fn xhci_interval(speed: u8, b_interval: u8) -> u8 {
    match speed {
        1 | 2 => log2_ceil_u32((b_interval.max(1) as u32) * 8).min(15),
        _ => b_interval.saturating_sub(1).min(15),
    }
}

struct HidKeyboardConfig {
    config_value: u8,
    interface_number: u8,
    endpoint_address: u8,
    max_packet_size: u16,
    b_interval: u8,
}

/// Walks a raw USB configuration descriptor (starting with the 9-byte Configuration Descriptor
/// itself) looking for an interface with class `3` (HID) / subclass `1` (Boot) / protocol `1`
/// (Keyboard), then the first Interrupt IN endpoint belonging to it. `None` if this device isn't a
/// HID boot keyboard at all, or has no such endpoint.
fn parse_hid_keyboard_config(bytes: &[u8]) -> Option<HidKeyboardConfig> {
    const DESC_CONFIGURATION: u8 = 2;
    const DESC_INTERFACE: u8 = 4;
    const DESC_ENDPOINT: u8 = 5;
    const EP_ATTR_TYPE_MASK: u8 = 0x3;
    const EP_ATTR_TYPE_INTERRUPT: u8 = 0x3;
    const EP_ADDR_DIR_IN: u8 = 0x80;

    if bytes.len() < 9 || bytes[1] != DESC_CONFIGURATION {
        return None;
    }
    let config_value = bytes[5];

    let mut offset = 9usize;
    let mut current_interface: Option<u8> = None;
    let mut is_boot_keyboard = false;

    while offset + 2 <= bytes.len() {
        let len = bytes[offset] as usize;
        if len < 2 || offset + len > bytes.len() {
            break;
        }
        let desc_type = bytes[offset + 1];
        match desc_type {
            DESC_INTERFACE if len >= 9 => {
                current_interface = Some(bytes[offset + 2]);
                let (class, subclass, protocol) =
                    (bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
                is_boot_keyboard = class == 3 && subclass == 1 && protocol == 1;
            }
            DESC_ENDPOINT if len >= 7 && is_boot_keyboard => {
                let endpoint_address = bytes[offset + 2];
                let attributes = bytes[offset + 3];
                if attributes & EP_ATTR_TYPE_MASK == EP_ATTR_TYPE_INTERRUPT
                    && endpoint_address & EP_ADDR_DIR_IN != 0
                {
                    return Some(HidKeyboardConfig {
                        config_value,
                        interface_number: current_interface?,
                        endpoint_address,
                        max_packet_size: u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]),
                        b_interval: bytes[offset + 6],
                    });
                }
            }
            _ => {}
        }
        offset += len;
    }
    None
}

/// Enumerates and configures the device found on `port` (already reset, with the given Port
/// Speed ID) as a HID boot-protocol keyboard: enable slot, address device, read the device and
/// configuration descriptors, `SET_CONFIGURATION`, configure the interrupt-IN endpoint,
/// `SET_PROTOCOL`(Boot)/`SET_IDLE`(0), then arm the first report read. `None` on any failure, or
/// if the device simply isn't a HID boot keyboard -- always logged by the caller.
pub(crate) fn bring_up(
    controller: &mut Xhci,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
    port: u8,
    speed: u8,
) -> Option<KeyboardDevice> {
    let slot_id = controller.enable_slot()?;

    let (input_virt, input_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let (_, output_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let (ep0_virt, ep0_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let mut ep0_ring = TrbRing::new(ep0_virt, ep0_phys);

    write_input_control_context(input_virt, (1 << 0) | (1 << 1), 0);
    write_slot_context(input_virt + 32, speed, port, 1);
    write_endpoint_context(
        input_virt + 64,
        EndpointType::Control,
        initial_ep0_max_packet(speed),
        0,
        ep0_ring.initial_dequeue_pointer(),
    );

    controller.set_dcbaa_entry(slot_id, output_phys);
    if !controller.address_device(slot_id, input_phys) {
        serial_println!("[usb] port {}: Address Device command failed", port);
        return None;
    }

    let (desc_virt, desc_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;

    // First 8 bytes of the device descriptor -- enough to learn the real bMaxPacketSize0 for a
    // Full-Speed device (Low/High/Super Speed all use a spec-fixed value already applied above).
    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_STD_DEV_TO_HOST,
        REQ_GET_DESCRIPTOR,
        DESC_TYPE_DEVICE,
        0,
        Some((desc_phys, 8)),
    )?;
    if speed == 1 {
        let real_max_packet = unsafe { core::ptr::read_volatile(desc_virt.as_ptr::<u8>().add(7)) };
        if real_max_packet != 0 && real_max_packet as u16 != initial_ep0_max_packet(speed) {
            write_input_control_context(input_virt, 1 << 1, 0);
            write_endpoint_context(
                input_virt + 64,
                EndpointType::Control,
                real_max_packet as u16,
                0,
                ep0_ring.initial_dequeue_pointer(),
            );
            if !controller.evaluate_context(slot_id, input_phys) {
                serial_println!(
                    "[usb] port {}: Evaluate Context (EP0 max packet refinement) failed -- \
                     continuing with the initial guess",
                    port
                );
            }
        }
    }

    // Full 18-byte device descriptor.
    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_STD_DEV_TO_HOST,
        REQ_GET_DESCRIPTOR,
        DESC_TYPE_DEVICE,
        0,
        Some((desc_phys, 18)),
    )?;
    let vendor = unsafe { core::ptr::read_volatile(desc_virt.as_ptr::<u16>().add(4)) };
    let product = unsafe { core::ptr::read_volatile(desc_virt.as_ptr::<u16>().add(5)) };
    serial_println!(
        "[usb] port {}: device descriptor read, VID:PID {:04x}:{:04x}",
        port,
        vendor,
        product
    );

    // Configuration descriptor: a 9-byte header first (to learn the real wTotalLength), then the
    // whole thing (interface + HID + endpoint descriptors included) in one shot.
    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_STD_DEV_TO_HOST,
        REQ_GET_DESCRIPTOR,
        DESC_TYPE_CONFIGURATION,
        0,
        Some((desc_phys, 9)),
    )?;
    let total_len = unsafe { core::ptr::read_volatile(desc_virt.as_ptr::<u16>().add(1)) };
    let read_len = (total_len as usize).clamp(9, 4096) as u16;
    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_STD_DEV_TO_HOST,
        REQ_GET_DESCRIPTOR,
        DESC_TYPE_CONFIGURATION,
        0,
        Some((desc_phys, read_len)),
    )?;

    let config_bytes =
        unsafe { core::slice::from_raw_parts(desc_virt.as_ptr::<u8>(), read_len as usize) };
    let parsed = parse_hid_keyboard_config(config_bytes)?;
    serial_println!(
        "[usb] port {}: HID boot keyboard, interface {}, interrupt IN endpoint {:#04x}, \
         max packet {}, bInterval {}",
        port,
        parsed.interface_number,
        parsed.endpoint_address,
        parsed.max_packet_size,
        parsed.b_interval
    );

    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_STD_HOST_TO_DEV,
        REQ_SET_CONFIGURATION,
        parsed.config_value as u16,
        0,
        None,
    )?;

    let ep_dci = endpoint_dci(parsed.endpoint_address & 0x0F, true);
    let (int_virt, int_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let mut interrupt_ring = TrbRing::new(int_virt, int_phys);

    write_input_control_context(input_virt, (1 << 0) | (1 << ep_dci), 0);
    write_slot_context(input_virt + 32, speed, port, ep_dci);
    write_endpoint_context(
        input_virt + 32 * (ep_dci as u64 + 1),
        EndpointType::InterruptIn,
        parsed.max_packet_size.max(8),
        xhci_interval(speed, parsed.b_interval),
        interrupt_ring.initial_dequeue_pointer(),
    );
    if !controller.configure_endpoint(slot_id, input_phys) {
        serial_println!("[usb] port {}: Configure Endpoint command failed", port);
        return None;
    }

    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_CLASS_INTERFACE_HOST_TO_DEV,
        HID_REQ_SET_PROTOCOL,
        HID_BOOT_PROTOCOL,
        parsed.interface_number as u16,
        None,
    )?;
    controller.control_transfer_in(
        &mut ep0_ring,
        slot_id,
        BM_CLASS_INTERFACE_HOST_TO_DEV,
        HID_REQ_SET_IDLE,
        0,
        parsed.interface_number as u16,
        None,
    )?;

    let (report_buf_virt, report_buf_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    enqueue_normal_in(&mut interrupt_ring, report_buf_phys, 8);
    controller.ring_endpoint_doorbell(slot_id, ep_dci);

    Some(KeyboardDevice {
        slot_id,
        interrupt_ep_dci: ep_dci,
        interrupt_ring,
        report_buf_virt,
        report_buf_phys,
        prev_report: [0; 8],
        repeat_usage: None,
        repeat_next_tick: 0,
    })
}
