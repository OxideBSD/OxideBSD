//! Shared device enumeration for `super`: bring a device on a root port from Default to Addressed
//! and read its descriptors, so the port loop can inspect what it is before committing to a driver
//! (`hid_keyboard::finish`, `storage::finish`). Doing this once per port -- rather than letting
//! each driver enable its own slot and address the device -- is what lets a keyboard and a mass-
//! storage stick share one code path, and avoids leaving a slot that still owns the port when the
//! first guess is wrong.

use alloc::vec::Vec;

use x86_64::structures::paging::{FrameAllocator, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::xhci::{
    EndpointType, TrbRing, Xhci, alloc_zeroed_page, write_endpoint_context,
    write_input_control_context, write_slot_context,
};
use crate::serial_println;

// Standard USB requests and descriptor types (USB 2.0 §9.4).
const REQ_GET_DESCRIPTOR: u8 = 0x06;
const DESC_TYPE_DEVICE: u16 = 1 << 8;
const DESC_TYPE_CONFIGURATION: u16 = 2 << 8;
const BM_STD_DEV_TO_HOST: u8 = 0x80;

/// A device brought up to the Addressed state, with its full configuration descriptor read. The
/// slot, its ep0 transfer ring and input-context page are kept for a driver's `finish` step
/// (`SET_CONFIGURATION` and endpoint setup), which happens on this same slot -- no re-addressing.
pub(crate) struct EnumeratedDevice {
    pub(crate) slot_id: u8,
    pub(crate) speed: u8,
    pub(crate) port: u8,
    pub(crate) input_virt: VirtAddr,
    pub(crate) input_phys: PhysAddr,
    pub(crate) ep0_ring: TrbRing,
    pub(crate) config: Vec<u8>,
    pub(crate) vendor: u16,
    pub(crate) product: u16,
}

/// The default control-endpoint max packet size for a Port Speed ID (xHCI Table 5-12 / the USB
/// specs): SuperSpeed 512, High 64, Low/Full 8 -- a Full-Speed device's real value is refined from
/// its descriptor below.
fn initial_ep0_max_packet(speed: u8) -> u16 {
    match speed {
        4 => 512,
        3 => 64,
        _ => 8,
    }
}

/// Enables a slot for the device on `port` (already reset, with the given Port Speed ID), sets up
/// its control endpoint, addresses it, and reads its device and configuration descriptors. `None`
/// (logged) on any failure. Uses synchronous control transfers -- the Event Ring has no service
/// owner yet during boot enumeration.
pub(crate) fn enumerate(
    controller: &mut Xhci,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
    port: u8,
    speed: u8,
) -> Option<EnumeratedDevice> {
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
        serial_println!("[usb] port {}: Address Device failed", port);
        return None;
    }

    let (desc_virt, desc_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;

    // First 8 bytes of the device descriptor -- enough to learn a Full-Speed device's real
    // bMaxPacketSize0 (Low/High/SuperSpeed use the spec-fixed value already applied above).
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
                    "[usb] port {}: Evaluate Context (ep0 max packet) failed -- using the initial guess",
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

    // Configuration descriptor: a 9-byte header (for wTotalLength), then the whole thing.
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
    let config =
        unsafe { core::slice::from_raw_parts(desc_virt.as_ptr::<u8>(), read_len as usize) }
            .to_vec();

    serial_println!(
        "[usb] port {}: device VID:PID {:04x}:{:04x}, {} byte config descriptor",
        port,
        vendor,
        product,
        read_len
    );

    Some(EnumeratedDevice {
        slot_id,
        speed,
        port,
        input_virt,
        input_phys,
        ep0_ring,
        config,
        vendor,
        product,
    })
}
