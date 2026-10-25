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

mod enumerate;
mod hid_keyboard;
pub(crate) mod storage;
mod xhci;

use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::serial_println;

struct UsbState {
    controller: xhci::Xhci,
    keyboard: Option<hid_keyboard::KeyboardDevice>,
    /// The configured mass-storage devices (`usb0`, ...); their bulk rings and completion state
    /// live here, reached by slot id from `storage_xfer`.
    storage: alloc::vec::Vec<storage::StorageDevice>,
    /// Whether the controller delivers completions as MSI-X (`msi_handler`) rather than relying on
    /// the tick-driven `poll` fallback. Either way `poll` still drains the ring as a safety net
    /// and drives keyboard auto-repeat.
    msi_armed: bool,
}

/// One Bulk-Only command at a time across all mass-storage devices (one Event Ring, one
/// completion slot per device; serialising keeps the transport model simple).
static STORAGE_COMMAND: Mutex<()> = Mutex::new(());
/// The next Command Block Wrapper tag (`storage`).
static STORAGE_TAG: AtomicU32 = AtomicU32::new(1);
/// How long a single bulk stage waits before it's called a transport failure.
const STORAGE_TIMEOUT_MS: u64 = 10_000;

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

    // One keyboard (the first found) and every mass-storage device. A port holds one device, so
    // for each: try the keyboard first (its path is unchanged for a real keyboard), then storage.
    // A storage device fails the keyboard attempt after being addressed and is then re-addressed
    // to a fresh slot -- a minor slot leak that a shared enumerator will fold away with hubs.
    let mut keyboard = None;
    let mut storage = alloc::vec::Vec::new();
    for port in 1..=controller.max_ports() {
        let Some(speed) = controller.reset_port(port) else {
            continue;
        };
        serial_println!("[usb] device connected on port {} (speed id {})", port, speed);
        // Enumerate once (one slot, addressed, descriptors read), then dispatch by what it is --
        // so a wrong first guess doesn't leave a slot owning the port.
        let Some(mut dev) =
            enumerate::enumerate(&mut controller, frame_allocator, phys_mem_offset, port, speed)
        else {
            continue;
        };
        if keyboard.is_none()
            && let Some(kb) =
                hid_keyboard::finish(&mut controller, frame_allocator, phys_mem_offset, &mut dev)
        {
            serial_println!("[usb] USB HID keyboard ready on port {}", port);
            keyboard = Some(kb);
            continue;
        }
        match storage::finish(&mut controller, frame_allocator, phys_mem_offset, &mut dev) {
            Some(sd) => {
                serial_println!("[usb] USB mass storage ready on port {} (slot {})", port, sd.slot_id());
                storage.push(sd);
            }
            None => {
                serial_println!(
                    "[usb] port {}: not a HID boot keyboard or BOT mass-storage device -- skipping",
                    port
                );
            }
        }
    }
    if keyboard.is_none() && storage.is_empty() {
        serial_println!("[usb] xHCI controller up, but no keyboard or mass storage on any port");
    }

    // Boot-time enumeration is done (it spin-polled the Event Ring synchronously), so it's now
    // safe to hand the ring to the MSI handler. Store the state first, then arm MSI-X holding the
    // state lock -- so if the very first completion interrupts mid-arm, `msi_handler` simply bails
    // (lock held) and the tick `poll` drains it a moment later.
    *STATE.lock() = Some(UsbState {
        controller,
        keyboard,
        storage,
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
    let mut had_storage = false;
    while let Some(evt) = state.controller.poll_event() {
        if let Some(keyboard) = state.keyboard.as_mut()
            && keyboard.handle_transfer_event(&mut state.controller, evt)
        {
            continue;
        }
        if state.storage.iter_mut().any(|d| d.handle_event(evt)) {
            had_storage = true;
            continue;
        }
        // Unclaimed: dropped, same as the driver has always done with a stray event.
    }
    if state.msi_armed {
        state.controller.ack_interrupter();
    }
    // A storage completion was recorded -- wake whoever's blocked in `storage_xfer`. Safe from
    // interrupt context on one core (IF is clear), the same way `virtio_scsi`'s handler wakes.
    if had_storage {
        super::dma::wake_disk_waiters(&mut crate::process::table().lock());
    }
}

/// The next CBW tag (`storage`).
pub(crate) fn next_storage_tag() -> u32 {
    STORAGE_TAG.fetch_add(1, Ordering::Relaxed)
}

/// Serialises Bulk-Only commands (held for a whole CBW/data/CSW transaction).
pub(crate) fn storage_command_lock() -> spin::MutexGuard<'static, ()> {
    STORAGE_COMMAND.lock()
}

/// One bulk stage for mass-storage device `slot_id`: enqueue `len` bytes at `phys` on endpoint
/// `ep_dci` (a chained data TD if `td`, else a single-TRB CBW/CSW), ring its doorbell, and wait
/// for the completion. Returns the residual (bytes not moved) on success. The wait sleeps through
/// the scheduler at run time (woken by the Event Ring service) and spins at boot, via `dma` --
/// never holding the state lock across it, so the service can take it to record the completion.
pub(crate) fn storage_xfer(
    slot_id: u8,
    ep_dci: u8,
    phys: PhysAddr,
    len: u32,
    td: bool,
) -> Result<u32, ()> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut guard = STATE.lock();
        let Some(dev) = guard
            .as_mut()
            .and_then(|st| st.storage.iter_mut().find(|d| d.slot_id() == slot_id))
        else {
            return Err(());
        };
        dev.arm(ep_dci);
        if td {
            xhci::enqueue_bulk_td(dev.ring_for(ep_dci), phys, len);
        } else {
            xhci::enqueue_normal_in(dev.ring_for(ep_dci), phys, len as u16);
        }
        Ok(())
    })?;
    // Doorbell after arming (a separate STATE take so the borrow of the controller doesn't overlap
    // the device's ring above).
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(st) = STATE.lock().as_ref() {
            st.controller.ring_endpoint_doorbell(slot_id, ep_dci);
        }
    });
    if !super::dma::wait_for_disk(STORAGE_TIMEOUT_MS, || storage_done(slot_id)) {
        serial_println!("[usb] storage slot {}: transfer on endpoint {} timed out", slot_id, ep_dci);
        return Err(());
    }
    let (ok, residual) = x86_64::instructions::interrupts::without_interrupts(|| {
        STATE
            .lock()
            .as_ref()
            .and_then(|st| st.storage.iter().find(|d| d.slot_id() == slot_id))
            .and_then(|d| d.completion())
    })
    .ok_or(())?;
    if ok { Ok(residual) } else { Err(()) }
}

fn storage_done(slot_id: u8) -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        STATE
            .lock()
            .as_ref()
            .and_then(|st| st.storage.iter().find(|d| d.slot_id() == slot_id))
            .map(|d| d.completion().is_some())
            .unwrap_or(false)
    })
}

/// Probes every configured mass-storage device's logical unit, for `drivers::disk` to register.
/// Called once file systems are coming up, after `init` armed the controller -- the bulk probes
/// (`INQUIRY`, `READ CAPACITY`) run interrupt-driven. The state lock is dropped before probing,
/// since each probe re-takes it through `storage_xfer`.
pub(crate) fn probe_storage() -> alloc::vec::Vec<storage::Found> {
    let units: alloc::vec::Vec<storage::MsdUnit> = STATE
        .lock()
        .as_ref()
        .map(|st| st.storage.iter().map(|d| d.unit()).collect())
        .unwrap_or_default();
    serial_println!("[usb] probing {} mass-storage unit(s)", units.len());
    units.into_iter().filter_map(storage::probe).collect()
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
