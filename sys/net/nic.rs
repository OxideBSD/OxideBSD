//! The interface future protocol code (ARP/IPv4/... in later phases) and boot-time driver
//! probing call through, so a second driver (virtio-net, e1000, ...) can be added later without
//! every caller changing. Only one driver is ever installed today -- see
//! `rtl8139::probe_and_init` -- no probe table or multi-NIC management exists yet, deliberately;
//! see this repo's networking plan for why that's deferred rather than built speculatively now.

use alloc::boxed::Box;
use alloc::vec::Vec;

use spin::Mutex;

#[derive(Debug, Clone, Copy)]
pub enum NicError {
    NoTxSlotAvailable,
}

pub trait NicDriver: Send {
    /// Transmits one Ethernet frame (dest MAC + src MAC + ethertype + payload, no FCS -- the NIC
    /// appends its own CRC). Frames shorter than the Ethernet minimum are padded by the driver.
    fn send(&mut self, frame: &[u8]) -> Result<(), NicError>;

    /// Returns the next received frame not yet handed to the caller, if any. Never blocks.
    fn poll_recv(&mut self) -> Option<Vec<u8>>;

    fn mac_address(&self) -> [u8; 6];
}

/// The single installed NIC, if a driver's own `probe_and_init` found and initialized one at
/// boot. `None` if no supported NIC is present -- not fatal, callers should treat networking as
/// simply unavailable.
pub static NIC: Mutex<Option<Box<dyn NicDriver>>> = Mutex::new(None);
