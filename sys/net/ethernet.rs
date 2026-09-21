//! Ethernet frame parsing/construction -- the lowest layer of the protocol stack (Phase 2). Reads
//! frames handed up from `rtl8139::poll_recv` (already stripped of the trailing CRC by the
//! driver) and dispatches by ethertype; builds outbound frames for `arp`/`ipv4` to send through
//! `nic::NIC`.

use alloc::vec::Vec;

use super::{arp, ipv4, nic};

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

const HEADER_LEN: usize = 14;

/// This driver's own MAC address, if a NIC is installed. `None` means networking is entirely
/// unavailable this boot (see `rtl8139::init`'s own doc comment).
pub fn our_mac() -> Option<[u8; 6]> {
    nic::NIC.lock().as_ref().map(|driver| driver.mac_address())
}

/// Parses one received frame and dispatches its payload by ethertype. Anything not ARP/IPv4
/// (later phases' concern, or simply unsupported) is silently dropped -- matches how any real
/// stack ignores ethertypes it doesn't handle.
pub fn handle_frame(frame: &[u8]) {
    if frame.len() < HEADER_LEN {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[HEADER_LEN..];

    match ethertype {
        ETHERTYPE_ARP => arp::handle_packet(payload),
        ETHERTYPE_IPV4 => ipv4::handle_packet(payload),
        _ => {}
    }
}

/// Builds and transmits one Ethernet frame. `None` if no NIC is installed or the send failed.
pub fn send_frame(dest_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Option<()> {
    let src_mac = our_mac()?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&dest_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);

    nic::NIC.lock().as_mut()?.send(&frame).ok()
}
