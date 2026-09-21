//! A minimal ARP implementation: answers requests for our own IP, learns mappings from any ARP
//! traffic seen, and can originate requests to resolve a target. Fixed-size table, no heap --
//! matches this kernel's usual "small array behind a `Mutex`" shape for driver/subsystem state,
//! even though this lives in core kernel, not an actual dynamically-loaded module.

use spin::Mutex;

use super::ethernet::{self, BROADCAST_MAC, ETHERTYPE_ARP};
use super::ipv4::{GUEST_IP, Ipv4Addr};

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const OPER_REQUEST: u16 = 1;
const OPER_REPLY: u16 = 2;
const PACKET_LEN: usize = 28;

const TABLE_SIZE: usize = 16;

type ArpTable = [Option<(Ipv4Addr, [u8; 6])>; TABLE_SIZE];

static TABLE: Mutex<ArpTable> = Mutex::new([None; TABLE_SIZE]);

fn learn(ip: Ipv4Addr, mac: [u8; 6]) {
    let mut table = TABLE.lock();
    if let Some(slot) = table
        .iter_mut()
        .find(|entry| matches!(entry, Some((existing_ip, _)) if *existing_ip == ip))
    {
        *slot = Some((ip, mac));
        return;
    }
    if let Some(slot) = table.iter_mut().find(|entry| entry.is_none()) {
        *slot = Some((ip, mac));
        return;
    }
    // Table full -- evict the first entry. No LRU/aging; fine at this table's small size and
    // this phase's scope (a handful of hosts on a QEMU SLIRP network).
    table[0] = Some((ip, mac));
}

/// Looks up a previously learned mapping. Never blocks or sends a request itself -- callers that
/// need a fresh resolution should call `send_request` and retry (see `ipv4::send_packet`'s own
/// resolve-and-retry loop).
pub fn resolve(ip: Ipv4Addr) -> Option<[u8; 6]> {
    TABLE
        .lock()
        .iter()
        .find_map(|entry| entry.and_then(|(existing_ip, mac)| (existing_ip == ip).then_some(mac)))
}

/// Parses one ARP packet: replies to requests for our own IP, and learns the sender's mapping
/// from any request or reply seen (standard ARP behavior).
pub fn handle_packet(payload: &[u8]) {
    if payload.len() < PACKET_LEN {
        return;
    }
    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 {
        return;
    }
    let oper = u16::from_be_bytes([payload[6], payload[7]]);
    let sender_mac: [u8; 6] = payload[8..14].try_into().unwrap();
    let sender_ip: Ipv4Addr = payload[14..18].try_into().unwrap();
    let target_ip: Ipv4Addr = payload[24..28].try_into().unwrap();

    learn(sender_ip, sender_mac);

    if oper == OPER_REQUEST && target_ip == GUEST_IP {
        send_reply(sender_mac, sender_ip);
    }
}

fn build_packet(
    oper: u16,
    our_mac: [u8; 6],
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    packet[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    packet[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
    packet[4] = 6; // HLEN
    packet[5] = 4; // PLEN
    packet[6..8].copy_from_slice(&oper.to_be_bytes());
    packet[8..14].copy_from_slice(&our_mac);
    packet[14..18].copy_from_slice(&GUEST_IP);
    packet[18..24].copy_from_slice(&target_mac);
    packet[24..28].copy_from_slice(&target_ip);
    packet
}

fn send_reply(target_mac: [u8; 6], target_ip: Ipv4Addr) {
    let Some(our_mac) = ethernet::our_mac() else {
        return;
    };
    let packet = build_packet(OPER_REPLY, our_mac, target_mac, target_ip);
    ethernet::send_frame(target_mac, ETHERTYPE_ARP, &packet);
}

/// Broadcasts a request to resolve `target_ip`. Fire-and-forget -- callers poll `resolve`
/// afterward.
pub fn send_request(target_ip: Ipv4Addr) {
    let Some(our_mac) = ethernet::our_mac() else {
        return;
    };
    let packet = build_packet(OPER_REQUEST, our_mac, [0u8; 6], target_ip);
    ethernet::send_frame(BROADCAST_MAC, ETHERTYPE_ARP, &packet);
}
