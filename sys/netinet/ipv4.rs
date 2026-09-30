//! Minimal IPv4: parses inbound packets and dispatches by protocol number, builds and sends
//! outbound ones. No fragmentation, no options. Which interface a packet leaves by, its next hop
//! and its source address come from `net::ifnet::route`: `lo0` for 127.0.0.0/8 and the host's own
//! addresses, `rl0` for the rest, off-subnet destinations through the default gateway (SLIRP only
//! answers ARP for its own virtual addresses, so an off-link destination is never ARPed directly).

use alloc::vec::Vec;

use super::{arp, icmp, tcp, udp};
use crate::net::ethernet;
use crate::net::ifnet::{self, Interface};

pub type Ipv4Addr = [u8; 4];

/// `rl0`'s address, SLIRP's default guest IP under QEMU's `-nic user` backend (`net::ifnet`).
pub const GUEST_IP: Ipv4Addr = ifnet::ETHER_ADDR;
/// SLIRP's default gateway -- also answers ICMP echo requests directed at itself, which is what
/// `tests/icmp_smoke.rs` uses to verify this stack against real (if virtualized) network
/// behavior without needing host-side raw-socket privileges.
pub const GATEWAY_IP: Ipv4Addr = ifnet::DEFAULT_GATEWAY;
/// SLIRP's built-in DNS relay (forwards to whatever resolver the host itself uses) -- what
/// `sys/modules/oxfs`'s seeded `/etc/resolv.conf` points musl's real DNS stub resolver
/// (`external/mit/musl/src/network/`) at. Real UDP, real IPv4, real ICMP-adjacent traffic -- no
/// DNS protocol logic lives in this kernel at all, matching how `open`/`execve`/`stat` are ported
/// (make musl's own libc code work over this ABI, don't reimplement it kernel-side).
pub const DNS_SERVER_IP: Ipv4Addr = [10, 0, 2, 3];

pub const PROTO_ICMP: u8 = 1;

const VERSION_IHL: u8 = 0x45; // version 4, IHL 5 (20-byte header, no options)
pub(crate) const DEFAULT_TTL: u8 = 64;
/// `pub(super)`, not private -- `icmp::handle_packet` needs it to strip the IP header back off the
/// full packet it's handed for raw-socket delivery (see `icmp.rs`'s own doc comment on why a raw
/// `SOCK_RAW`/`IPPROTO_ICMP` socket needs the IP header included, unlike UDP/TCP's payload-only
/// delivery).
pub(super) const HEADER_LEN: usize = 20;

/// Internet checksum (RFC 1071): ones'-complement sum of 16-bit words, carries folded back in,
/// then complemented. Shared by the IPv4 header itself and, with no pseudo-header (unlike UDP/
/// TCP), ICMP.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for chunk in pairs {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses one IPv4 packet that arrived on `from` and dispatches it by protocol. It must be for
/// this host: over loopback any of its addresses; over Ethernet `rl0`'s, and never 127.0.0.0/8
/// (a "martian", which BSD drops too).
pub fn handle_packet(payload: &[u8], from: Interface) {
    if payload.len() < HEADER_LEN || payload[0] != VERSION_IHL {
        return;
    }
    let total_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let protocol = payload[9];
    let src_ip: Ipv4Addr = payload[12..16].try_into().unwrap();
    let dst_ip: Ipv4Addr = payload[16..20].try_into().unwrap();

    let for_us = match from {
        Interface::Loopback => ifnet::is_local(dst_ip),
        Interface::Ethernet => dst_ip == GUEST_IP && !ifnet::is_loopback_net(src_ip),
    };
    if !for_us || total_length < HEADER_LEN || total_length > payload.len() {
        return;
    }
    let ip_payload = &payload[HEADER_LEN..total_length];

    match protocol {
        // Unlike udp/tcp::handle_packet, icmp::handle_packet gets the *whole* packet (header
        // included), not just `ip_payload` -- a raw `SOCK_RAW`/`IPPROTO_ICMP` socket needs the
        // real IP header prepended to what it reads back (matching real Linux raw-socket
        // semantics, which `ping`'s own receive path directly relies on), not just the ICMP
        // portion the existing echo-request/reply logic operates on.
        PROTO_ICMP => icmp::handle_packet(&payload[..total_length], src_ip, dst_ip),
        udp::PROTO_UDP => udp::handle_packet(ip_payload, src_ip, dst_ip),
        tcp::PROTO_TCP => tcp::handle_packet(ip_payload, src_ip, dst_ip),
        _ => {}
    }
}

/// Builds and sends one IPv4 packet from `src` (the sender's bound address, or the route's
/// source) to `dest_ip`, over the interface `net::ifnet::route` picks. Looped back through
/// `if_loop`'s queue, or out `rl0` after resolving the next hop's MAC via `arp`, sending a request
/// and giving it a bounded wait if it isn't already known -- callers run in a normal
/// (non-interrupt) context where a short busy-wait is acceptable. A known simplification: a real
/// stack would queue the packet and retry asynchronously instead of blocking the caller.
pub fn send_packet(src: Ipv4Addr, dest_ip: Ipv4Addr, protocol: u8, payload: &[u8]) -> Option<()> {
    let route = ifnet::route(dest_ip)?;

    let total_length = HEADER_LEN + payload.len();
    let mut packet = Vec::with_capacity(total_length);
    packet.push(VERSION_IHL);
    packet.push(0); // DSCP/ECN
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // identification
    packet.extend_from_slice(&[0, 0]); // flags/fragment offset
    packet.push(DEFAULT_TTL);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]); // header checksum placeholder
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dest_ip);
    packet.extend_from_slice(payload);

    let sum = checksum(&packet[..HEADER_LEN]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());

    match route.interface {
        Interface::Loopback => crate::net::if_loop::output(packet),
        Interface::Ethernet => {
            let dest_mac = resolve_with_retry(route.next_hop)?;
            ethernet::send_frame(dest_mac, ethernet::ETHERTYPE_IPV4, &packet)
        }
    }
}

fn resolve_with_retry(ip: Ipv4Addr) -> Option<[u8; 6]> {
    if let Some(mac) = arp::resolve(ip) {
        return Some(mac);
    }
    arp::send_request(ip);
    // Bounded by `crate::tsc`, not `crate::cpu::interrupts::ticks()`/an arbitrary spin count -- see
    // rtl8139_smoke's own precedent for why a few seconds of budget is generous headroom, not a
    // tight timing assumption.
    //
    // `hint::spin_loop()`, not `hlt()`: this function is reachable from a real syscall
    // (`udp`/`icmp`'s `sendto` handlers), and `sys/syscall.rs`'s own SFMASK setup clears
    // `RFLAGS::INTERRUPT_FLAG` for a syscall's *entire* duration, not just its entry -- `hlt()`
    // only wakes on an unmasked interrupt or an NMI, so calling it here would freeze the CPU
    // permanently the instant a reply hadn't already arrived before this loop started. A plain
    // busy-spin still lets `poll()` keep draining the NIC's ring -- packet arrival there is a
    // hardware DMA-like effect, not gated on this core's interrupt-enable state -- so a real
    // reply is still found the moment it lands.
    //
    // The deadline itself must use `crate::tsc`, not `ticks()`: `ticks()` is driven entirely by
    // the timer IRQ, which can't fire while this syscall has interrupts masked -- a tick-based
    // deadline here would be frozen at whatever value it had when the syscall began and could
    // never actually elapse, turning "give up after N ticks" into "never gives up" for a
    // genuinely unreachable destination. Confirmed live by the identical bug in `net::
    // oxidebsd_sys_poll` (see `crate::tsc`'s own doc comment) -- fixed here for the same reason.
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(5000);
    while crate::cpu::tsc::now() < deadline {
        crate::net::poll();
        if let Some(mac) = arp::resolve(ip) {
            return Some(mac);
        }
        core::hint::spin_loop();
    }
    None
}
