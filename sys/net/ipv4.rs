//! Minimal IPv4: parses inbound packets and dispatches by protocol number, builds and sends
//! outbound ones. No fragmentation, no options, no real routing table -- just one default-gateway
//! rule (`next_hop`, below): anything outside `GUEST_IP`'s own `/24` goes to `GATEWAY_IP`'s MAC
//! instead of trying (and always failing) to ARP the real destination directly, since SLIRP only
//! answers ARP for its own virtual IPs. Without that rule, nothing off the local subnet -- which
//! is to say any real internet destination at all -- could ever be reached, only SLIRP's own
//! gateway/DNS-relay addresses. See this repo's networking plan for what's deferred to later
//! phases.

use alloc::vec::Vec;

use super::{arp, ethernet, icmp, tcp, udp};

pub type Ipv4Addr = [u8; 4];

/// SLIRP's default guest IP under QEMU's `-nic user` backend. No DHCP client exists -- an
/// explicit non-goal until something needs one (see this repo's networking plan).
pub const GUEST_IP: Ipv4Addr = [10, 0, 2, 15];
/// SLIRP's default gateway -- also answers ICMP echo requests directed at itself, which is what
/// `tests/icmp_smoke.rs` uses to verify this stack against real (if virtualized) network
/// behavior without needing host-side raw-socket privileges.
pub const GATEWAY_IP: Ipv4Addr = [10, 0, 2, 2];
/// SLIRP's built-in DNS relay (forwards to whatever resolver the host itself uses) -- what
/// `sys/modules/oxfs`'s seeded `/etc/resolv.conf` points musl's real DNS stub resolver
/// (`external/mit/musl/src/network/`) at. Real UDP, real IPv4, real ICMP-adjacent traffic -- no
/// DNS protocol logic lives in this kernel at all, matching how `open`/`execve`/`stat` are ported
/// (make musl's own libc code work over this ABI, don't reimplement it kernel-side).
pub const DNS_SERVER_IP: Ipv4Addr = [10, 0, 2, 3];

pub const PROTO_ICMP: u8 = 1;

const VERSION_IHL: u8 = 0x45; // version 4, IHL 5 (20-byte header, no options)
const DEFAULT_TTL: u8 = 64;
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

/// Parses one IPv4 packet and dispatches by protocol. Anything but ICMP is later phases' concern
/// (UDP/TCP) or simply unsupported -- silently dropped.
pub fn handle_packet(payload: &[u8]) {
    if payload.len() < HEADER_LEN || payload[0] != VERSION_IHL {
        return;
    }
    let total_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let protocol = payload[9];
    let src_ip: Ipv4Addr = payload[12..16].try_into().unwrap();
    let dst_ip: Ipv4Addr = payload[16..20].try_into().unwrap();

    if dst_ip != GUEST_IP || total_length < HEADER_LEN || total_length > payload.len() {
        return;
    }
    let ip_payload = &payload[HEADER_LEN..total_length];

    match protocol {
        // Unlike udp/tcp::handle_packet, icmp::handle_packet gets the *whole* packet (header
        // included), not just `ip_payload` -- a raw `SOCK_RAW`/`IPPROTO_ICMP` socket needs the
        // real IP header prepended to what it reads back (matching real Linux raw-socket
        // semantics, which `ping`'s own receive path directly relies on), not just the ICMP
        // portion the existing echo-request/reply logic operates on.
        PROTO_ICMP => icmp::handle_packet(&payload[..total_length], src_ip),
        udp::PROTO_UDP => udp::handle_packet(ip_payload, src_ip),
        tcp::PROTO_TCP => tcp::handle_packet(ip_payload, src_ip),
        _ => {}
    }
}

/// Real routing is out of scope (see this file's own doc comment), but a *default gateway* is
/// the one routing decision every host makes even with an otherwise-empty routing table -- and
/// without it, nothing off the local `/24` (i.e. anything real internet traffic would ever want to
/// reach: `ping 1.1.1.1`, DNS to a nameserver other than SLIRP's own relay, ...) could ever ARP-
/// resolve at all, since SLIRP only answers ARP for its own virtual IPs (`GATEWAY_IP`/
/// `DNS_SERVER_IP`), never for an arbitrary off-link address. Returns the IP whose *MAC* should
/// receive the Ethernet frame -- `dest_ip` itself if it's on-link, `GATEWAY_IP` otherwise. The
/// packet's own IP header destination is never touched here; only the link-layer next hop changes,
/// same as real IP routing.
pub(crate) fn next_hop(dest_ip: Ipv4Addr) -> Ipv4Addr {
    if dest_ip[..3] == GUEST_IP[..3] {
        dest_ip
    } else {
        GATEWAY_IP
    }
}

/// Builds and sends one IPv4 packet. Resolves the real next hop's (see `next_hop`) MAC via `arp`,
/// sending a request and giving it a bounded wait if it isn't already known -- callers run in a
/// normal (non-interrupt) context where a short busy-wait is acceptable, matching how
/// `tests/rtl8139_smoke.rs`'s own test loop already waits for a reply. A known simplification: a
/// real stack would queue the packet and retry asynchronously instead of blocking the caller.
pub fn send_packet(dest_ip: Ipv4Addr, protocol: u8, payload: &[u8]) -> Option<()> {
    let dest_mac = resolve_with_retry(next_hop(dest_ip))?;

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
    packet.extend_from_slice(&GUEST_IP);
    packet.extend_from_slice(&dest_ip);
    packet.extend_from_slice(payload);

    let sum = checksum(&packet[..HEADER_LEN]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());

    ethernet::send_frame(dest_mac, ethernet::ETHERTYPE_IPV4, &packet)
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
        super::poll();
        if let Some(mac) = arp::resolve(ip) {
            return Some(mac);
        }
        core::hint::spin_loop();
    }
    None
}
