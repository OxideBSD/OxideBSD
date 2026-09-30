//! `lo0`'s output (BSD's `if_loop`): a looped packet is queued, not handed straight to the
//! receive path, which would re-enter a protocol's lock from inside its own send. `net::poll`
//! drains the queue ahead of the NIC, and queueing wakes whoever waits on a socket, as a received
//! frame's interrupt does, so a looped packet is processed without waiting for the periodic wake.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use spin::Mutex;

/// Packets queued at most, as BSD's `ifqmaxlen`; beyond it output fails (`ENOBUFS` to a caller
/// that reports it), as a full interface queue does.
const QUEUE_MAX: usize = 512;

static QUEUE: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// Queues one IPv4 packet for input. `None` if the queue is full.
pub fn output(packet: Vec<u8>) -> Option<()> {
    {
        let mut q = QUEUE.lock();
        if q.len() >= QUEUE_MAX {
            return None;
        }
        q.push_back(packet);
    }
    // As rtl8139's interrupt: a contended table lock only delays this to the periodic wake.
    if let Some(mut table) = crate::process::table().try_lock() {
        crate::process::wake_pollers(&mut table);
    }
    Some(())
}

/// Takes the next queued packet.
pub fn dequeue() -> Option<Vec<u8>> {
    QUEUE.lock().pop_front()
}
