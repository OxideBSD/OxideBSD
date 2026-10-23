//! `sync(8)`: writes everything the system holds in memory for its disks out to them.
//! Arguments are ignored, as on the BSDs.

pub(crate) fn main() {
    // SAFETY: sync(2) takes no arguments.
    unsafe { libc::sync() };
}
