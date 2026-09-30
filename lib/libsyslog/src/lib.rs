//! System logging, the parts every logging program shares (OxideBSD-doc `SYSLOG.md`):
//!
//! - [`pri`]: `syslog(3)` priorities, and the facility and level names of `syslog.conf(5)`;
//! - [`msg`]: parsing a received message (RFC 3164 or RFC 5424) and writing one out;
//! - [`time`]: broken-down local time, the one thing here that asks the C library.

pub mod msg;
pub mod pri;
pub mod time;

pub use msg::{Message, Stamp};
pub use pri::{Facility, Level};

/// The local log socket (`SYSLOG.md` §6.1).
pub const PATH_LOG: &str = "/dev/log";
/// The kernel message buffer (`SYSLOG.md` §4).
pub const PATH_KLOG: &str = "/dev/klog";
/// The UDP port of RFC 3164 and RFC 5426.
pub const SYSLOG_PORT: u16 = 514;
