//! `adjkerntz(8)`: tells the kernel the local time zone's offset from UTC (`kern.utc_offset`,
//! minutes east), for the file systems whose timestamps are local time (msdosfs; OxideBSD-doc
//! `VFS.md` §9.2, `TIMEZONE.md` §4.3). FreeBSD's name; unlike FreeBSD's it never touches the
//! clock, which keeps UTC.
//!
//! ```text
//! adjkerntz -a
//! ```
//!
//! Reads the offset in effect now from `/etc/localtime` (UTC without it; `TZ` is ignored, since
//! the kernel's offset is the system's, not a user's) and sets the sysctl. rc(8)
//! runs it at boot and cron(8) every hour, so the offset follows daylight saving time; tzsetup(8)
//! runs it after changing the zone.

use std::process::ExitCode;

unsafe extern "C" {
    fn sysctlbyname(name: *const libc::c_char, oldp: *mut libc::c_void, oldlenp: *mut usize, newp: *const libc::c_void, newlen: usize) -> i32;
}

fn usage() -> ExitCode {
    eprintln!("usage: adjkerntz -a");
    ExitCode::from(1)
}

/// The local zone's offset from UTC now, in minutes east.
fn local_offset() -> i32 {
    // SAFETY: single-threaded; localtime_r (which reads the zone itself) writes only `tm`.
    unsafe {
        std::env::remove_var("TZ");
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return 0;
        }
        (tm.tm_gmtoff / 60) as i32
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 || args[0] != "-a" {
        return usage();
    }
    let want = local_offset();
    let name = c"kern.utc_offset";
    // Set even when it's the kernel's already: the first setting tells the kernel the zone is
    // known, which a CMOS clock keeping local time waits for (`machdep.wall_cmos_clock`).
    // SAFETY: `want` is valid for the call.
    if unsafe { sysctlbyname(name.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), (&raw const want).cast(), size_of::<i32>()) } != 0 {
        eprintln!("adjkerntz: kern.utc_offset: {}", std::io::Error::last_os_error());
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
