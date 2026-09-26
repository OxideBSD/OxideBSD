//! `pam_lastlog(8)`: shows the user's previous login and records this one, in `/var/log/lastlogx`
//! (session management), as FreeBSD's and NetBSD's `login` do through PAM.
//!
//! The file holds NetBSD's `struct lastlogx` for each uid, at offset `uid * size_of`.

use std::ffi::{c_char, c_int};
use std::io::{Read, Seek, SeekFrom, Write};

use super::PamModule;
use crate::*;

pub const LASTLOGX: &str = "/var/log/lastlogx";

/// NetBSD's `struct lastlogx`: when, on which line, from which host.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lastlogx {
    pub tv_sec: i64,
    pub tv_usec: i64,
    pub line: [u8; 32],
    pub host: [u8; 256],
    pub ss: [u8; 128],
}

const SIZE: u64 = size_of::<Lastlogx>() as u64;

fn field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn set_field(dst: &mut [u8], s: &str) {
    let n = s.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

pub fn read(uid: u32) -> Option<Lastlogx> {
    let mut f = std::fs::File::open(LASTLOGX).ok()?;
    f.seek(SeekFrom::Start(uid as u64 * SIZE)).ok()?;
    let mut buf = [0u8; SIZE as usize];
    f.read_exact(&mut buf).ok()?;
    // SAFETY: Lastlogx is plain old data of exactly this size.
    let ll: Lastlogx = unsafe { std::mem::transmute(buf) };
    (ll.tv_sec != 0).then_some(ll)
}

pub fn write(uid: u32, ll: &Lastlogx) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(LASTLOGX)?;
    f.seek(SeekFrom::Start(uid as u64 * SIZE))?;
    // SAFETY: as read().
    let buf: [u8; SIZE as usize] = unsafe { std::mem::transmute(*ll) };
    f.write_all(&buf)
}

/// `ctime(3)` without the year, as the BSDs print a last login.
fn when(t: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // SAFETY: localtime_r into a local.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!(
        "{} {} {:2} {:02}:{:02}:{:02}",
        DAYS[tm.tm_wday as usize % 7],
        MONTHS[tm.tm_mon as usize % 12],
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

unsafe extern "C" fn open_session(pamh: *mut PamHandle, flags: c_int, _: c_int, _: *const *const c_char) -> c_int {
    let Ok(user) = super::user(pamh) else { return PAM_SERVICE_ERR };
    let Some(entry) = pwd::lookup(&user) else { return PAM_USER_UNKNOWN };
    if flags & PAM_SILENT == 0
        && let Some(last) = read(entry.uid)
    {
        let host = field(&last.host);
        let text = if host.is_empty() {
            format!("Last login: {} on {}", when(last.tv_sec), field(&last.line))
        } else {
            format!("Last login: {} from {host}", when(last.tv_sec))
        };
        info(pamh, &text);
    }
    let tty = get_item_str(pamh, PAM_TTY).unwrap_or_default();
    let mut ll = Lastlogx { tv_sec: super::now(), tv_usec: 0, line: [0; 32], host: [0; 256], ss: [0; 128] };
    set_field(&mut ll.line, tty.strip_prefix("/dev/").unwrap_or(&tty));
    set_field(&mut ll.host, &get_item_str(pamh, PAM_RHOST).unwrap_or_default());
    // A missing /var/log isn't worth refusing the login over.
    let _ = write(entry.uid, &ll);
    PAM_SUCCESS
}

unsafe extern "C" fn close_session(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

pub static MODULE: PamModule = PamModule {
    path: c"pam_lastlog.so".as_ptr(),
    func: [None, None, None, Some(open_session), Some(close_session), None],
    dlh: std::ptr::null_mut(),
};
