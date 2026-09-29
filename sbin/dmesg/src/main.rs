//! `dmesg(8)`: prints the kernel message buffer (OxideBSD-doc `SYSLOG.md` §3), FreeBSD's utility.
//!
//! ```text
//! dmesg [-ac]
//! ```
//!
//! Reads `kern.msgbuf` without consuming it (`/dev/klog` is syslogd's). A line carrying a
//! `<N>` priority is shown, without it, only if its facility is the kernel's, unless `-a` shows
//! everything as stored. If the buffer has wrapped, its first line is a fragment and is left out.
//! `-c` empties the buffer (`kern.msgbuf_clear`) after printing it.

use std::io::Write;
use std::process::ExitCode;

#[cfg(target_os = "oxidebsd")]
unsafe extern "C" {
    fn sysctlbyname(name: *const libc::c_char, oldp: *mut u8, oldlenp: *mut usize, newp: *const u8, newlen: usize) -> i32;
}

#[cfg(target_os = "oxidebsd")]
fn sysctl_by_name(name: &str, old: Option<&mut Vec<u8>>, new: Option<&[u8]>) -> std::io::Result<usize> {
    let c = std::ffi::CString::new(name).unwrap();
    let (newp, newlen) = new.map_or((std::ptr::null(), 0), |n| (n.as_ptr(), n.len()));
    let mut len = old.as_ref().map_or(0, |o| o.len());
    let oldp = old.map_or(std::ptr::null_mut(), |o| o.as_mut_ptr());
    // SAFETY: every pointer is valid for the length passed with it.
    if unsafe { sysctlbyname(c.as_ptr(), oldp, &mut len, newp, newlen) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(len)
}

#[cfg(not(target_os = "oxidebsd"))]
fn sysctl_by_name(_name: &str, _old: Option<&mut Vec<u8>>, _new: Option<&[u8]>) -> std::io::Result<usize> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// `kern.msgbuf`, and whether it has wrapped (it's as long as `kern.msgbufsize`).
fn read_msgbuf() -> std::io::Result<(Vec<u8>, bool)> {
    let mut size = vec![0u8; 4];
    sysctl_by_name("kern.msgbufsize", Some(&mut size), None)?;
    let bufsize = i32::from_ne_bytes(size[..4].try_into().unwrap()) as usize;
    loop {
        let len = sysctl_by_name("kern.msgbuf", None, None)?;
        let mut buf = vec![0u8; len + 4096];
        match sysctl_by_name("kern.msgbuf", Some(&mut buf), None) {
            Ok(n) => {
                buf.truncate(n);
                if buf.last() == Some(&0) {
                    buf.pop();
                }
                let wrapped = buf.len() >= bufsize;
                return Ok((buf, wrapped));
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// What `dmesg` prints of `buf`.
fn render(buf: &[u8], wrapped: bool, all: bool) -> Vec<u8> {
    let mut text = buf;
    if wrapped && !all {
        // The oldest line was partly overwritten.
        text = match text.iter().position(|&b| b == b'\n') {
            Some(i) => &text[i + 1..],
            None => &[],
        };
    }
    let mut out = Vec::with_capacity(text.len());
    for line in text.split_inclusive(|&b| b == b'\n') {
        if all {
            out.extend_from_slice(line);
            continue;
        }
        match priority(line) {
            // Facility 0 is the kernel's; other facilities' records aren't shown.
            Some((pri, rest)) if pri >> 3 == 0 => out.extend_from_slice(rest),
            Some(_) => {}
            None => out.extend_from_slice(line),
        }
    }
    out
}

/// A `<N>` prefix: the priority and what follows it.
fn priority(line: &[u8]) -> Option<(u32, &[u8])> {
    let rest = line.strip_prefix(b"<")?;
    let end = rest.iter().position(|&b| b == b'>')?;
    if end == 0 || end > 3 || !rest[..end].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let pri = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
    Some((pri, &rest[end + 1..]))
}

fn main() -> ExitCode {
    let (mut all, mut clear) = (false, false);
    for arg in std::env::args().skip(1) {
        match arg.strip_prefix('-') {
            Some(letters) if !letters.is_empty() => {
                for c in letters.chars() {
                    match c {
                        'a' => all = true,
                        'c' => clear = true,
                        _ => {
                            eprintln!("dmesg: illegal option -- {c}\nusage: dmesg [-ac]");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            _ => {
                eprintln!("usage: dmesg [-ac]");
                return ExitCode::from(1);
            }
        }
    }
    let (buf, wrapped) = match read_msgbuf() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("dmesg: kern.msgbuf: {e}");
            return ExitCode::from(1);
        }
    };
    let mut out = render(&buf, wrapped, all);
    if !out.is_empty() && out.last() != Some(&b'\n') {
        out.push(b'\n');
    }
    let _ = std::io::stdout().write_all(&out);
    if clear
        && let Err(e) = sysctl_by_name("kern.msgbuf_clear", None, Some(&1i32.to_ne_bytes()))
    {
        eprintln!("dmesg: kern.msgbuf_clear: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priorities() {
        let buf = b"plain\n<6>kernel info\n<30>daemon notice\n<x>not a tag\n";
        assert_eq!(render(buf, false, false), b"plain\nkernel info\n<x>not a tag\n");
        assert_eq!(render(buf, false, true), buf.to_vec());
    }

    #[test]
    fn wrapped() {
        assert_eq!(render(b"ment of a line\nwhole\n", true, false), b"whole\n");
        assert_eq!(render(b"ment of a line\nwhole\n", false, false), b"ment of a line\nwhole\n");
    }
}
