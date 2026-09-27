//! `passwd(1)`: changes a user's password through PAM's password chain (LOGIN.md §6 in
//! OxideBSD-doc), which `pam_unix` answers by rewriting `/etc/master.passwd` and `/etc/passwd`.
//!
//! ```text
//! passwd [user]
//! ```
//!
//! Without an argument it changes the caller's own password. Only root may name another user;
//! everyone else is first asked for their current password. passwd must run as root to write
//! the account files, so until the kernel honors the set-user-ID bit on exec, only root can use
//! it.

use std::ffi::CString;
use std::process::ExitCode;

static CONV: pam::PamConv = pam::PamConv { conv: Some(pam::openpam_ttyconv), appdata_ptr: std::ptr::null_mut() };

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // SAFETY: getuid(2).
    let uid = unsafe { libc::getuid() };
    let user = match args.as_slice() {
        [] => match pwd::lookup_uid(uid) {
            Some(e) => e.name,
            None => {
                eprintln!("passwd: who are you? (uid {uid} has no account)");
                return ExitCode::FAILURE;
            }
        },
        [name] if !name.starts_with('-') => name.clone(),
        _ => {
            eprintln!("usage: passwd [user]");
            return ExitCode::from(64);
        }
    };
    let Some(entry) = pwd::lookup(&user) else {
        eprintln!("passwd: unknown user {user}");
        return ExitCode::FAILURE;
    };
    if uid != 0 && entry.uid != uid {
        eprintln!("passwd: {user}: permission denied");
        return ExitCode::FAILURE;
    }

    pam::link();
    let Ok(cuser) = CString::new(user.as_str()) else { return ExitCode::FAILURE };
    let mut h = std::ptr::null_mut();
    // SAFETY: CONV lives for the program; OpenPAM copies the strings.
    let r = unsafe { pam::pam_start(c"passwd".as_ptr(), cuser.as_ptr(), &CONV, &mut h) };
    if r != pam::PAM_SUCCESS {
        eprintln!("passwd: pam_start: {}", pam::strerror(h, r));
        return ExitCode::FAILURE;
    }
    println!("Changing local password for {user}");
    let r = unsafe { pam::pam_chauthtok(h, 0) };
    let ok = r == pam::PAM_SUCCESS;
    if !ok {
        eprintln!("passwd: {}", pam::strerror(h, r));
    }
    unsafe { pam::pam_end(h, r) };
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
