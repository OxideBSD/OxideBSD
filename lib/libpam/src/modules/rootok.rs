//! `pam_rootok`: authentication succeeds when the caller's real user ID is root, so root's
//! `su(1)` asks for no password (FreeBSD's `pam_rootok(8)`, first in `/etc/pam.d/su`). Anyone
//! else fails, and the policy goes on to its next module.

use std::ffi::{c_char, c_int};

use super::PamModule;
use crate::{PAM_AUTH_ERR, PAM_SUCCESS, PamHandle};

unsafe extern "C" fn authenticate(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    // SAFETY: getuid(2).
    if unsafe { libc::getuid() } == 0 { PAM_SUCCESS } else { PAM_AUTH_ERR }
}

unsafe extern "C" fn setcred(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

pub static MODULE: PamModule = PamModule {
    path: c"pam_rootok.so".as_ptr(),
    func: [Some(authenticate), Some(setcred), None, None, None, None],
    dlh: std::ptr::null_mut(),
};
