//! `pam_securetty(8)`: refuses root on a terminal `/etc/ttys` doesn't mark `secure` (account
//! management). Other users, and sessions with no terminal, pass.

use std::ffi::{c_char, c_int};

use super::PamModule;
use crate::{PAM_AUTH_ERR, PAM_SUCCESS, PAM_TTY, PamHandle};

unsafe extern "C" fn acct_mgmt(pamh: *mut PamHandle, _flags: c_int, _: c_int, _: *const *const c_char) -> c_int {
    let Ok(user) = super::user(pamh) else { return PAM_AUTH_ERR };
    if !pwd::lookup(&user).is_some_and(|e| e.uid == 0) {
        return PAM_SUCCESS;
    }
    let Some(tty) = crate::get_item_str(pamh, PAM_TTY) else { return PAM_SUCCESS };
    let name = tty.strip_prefix("/dev/").unwrap_or(&tty);
    if ttyent::is_secure(name) { PAM_SUCCESS } else { PAM_AUTH_ERR }
}

pub static MODULE: PamModule = PamModule {
    path: c"pam_securetty.so".as_ptr(),
    func: [None, None, Some(acct_mgmt), None, None, None],
    dlh: std::ptr::null_mut(),
};
