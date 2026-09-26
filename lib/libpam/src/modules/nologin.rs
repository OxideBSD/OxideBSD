//! `pam_nologin(8)`: while `/etc/nologin` exists (`shutdown(8)` creates it), shows it and refuses
//! every user but root (account management).

use std::ffi::{c_char, c_int};

use super::PamModule;
use crate::{PAM_AUTH_ERR, PAM_SUCCESS, PamHandle};

pub const NOLOGIN: &str = "/etc/nologin";

unsafe extern "C" fn acct_mgmt(pamh: *mut PamHandle, _flags: c_int, _: c_int, _: *const *const c_char) -> c_int {
    let Ok(text) = std::fs::read_to_string(NOLOGIN) else { return PAM_SUCCESS };
    let Ok(user) = super::user(pamh) else { return PAM_AUTH_ERR };
    if pwd::lookup(&user).is_some_and(|e| e.uid == 0) {
        return PAM_SUCCESS;
    }
    crate::error(pamh, text.trim_end());
    PAM_AUTH_ERR
}

pub static MODULE: PamModule = PamModule {
    path: c"pam_nologin.so".as_ptr(),
    func: [None, None, Some(acct_mgmt), None, None, None],
    dlh: std::ptr::null_mut(),
};
