//! `pam_unix(8)`: passwords in `/etc/master.passwd` (LOGIN.md §6.3).
//!
//! Options: `nullok` lets an account with an empty password in without one.

use std::ffi::{c_char, c_int};

use super::PamModule;
use crate::*;

unsafe extern "C" fn authenticate(pamh: *mut PamHandle, flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let user = match super::user(pamh) {
        Ok(u) => u,
        Err(e) => return e,
    };
    let entry = pwd::lookup(&user);
    if let Some(e) = &entry
        && e.password.is_empty()
    {
        let allowed = super::has_option(argc, argv, "nullok") && flags & PAM_DISALLOW_NULL_AUTHTOK == 0;
        return if allowed { PAM_SUCCESS } else { PAM_AUTH_ERR };
    }
    // Ask even for an unknown user, so a failure doesn't say whether the account exists.
    let password = match super::authtok(pamh, PAM_AUTHTOK) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match entry {
        Some(e) if !e.locked() && password_matches(&password, &e.password) => PAM_SUCCESS,
        _ => PAM_AUTH_ERR,
    }
}

unsafe extern "C" fn setcred(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

/// Account expiry, and a password past its change time.
unsafe extern "C" fn acct_mgmt(pamh: *mut PamHandle, _flags: c_int, _: c_int, _: *const *const c_char) -> c_int {
    let user = match super::user(pamh) {
        Ok(u) => u,
        Err(e) => return e,
    };
    let Some(e) = pwd::lookup(&user) else { return PAM_USER_UNKNOWN };
    let now = super::now();
    if e.expire != 0 && now >= e.expire {
        error(pamh, "Sorry -- your account has expired.");
        return PAM_ACCT_EXPIRED;
    }
    if e.change != 0 && now >= e.change {
        error(pamh, "Sorry -- your password has expired.");
        return PAM_NEW_AUTHTOK_REQD;
    }
    PAM_SUCCESS
}

/// Changes the password: the preliminary check asks non-root users for the old one, the update
/// asks for the new one twice (OpenPAM prompts again itself) and installs it.
unsafe extern "C" fn chauthtok(pamh: *mut PamHandle, flags: c_int, _: c_int, _: *const *const c_char) -> c_int {
    let user = match super::user(pamh) {
        Ok(u) => u,
        Err(e) => return e,
    };
    let Ok(mut entries) = pwd::read_master() else { return PAM_AUTHTOK_ERR };
    let Some(i) = entries.iter().position(|e| e.name == user) else { return PAM_USER_UNKNOWN };
    if flags & PAM_PRELIM_CHECK != 0 {
        // SAFETY: getuid(2).
        if unsafe { libc::getuid() } == 0 || entries[i].password.is_empty() {
            return PAM_SUCCESS;
        }
        let old = match super::authtok(pamh, PAM_OLDAUTHTOK) {
            Ok(p) => p,
            Err(e) => return e,
        };
        return if password_matches(&old, &entries[i].password) { PAM_SUCCESS } else { PAM_PERM_DENIED };
    }
    if flags & PAM_UPDATE_AUTHTOK == 0 {
        return PAM_SERVICE_ERR;
    }
    let new = match super::authtok(pamh, PAM_AUTHTOK) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let Some(hash) = hash_password(&new) else { return PAM_AUTHTOK_ERR };
    entries[i].password = hash;
    entries[i].change = 0;
    match pwd::install(&entries) {
        Ok(()) => PAM_SUCCESS,
        Err(_) => PAM_AUTHTOK_ERR,
    }
}

pub static MODULE: PamModule = PamModule {
    path: c"pam_unix.so".as_ptr(),
    func: [Some(authenticate), Some(setcred), Some(acct_mgmt), None, None, Some(chauthtok)],
    dlh: std::ptr::null_mut(),
};
