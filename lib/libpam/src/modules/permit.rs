//! `pam_permit` and `pam_deny`: every function succeeds, or fails.

use std::ffi::{c_char, c_int};

use super::PamModule;
use crate::{PAM_AUTH_ERR, PAM_SUCCESS, PamHandle};

unsafe extern "C" fn permit(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

unsafe extern "C" fn deny(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_AUTH_ERR
}

pub static PERMIT: PamModule = PamModule { path: c"pam_permit.so".as_ptr(), func: [Some(permit); 6], dlh: std::ptr::null_mut() };
pub static DENY: PamModule = PamModule { path: c"pam_deny.so".as_ptr(), func: [Some(deny); 6], dlh: std::ptr::null_mut() };
