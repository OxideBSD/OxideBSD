//! OxideBSD's PAM modules (LOGIN.md §6.3), and the table OpenPAM finds them in
//! (`external/bsd/openpam/lib/libpam/openpam_static.c`).

use std::ffi::{CStr, c_char, c_int, c_void};

use crate::PamHandle;

mod lastlog;
mod nologin;
mod permit;
mod securetty;
mod unix;

pub type PamFunc = Option<unsafe extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int>;

/// OpenPAM's `struct pam_module`: the name `pam.d` policies use (`pam_unix.so`), and its
/// functions in the order authenticate, setcred, acct_mgmt, open_session, close_session,
/// chauthtok.
#[repr(C)]
pub struct PamModule {
    pub path: *const c_char,
    pub func: [PamFunc; 6],
    pub dlh: *mut c_void,
}

// SAFETY: read-only after link time; OpenPAM never writes a static module (`dlh` stays NULL).
unsafe impl Sync for PamModule {}

#[repr(transparent)]
pub struct Table(pub [*const PamModule; 7]);

// SAFETY: as PamModule.
unsafe impl Sync for Table {}

#[unsafe(no_mangle)]
pub static openpam_static_modules: Table = Table([
    &unix::MODULE,
    &nologin::MODULE,
    &securetty::MODULE,
    &lastlog::MODULE,
    &permit::PERMIT,
    &permit::DENY,
    std::ptr::null(),
]);

/// Whether the policy line gave this module the option `name`.
pub(crate) fn has_option(argc: c_int, argv: *const *const c_char, name: &str) -> bool {
    (0..argc as usize).any(|i| {
        // SAFETY: OpenPAM passes argc valid C strings.
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) };
        arg.to_bytes() == name.as_bytes()
    })
}

/// The user being authenticated (`pam_get_user`, prompting if unknown).
pub(crate) fn user(pamh: *mut PamHandle) -> Result<String, c_int> {
    let mut p: *const c_char = std::ptr::null();
    // SAFETY: pam_get_user stores a C string owned by the handle.
    let r = unsafe { crate::pam_get_user(pamh, &mut p, std::ptr::null()) };
    if r != crate::PAM_SUCCESS || p.is_null() {
        return Err(if r == crate::PAM_SUCCESS { crate::PAM_SERVICE_ERR } else { r });
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// `pam_get_authtok` for `item`, as a `String`.
pub(crate) fn authtok(pamh: *mut PamHandle, item: c_int) -> Result<String, c_int> {
    let mut p: *const c_char = std::ptr::null();
    // SAFETY: as user().
    let r = unsafe { crate::pam_get_authtok(pamh, item, &mut p, std::ptr::null()) };
    if r != crate::PAM_SUCCESS || p.is_null() {
        return Err(if r == crate::PAM_SUCCESS { crate::PAM_AUTH_ERR } else { r });
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

pub(crate) fn now() -> i64 {
    // SAFETY: time(NULL).
    unsafe { libc::time(std::ptr::null_mut()) }
}
