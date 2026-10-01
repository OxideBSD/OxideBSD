//! OpenPAM for Rust programs, and OxideBSD's PAM modules (LOGIN.md §6 in OxideBSD-doc).
//!
//! OxideBSD has no `dlopen`, so modules are linked into the programs that use them. OpenPAM finds
//! them in `openpam_static_modules[]`, which this crate defines; a program calls [`link`] once so
//! the linker keeps the table.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

pub mod modules;

pub enum PamHandle {}

#[repr(C)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

#[repr(C)]
pub struct PamConv {
    pub conv: Option<unsafe extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int>,
    pub appdata_ptr: *mut c_void,
}

// SAFETY: OpenPAM only reads a conversation structure; a program may keep one in a static.
unsafe impl Sync for PamConv {}

// pam_constants.h
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SERVICE_ERR: c_int = 3;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_PERM_DENIED: c_int = 7;
pub const PAM_MAXTRIES: c_int = 8;
pub const PAM_AUTH_ERR: c_int = 9;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 10;
pub const PAM_USER_UNKNOWN: c_int = 13;
pub const PAM_ACCT_EXPIRED: c_int = 17;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_AUTHTOK_ERR: c_int = 20;
pub const PAM_IGNORE: c_int = 25;

pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

pub const PAM_SILENT: c_int = i32::MIN;
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;
pub const PAM_ESTABLISH_CRED: c_int = 0x1;
pub const PAM_DELETE_CRED: c_int = 0x2;
pub const PAM_PRELIM_CHECK: c_int = 0x1;
pub const PAM_UPDATE_AUTHTOK: c_int = 0x2;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x4;

pub const PAM_SERVICE: c_int = 1;
pub const PAM_USER: c_int = 2;
pub const PAM_TTY: c_int = 3;
pub const PAM_RHOST: c_int = 4;
pub const PAM_CONV: c_int = 5;
pub const PAM_AUTHTOK: c_int = 6;
pub const PAM_OLDAUTHTOK: c_int = 7;

#[link(name = "pam", kind = "static")]
unsafe extern "C" {
    pub fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, pamh: *mut *mut PamHandle) -> c_int;
    pub fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    pub fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_setcred(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_open_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_close_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_chauthtok(pamh: *mut PamHandle, flags: c_int) -> c_int;
    pub fn pam_get_item(pamh: *const PamHandle, item: c_int, value: *mut *const c_void) -> c_int;
    pub fn pam_set_item(pamh: *mut PamHandle, item: c_int, value: *const c_void) -> c_int;
    pub fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    pub fn pam_get_authtok(pamh: *mut PamHandle, item: c_int, authtok: *mut *const c_char, prompt: *const c_char) -> c_int;
    pub fn pam_strerror(pamh: *const PamHandle, error: c_int) -> *const c_char;
    pub fn pam_getenvlist(pamh: *mut PamHandle) -> *mut *mut c_char;
    pub fn pam_info(pamh: *const PamHandle, fmt: *const c_char, ...) -> c_int;
    pub fn pam_error(pamh: *const PamHandle, fmt: *const c_char, ...) -> c_int;
    /// OpenPAM's terminal conversation function.
    pub fn openpam_ttyconv(n: c_int, msg: *mut *const PamMessage, resp: *mut *mut PamResponse, data: *mut c_void) -> c_int;
}

unsafe extern "C" {
    pub fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

/// A conversation for programs with no one to ask, such as a daemon checking an account: every
/// prompt fails (OpenPAM's `openpam_nullconv`).
pub unsafe extern "C" fn nullconv(_n: c_int, _msg: *mut *const PamMessage, _resp: *mut *mut PamResponse, _data: *mut c_void) -> c_int {
    PAM_CONV_ERR
}

/// Keeps the module table in the program: a program using PAM calls this once.
pub fn link() {
    std::hint::black_box(&modules::openpam_static_modules);
}

/// `pam_strerror` as a `String`.
pub fn strerror(pamh: *const PamHandle, error: c_int) -> String {
    // SAFETY: pam_strerror returns a static string.
    unsafe { CStr::from_ptr(pam_strerror(pamh, error)) }.to_string_lossy().into_owned()
}

/// A string item (`PAM_USER`, `PAM_TTY`, `PAM_RHOST`...), if set.
pub fn get_item_str(pamh: *const PamHandle, item: c_int) -> Option<String> {
    let mut p: *const c_void = std::ptr::null();
    // SAFETY: OpenPAM stores these items as C strings.
    if unsafe { pam_get_item(pamh, item, &mut p) } != PAM_SUCCESS || p.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(p as *const c_char) }.to_string_lossy().into_owned())
}

/// Shows `text` through the conversation function.
pub fn info(pamh: *const PamHandle, text: &str) {
    if let Ok(t) = CString::new(text) {
        // SAFETY: a "%s" format with one C string argument.
        unsafe { pam_info(pamh, c"%s".as_ptr(), t.as_ptr()) };
    }
}

pub fn error(pamh: *const PamHandle, text: &str) {
    if let Ok(t) = CString::new(text) {
        // SAFETY: as info.
        unsafe { pam_error(pamh, c"%s".as_ptr(), t.as_ptr()) };
    }
}

/// `crypt(3)`: whether `password` hashes to `hash`.
pub fn password_matches(password: &str, hash: &str) -> bool {
    let (Ok(key), Ok(salt)) = (CString::new(password), CString::new(hash)) else { return false };
    // SAFETY: crypt returns a static buffer or NULL.
    let out = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    !out.is_null() && unsafe { CStr::from_ptr(out) }.to_bytes() == hash.as_bytes()
}

/// A new SHA-512 (`$6$`) `crypt(3)` hash of `password`, with a random salt.
pub fn hash_password(password: &str) -> Option<String> {
    const SALT_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut raw = [0u8; 16];
    use std::io::Read;
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut raw).ok()?;
    let salt: String = raw.iter().map(|b| SALT_CHARS[*b as usize % SALT_CHARS.len()] as char).collect();
    let (key, salt) = (CString::new(password).ok()?, CString::new(format!("$6${salt}$")).ok()?);
    // SAFETY: as password_matches.
    let out = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    (!out.is_null()).then(|| unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned())
}
