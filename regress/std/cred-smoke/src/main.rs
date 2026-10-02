//! Process credentials (`OxideBSD-doc/SUDO.md` §5.1), checked end to end by
//! `tests/cred_syscall_smoke.rs`. The kernel starts this as pid 1 (root); it is also seeded as
//! `/usr/tests/cred/cred-smoke`, which the steps below copy and run again in other roles:
//!
//! - `main` (pid 1, root): sets up files, then forks a child that becomes uid 1000 and checks the
//!   `set*id` rules, group permission, `kill` permission, a set-user-ID-root copy of this program
//!   (`suid`), a set-user-ID script (`script`), the clearing of set-ID bits by a write and by
//!   `chown`, a set-user-ID program on a `nosuid` mount, and `/proc/self/status`. Reports
//!   through `SYS_TEST_EXIT`.

use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

const SYS_TEST_EXIT: libc::c_long = 9999;
const SELF: &str = "/usr/tests/cred/cred-smoke";
const SUID: &str = "/tmp/cred-suid";
const SCRIPT: &str = "/tmp/cred-script";
const ROOT_ONLY: &str = "/tmp/cred-root-only";
const GROUP_FILE: &str = "/tmp/cred-group-20";
const USER_SUID: &str = "/tmp/cred-user-suid";
const USER: u32 = 1000;
const NOSUID_DIR: &str = "/tmp/cred-nosuid";
const NOSUID_PROG: &str = "/tmp/cred-nosuid/suid";
/// `nmount(2)`, OxideBSD's number.
const SYS_NMOUNT: libc::c_long = 584;

fn finish(pass: bool, why: &str) -> ! {
    println!("cred-smoke: {} {why}", if pass { "PASS" } else { "FAIL" });
    unsafe { libc::syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }) };
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// In a child: report a failure by exit status 1 (the parent prints nothing more useful).
fn check(ok: bool, why: &str) {
    if !ok {
        eprintln!("cred-smoke: FAIL {why}");
        std::process::exit(1);
    }
    println!("cred-smoke: ok: {why}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn res_uid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

fn res_gid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

fn access(path: &str, mode: libc::c_int, flags: libc::c_int) -> bool {
    let p = CString::new(path).unwrap();
    unsafe { libc::faccessat(libc::AT_FDCWD, p.as_ptr(), mode, flags) == 0 }
}

fn mode_of(path: &str) -> u32 {
    std::fs::metadata(path).map(|m| m.mode() & 0o7777).unwrap_or(0)
}

fn chown(path: &str, uid: u32, gid: u32) -> i32 {
    let p = CString::new(path).unwrap();
    if unsafe { libc::chown(p.as_ptr(), uid, gid) } == 0 { 0 } else { errno() }
}

fn copy_self(to: &str, mode: u32, uid: u32, gid: u32) {
    std::fs::copy(SELF, to).unwrap_or_else(|e| finish(false, &format!("copy to {to}: {e}")));
    if chown(to, uid, gid) != 0 {
        finish(false, &format!("chown {to}"));
    }
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Runs `cmd` and returns whether it exited 0.
fn ran_ok(mut cmd: Command) -> bool {
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Mounts a tmpfs on `NOSUID_DIR` with `nosuid`, through `nmount(2)`.
fn mount_nosuid_tmpfs() {
    let pairs = ["fstype", "tmpfs", "fspath", NOSUID_DIR, "nosuid", ""];
    let strings: Vec<CString> = pairs.iter().map(|p| CString::new(*p).unwrap()).collect();
    let iov: Vec<libc::iovec> = strings
        .iter()
        .map(|s| libc::iovec { iov_base: s.as_ptr() as *mut _, iov_len: s.as_bytes_with_nul().len() })
        .collect();
    let r = unsafe { libc::syscall(SYS_NMOUNT, iov.as_ptr(), iov.len() as libc::c_uint, 0) };
    if r != 0 {
        finish(false, &format!("nmount nosuid tmpfs: {}", std::io::Error::last_os_error()));
    }
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if !mounts.lines().any(|l| l.contains(NOSUID_DIR) && l.contains("nosuid")) {
        finish(false, &format!("/proc/mounts doesn't show nosuid: {mounts:?}"));
    }
}

/// `/proc/<pid>/stat`'s start time (field 22, clock ticks since boot).
fn start_time(pid: &str) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let rest = stat.rfind(')').map(|i| &stat[i + 1..]).unwrap_or("");
    // After the command: state is field 3, so field 22 is the 20th word.
    rest.split_whitespace().nth(19).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// SUDO.md §5.2.2 and §5.3: `ttyname`, a real process start time, and Linux's `getrandom` number.
fn sudo_prerequisites() {
    let tty = CString::new("/dev/ttyv0").unwrap();
    let fd = unsafe { libc::open(tty.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        finish(false, "open /dev/ttyv0");
    }
    let mut name = [0u8; 64];
    let r = unsafe { libc::ttyname_r(fd, name.as_mut_ptr().cast(), name.len()) };
    let got = std::ffi::CStr::from_bytes_until_nul(&name).map(|c| c.to_string_lossy().into_owned()).unwrap_or_default();
    if r != 0 || got != "/dev/ttyv0" {
        finish(false, &format!("ttyname_r: {r} {got:?}"));
    }
    println!("cred-smoke: ok: ttyname gives /dev/ttyv0");
    unsafe { libc::close(fd) };

    let mut buf = [0u8; 16];
    let n = unsafe { libc::syscall(318, buf.as_mut_ptr(), buf.len(), 0) };
    if n != 16 || buf == [0u8; 16] {
        finish(false, &format!("getrandom through 318 returned {n}"));
    }
    println!("cred-smoke: ok: getrandom at Linux's number");

    std::thread::sleep(std::time::Duration::from_millis(50));
    let parent = start_time("self");
    match unsafe { libc::fork() } {
        0 => {
            let me = start_time("self");
            std::process::exit(if me > 0 && me >= parent { 0 } else { 1 });
        }
        child => {
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                finish(false, &format!("/proc start time: parent {parent}, child not later or zero"));
            }
        }
    }
    println!("cred-smoke: ok: /proc/<pid>/stat start time");
}

/// The unprivileged child (uid 1000, gid 1000, groups {20}).
fn as_user() -> ! {
    unsafe {
        let groups = [20u32];
        check(libc::setgroups(1, groups.as_ptr()) == 0, "root may setgroups");
        check(libc::setresgid(USER, USER, USER) == 0, "root may setresgid");
        check(libc::setresuid(USER, USER, USER) == 0, "root may setresuid");
    }
    check(res_uid() == (USER, USER, USER), "getresuid after dropping root");
    check(res_gid() == (USER, USER, USER), "getresgid after dropping root");
    let mut list = [0u32; 8];
    let n = unsafe { libc::getgroups(8, list.as_mut_ptr()) };
    check(n == 1 && list[0] == 20, "getgroups returns the supplementary group");
    check(unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 1, "getgroups(0) counts");

    // No way back to root.
    check(unsafe { libc::setuid(0) } == -1 && errno() == libc::EPERM, "setuid(0) without privilege is EPERM");
    check(unsafe { libc::seteuid(0) } == -1 && errno() == libc::EPERM, "seteuid(0) without privilege is EPERM");
    check(unsafe { libc::setresuid(0, 0, 0) } == -1 && errno() == libc::EPERM, "setresuid(0) is EPERM");
    check(unsafe { libc::setgroups(0, std::ptr::null()) } == -1 && errno() == libc::EPERM, "setgroups needs privilege");
    check(unsafe { libc::setuid(USER) } == 0, "setuid to one's own uid");
    check(unsafe { libc::kill(1, 0) } == -1 && errno() == libc::EPERM, "kill of a root process is EPERM");

    // Files: group permission through a supplementary group; access(2) uses the real IDs.
    check(std::fs::read(GROUP_FILE).is_ok(), "read through supplementary group 20");
    check(std::fs::read(ROOT_ONLY).is_err(), "a root-only file stays closed");

    // chown by an owner: the group to one it is in, never the owner; set-ID bits cleared.
    check(chown(USER_SUID, u32::MAX, 0) == libc::EPERM, "owner can't chown to a group it isn't in");
    check(chown(USER_SUID, 0, u32::MAX) == libc::EPERM, "owner can't give the file away");
    check(mode_of(USER_SUID) & 0o4000 != 0, "set-user-ID bit before the write");
    std::fs::OpenOptions::new().append(true).open(USER_SUID).and_then(|mut f| {
        use std::io::Write;
        f.write_all(b"x")
    }).unwrap_or_else(|e| { check(false, &format!("write {USER_SUID}: {e}")); });
    check(mode_of(USER_SUID) & 0o6000 == 0, "a write by non-root clears the set-ID bits");
    std::fs::set_permissions(USER_SUID, std::fs::Permissions::from_mode(0o6755)).unwrap();
    check(chown(USER_SUID, u32::MAX, 20) == 0, "owner may chown to a group it is in");
    check(mode_of(USER_SUID) & 0o6000 == 0, "chown by non-root clears the set-ID bits");

    // /proc/self/status.
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    check(status.contains("Uid:\t1000\t1000\t1000\t1000"), "/proc/self/status Uid line");
    check(status.contains("Groups: 20"), "/proc/self/status Groups line");

    // A set-user-ID-root program, and a set-user-ID script.
    let mut suid = Command::new(SUID);
    suid.arg0(SUID).arg("suid");
    check(ran_ok(suid), "set-user-ID-root program (see its checks above)");
    let mut script = Command::new(SCRIPT);
    script.arg0(SCRIPT);
    check(ran_ok(script), "set-user-ID script runs without privilege");
    let mut nosuid = Command::new(NOSUID_PROG);
    nosuid.arg0(NOSUID_PROG).arg("nosuid");
    check(ran_ok(nosuid), "set-user-ID program on a nosuid mount runs without privilege");
    std::process::exit(0);
}

/// Run from `as_user` through the set-user-ID-root copy.
fn suid() -> ! {
    check(res_uid() == (USER, 0, 0), "set-user-ID exec: real 1000, effective and saved 0");
    check(unsafe { libc::getauxval(libc::AT_SECURE) } == 1, "AT_SECURE is 1");
    check(!access(ROOT_ONLY, libc::R_OK, 0), "access(2) uses the real uid");
    check(access(ROOT_ONLY, libc::R_OK, libc::AT_EACCESS), "faccessat(AT_EACCESS) uses the effective uid");
    check(std::fs::read(ROOT_ONLY).is_ok(), "open uses the effective uid");
    check(unsafe { libc::seteuid(USER) } == 0, "drop to the real uid");
    check(res_uid() == (USER, USER, 0), "seteuid keeps the saved uid");
    check(unsafe { libc::seteuid(0) } == 0, "regain root from the saved uid");
    check(unsafe { libc::setreuid(u32::MAX, USER) } == 0, "setreuid(-1, 1000)");
    check(res_uid() == (USER, USER, 0), "setreuid to the real uid keeps the saved uid (FreeBSD)");
    check(unsafe { libc::seteuid(0) } == 0, "so root can still be regained");
    check(unsafe { libc::setreuid(USER, USER) } == 0, "setreuid(1000, 1000)");
    check(res_uid() == (USER, USER, USER), "setting the real uid sets the saved uid too");
    check(unsafe { libc::seteuid(0) } == -1, "root can't be regained after that");
    std::process::exit(0);
}

/// Run as `cred-smoke script <path>` by the set-user-ID script's `#!` line.
fn script() -> ! {
    check(res_uid() == (USER, USER, USER), "the script's set-user-ID bit is ignored");
    check(unsafe { libc::getauxval(libc::AT_SECURE) } == 0, "AT_SECURE is 0 for a plain exec");
    std::process::exit(0);
}

fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    match role.as_str() {
        "suid" => suid(),
        "script" => script(),
        "nosuid" => {
            check(res_uid() == (USER, USER, USER), "nosuid: the set-user-ID bit is ignored");
            std::process::exit(0);
        }
        _ => {}
    }
    if std::process::id() != 1 {
        finish(false, "not started as pid 1");
    }
    if res_uid() != (0, 0, 0) || res_gid() != (0, 0, 0) {
        finish(false, "pid 1 isn't root");
    }
    let _ = std::fs::create_dir_all("/tmp");
    copy_self(SUID, 0o4755, 0, 0);
    copy_self(USER_SUID, 0o4755, USER, USER);
    std::fs::write(SCRIPT, format!("#!{SELF} script\n")).unwrap();
    if chown(SCRIPT, 0, 0) != 0 {
        finish(false, "chown script");
    }
    std::fs::set_permissions(SCRIPT, std::fs::Permissions::from_mode(0o4755)).unwrap();
    std::fs::write(ROOT_ONLY, b"secret").unwrap();
    std::fs::set_permissions(ROOT_ONLY, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(GROUP_FILE, b"group").unwrap();
    if chown(GROUP_FILE, 0, 20) != 0 {
        finish(false, "chown group file");
    }
    std::fs::set_permissions(GROUP_FILE, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::create_dir_all(NOSUID_DIR).unwrap();
    mount_nosuid_tmpfs();
    copy_self(NOSUID_PROG, 0o4755, 0, 0);
    if mode_of(SUID) != 0o4755 {
        finish(false, &format!("chmod 4755 gave {:o}", mode_of(SUID)));
    }

    sudo_prerequisites();

    match unsafe { libc::fork() } {
        0 => as_user(),
        -1 => finish(false, "fork"),
        child => {
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            let ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            finish(ok, "credentials, set-user-ID exec, access(2), chown and groups");
        }
    }
}
