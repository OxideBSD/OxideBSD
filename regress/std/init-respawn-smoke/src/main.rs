//! The kernel's supervision of pid 1 (INIT.md §9), driven by `tests/init_respawn_smoke.rs`,
//! which registers this program as both init and the emergency program. Each start reads
//! `/proc/initdeaths` to see how far along it is:
//!
//! 1. no deaths: user-space signals without a handler (SIGTERM, SIGKILL, even to itself) must
//!    not kill pid 1; then it exits with status 7;
//! 2. one death, `exit 7`: it crashes (SIGSEGV at address 0), which must still kill it;
//! 3. two deaths, the second a SIGSEGV fault: exits again -- the third death in 30 seconds;
//! 4. run as the emergency program: all three deaths are listed. Pass.

const SYS_TEST_EXIT: libc::c_long = 9999;

fn finish(pass: bool, why: &str) -> ! {
    println!("init-respawn-smoke: {} {why}", if pass { "PASS" } else { "FAIL" });
    unsafe { libc::syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }) };
    loop {
        std::hint::spin_loop();
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let deaths = std::fs::read_to_string("/proc/initdeaths").unwrap_or_else(|e| finish(false, &format!("/proc/initdeaths: {e}")));
    let deaths: Vec<Vec<&str>> = deaths.lines().map(|l| l.split_whitespace().collect()).collect();
    println!("init-respawn-smoke: {mode} as pid {}, {} death(s) recorded", std::process::id(), deaths.len());
    if std::process::id() != 1 {
        finish(false, "not running as pid 1");
    }

    if mode == "emergency" {
        let causes: Vec<&str> = deaths.iter().map(|d| d.get(1).copied().unwrap_or("?")).collect();
        if causes != ["exit", "signal", "exit"] {
            finish(false, &format!("emergency saw deaths {causes:?}"));
        }
        finish(true, "three deaths in 30 seconds started the emergency program");
    }

    match deaths.len() {
        0 => {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGKILL, libc::SIGSTOP] {
                if unsafe { libc::kill(1, sig) } != 0 {
                    finish(false, &format!("kill(1, {sig}) failed"));
                }
            }
            // A kill reaches its target by the next return to user space; still here means
            // every one was discarded.
            std::thread::sleep(std::time::Duration::from_millis(100));
            println!("init-respawn-smoke: survived SIGTERM, SIGINT, SIGKILL and SIGSTOP; exiting 7");
            std::process::exit(7);
        }
        1 => {
            if deaths[0][1..] != ["exit", "7"] {
                finish(false, &format!("first death recorded as {:?}", deaths[0]));
            }
            println!("init-respawn-smoke: crashing");
            unsafe { std::ptr::null_mut::<u32>().write_volatile(1) };
            finish(false, "survived a write to address 0");
        }
        2 => {
            let d = &deaths[1];
            if d.get(1..3) != Some(&["signal", "11"][..]) || d.get(3) != Some(&"ip") || d.get(5..7) != Some(&["addr", "0x0"][..]) {
                finish(false, &format!("second death recorded as {d:?}"));
            }
            std::process::exit(9);
        }
        n => finish(false, &format!("started as init after {n} deaths; expected the emergency program")),
    }
}
