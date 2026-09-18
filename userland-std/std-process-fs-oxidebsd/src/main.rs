//! v0.3.0's "first real `std` consumer" proof (see `OxideBSD-doc/ROADMAP.md`'s v0.3.0 scope:
//! "only what a first real consumer needs -- process spawn/wait, signals, stdio, basic fs"):
//! distinct from `std-hello-oxidebsd`, which only proves target identity (`println!` +
//! `process::exit`). This crate exercises real `std` API surface a genuine program would use --
//! `std::fs` and `std::process::Command` driving their own internal `fork`+`execve`+`waitpid`
//! through `sys::pal::unix`, not just the runtime-startup/shutdown path.
//!
//! No `#![feature(restricted_std)]` -- same real, fully-supported target as `std-hello-oxidebsd`.

use std::process::Command;

const TMP_PATH: &str = "/tmp/std_process_fs_oxidebsd_smoke.txt";
const CONTENTS: &str = "hello from real std on oxidebsd\n";

fn main() {
    // Real basic fs: write, read back, remove.
    std::fs::write(TMP_PATH, CONTENTS).expect("std::fs::write failed");
    let read_back = std::fs::read_to_string(TMP_PATH).expect("std::fs::read_to_string failed");
    assert_eq!(read_back, CONTENTS, "file contents did not round-trip");
    std::fs::remove_file(TMP_PATH).expect("std::fs::remove_file failed");

    // Real process spawn/wait: std::process::Command driving its own fork+execve+waitpid
    // (sys::pal::unix::process), not this crate's own runtime-startup fork the kernel already
    // drove to get here.
    let status = Command::new("/bin/true")
        .status()
        .expect("failed to spawn /bin/true via std::process::Command");
    assert!(status.success(), "/bin/true did not exit successfully");

    let output = Command::new("/bin/echo")
        .arg("std::process::Command")
        .output()
        .expect("failed to spawn /bin/echo via std::process::Command");
    assert!(output.status.success(), "/bin/echo did not exit successfully");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "std::process::Command\n",
        "captured child stdout did not match"
    );

    // Real stdio.
    println!(
        "std-process-fs-oxidebsd: fs + process::Command + stdio all real, target_os = {}",
        std::env::consts::OS
    );

    std::process::exit(42);
}
