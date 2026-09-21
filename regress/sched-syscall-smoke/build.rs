//! Passes the custom linker script as a link arg for just this crate's own binary -- same
//! reasoning `regress/clock-syscall-smoke/build.rs` already documents in full.

fn main() {
    let linker_script = concat!(env!("CARGO_MANIFEST_DIR"), "/linker.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
