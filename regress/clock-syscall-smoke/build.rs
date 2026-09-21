//! Passes the custom linker script as a link arg for just this crate's own binary -- same reasoning
//! `regress/posix-timer-syscall-smoke/build.rs` already documents in full (RUSTFLAGS would apply
//! uniformly to every unit in the build, including the `-Z build-std`-compiled core/alloc/
//! compiler_builtins, forcing an unwanted rebuild every time this crate and the kernel crate are
//! built back to back with different flags).

fn main() {
    let linker_script = concat!(env!("CARGO_MANIFEST_DIR"), "/linker.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
