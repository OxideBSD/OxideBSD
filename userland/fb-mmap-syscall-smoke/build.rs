//! Passes the custom linker script as a link arg for just this crate's own binary -- see
//! `userland/uid-syscall-smoke/build.rs`'s own doc comment for why RUSTFLAGS isn't used instead.

fn main() {
    let linker_script = concat!(env!("CARGO_MANIFEST_DIR"), "/linker.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
