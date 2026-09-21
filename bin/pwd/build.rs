//! Real PIE/ASLR loading model (see `sys/process/aslr.rs`'s own doc comment) -- deliberately no
//! `-T<linker.ld>` at all. See `regress/pie-aslr-smoke/build.rs`'s identical doc comment for why
//! letting `rust-lld`'s completely default link script run is required, not just simpler.

fn main() {
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
}
