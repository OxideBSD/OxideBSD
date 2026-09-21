//! Migrated onto the real PIE/ASLR loading model (see `sys/process/aslr.rs`'s own doc comment) --
//! deliberately no `-T<linker.ld>` at all, letting `rust-lld`'s completely default link script
//! run (see `regress/pie-aslr-smoke/build.rs`'s identical doc comment for why this is required,
//! not just simpler: it correctly places the ELF header/program-header table inside the first
//! `PT_LOAD` segment, unlike a custom minimal script). No more fixed load-address bookkeeping --
//! the real runtime address now comes from a kernel-chosen, per-`execve()`-randomized bias.

fn main() {
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
}
