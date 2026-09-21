//! Deliberately no `-T<linker.ld>` at all -- see `build.rs`'s own `build_pie_crate_at` doc
//! comment for why letting `rust-lld`'s completely default link script run (for *this* crate
//! only) is required, not just simpler: it's what places the ELF header/program-header table
//! inside the first `PT_LOAD` segment, which every other `regress/*`'s own minimal custom
//! `linker.ld` deliberately does not do. `-pie` asks for a real `ET_DYN` (a genuine
//! position-independent executable) instead of the implicit fixed-address `ET_EXEC` default;
//! `--no-dynamic-linker` omits `PT_INTERP` entirely -- this is a "static-pie"-shaped binary, no
//! real interpreter needed.

fn main() {
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
}
