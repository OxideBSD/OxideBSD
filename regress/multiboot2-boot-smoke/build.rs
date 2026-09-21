//! Passes the Multiboot2 trampoline's own dedicated linker script as a link arg for just this
//! crate's own binary -- same rationale as every `regress/*` crate's own `build.rs` (see e.g.
//! `regress/fork-exec-smoke/build.rs`): a `RUSTFLAGS` override would apply uniformly to every
//! unit in the build (including the `-Z build-std`-compiled core/alloc/compiler_builtins), forcing
//! them to rebuild every time this crate and the kernel crate are built back to back with
//! different flags.
//!
//! Unlike a `regress/*` crate's own same-directory `linker.ld`, this one lives at the repo root
//! (`x86_64-oxidebsd-multiboot2.ld`) -- it's a second, standalone sibling of the kernel's own
//! `x86_64-oxidebsd.ld`, not something scoped to this one binary.

use std::path::Path;

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let linker_script = Path::new(manifest_dir)
        .join("../../x86_64-oxidebsd-multiboot2.ld")
        .canonicalize()
        .expect("x86_64-oxidebsd-multiboot2.ld not found at repo root");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    println!("cargo:rerun-if-changed={}", linker_script.display());
}
