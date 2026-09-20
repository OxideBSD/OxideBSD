//! Passes the Multiboot2 trampoline's own dedicated linker script as a link arg for just this
//! crate's own binary -- identical rationale to `smoke/multiboot2-boot-smoke/build.rs` (see that
//! file's own doc comment): a `RUSTFLAGS` override would apply uniformly to every unit in the
//! build (including the `-Z build-std`-compiled core/alloc/compiler_builtins), forcing them to
//! rebuild every time this crate and the kernel crate are built back to back with different flags.
//!
//! Lives at the repo root (`x86_64-oxidebsd-multiboot2.ld`), same standalone sibling of the
//! kernel's own `x86_64-oxidebsd.ld` that `multiboot2-boot-smoke` already shares.

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
