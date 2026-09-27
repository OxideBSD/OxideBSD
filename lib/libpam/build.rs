//! Points the linker at OpenPAM's `libpam.a` (`#[link(name = "pam")]` in `src/lib.rs`). The root
//! `build.rs` builds it with musl and passes its directory as `OXIDEBSD_LIBPAM_DIR`; a host build
//! that sets nothing links whatever `libpam.a` the host linker finds.

fn main() {
    println!("cargo:rerun-if-env-changed=OXIDEBSD_LIBPAM_DIR");
    if let Ok(dir) = std::env::var("OXIDEBSD_LIBPAM_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        // cargo doesn't otherwise notice a rebuilt archive.
        println!("cargo:rerun-if-changed={dir}/libpam.a");
    }
}
