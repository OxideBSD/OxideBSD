//! Points the linker at ncurses' `libncursesw.a` (`#[link(name = "ncursesw")]` in `src/curses.rs`).
//! The root `build.rs` builds it with musl and passes its directory as `OXIDEBSD_NCURSES_DIR`; a
//! host build that sets nothing links the host's.

fn main() {
    println!("cargo:rerun-if-env-changed=OXIDEBSD_NCURSES_DIR");
    if let Ok(dir) = std::env::var("OXIDEBSD_NCURSES_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        // cargo doesn't otherwise notice a rebuilt archive.
        println!("cargo:rerun-if-changed={dir}/libncursesw.a");
    }
}
