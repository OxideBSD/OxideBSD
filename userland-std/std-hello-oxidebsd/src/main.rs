//! Real Rust `std` on OxideBSD's own real `x86_64-unknown-oxidebsd` target (see
//! `x86_64-unknown-oxidebsd.json` and `third_party/rust`'s `oxidebsd` branch) -- distinct from
//! `userland-std/std-hello`, which deliberately stays on the cheaper `x86_64-unknown-linux-musl`
//! target from the earlier spike. This crate proves the real thing: a binary that genuinely
//! reports `target_os = "oxidebsd"`, not borrowed Linux identity.
//!
//! `#![feature(restricted_std)]` is required for any `-Z build-std` target `std` doesn't
//! recognize as fully supported -- standard for any bespoke target, not oxidebsd-specific.
//!
//! Built via `build.rs`'s `build_std_oxidebsd_userland_crate` -- a real `-Z
//! build-std=std,core,alloc,panic_abort` recompile of `std`/`core`/`alloc` from our own forked
//! `third_party/rust` source every time (no prebuilt `std` exists for a brand-new custom target),
//! using the `RUSTC_WRAPPER`-forced-`--sysroot` mechanism documented on that function.
#![feature(restricted_std)]

fn main() {
    println!(
        "std-hello-oxidebsd: real Rust std on our own x86_64-unknown-oxidebsd target, target_os = {}",
        std::env::consts::OS
    );
    std::process::exit(42);
}
