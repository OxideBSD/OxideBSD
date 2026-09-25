//! Real Rust `std` on OxideBSD's own real `x86_64-unknown-oxidebsd` target (see
//! `x86_64-unknown-oxidebsd.json` and `external/mit/rust`'s `oxidebsd` branch) -- distinct from
//! `regress/std/std-hello`, which deliberately stays on the cheaper `x86_64-unknown-linux-musl`
//! target from the earlier spike. This crate proves the real thing: a binary that genuinely
//! reports `target_os = "oxidebsd"`, not borrowed Linux identity.
//!
//! No `#![feature(restricted_std)]` here -- `library/std/build.rs` lists `oxidebsd` alongside
//! `linux`/`freebsd`/etc. in its allowlist, so std treats this as a real, fully-supported target
//! rather than one it merely tolerates under an unstable feature gate.
//!
//! Built via `build.rs`'s `build_std_oxidebsd_userland_crate` -- a real `-Z
//! build-std=std,core,alloc,panic_abort,panic_unwind` recompile of `std`/`core`/`alloc` from our own forked
//! `external/mit/rust` source every time (no prebuilt `std` exists for a brand-new custom target),
//! using the `RUSTC_WRAPPER`-forced-`--sysroot` mechanism documented on that function.

//!
//! Also proves `panic=unwind` works (libunwind over musl's `dl_iterate_phdr`): the wrapper expects
//! exit status 42, which is only reached if a caught panic really unwound.
fn main() {
    println!(
        "std-hello-oxidebsd: real Rust std on our own x86_64-unknown-oxidebsd target, target_os = {}",
        std::env::consts::OS
    );
    std::panic::set_hook(Box::new(|_| {})); // the panic below is expected; don't print it
    let unwound = std::panic::catch_unwind(|| panic!("unwind test")).is_err();
    println!("std-hello-oxidebsd: catch_unwind caught a panic: {unwound}");
    std::process::exit(if unwound { 42 } else { 1 });
}
