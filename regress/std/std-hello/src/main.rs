//! Phase-0 spike for real Rust `std` on OxideBSD (see the "Rust std target" plan) — proves a
//! genuinely unmodified, prebuilt upstream `std` (the real Tier-1 `x86_64-unknown-linux-musl`
//! target, not a custom `sys/pal/oxidebsd` fork of `rust-lang/rust`) can be statically linked
//! against this project's own patched musl sysroot (`target/musl-sysroot`, built by
//! `build.rs`'s `build_musl_sysroot`) and run correctly against OxideBSD's native syscall ABI.
//!
//! Built directly via `rustc` (see `build.rs`'s `build_std_hello_spike`), not `cargo` — the
//! surrounding workspace's `.cargo/config.toml` targets `x86_64-oxidebsd.json` with
//! `-Z build-std=core,alloc,compiler_builtins`, which must not leak into this build at all: this
//! binary uses the real prebuilt `std` for `x86_64-unknown-linux-musl`, no `-Z build-std` here.
fn main() {
    println!("std-hello: real Rust std running on OxideBSD, via our own musl sysroot");
    std::process::exit(42);
}
