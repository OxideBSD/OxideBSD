//! The shared runtime for OxideBSD's native (raw-`SYSCALL`, no musl/libc) `/bin` utilities --
//! `#![no_std]`, freestanding, deliberately named for its real eventual destination
//! (this project's own long-deferred from-scratch `oxlibc` goal) rather than a placeholder name,
//! since it genuinely is that seed, not a throwaway. Today it's a small fraction of a real libc
//! (syscall stubs, a real entry point, `exit()`, filesystem wrappers, a tiny flag scanner) -- grown
//! only as far as the first batch of native utilities (`bin/echo`, `bin/cat`, ...) actually needs.
//!
//! Every consumer is a genuine PIE main binary (see `sys/process/aslr.rs`'s own doc comment) --
//! built via `build.rs`'s `build_pie_crate_at`, never `build_module_crate`/`sys/module.rs`'s
//! dynamic kernel-module loader. Real per-`execve()` ASLR is what actually loads it; this crate
//! must contribute no addresses-as-data (verified per binary by `build.rs`'s
//! `assert_zero_relocations` -- which is why there's no `core::fmt`, no tables of slices, and
//! `-C panic=immediate-abort`, see `build_pie_crate_at`'s own doc comment).
#![no_std]

pub mod args;
pub mod entry;
pub mod exit;
pub mod fs;
pub mod io;
pub mod path;
pub mod syscall;

pub use exit::exit;
pub use syscall::{syscall3, syscall4};
