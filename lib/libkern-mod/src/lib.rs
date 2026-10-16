//! Kernel module support: link this crate and a module can use `alloc` (`Box`, `Vec`,
//! `BTreeMap`, `format!`) at any time it runs, as kernel code does (VFS.md §3.1).
//!
//! A module depends on it and names it once so the linker keeps it:
//!
//! ```ignore
//! extern crate alloc;
//! use kern_mod as _;
//! ```
//!
//! The global allocator below calls the kernel's `oxidebsd_kmalloc`/`oxidebsd_kfree`
//! (`sys/module.rs`), which allocate from the kernel heap and charge the module: the loader writes
//! the module's charge id into `KERN_MOD_ID` before `module_init` runs, and the bytes it holds show
//! as `kern.module.<name>.alloc`.
//!
//! An allocation the heap can't satisfy returns null. Through an infallible API (`Box::new`,
//! `Vec::push`) that ends in the kernel's `module_alloc_error`, fatal to the call like any module
//! panic (oxfs's reboots), so code that can fail cleanly uses `try_reserve`, `Box::try_new` and
//! friends and returns `ENOMEM`. The heap is an eighth of RAM: 8 MiB on a 64 MB machine.
#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" {
    fn oxidebsd_kmalloc(size: u64, align: u64, id: u32) -> *mut u8;
    fn oxidebsd_kfree(ptr: *mut u8, size: u64, align: u64, id: u32);
}

/// This module's charge id, written by the kernel's loader (`sys/module.rs`, `CHARGE_ID_SYMBOL`)
/// after relocation. 0 until then, which charges no module.
#[unsafe(export_name = "kern_mod_id")]
pub static KERN_MOD_ID: AtomicU32 = AtomicU32::new(0);

struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { oxidebsd_kmalloc(layout.size() as u64, layout.align() as u64, KERN_MOD_ID.load(Ordering::Relaxed)) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            oxidebsd_kfree(ptr, layout.size() as u64, layout.align() as u64, KERN_MOD_ID.load(Ordering::Relaxed))
        }
    }
}

#[global_allocator]
static HEAP: KernelHeap = KernelHeap;
