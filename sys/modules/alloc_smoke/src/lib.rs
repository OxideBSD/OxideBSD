//! Test-only module for `tests/kmod_alloc_syscall_smoke.rs`: uses `alloc` and `core::fmt` from a
//! system call handler, through `lib/libkern-mod` (VFS.md §3.1). Never loaded at boot.
//!
//! One test system call, `SYS_ALLOC_SMOKE` (9995), with an operation in its first argument:
//!
//! - `OP_FILL`: builds trait objects, a growing `Vec`, a `BTreeMap` and a `format!`ed string, keeps
//!   them in `HELD`, and returns a checksum of them the driver compares with its own.
//! - `OP_DROP`: frees everything `HELD` holds; returns 0.
//! - `OP_HUGE`: asks `try_reserve` for far more than any heap holds and returns 0 if it failed
//!   cleanly (the null path, no panic), 1 if it somehow succeeded.
#![no_std]

extern crate alloc;
use kern_mod as _;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
}

const SYS_ALLOC_SMOKE: u64 = 9995;
const OP_FILL: u64 = 1;
const OP_DROP: u64 = 2;
const OP_HUGE: u64 = 3;
const EINVAL: i64 = 22;

trait Shape {
    fn area(&self) -> u64;
}

struct Square(u64);
struct Rect(u64, u64);

impl Shape for Square {
    fn area(&self) -> u64 {
        self.0 * self.0
    }
}

impl Shape for Rect {
    fn area(&self) -> u64 {
        self.0 * self.1
    }
}

struct Held {
    shapes: Vec<Box<dyn Shape>>,
    map: BTreeMap<u64, Vec<u8>>,
    text: String,
}

/// What `OP_FILL` built, until `OP_DROP`. One system call at a time (interrupts are masked for a
/// whole call), so a plain `static mut` is enough.
static mut HELD: Option<Held> = None;

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

/// Fills `HELD` and returns sum of areas + sum of map value lengths + the text's length. The
/// driver computes the same from the same inputs: areas 1..=64 squares and 1x2..64x65 rects, map
/// values of length 0..256, and the text below.
fn fill(seed: u64) -> i64 {
    let mut shapes: Vec<Box<dyn Shape>> = Vec::new();
    for n in 1..=64 {
        shapes.push(Box::new(Square(n)));
        shapes.push(Box::new(Rect(n, n + 1)));
    }
    let mut map = BTreeMap::new();
    for n in 0..256u64 {
        map.insert(n, alloc::vec![n as u8; n as usize]);
    }
    let text = alloc::format!("alloc_smoke seed={seed:#x} shapes={} keys={:?}\n", shapes.len(), (0u8, "z"));
    log(&text);
    let sum = shapes.iter().map(|s| s.area()).sum::<u64>()
        + map.values().map(|v| v.len() as u64).sum::<u64>()
        + text.len() as u64;
    unsafe { *core::ptr::addr_of_mut!(HELD) = Some(Held { shapes, map, text }) };
    sum as i64
}

extern "C" fn handle_alloc_smoke(op: u64, seed: u64, _a2: u64, _a3: u64) -> i64 {
    match op {
        OP_FILL => fill(seed),
        OP_DROP => {
            unsafe { *core::ptr::addr_of_mut!(HELD) = None };
            0
        }
        OP_HUGE => {
            let mut v: Vec<u8> = Vec::new();
            match v.try_reserve(1 << 40) {
                Ok(()) => 1,
                Err(_) => 0,
            }
        }
        _ => -EINVAL,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_ALLOC_SMOKE, handle_alloc_smoke);
    }
    // An allocation in module_init too, freed before it returns.
    let message = alloc::format!("[module] alloc_smoke: module_init running (registered {SYS_ALLOC_SMOKE})\n");
    log(&message);
    0
}
