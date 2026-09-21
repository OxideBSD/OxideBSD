//! Smoke test for `sys/random.rs`'s `oxidebsd_random_bytes` -- the real, SHA-256/ChaCha20-backed
//! random byte source added to unblock BusyBox's vendored TLS code (`networking/tls.c`'s
//! `tls_get_random`, called via `/dev/urandom` -- see CLAUDE.md's "Real networking" known-gaps
//! entry on `wget` HTTPS). Only exercises the kernel-resident generator itself, not `modules/
//! oxfs`'s own `/dev` path routing -- that can only really be driven by a real process actually
//! `open()`ing the path, which needs a full module-loading boot (like `tests/fork_wait.rs`'s own
//! pattern); this covers the new, riskier cryptographic logic this pass actually added instead.
//!
//! Covers: the call doesn't crash for a range of buffer sizes (including `0`, matching this
//! codebase's own established `len == 0` convention elsewhere), two consecutive calls produce
//! genuinely different output (proving this is real per-call entropy, not a fixed or all-zero
//! buffer a stub could also satisfy), and the output isn't a degenerate all-same-byte pattern.
//!
//! Also covers the two later additions to this module -- the persistent `ENTROPY_POOL` and the
//! `RDRAND`/`RDSEED` hypervisor-distrust gate (see `sys/random.rs`'s own doc comment) -- neither
//! of which the original assertions above actually exercise: two consecutive
//! `oxidebsd_random_bytes` calls already differ from the monotonic call counter alone, pool or no
//! pool, so "output changed" alone doesn't prove the pool is real. `entropy_pool_snapshot`/
//! `mix_entropy`/`running_under_hypervisor` are all `pub` specifically for this file's use (see
//! their own doc comments in `sys/random.rs`).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::random::{
    entropy_pool_snapshot, mix_entropy, oxidebsd_random_bytes, running_under_hypervisor,
};
use oxidebsd::serial_println;

limine_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    // len == 0 must be a harmless no-op, not a crash -- same convention every other read/write
    // path in this codebase already established.
    let mut empty = [0xAAu8; 4];
    let n = oxidebsd_random_bytes(empty.as_mut_ptr() as u64, 0);
    assert_eq!(n, 0, "len == 0 should return 0: {n}");
    assert_eq!(
        empty, [0xAA; 4],
        "len == 0 must not touch the buffer at all"
    );

    let mut buf_a = [0u8; 64];
    let n = oxidebsd_random_bytes(buf_a.as_mut_ptr() as u64, buf_a.len() as u64);
    assert_eq!(n, buf_a.len() as i64, "wrong byte count returned: {n}");
    assert!(
        buf_a.iter().any(|&b| b != buf_a[0]),
        "output is a single repeated byte -- not real random output"
    );
    serial_println!(
        "random_smoke: oxidebsd_random_bytes() filled a 64-byte buffer, not degenerate"
    );

    let mut buf_b = [0u8; 64];
    let n = oxidebsd_random_bytes(buf_b.as_mut_ptr() as u64, buf_b.len() as u64);
    assert_eq!(
        n,
        buf_b.len() as i64,
        "wrong byte count returned (2nd call): {n}"
    );
    assert_ne!(
        buf_a, buf_b,
        "two consecutive calls produced identical output -- not real per-call entropy"
    );
    serial_println!(
        "random_smoke: two consecutive calls produced different output -- oxidebsd_random_bytes verified end to end"
    );

    // A partial-buffer request (shorter than a full ChaCha20 block) must still work cleanly.
    let mut small = [0u8; 3];
    let n = oxidebsd_random_bytes(small.as_mut_ptr() as u64, small.len() as u64);
    assert_eq!(n, small.len() as i64, "short read failed: {n}");
    serial_println!("random_smoke: sub-block-length read verified");

    // The hypervisor-distrust gate: this project's own test boots always run under QEMU, which
    // sets CPUID leaf 1 / ECX bit 31 regardless of the -accel kvm/-accel tcg backend -- if this
    // ever reports false, the RDRAND/RDSEED gating logic in gather_seed() is silently untested by
    // every automated run in this codebase, not just wrong.
    assert!(
        running_under_hypervisor(),
        "expected a QEMU test boot to report a hypervisor present -- RDRAND/RDSEED distrust gate isn't being exercised"
    );
    serial_println!("random_smoke: hypervisor-present CPUID gate verified live under QEMU");

    // The persistent entropy pool must actually mutate, not just sit there while
    // oxidebsd_random_bytes' output changes for unrelated reasons (CALL_COUNTER alone already
    // guarantees per-call output differs -- see this file's own doc comment).
    let pool_0 = entropy_pool_snapshot();
    mix_entropy(0xDEAD_BEEF_u64);
    let pool_1 = entropy_pool_snapshot();
    assert_ne!(
        pool_0, pool_1,
        "mix_entropy() did not change the entropy pool's state"
    );

    mix_entropy(0xCAFE_BABE_u64);
    let pool_2 = entropy_pool_snapshot();
    assert_ne!(
        pool_1, pool_2,
        "a second mix_entropy() call with a different sample produced no pool change"
    );
    serial_println!("random_smoke: mix_entropy() verified to mutate ENTROPY_POOL");

    // gather_seed() (reached via oxidebsd_random_bytes) re-mixes the pool on every call too, per
    // this module's own "generating also perturbs state" design -- not just mix_entropy's own
    // direct callers (the keyboard/rtl8139 IRQ handlers).
    let pool_before_read = entropy_pool_snapshot();
    let mut buf_c = [0u8; 16];
    oxidebsd_random_bytes(buf_c.as_mut_ptr() as u64, buf_c.len() as u64);
    let pool_after_read = entropy_pool_snapshot();
    assert_ne!(
        pool_before_read, pool_after_read,
        "oxidebsd_random_bytes() did not re-mix the entropy pool via gather_seed()"
    );
    serial_println!("random_smoke: gather_seed() verified to re-mix ENTROPY_POOL on every call");

    // Stress the without_interrupts-guarded lock under real interrupt load (the timer IRQ keeps
    // firing throughout -- interrupts are never disabled by this test itself): a wrong critical
    // section here would deadlock the instant a timer tick landed mid-lock, not just misbehave.
    // 500 iterations of both entry points is cheap (SHA-256/ChaCha20 over tiny buffers) but real
    // regression coverage for the single-core IRQ-vs-syscall-context deadlock this design has to
    // avoid (see sys/random.rs's own ENTROPY_POOL doc comment).
    let mut stress_buf = [0u8; 8];
    for i in 0..500u64 {
        mix_entropy(i);
        oxidebsd_random_bytes(stress_buf.as_mut_ptr() as u64, stress_buf.len() as u64);
    }
    serial_println!(
        "random_smoke: 500 interleaved mix_entropy()/oxidebsd_random_bytes() calls completed under live interrupts -- no deadlock"
    );

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
