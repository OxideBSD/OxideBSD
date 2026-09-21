//! A real, cryptographically-mixed random byte source backing `/dev/random`/`/dev/urandom`
//! (`sys/modules/oxfs/`'s synthetic `/dev` -- see that module's own `dev_open`). Every call gathers
//! several independent, hard-for-an-outside-observer-to-predict values (the CPU cycle counter,
//! PIT tick count, RTC wall-clock, a monotonic call counter, a stack address, real hardware
//! `RDRAND`/`RDSEED` output when the CPU supports it, and the persistent entropy pool below),
//! hashes them all together with SHA-256 (RustCrypto's `sha2` crate) into a 32-byte key, then
//! generates the caller's requested output as a ChaCha20 (RustCrypto's `chacha20` crate) keystream
//! under that key -- the same "gather a pile of diverse state, hash it into a seed, drive a real
//! algorithm with it" design Pokemon Black/White's own famous RNG made popular, just with a real
//! stream cipher standing in for that game's own LCG.
//!
//! **`ENTROPY_POOL`: a real, persistent accumulator, distinct from `gather_seed`'s own per-call
//! snapshot.** The original version of this module re-derived everything from scratch on every
//! call -- under QEMU/TCG without `RDRAND` (the common dev-loop case), that leaves the generator
//! with almost nothing genuinely hard to predict: RTC has 1-second granularity, PIT ticks advance
//! at a fixed 100 Hz, the call counter is fully deterministic (its job is uniqueness, not
//! unpredictability), and the stack-address sample is a fixed local, essentially constant call to
//! call. `mix_entropy` folds real, externally-triggered timing jitter -- the exact `RDTSC` value
//! at which a keyboard IRQ or a network-frame IRQ happened to land, both driven by events outside
//! this kernel's own control -- into a small pool on every such interrupt (see the keyboard and
//! rtl8139 IRQ handlers' own call sites). Deliberately *not* fed by the periodic timer tick: a
//! period signal is close to the opposite of an entropy source, and it's the hottest IRQ in the
//! kernel, not worth the added lock traffic. `gather_seed` folds the pool's current state into
//! every output and also re-mixes it with a fresh `RDTSC` sample as part of the same critical
//! section, so the pool keeps evolving even across calls with no intervening IRQ activity --
//! same "generating also perturbs state" reasoning a Fortuna-style generator uses.
//!
//! **No fixed reseed-interval policy** -- unlike real Linux's `/dev/urandom` (a long-lived pool,
//! reseeded on a schedule), every call here derives an independent key from the pool's *current*
//! state plus fresh per-call sources, so there's no interval to get wrong. A fixed, all-zero
//! ChaCha20 nonce is safe specifically *because* of this: the algorithm's real security
//! requirement is "never reuse a `(key, nonce)` pair," and `CALL_COUNTER` (strictly monotonic,
//! folded into every seed) guarantees a freshly derived key is never reused across two different
//! calls, independent of how much real entropy any other source contributed that call.
//!
//! **Crypto primitives are vetted, external crates (`sha2`/`chacha20`), not hand-rolled** --
//! deliberately different from this codebase's usual "own the small stuff" bias (`src/pic.rs`
//! instead of `pic8259`, the hand-written syscall ABI, ...): a subtle bug in a hand-written hash
//! or stream cipher is far harder to catch than one in a driver or allocator, and this is exactly
//! the class of code where "well-audited, widely used implementation" outweighs "we wrote it
//! ourselves," the same reasoning `linked_list_allocator`/the `x86_64` crate already followed.
//!
//! Not a real Linux-style entropy pool with a blocking-until-enough-entropy distinction -- both
//! `/dev/random` and `/dev/urandom` share this exact same source, matching modern Linux's own
//! post-5.6 stance that the two barely differ once a pool is initialized. Still an honest gap
//! versus a hardware TRNG: with no `RDRAND`/`RDSEED` and no interrupt activity yet (e.g. the very
//! first read right at boot, before any keystroke or packet has landed), the pool starts at all
//! zeroes and the generator is leaning on the same weak per-call sources as before this pool
//! existed -- this change raises the floor for any *sustained* use, not the very first call.
//!
//! **`RDRAND`/`RDSEED` are only ever trusted on real bare metal, never under a hypervisor.**
//! `CPUID` reporting the instruction as CPU-supported only proves the *physical* CPU has it -- it
//! says nothing about whether the specific hypervisor a guest happens to be running under is
//! passing it through honestly. Both Intel VT-x and AMD SVM expose an execution-control bit
//! ("RDRAND exiting"/"RDSEED exiting") that lets a hypervisor trap either instruction and
//! substitute any value it wants, while the guest still observes a clean success -- there is no
//! way to detect this from inside the guest. `running_under_hypervisor()` checks the standard
//! `CPUID` leaf `1`, `ECX` bit `31` ("hypervisor present," set by every major hypervisor
//! including QEMU/KVM, VMware, Hyper-V, Xen) and `rdrand_available`/`rdseed_available` both treat
//! the instruction as unavailable whenever it's set -- real hardware entropy is only ever used
//! when nothing between this kernel and the physical CPU could be lying about it. Under any
//! detected hypervisor (this project's own QEMU dev/test loop included), the persistent
//! `ENTROPY_POOL`'s IRQ-jitter accumulation above is the real floor instead.

use core::arch::x86_64::{__cpuid, __cpuid_count, _rdtsc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use spin::Mutex;

static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);
static RDRAND_CHECKED: AtomicBool = AtomicBool::new(false);
static RDRAND_AVAILABLE: AtomicBool = AtomicBool::new(false);
static RDSEED_CHECKED: AtomicBool = AtomicBool::new(false);
static RDSEED_AVAILABLE: AtomicBool = AtomicBool::new(false);
static HYPERVISOR_CHECKED: AtomicBool = AtomicBool::new(false);
static HYPERVISOR_PRESENT: AtomicBool = AtomicBool::new(false);

/// Persistent entropy pool -- see this module's own doc comment. Guarded with
/// `without_interrupts`, not a plain lock: `mix_entropy` is called from IRQ handlers that already
/// run with interrupts disabled (interrupt gates), but `gather_seed`'s own read+re-mix runs from
/// arbitrary syscall context with interrupts enabled -- on this single core, holding the lock
/// there without also disabling interrupts first would deadlock the instant a keyboard/network IRQ
/// landed mid-critical-section and tried to mix into the same pool the interrupted context still
/// holds.
static ENTROPY_POOL: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);

/// Checked once (via `CPUID` leaf `1`, `ECX` bit `31`, the standard "hypervisor present" signal
/// every major hypervisor sets) and cached -- see this module's own doc comment for why
/// `RDRAND`/`RDSEED` are gated on this rather than trusted whenever `CPUID` claims support.
///
/// `pub`, not `pub(crate)` -- same "kept public for test use" precedent `mix_entropy` already
/// has. `tests/random_smoke.rs` asserts this is `true` under this project's own QEMU-based test
/// boots, so the `RDRAND`/`RDSEED` distrust gate is actually verified live, not just trusted by
/// code inspection.
pub fn running_under_hypervisor() -> bool {
    if !HYPERVISOR_CHECKED.load(Ordering::Relaxed) {
        // CPUID leaf 1 is always a valid, side-effect-free query on x86_64 -- safe in this Rust
        // version, no unsafe block needed.
        let regs = __cpuid(1);
        HYPERVISOR_PRESENT.store(regs.ecx & (1 << 31) != 0, Ordering::Relaxed);
        HYPERVISOR_CHECKED.store(true, Ordering::Relaxed);
    }
    HYPERVISOR_PRESENT.load(Ordering::Relaxed)
}

/// Checked once (via `CPUID` leaf `1`, `ECX` bit `30`) and cached -- real hardware entropy is a
/// bonus input when present, not a hard requirement (QEMU/TCG without KVM, an old host CPU, or
/// simply running under any hypervisor at all -- see `running_under_hypervisor` above -- means
/// this stays unavailable; `gather_seed` below still has plenty of other jittery sources).
fn rdrand_available() -> bool {
    if !RDRAND_CHECKED.load(Ordering::Relaxed) {
        // CPUID leaf 1 is always a valid, side-effect-free query on x86_64 -- safe in this Rust
        // version, no unsafe block needed.
        let regs = __cpuid(1);
        RDRAND_AVAILABLE.store(regs.ecx & (1 << 30) != 0, Ordering::Relaxed);
        RDRAND_CHECKED.store(true, Ordering::Relaxed);
    }
    RDRAND_AVAILABLE.load(Ordering::Relaxed) && !running_under_hypervisor()
}

/// Only ever called after `rdrand_available()` has confirmed `CPUID` reports the instruction
/// supported -- `#[target_feature]` (rather than a blanket `-C target-feature=+rdrand` for the
/// whole kernel) keeps this the one function allowed to emit the instruction. Intel's own
/// documented retry protocol: a handful of attempts is more than enough in practice.
#[target_feature(enable = "rdrand")]
unsafe fn rdrand64() -> Option<u64> {
    let mut val: u64 = 0;
    for _ in 0..10 {
        // _rdrand64_step is safe in this Rust version -- this function's own `unsafe` comes
        // entirely from the `#[target_feature(enable = "rdrand")]` above, not from this call.
        if core::arch::x86_64::_rdrand64_step(&mut val) == 1 {
            return Some(val);
        }
        core::hint::spin_loop();
    }
    None
}

/// Checked once (via `CPUID` leaf `7`, sub-leaf `0`, `EBX` bit `18`) and cached, same pattern as
/// `rdrand_available` above -- including the same hypervisor-distrust gate. `RDSEED` draws
/// directly from the CPU's own conditioned entropy source rather than `RDRAND`'s DRBG-expanded
/// output -- a strictly stronger real source when present, worth mixing in alongside `RDRAND`
/// rather than instead of it, but no more trustworthy than `RDRAND` about being honestly passed
/// through by whatever hypervisor (if any) sits between this kernel and the physical CPU.
fn rdseed_available() -> bool {
    if !RDSEED_CHECKED.load(Ordering::Relaxed) {
        // CPUID leaf 7 is always a valid, side-effect-free query on x86_64 -- safe in this Rust
        // version, no unsafe block needed.
        let regs = __cpuid_count(7, 0);
        RDSEED_AVAILABLE.store(regs.ebx & (1 << 18) != 0, Ordering::Relaxed);
        RDSEED_CHECKED.store(true, Ordering::Relaxed);
    }
    RDSEED_AVAILABLE.load(Ordering::Relaxed) && !running_under_hypervisor()
}

/// Only ever called after `rdseed_available()` has confirmed `CPUID` reports the instruction
/// supported. Intel recommends more retries for `RDSEED` than `RDRAND` (its underlying entropy
/// source can be conditioning-limited under sustained back-to-back draws) -- this is a single,
/// infrequent per-call draw, not a bulk source, so a bounded retry budget is still appropriate,
/// just larger than `rdrand64`'s.
#[target_feature(enable = "rdseed")]
unsafe fn rdseed64() -> Option<u64> {
    let mut val: u64 = 0;
    for _ in 0..32 {
        // _rdseed64_step is safe in this Rust version -- this function's own `unsafe` comes
        // entirely from the `#[target_feature(enable = "rdseed")]` above, not from this call.
        if core::arch::x86_64::_rdseed64_step(&mut val) == 1 {
            return Some(val);
        }
        core::hint::spin_loop();
    }
    None
}

/// Mixes one real-world timing sample into the persistent entropy pool -- called from the
/// keyboard and rtl8139 IRQ handlers (real, externally-triggered events: a human keystroke, a
/// network frame's arrival), not from the periodic timer tick. `sample` is handler-specific
/// context (e.g. the raw scancode, or the NIC's ISR cause bits) -- folded in alongside a fresh
/// `RDTSC` read, which is where the real unpredictability comes from: the *exact* cycle count at
/// which an asynchronous, externally-triggered event happened to land, not the sample value
/// itself. `pub`, not `pub(crate)`: `tests/random_smoke.rs` exercises this directly (no IRQ
/// activity happens inside the test-boot QEMU instances that run it).
pub fn mix_entropy(sample: u64) {
    // SAFETY: RDTSC is a plain, always-available x86_64 instruction.
    let tsc = unsafe { _rdtsc() };
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut pool = ENTROPY_POOL.lock();
        let mut hasher = Sha256::new();
        hasher.update(*pool);
        hasher.update(sample.to_le_bytes());
        hasher.update(tsc.to_le_bytes());
        *pool = hasher.finalize().into();
    });
}

/// Test-only snapshot of the persistent entropy pool's current raw state -- lets
/// `tests/random_smoke.rs` verify `mix_entropy`/`gather_seed` actually mutate the pool, not just
/// that `oxidebsd_random_bytes`'s final output happens to differ call to call (which the
/// monotonic `CALL_COUNTER` alone would already guarantee, pool or no pool). Same "kept `pub` for
/// test use" precedent as `mix_entropy` itself.
pub fn entropy_pool_snapshot() -> [u8; 32] {
    x86_64::instructions::interrupts::without_interrupts(|| *ENTROPY_POOL.lock())
}

/// Gathers this call's own pile of entropy sources and hashes them into a 32-byte SHA-256 digest
/// -- see this module's own doc comment for the full design.
fn gather_seed() -> [u8; 32] {
    let mut hasher = Sha256::new();

    // SAFETY: RDTSC is a plain, always-available x86_64 instruction (no CPUID gate needed, unlike
    // RDRAND below) -- just reads the CPU's free-running cycle counter.
    let tsc = unsafe { _rdtsc() };
    hasher.update(tsc.to_le_bytes());

    hasher.update(crate::cpu::interrupts::ticks().to_le_bytes());
    hasher.update((crate::cpu::rtc::unix_epoch_seconds() as u64).to_le_bytes());
    hasher.update(CALL_COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());

    // A stack address -- varies with call depth/whatever else has touched this kernel stack
    // recently, a weak but free extra source alongside the stronger ones above.
    let stack_marker: u8 = 0;
    hasher.update((&raw const stack_marker as u64).to_le_bytes());

    if rdrand_available() {
        // SAFETY: rdrand_available() just confirmed CPUID reports this instruction supported.
        if let Some(r) = unsafe { rdrand64() } {
            hasher.update(r.to_le_bytes());
        }
    }
    if rdseed_available() {
        // SAFETY: rdseed_available() just confirmed CPUID reports this instruction supported.
        if let Some(r) = unsafe { rdseed64() } {
            hasher.update(r.to_le_bytes());
        }
    }

    // Fold in the persistent entropy pool (real accumulated keyboard/network IRQ jitter since
    // boot -- see `mix_entropy` and this module's own doc comment) and re-mix it with a fresh TSC
    // sample in the same critical section, so the pool keeps evolving even across calls with no
    // intervening IRQ activity.
    let pool_tsc = unsafe { _rdtsc() };
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut pool = ENTROPY_POOL.lock();
        hasher.update(*pool);
        let mut reseed = Sha256::new();
        reseed.update(*pool);
        reseed.update(pool_tsc.to_le_bytes());
        *pool = reseed.finalize().into();
    });

    hasher.finalize().into()
}

/// One real random `u64` for a kernel-internal caller that just needs a number, not a
/// user-buffer write (e.g. `process::aslr::pick_bias`'s per-`execve()` PIE load-bias
/// randomization) -- reuses `gather_seed()` directly rather than duplicating any RNG logic or
/// going through `oxidebsd_random_bytes`'s pointer/len C-ABI shape, which has no natural
/// "just give me a u64" calling convention. `pub(crate)`, not `pub`: unlike `mix_entropy`/
/// `entropy_pool_snapshot`, no test needs this directly today.
pub(crate) fn kernel_random_u64() -> u64 {
    u64::from_le_bytes(gather_seed()[0..8].try_into().unwrap())
}

/// Fills `[ptr, ptr+len)` with real, cryptographically-mixed random bytes -- backs oxfs's
/// synthetic `/dev/random`/`/dev/urandom` (see this module's own doc comment for the full design).
///
/// `pub`, not `pub(crate)` -- same "kept public for test use" precedent `syscall::
/// oxidebsd_sys_read`/`oxidebsd_sys_write` already have; `tests/random_smoke.rs` calls this
/// directly (oxfs's own `/dev` wiring can only really be exercised by a real process actually
/// opening the path, which needs a full module-loading boot -- this covers the new, riskier logic
/// this pass actually added).
pub extern "C" fn oxidebsd_random_bytes(ptr: u64, len: u64) -> i64 {
    let key = gather_seed();
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());

    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has -- ptr isn't checked against the caller's actual mappings first.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    buf.fill(0);
    cipher.apply_keystream(buf);
    len as i64
}
