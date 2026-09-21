//! Real framebuffer geometry query, backing `/dev/fb0` (`sys/modules/oxfs`'s `OpenFile::Framebuffer`)
//! and the `do_mmap` MMIO-mapping path (`process::mm::do_mmap_fb`). Deliberately thin: this file
//! owns no state of its own, just translates `boot::primary_framebuffer()`'s already-real,
//! boot-path-agnostic `FbInfo` response into a plain, `#[repr(C)]`, syscall/module-boundary-safe
//! shape.
//!
//! This is genuine, general-purpose framebuffer-device infrastructure (not doomgeneric-specific)
//! -- the first real graphical-output primitive a future desktop environment could also build on.

use crate::boot;

/// The wire format both `sys/modules/oxfs` (seeding a `/dev/fb0` device inode's backing info) and
/// `process::mm::do_mmap_fb` (deriving the physical range to map) consume. `#[repr(C)]`, same
/// "plain-old-data struct read through a raw pointer" discipline every other module-boundary
/// struct in this codebase already uses (`RawTermios`, `RawWinsize`, ...).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FbGeometry {
    /// Real physical base address (not the HHDM-mapped virtual one `FbInfo::address` itself
    /// holds) -- `fb.address - boot::hhdm_offset()`.
    pub phys_base: u64,
    /// `fb.height * fb.pitch` -- the real total byte extent, used to clamp any mmap request so it
    /// can never map past the framebuffer's own real bounds regardless of what length a caller
    /// asks for.
    pub len: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

/// `None` if Limine reported no usable framebuffer, or one that isn't `bpp == 32` -- the same
/// restriction `console::framebuffer::redraw_target` already imposes; no consumer of this
/// (`/dev/fb0`'s open path, `do_mmap_fb`) has any way to handle a narrower/wider real pixel
/// format yet.
pub fn current_fb_geometry() -> Option<FbGeometry> {
    let fb = boot::primary_framebuffer()?;
    if fb.bpp != 32 {
        return None;
    }
    Some(FbGeometry {
        phys_base: fb.address - boot::hhdm_offset(),
        len: fb.height * fb.pitch,
        width: fb.width as u32,
        height: fb.height as u32,
        pitch: fb.pitch as u32,
        bpp: fb.bpp as u32,
    })
}

/// Module-callable wrapper (see `sys/module.rs`'s hand-curated symbol table) -- writes the real
/// geometry through `out` and returns `0`, or returns `-1` (writing nothing) if no usable
/// framebuffer exists this boot. Same "plain `u64`/`i32` at the module boundary, raw pointer cast
/// inside" shape `random::oxidebsd_random_bytes` already establishes.
pub extern "C" fn oxidebsd_fb_geometry(out: u64) -> i32 {
    match current_fb_geometry() {
        Some(geom) => {
            // SAFETY: same known pointer-validation gap every other module-boundary write in
            // this codebase already has -- `out` isn't checked against the caller's actual
            // mapping first. Callers here are always this kernel's own modules (`oxfs`), never
            // raw userland pointers.
            unsafe { *(out as *mut FbGeometry) = geom };
            0
        }
        None => -1,
    }
}
