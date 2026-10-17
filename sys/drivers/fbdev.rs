//! The framebuffer device, `/dev/fb0` (`init`), and its geometry query, which `mmap` of it
//! (`process::mm::do_mmap_fb`) maps from: `boot::primary_framebuffer()`'s `FbInfo` as a plain
//! `#[repr(C)]` record.

use crate::boot;

/// What `FileOps::fb_geometry` writes, and `process::mm::do_mmap_fb` maps from. `#[repr(C)]`, same
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

/// `FileOps::fb_geometry` of `/dev/fb0`: writes the geometry through `out` and returns `0`, or
/// `-1` (writing nothing) if no usable framebuffer exists this boot.
extern "C" fn fb_geometry(_real_fd: u64, out: u64) -> i32 {
    match current_fb_geometry() {
        Some(geom) => {
            // SAFETY: `out` is a kernel buffer (`fd::framebuffer_geometry_of`'s), never a user
            // pointer, so not a `copyout` (USERMEM.md).
            unsafe { *(out as *mut FbGeometry) = geom };
            0
        }
        None => -1,
    }
}

/// Registers `/dev/fb0` (major 29, Linux's), when there is a usable framebuffer. Its pixels are
/// reached only through `mmap` (`process::mm::do_mmap_fb`); `read` and `write` fail `EBADF`.
pub fn init() {
    if current_fb_geometry().is_some() {
        let _ = crate::fs::devfs::make_dev("fb0", 29, 0, 0, 0, 0o666, fb_open);
    }
}

extern "C" fn fb_open(_major: u64, _minor: u64, flags: u64) -> i64 {
    use crate::fs::fd;
    if current_fb_geometry().is_none() {
        return -(crate::syscall::ENXIO as i64);
    }
    if let Err(e) = fd::check_room(1) {
        return -(e as i64);
    }
    let real_fd = fd::oxidebsd_alloc_fd();
    fd::finstall(real_fd, &FB_OPS, 0, fd::open_flag(flags), fd::FdKind::Module)
}

static FB_OPS: crate::fs::fd::FileOps = crate::fs::fd::FileOps {
    flags: crate::fs::fd::DFLAG_SEEKABLE,
    fb_geometry: Some(fb_geometry),
    ..crate::fs::fd::FileOps::NONE
};
