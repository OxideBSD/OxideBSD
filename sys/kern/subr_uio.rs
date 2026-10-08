//! Data transfer between a descriptor's backend and the caller's buffers: `uio(9)` and
//! `uiomove(9)`, as on the BSDs (`OxideBSD-doc/USERMEM.md` §4.4).
//!
//! A system call that reads or writes builds one `Uio` from the caller's buffer, or its whole
//! `iovec` array, and hands it to the backend, which moves data with `uiomove` as often as it likes.
//! User segments go through `copyin`/`copyout` and fail with `EFAULT`; kernel segments are plain
//! copies.
//!
//! A copy that faults on a user stack page not grown yet grows it (`mm::try_grow_user_stack`, which
//! takes no process table lock and only `try_lock`s the frame allocator). Copying while holding
//! the frame allocator's lock therefore fails such a copy with `EFAULT` instead.

use alloc::vec::Vec;

use crate::memory::usercopy::{UserPtr, copyin, copyout};
use crate::syscall::{EFAULT, EINVAL};

/// `FOF_OFFSET`: use `Uio::offset`, not the description's own position (`pread`/`pwrite`).
pub(crate) const FOF_OFFSET: u64 = 1;

/// Which way data moves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum UioRw {
    /// From the backend out to the segments (`read`).
    Read,
    /// From the segments in to the backend (`write`).
    Write,
}

/// Whose addresses the segments are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum UioSeg {
    User,
    /// Kernel buffers: a module's own I/O (`oxidebsd_uio_kernel_new`), and later core dumps,
    /// `sendfile` and in-kernel file I/O (USERMEM.md §4.4).
    Kernel,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct IoSeg {
    pub base: u64,
    pub len: u64,
}

/// One transfer: the segments still to fill or drain, in order.
pub(crate) struct Uio {
    iov: Vec<IoSeg>,
    /// The segment being moved through, and how far into it.
    idx: usize,
    seg_off: u64,
    resid: u64,
    offset: u64,
    rw: UioRw,
    seg: UioSeg,
}

impl Uio {
    /// A transfer over `iov`. `EINVAL` if the lengths add up past `isize::MAX` (POSIX's
    /// `ssize_t` overflow), as for `readv`/`writev`.
    pub(crate) fn new(iov: Vec<IoSeg>, rw: UioRw, seg: UioSeg, offset: u64) -> Result<Self, u64> {
        let mut resid: u64 = 0;
        for s in &iov {
            resid = resid.checked_add(s.len).filter(|&r| r <= isize::MAX as u64).ok_or(EINVAL)?;
        }
        Ok(Uio { iov, idx: 0, seg_off: 0, resid, offset, rw, seg })
    }

    /// One user buffer, for `read`/`write`/`pread`/`pwrite`.
    pub(crate) fn user(base: u64, len: u64, rw: UioRw, offset: u64) -> Result<Self, u64> {
        Self::new(alloc::vec![IoSeg { base, len }], rw, UioSeg::User, offset)
    }

    pub(crate) fn resid(&self) -> u64 {
        self.resid
    }

    /// Moves up to `kbuf.len()` bytes between `kbuf` and the next part of the segments: out of
    /// `kbuf` for `Read`, into it for `Write`. Returns how many moved (less than `kbuf.len()` only
    /// when the transfer is complete). On `EFAULT` nothing of the failing piece counts as moved.
    pub(crate) fn uiomove(&mut self, kbuf: &mut [u8]) -> Result<usize, u64> {
        // SAFETY: `kbuf` is valid for reads and writes of its length.
        unsafe { self.move_raw(kbuf.as_mut_ptr(), kbuf.len()) }
    }

    /// `uiomove` for a `Read` transfer, from a buffer that is only read.
    pub(crate) fn uiomove_out(&mut self, data: &[u8]) -> Result<usize, u64> {
        assert_eq!(self.rw, UioRw::Read, "uiomove_out on a write transfer");
        // SAFETY: a `Read` transfer only reads `data`.
        unsafe { self.move_raw(data.as_ptr().cast_mut(), data.len()) }
    }

    /// `uiomove` for a `Write` transfer, into `buf`.
    pub(crate) fn uiomove_in(&mut self, buf: &mut [u8]) -> Result<usize, u64> {
        assert_eq!(self.rw, UioRw::Write, "uiomove_in on a read transfer");
        self.uiomove(buf)
    }

    /// # Safety
    ///
    /// `kbuf` is valid for `len` bytes: for reads always, for writes when this is a `Write`
    /// transfer.
    unsafe fn move_raw(&mut self, kbuf: *mut u8, len: usize) -> Result<usize, u64> {
        let mut done = 0;
        while done < len && self.resid > 0 {
            let s = self.iov[self.idx];
            let avail = s.len - self.seg_off;
            if avail == 0 {
                self.idx += 1;
                self.seg_off = 0;
                continue;
            }
            let n = avail.min((len - done) as u64) as usize;
            let addr = s.base.wrapping_add(self.seg_off);
            // SAFETY: within `kbuf`'s `len` bytes, per this function's contract.
            let k = unsafe { kbuf.add(done) };
            match (self.rw, self.seg) {
                (UioRw::Read, UioSeg::User) => {
                    // SAFETY: as above; only read.
                    copyout(unsafe { core::slice::from_raw_parts(k, n) }, UserPtr::new(addr))?
                }
                (UioRw::Write, UioSeg::User) => {
                    // SAFETY: as above; a Write transfer's buffer is writable.
                    copyin(UserPtr::new(addr), unsafe { core::slice::from_raw_parts_mut(k, n) })?
                }
                // SAFETY: a kernel segment is a kernel buffer of at least its length, set up by
                // the in-kernel caller that built this transfer.
                (UioRw::Read, UioSeg::Kernel) => unsafe {
                    core::ptr::copy(k.cast_const(), addr as *mut u8, n)
                },
                (UioRw::Write, UioSeg::Kernel) => unsafe {
                    core::ptr::copy(addr as *const u8, k, n)
                },
            }
            self.seg_off += n as u64;
            self.resid -= n as u64;
            self.offset = self.offset.wrapping_add(n as u64);
            done += n;
        }
        Ok(done)
    }

    /// Gives back the last `n` bytes moved, as if they hadn't been: for a writer that copied in
    /// more than its backend then took.
    pub(crate) fn rewind(&mut self, mut n: u64) {
        while n > 0 {
            if self.seg_off == 0 {
                if self.idx == 0 {
                    break;
                }
                self.idx -= 1;
                self.seg_off = self.iov[self.idx].len;
                continue;
            }
            let k = self.seg_off.min(n);
            self.seg_off -= k;
            self.resid += k;
            self.offset = self.offset.wrapping_sub(k);
            n -= k;
        }
    }
}

/// `uiomove` for modules (`sys/module.rs`'s symbol table): moves up to `len` bytes between `kbuf`
/// and `uio`, in the transfer's direction. Returns the count moved, or `-errno`.
pub(crate) extern "C" fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: *mut Uio) -> i64 {
    if uio.is_null() {
        return -(EFAULT as i64);
    }
    // SAFETY: the module passes the `Uio` it was handed and its own buffer of `len` bytes; for a
    // `Read` transfer the buffer is only read from.
    match unsafe { (*uio).move_raw(kbuf, len as usize) } {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

/// A transfer over one kernel buffer, for a module doing I/O on its own descriptors (oxfs's
/// format self-check): `rw` is `0` for a read, `1` for a write. Freed with `oxidebsd_uio_free`.
pub(crate) extern "C" fn oxidebsd_uio_kernel_new(buf: *mut u8, len: u64, rw: u64) -> *mut Uio {
    let rw = if rw == 0 { UioRw::Read } else { UioRw::Write };
    let iov = alloc::vec![IoSeg { base: buf as u64, len }];
    match Uio::new(iov, rw, UioSeg::Kernel, 0) {
        Ok(uio) => alloc::boxed::Box::into_raw(alloc::boxed::Box::new(uio)),
        Err(_) => core::ptr::null_mut(),
    }
}

/// Frees a transfer made by `oxidebsd_uio_kernel_new`.
pub(crate) extern "C" fn oxidebsd_uio_free(uio: *mut Uio) {
    if !uio.is_null() {
        // SAFETY: made by `oxidebsd_uio_kernel_new`, freed once.
        drop(unsafe { alloc::boxed::Box::from_raw(uio) });
    }
}

/// Bytes still to transfer, for modules.
pub(crate) extern "C" fn oxidebsd_uio_resid(uio: *const Uio) -> u64 {
    // SAFETY: the module passes the `Uio` it was handed.
    unsafe { (*uio).resid }
}

/// The transfer's file offset (meaningful with `FOF_OFFSET`), for modules.
pub(crate) extern "C" fn oxidebsd_uio_offset(uio: *const Uio) -> u64 {
    // SAFETY: as above.
    unsafe { (*uio).offset }
}
