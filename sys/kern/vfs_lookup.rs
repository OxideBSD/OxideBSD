//! Path lookup (`namei`, OxideBSD-doc `VFS.md` §6.1): a path to a vnode, component by component
//! through each directory's `lookup`, the name cache in front. FreeBSD's `vfs_lookup.c` in
//! miniature.
//!
//! - An absolute path starts at the process's root, a relative one at the start directory (the
//!   cwd, or an `*at()` call's directory descriptor, passed explicitly).
//! - Searching a directory needs execute permission on it (`VEXEC`).
//! - A directory with a mount on it continues at the mount's root; `..` at a mount's root
//!   continues at `..` of the directory it covers (FreeBSD's `VV_ROOT` handling), and `..` at the
//!   process's root stays there (the chroot boundary).
//! - Symbolic links are followed in the middle of a path always, at its end when asked
//!   (`FOLLOW`) or when a slash follows; at most `MAXSYMLINKS` (32, as FreeBSD) per lookup, and
//!   the expanded path is held to `PATH_MAX`.
//! - A trailing slash requires a directory (or a missing last component a `CREATE` may make one).

use alloc::vec::Vec;
use core::ptr;

use vfs_if::*;

use crate::kern::vfs_cache::{self, Hit};
use crate::kern::vfs_mount;
use crate::kern::vfs_subr::{vref, vrele};
use crate::kern::vnode_if::*;

pub(crate) const PATH_MAX: usize = 4096;
pub(crate) const NAME_MAX: usize = 255;
pub(crate) const MAXSYMLINKS: u32 = 32;

pub(crate) const ENOENT: i32 = 2;
pub(crate) const ENAMETOOLONG: i32 = 36;
pub(crate) const ELOOP: i32 = 40;
pub(crate) const EISDIR: i32 = 21;

/// What `namei` is asked.
pub(crate) struct NameiData<'a> {
    pub path: &'a [u8],
    /// `LOOKUP`, `CREATE`, `DELETE`, `RENAME`: what the caller means to do with the last component.
    pub nameiop: u32,
    /// Follow a symbolic link as the last component.
    pub follow: bool,
    /// Where a relative path starts (referenced by the caller); null for the cwd.
    pub startdir: *mut Vnode,
    pub cred: &'a Ucred,
}

/// What `namei` found. Every non-null vnode is referenced: the caller `vrele`s them.
pub(crate) struct Namei {
    /// The directory holding the last component; null when the path ended in `.`, `..` or a slash
    /// after a directory (no last component of its own: `/`, `a/.`).
    pub dvp: *mut Vnode,
    /// The file; null when the last component is missing and the caller may create it
    /// (`CREATE`/`RENAME`).
    pub vp: *mut Vnode,
    /// The last component (empty for `/`).
    pub last: Vec<u8>,
    /// The path ended in a slash.
    pub trailing_slash: bool,
}

impl Namei {
    /// Drops both references.
    pub(crate) fn release(self) {
        if !self.vp.is_null() {
            vrele(self.vp);
        }
        if !self.dvp.is_null() {
            vrele(self.dvp);
        }
    }

    /// Keeps only `vp`.
    pub(crate) fn into_vp(self) -> *mut Vnode {
        if !self.dvp.is_null() {
            vrele(self.dvp);
        }
        self.vp
    }

    pub(crate) fn cn(&self, nameiop: u32, cred: &Ucred) -> ComponentName {
        ComponentName {
            cn_nameiop: nameiop,
            cn_flags: ISLASTCN,
            cn_cred: cred,
            cn_nameptr: self.last.as_ptr(),
            cn_namelen: self.last.len(),
        }
    }
}

/// The calling process's root directory (the system's, unless chrooted), referenced.
fn process_root() -> *mut Vnode {
    let vp = crate::process::current_dir_vnode(false);
    let vp = if vp.is_null() { vfs_mount::rootvnode() } else { vp };
    vref(vp);
    vp
}

/// The calling process's cwd, referenced.
fn process_cwd() -> *mut Vnode {
    let vp = crate::process::current_dir_vnode(true);
    let vp = if vp.is_null() { vfs_mount::rootvnode() } else { vp };
    vref(vp);
    vp
}

/// Replaces `*vp` (referenced) with the root of the mount stacked on it, as many as there are.
pub(crate) fn cross_mounts(vp: &mut *mut Vnode) -> Result<(), i32> {
    loop {
        // SAFETY: `*vp` is referenced.
        let mp = unsafe { (**vp).v_mountedhere };
        if mp.is_null() {
            return Ok(());
        }
        let root = vfs_mount::vfs_root(mp)?;
        vrele(*vp);
        *vp = root;
    }
}

/// `..` of `dp` (referenced; replaced): at a mount's root, first down to the directory it covers.
/// At the process's root, `dp` itself.
fn dotdot(dp: &mut *mut Vnode, root: *mut Vnode, cred: &Ucred) -> Result<(), i32> {
    loop {
        if *dp == root || *dp == vfs_mount::rootvnode() {
            return Ok(());
        }
        // SAFETY: `*dp` is referenced; its mount lives while it does.
        let (flag, covered) = unsafe { ((**dp).v_flag, (*(**dp).v_mount).mnt_vnodecovered) };
        if flag & VV_ROOT == 0 || covered.is_null() {
            break;
        }
        vref(covered);
        vrele(*dp);
        *dp = covered;
    }
    let cn = ComponentName {
        cn_nameiop: LOOKUP,
        cn_flags: ISDOTDOT,
        cn_cred: cred,
        cn_nameptr: b"..".as_ptr(),
        cn_namelen: 2,
    };
    let parent = vop_lookup(*dp, &cn)?;
    vrele(*dp);
    *dp = parent;
    Ok(())
}

/// One component in `dp`: the cache, then the file system. `Ok(null)` for a missing name.
/// Whether the name cache may keep `dp`'s names (`VFCF_NOCACHE`).
fn cacheable(dp: *mut Vnode) -> bool {
    // SAFETY: `dp` is referenced; its mount and type are live.
    unsafe { (*(*(*dp).v_mount).mnt_vfc).flags & VFCF_NOCACHE == 0 }
}

fn lookup_component(dp: *mut Vnode, name: &[u8], nameiop: u32, islast: bool, cred: &Ucred) -> Result<*mut Vnode, i32> {
    let cache = cacheable(dp);
    match if cache { vfs_cache::lookup(dp, name) } else { None } {
        Some(Hit::Found(vp)) => {
            vref(vp);
            return Ok(vp);
        }
        Some(Hit::Missing) if nameiop == LOOKUP || !islast => return Err(ENOENT),
        Some(Hit::Missing) => return Ok(ptr::null_mut()),
        None => {}
    }
    let cn = ComponentName {
        cn_nameiop: if islast { nameiop } else { LOOKUP },
        cn_flags: (if islast { ISLASTCN } else { 0 }) | MAKEENTRY,
        cn_cred: cred,
        cn_nameptr: name.as_ptr(),
        cn_namelen: name.len(),
    };
    match vop_lookup(dp, &cn) {
        Ok(vp) => {
            if cache {
                vfs_cache::enter(dp, name, vp);
            }
            Ok(vp)
        }
        Err(EJUSTRETURN) if islast && nameiop != LOOKUP => Ok(ptr::null_mut()),
        Err(ENOENT) if islast && nameiop != LOOKUP => Ok(ptr::null_mut()),
        Err(ENOENT) => {
            if cache && (nameiop == LOOKUP || !islast) {
                vfs_cache::enter(dp, name, ptr::null_mut());
            }
            Err(ENOENT)
        }
        Err(e) => Err(e),
    }
}

/// A symbolic link's target, at most `PATH_MAX` bytes.
pub(crate) fn readlink_kernel(vp: *mut Vnode, cred: &Ucred) -> Result<Vec<u8>, i32> {
    let mut buf = alloc::vec![0u8; PATH_MAX];
    use crate::kern::subr_uio::{IoSeg, Uio, UioRw, UioSeg}; // shadows vfs_if::Uio (the handle)
    let seg = IoSeg { base: buf.as_mut_ptr() as u64, len: PATH_MAX as u64 };
    let mut uio = Uio::new(alloc::vec![seg], UioRw::Read, UioSeg::Kernel, 0).map_err(|e| e as i32)?;
    let n = vop_readlink(vp, &mut uio as *mut Uio as u64, cred)?;
    buf.truncate(n);
    Ok(buf)
}

/// `namei`.
pub(crate) fn namei(nd: &NameiData) -> Result<Namei, i32> {
    if nd.path.is_empty() {
        return Err(ENOENT);
    }
    if nd.path.len() > PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    let root = process_root();
    let result = walk(nd, root);
    vrele(root);
    result
}

fn walk(nd: &NameiData, root: *mut Vnode) -> Result<Namei, i32> {
    let cred = nd.cred;
    let mut buf: Vec<u8> = nd.path.to_vec();
    let mut pos = 0usize;
    let mut links = 0u32;
    let mut dp = if buf[0] == b'/' {
        vref(root);
        root
    } else if nd.startdir.is_null() {
        process_cwd()
    } else {
        vref(nd.startdir);
        nd.startdir
    };
    loop {
        while pos < buf.len() && buf[pos] == b'/' {
            pos += 1;
        }
        if pos == buf.len() {
            // Nothing after the last directory: the path names `dp` itself (`/`, `a/`, `.`
            // resolved away). A create or delete of it has no name to work on.
            if nd.nameiop != LOOKUP {
                vrele(dp);
                return Err(EISDIR);
            }
            return Ok(Namei { dvp: ptr::null_mut(), vp: dp, last: Vec::new(), trailing_slash: true });
        }
        let start = pos;
        while pos < buf.len() && buf[pos] != b'/' {
            pos += 1;
        }
        let name: Vec<u8> = buf[start..pos].to_vec();
        if name.len() > NAME_MAX {
            vrele(dp);
            return Err(ENAMETOOLONG);
        }
        let mut rest = pos;
        while rest < buf.len() && buf[rest] == b'/' {
            rest += 1;
        }
        let islast = rest == buf.len();
        let trailing_slash = islast && pos < buf.len();

        // SAFETY: `dp` is referenced.
        if unsafe { (*dp).v_type } != VDIR {
            vrele(dp);
            return Err(ENOTDIR);
        }
        let e = vop_access(dp, VEXEC, cred);
        if e != 0 {
            vrele(dp);
            return Err(e);
        }

        if name == b"." || name == b".." {
            if name == b".." {
                if let Err(e) = dotdot(&mut dp, root, cred) {
                    vrele(dp);
                    return Err(e);
                }
            }
            if islast {
                if nd.nameiop != LOOKUP {
                    vrele(dp);
                    return Err(EINVAL);
                }
                return Ok(Namei { dvp: ptr::null_mut(), vp: dp, last: name, trailing_slash });
            }
            continue;
        }

        let mut vp = match lookup_component(dp, &name, nd.nameiop, islast, cred) {
            Ok(vp) => vp,
            Err(e) => {
                vrele(dp);
                return Err(e);
            }
        };
        if vp.is_null() {
            // Missing last component of a create or rename: the caller makes it.
            return Ok(Namei { dvp: dp, vp, last: name, trailing_slash });
        }
        // A create, delete or rename works on the name in `dp`, not on what's mounted there.
        if (!islast || nd.nameiop == LOOKUP)
            && let Err(e) = cross_mounts(&mut vp)
        {
            vrele(vp);
            vrele(dp);
            return Err(e);
        }
        // SAFETY: `vp` is referenced.
        let is_link = unsafe { (*vp).v_type } == VLNK;
        if is_link && (!islast || nd.follow || trailing_slash) {
            links += 1;
            if links > MAXSYMLINKS {
                vrele(vp);
                vrele(dp);
                return Err(ELOOP);
            }
            let target = readlink_kernel(vp, cred);
            vrele(vp);
            let target = match target {
                Ok(t) if t.is_empty() => {
                    vrele(dp);
                    return Err(ENOENT);
                }
                Ok(t) => t,
                Err(e) => {
                    vrele(dp);
                    return Err(e);
                }
            };
            // The target replaces the component; the rest of the path follows it.
            let mut next = target;
            if pos < buf.len() {
                next.extend_from_slice(&buf[pos..]);
            }
            if next.len() > PATH_MAX {
                vrele(dp);
                return Err(ENAMETOOLONG);
            }
            if next[0] == b'/' {
                vrele(dp);
                vref(root);
                dp = root;
            }
            buf = next;
            pos = 0;
            continue;
        }
        if islast {
            // SAFETY: `vp` is referenced.
            if trailing_slash && unsafe { (*vp).v_type } != VDIR {
                vrele(vp);
                vrele(dp);
                return Err(ENOTDIR);
            }
            return Ok(Namei { dvp: dp, vp, last: name, trailing_slash });
        }
        vrele(dp);
        dp = vp;
    }
}
