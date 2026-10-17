//! Vnodes (OxideBSD-doc `VFS.md` §5): allocation, the `(mount, file ID)` hash, references, the
//! inactive and reclaim life cycle, recycling under `kern.maxvnodes`, and `vaccess`. FreeBSD's
//! `vfs_subr.c` and `vfs_hash.c` in miniature.
//!
//! A vnode is kernel memory (`Box<Vnode>`) with its file system's private data (`v_data`, the
//! size its `VfsConf` declares) allocated beside it. Two counts keep it: the use count (a
//! descriptor, a cwd or root, a mapping, a caller between lookup and release) keeps the file
//! active; when it drops to 0 the file system's `inactive` runs (an unlinked file's storage goes)
//! and the vnode waits on the free list, still hashed, so a later lookup of the same file finds it
//! again. Past `kern.maxvnodes` the oldest free vnode is recycled: `reclaim`, out of the hash,
//! freed. The hold count keeps the memory but not the file (FreeBSD's `vhold`): a held vnode
//! isn't recycled.
//!
//! Locking: the tables below are behind spin locks taken only for their own updates, never across
//! a call into a file system; the file system calls themselves run under the VFS's giant lock
//! (`fs::fslock`, `VFS.md` §5.4), which every call into a file system module takes.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use vfs_if::*;

use crate::fs::fslock;

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const ENOMEM: i32 = 12;
const EOPNOTSUPP: i32 = 95;

/// A vnode's address as a key (raw pointers aren't `Send`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VnodeRef(usize);

impl VnodeRef {
    fn get(self) -> *mut Vnode {
        self.0 as *mut Vnode
    }
}

/// `(mount, file ID) -> vnode`.
static HASH: Mutex<BTreeMap<(usize, u64), VnodeRef>> = Mutex::new(BTreeMap::new());
/// Vnodes with use and hold counts 0, oldest first: recycled from the front.
static FREE: Mutex<FreeList> = Mutex::new(FreeList { by_age: BTreeMap::new(), age_of: BTreeMap::new(), next: 0 });

/// The free list, ordered by when each vnode went free, with removal by vnode in `O(log n)`.
struct FreeList {
    by_age: BTreeMap<u64, VnodeRef>,
    age_of: BTreeMap<VnodeRef, u64>,
    next: u64,
}

impl FreeList {
    fn push(&mut self, v: VnodeRef) {
        self.next += 1;
        self.by_age.insert(self.next, v);
        self.age_of.insert(v, self.next);
    }

    fn remove(&mut self, v: VnodeRef) {
        if let Some(age) = self.age_of.remove(&v) {
            self.by_age.remove(&age);
        }
    }

    fn pop_oldest(&mut self) -> Option<VnodeRef> {
        let (_, v) = self.by_age.pop_first()?;
        self.age_of.remove(&v);
        Some(v)
    }

    fn len(&self) -> usize {
        self.by_age.len()
    }
}
/// Every vnode allocated and not yet freed (`vfs.numvnodes`).
static NUMVNODES: AtomicU64 = AtomicU64::new(0);
/// `kern.maxvnodes` as set; 0: sized from RAM (`maxvnodes`).
pub(crate) static MAXVNODES: AtomicU64 = AtomicU64::new(0);

/// RAM per vnode `kern.maxvnodes` allows by default: a vnode costs the heap (an eighth of RAM)
/// about 150 bytes with its file system's data and hash entry, so a full table takes about a
/// fiftieth of the heap: 1024 vnodes at 64 MB, 131072 at 8 GB.
const RAM_PER_VNODE: u64 = 64 * 1024;

/// `kern.maxvnodes`: as set, else one per `RAM_PER_VNODE` of RAM, at least 1024.
pub(crate) fn maxvnodes() -> u64 {
    let set = MAXVNODES.load(Ordering::Relaxed);
    if set > 0 {
        return set;
    }
    (crate::memory::usable_ram_bytes() / RAM_PER_VNODE).clamp(1024, 4 << 20)
}

/// `vfs.numvnodes`, `vfs.freevnodes`.
pub(crate) fn stats() -> (u64, u64) {
    (NUMVNODES.load(Ordering::Relaxed), FREE.lock().len() as u64)
}

fn v_data_layout(size: usize) -> Layout {
    Layout::from_size_align(size.max(1), 16).expect("v_data layout")
}

fn vfc_of(mp: *mut Mount) -> &'static VfsConf {
    // SAFETY: a live mount's type is a registered static.
    unsafe { &*(*mp).mnt_vfc }
}

/// `getnewvnode`: a new vnode of `mp`, use count 1, not hashed. Recycles the oldest free vnode
/// first when the table is full.
pub(crate) fn getnewvnode(mp: *mut Mount, vtype: VType, fileid: u64, vops: *const VopVector) -> Result<*mut Vnode, i32> {
    if NUMVNODES.load(Ordering::Relaxed) >= maxvnodes() {
        recycle_one();
    }
    let vfc = vfc_of(mp);
    // SAFETY: a nonzero-size layout.
    let data = unsafe { alloc_zeroed(v_data_layout(vfc.v_data_size)) };
    if data.is_null() {
        return Err(ENOMEM);
    }
    let vp = Box::into_raw(Box::new(Vnode {
        v_type: vtype,
        v_flag: 0,
        v_usecount: 1,
        v_holdcnt: 0,
        v_mount: mp,
        v_op: if vops.is_null() { vfc.vops } else { vops },
        v_data: data as *mut c_void,
        v_fileid: fileid,
        v_mountedhere: ptr::null_mut(),
        v_rdev: 0,
        v_object: 0,
        v_un: 0,
        v_lower: ptr::null_mut(),
        v_writecount: 0,
        v_textcount: 0,
    }));
    NUMVNODES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `mp` is live (the caller is operating on it).
    unsafe { (*mp).mnt_nvnodes += 1 };
    Ok(vp)
}

/// The hashed vnode of `(mp, fileid)`, referenced (`vfs_hash_get`); off the free list if it was
/// there.
pub(crate) fn hash_get(mp: *mut Mount, fileid: u64) -> *mut Vnode {
    let Some(v) = HASH.lock().get(&(mp as usize, fileid)).copied() else {
        return ptr::null_mut();
    };
    vref(v.get());
    v.get()
}

pub(crate) fn hash_insert(vp: *mut Vnode) {
    // SAFETY: a vnode from `getnewvnode`.
    let key = unsafe { ((*vp).v_mount as usize, (*vp).v_fileid) };
    HASH.lock().insert(key, VnodeRef(vp as usize));
}

pub(crate) fn hash_rehash(vp: *mut Vnode, fileid: u64) {
    let mut hash = HASH.lock();
    // SAFETY: a live vnode.
    unsafe {
        hash.remove(&((*vp).v_mount as usize, (*vp).v_fileid));
        (*vp).v_fileid = fileid;
        hash.insert(((*vp).v_mount as usize, fileid), VnodeRef(vp as usize));
    }
}

/// `vref` of a vnode stored as a `u64` (0: none, nothing to reference); returns it.
pub(crate) fn vref_raw(vp: u64) -> u64 {
    if vp != 0 {
        vref(vp as *mut Vnode);
    }
    vp
}

/// Adds a use reference (`vref`), taking the vnode off the free list.
pub(crate) fn vref(vp: *mut Vnode) {
    // SAFETY: the caller holds the vnode some way (a reference, the hash under its lock).
    let v = unsafe { &mut *vp };
    v.v_usecount += 1;
    if v.v_usecount == 1 {
        v.v_flag &= !VI_INACTIVE;
        if v.v_holdcnt == 0 {
            FREE.lock().remove(VnodeRef(vp as usize));
        }
    }
}

/// Drops a use reference (`vrele`); the last runs `inactive` and frees the vnode to the free list.
pub(crate) fn vrele(vp: *mut Vnode) {
    // SAFETY: the caller's reference keeps it live.
    let v = unsafe { &mut *vp };
    assert!(v.v_usecount > 0, "vrele: vnode with no use reference");
    v.v_usecount -= 1;
    if v.v_usecount > 0 {
        return;
    }
    if v.v_flag & VI_DOOMED == 0 {
        // SAFETY: a live vnode's operations vector is a registered static.
        if let Some(inactive) = unsafe { (*v.v_op).inactive } {
            // The file system may free the file now, which recycles this vnode and drops what held
            // it (the page cache's hold): `VI_ININACT` keeps it for this function to free.
            v.v_flag |= VI_ININACT;
            {
                let _lock = fslock::Guard::for_call(inactive as usize as u64);
                inactive(vp);
            }
            v.v_flag &= !VI_ININACT;
        }
    }
    // `inactive` may have taken (and dropped) references of its own.
    if v.v_usecount > 0 {
        return;
    }
    v.v_flag |= VI_INACTIVE;
    if v.v_holdcnt == 0 {
        if v.v_flag & VI_DOOMED != 0 {
            free_vnode(vp);
        } else {
            FREE.lock().push(VnodeRef(vp as usize));
        }
    }
}

/// Drops a use reference from where a file system mustn't be entered (a spin lock held, the
/// process table's for one: dropping a thread group's cwd as it's reaped): queued, and released by
/// the next `drain_deferred`, which every VFS entry point runs.
pub(crate) fn vrele_deferred(vp: *mut Vnode) {
    // SAFETY: the caller's reference keeps it live.
    let v = unsafe { &mut *vp };
    if v.v_usecount > 1 {
        v.v_usecount -= 1;
        return;
    }
    DEFERRED.lock().push(VnodeRef(vp as usize));
}

static DEFERRED: Mutex<alloc::vec::Vec<VnodeRef>> = Mutex::new(alloc::vec::Vec::new());

/// Releases the references `vrele_deferred` queued.
pub(crate) fn drain_deferred() {
    loop {
        let Some(v) = DEFERRED.lock().pop() else { return };
        vrele(v.get());
    }
}

/// The file `(mp, fileid)` is gone (its storage freed): its vnode, if one is hashed, is reclaimed
/// so a new file given the same file ID gets a vnode of its own (FreeBSD's `vrecycle`). One on
/// the free list goes now; one between its last `vrele` and the free list (inside `inactive`) is
/// doomed, and that `vrele` frees it. One still in use is doomed.
pub(crate) fn vrecycle(mp: *mut Mount, fileid: u64) {
    let Some(v) = HASH.lock().get(&(mp as usize, fileid)).copied() else { return };
    let vp = v.get();
    let on_free_list = FREE.lock().age_of.contains_key(&v);
    if on_free_list {
        FREE.lock().remove(v);
        vgone(vp);
        free_vnode(vp);
    } else {
        vgone(vp);
    }
}

/// Whether `(mp, fileid)` has a vnode in use.
pub(crate) fn fileid_busy(mp: *mut Mount, fileid: u64) -> bool {
    let busy = HASH.lock().get(&(mp as usize, fileid)).is_some_and(|v| unsafe { (*v.get()).v_usecount } > 0);
    busy || DEFERRED.lock().iter().any(|v| unsafe { (*v.get()).v_mount == mp && (*v.get()).v_fileid == fileid })
}

/// Keeps the vnode's memory (`vhold`) without keeping the file active.
pub(crate) fn vhold(vp: *mut Vnode) {
    // SAFETY: as `vref`.
    let v = unsafe { &mut *vp };
    v.v_holdcnt += 1;
    if v.v_holdcnt == 1 && v.v_usecount == 0 {
        FREE.lock().remove(VnodeRef(vp as usize));
    }
}

pub(crate) fn vdrop(vp: *mut Vnode) {
    // SAFETY: the caller's hold keeps it live.
    let v = unsafe { &mut *vp };
    assert!(v.v_holdcnt > 0, "vdrop: vnode not held");
    v.v_holdcnt -= 1;
    if v.v_holdcnt == 0 && v.v_usecount == 0 && v.v_flag & VI_ININACT == 0 {
        if v.v_flag & VI_DOOMED != 0 {
            free_vnode(vp);
        } else {
            FREE.lock().push(VnodeRef(vp as usize));
        }
    }
}

/// Recycles the oldest free vnode, if any.
fn recycle_one() {
    let Some(v) = FREE.lock().pop_oldest() else { return };
    vgone(v.get());
    free_vnode(v.get());
}

/// Disassociates a vnode from its file (`vgone`): `reclaim`, out of the hash, operations no longer
/// reach the file system. Its memory stays until the last reference goes.
pub(crate) fn vgone(vp: *mut Vnode) {
    // SAFETY: the caller keeps it live.
    let v = unsafe { &mut *vp };
    if v.v_flag & VI_DOOMED != 0 {
        return;
    }
    v.v_flag |= VI_DOOMED;
    crate::kern::vfs_cache::purge(vp);
    {
        let mut hash = HASH.lock();
        let key = (v.v_mount as usize, v.v_fileid);
        if hash.get(&key).is_some_and(|f| f.0 == vp as usize) {
            hash.remove(&key);
        }
    }
    // SAFETY: as in `vrele`.
    if let Some(reclaim) = unsafe { (*v.v_op).reclaim } {
        let _lock = fslock::Guard::for_call(reclaim as usize as u64);
        reclaim(vp);
    }
    // Its file system is done with it: its data goes back now and it leaves the mount, which a
    // forced unmount may free while the vnode lives on in its holders.
    let mp = v.v_mount;
    // SAFETY: the vnode's live mount and its type, before it leaves them.
    unsafe {
        dealloc(v.v_data as *mut u8, v_data_layout(vfc_of(mp).v_data_size));
        (*mp).mnt_nvnodes -= 1;
    }
    v.v_data = ptr::null_mut();
    v.v_mount = dead_mount();
    v.v_type = VBAD;
    // Its cached pages are of a file that's gone or being forgotten (FreeBSD's
    // `vnode_destroy_vobject`). Last: dropping the cache's hold may free the vnode, when nothing
    // else has it.
    crate::memory::pagecache::vnode_gone(vp as u64);
}

/// Frees a doomed vnode with no references.
fn free_vnode(vp: *mut Vnode) {
    // SAFETY: `vp` came from `Box::into_raw` in `getnewvnode`, is doomed and unreferenced: nothing
    // else can reach it (the hash and the free list no longer hold it). `vgone` already gave its
    // file system's data back and left its mount.
    unsafe { drop(Box::from_raw(vp)) };
    NUMVNODES.fetch_sub(1, Ordering::Relaxed);
}

/// What a vnode belongs to once `vgone` has disassociated it (FreeBSD's `dead_mount` and deadfs
/// type): a doomed vnode can outlive its mount (a forced unmount, `revoke(2)` of a file still in
/// use), so it never points at one again.
fn dead_mount() -> *mut Mount {
    static DEAD: Mutex<usize> = Mutex::new(0);
    static DEAD_VOPS: VopVector = VopVector::DEFAULT;
    static DEAD_VFSOPS: VfsOps = VfsOps { mount: None, unmount: None, root: None, statfs: None, sync: None, vget: None };
    static DEAD_VFSCONF: VfsConf = VfsConf {
        name: b"deadfs".as_ptr(),
        name_len: 6,
        ops: &DEAD_VFSOPS,
        vops: &DEAD_VOPS,
        mnt_data_size: 0,
        v_data_size: 0,
        flags: VFCF_SYNTHETIC | VFCF_NOCACHE,
    };
    let mut dead = DEAD.lock();
    if *dead == 0 {
        *dead = Box::into_raw(Box::new(Mount {
            mnt_vfc: &DEAD_VFSCONF,
            mnt_flag: MNT_RDONLY,
            mnt_data: ptr::null_mut(),
            mnt_vnodecovered: ptr::null_mut(),
            mnt_dev: NODEV,
            mnt_fsid: 0,
            mnt_nvnodes: 0,
            mnt_onname: [0; MNAMELEN],
            mnt_fromname: [0; MNAMELEN],
        })) as usize;
    }
    *dead as *mut Mount
}

/// Reclaims every unreferenced vnode of `mp` (unmount's `vflush`). Returns how many vnodes of it
/// are still referenced.
pub(crate) fn vflush(mp: *mut Mount) -> u64 {
    let mine: alloc::vec::Vec<VnodeRef> = {
        let mut free = FREE.lock();
        // SAFETY: free vnodes are live.
        let mine: alloc::vec::Vec<VnodeRef> =
            free.by_age.values().copied().filter(|v| unsafe { (*v.get()).v_mount } == mp).collect();
        for &v in &mine {
            free.remove(v);
        }
        mine
    };
    for v in mine {
        vgone(v.get());
        free_vnode(v.get());
    }
    // SAFETY: `mp` is live.
    unsafe { (*mp).mnt_nvnodes }
}

/// Lets go of the page cache's idle entries for `mp`'s vnodes nothing uses: such an entry only
/// holds its vnode (`vhold`), which would keep the vnode off the free list and the mount busy.
/// Unmount drops them first, as FreeBSD's frees a vnode's cached pages with it.
pub(crate) fn release_cached(mp: *mut Mount) {
    let idle: alloc::vec::Vec<VnodeRef> = HASH
        .lock()
        .iter()
        .filter(|((m, _), _)| *m == mp as usize)
        .map(|(_, &v)| v)
        // SAFETY: hashed vnodes are live.
        .filter(|v| unsafe { (*v.get()).v_usecount == 0 && (*v.get()).v_holdcnt > 0 })
        .collect();
    for v in idle {
        crate::memory::pagecache::vnode_gone(v.get() as u64);
    }
}

/// Retires every vnode of `mp` still in use (a forced unmount, FreeBSD's `vflush(FORCECLOSE)`):
/// their holders keep doomed vnodes, whose operations reach no file system.
pub(crate) fn vgone_all(mp: *mut Mount) {
    let mine: alloc::vec::Vec<VnodeRef> =
        HASH.lock().iter().filter(|((m, _), _)| *m == mp as usize).map(|(_, &v)| v).collect();
    for v in mine {
        vgone(v.get());
    }
}

/// FreeBSD's `vaccess`: may `cred` do `accmode` to a file of type `vtype`, permission bits `mode`,
/// owned by `uid:gid`? Root may do anything but execute a file no one may execute.
pub(crate) fn vaccess(vtype: VType, mode: u32, uid: u32, gid: u32, accmode: u32, cred: &Ucred) -> i32 {
    let (cuid, real) = if accmode & VACCESS_REAL != 0 { (cred.cr_ruid, true) } else { (cred.cr_uid, false) };
    let want = accmode & (VREAD | VWRITE | VEXEC);
    if cuid == 0 {
        if want & VEXEC != 0 && vtype != VDIR && mode & 0o111 == 0 {
            return EACCES;
        }
        return 0;
    }
    if accmode & VADMIN != 0 && cuid != uid {
        return EPERM;
    }
    let in_group = if real {
        cred.cr_rgid == gid || cred.groupmember(gid)
    } else {
        cred.groupmember(gid)
    };
    // The owner's bits apply to the owner, the group's to a member, the rest to everyone else:
    // never the union (an owner denied by its own bits is denied).
    let granted = if cuid == uid {
        (mode >> 6) & 7
    } else if in_group {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    // VREAD/VWRITE/VEXEC are the owner bits (0o400/0o200/0o100).
    if (want >> 6) & !granted == 0 { 0 } else { EACCES }
}

/// The calling process's credentials as a `Ucred`.
pub(crate) fn current_ucred() -> Ucred {
    let c = crate::process::identity::current_cred();
    let mut cred = Ucred {
        cr_uid: c.euid,
        cr_gid: c.egid,
        cr_ruid: c.ruid,
        cr_rgid: c.rgid,
        cr_ngroups: c.groups.len().min(NGROUPS) as u32,
        cr_groups: [0; NGROUPS],
    };
    for (slot, g) in cred.cr_groups.iter_mut().zip(c.groups.iter()) {
        *slot = *g;
    }
    cred
}

// --- Module exports ------------------------------------------------------------------------------

pub(crate) extern "C" fn oxidebsd_getnewvnode(mp: *mut Mount, vtype: VType, fileid: u64, vpp: *mut *mut Vnode) -> i32 {
    match getnewvnode(mp, vtype, fileid, ptr::null()) {
        Ok(vp) => {
            // SAFETY: the caller passes a place for the vnode.
            unsafe { *vpp = vp };
            0
        }
        Err(e) => e,
    }
}

pub(crate) extern "C" fn oxidebsd_vfs_hash_get(mp: *mut Mount, fileid: u64) -> *mut Vnode {
    hash_get(mp, fileid)
}

pub(crate) extern "C" fn oxidebsd_vfs_hash_insert(vp: *mut Vnode) {
    hash_insert(vp)
}

pub(crate) extern "C" fn oxidebsd_vfs_hash_rehash(vp: *mut Vnode, fileid: u64) {
    hash_rehash(vp, fileid)
}

pub(crate) extern "C" fn oxidebsd_vfs_fileid_busy(mp: *mut Mount, fileid: u64) -> i32 {
    fileid_busy(mp, fileid) as i32
}

pub(crate) extern "C" fn oxidebsd_vfs_recycle(mp: *mut Mount, fileid: u64) {
    vrecycle(mp, fileid)
}

pub(crate) extern "C" fn oxidebsd_vhold(vp: *mut Vnode) {
    vhold(vp)
}

pub(crate) extern "C" fn oxidebsd_vdrop(vp: *mut Vnode) {
    vdrop(vp)
}

pub(crate) extern "C" fn oxidebsd_vref(vp: *mut Vnode) {
    vref(vp)
}

pub(crate) extern "C" fn oxidebsd_vrele(vp: *mut Vnode) {
    vrele(vp)
}

pub(crate) extern "C" fn oxidebsd_vaccess(
    vtype: VType,
    mode: u32,
    uid: u32,
    gid: u32,
    accmode: u32,
    cred: *const Ucred,
) -> i32 {
    if cred.is_null() {
        return EOPNOTSUPP;
    }
    // SAFETY: the kernel's own `Ucred`, passed back by the file system.
    vaccess(vtype, mode, uid, gid, accmode, unsafe { &*cred })
}
