//! The name cache (OxideBSD-doc `VFS.md` §6.2): `(directory vnode, name) -> vnode`, with negative
//! entries for names that aren't there, so a lookup of a path walked before needn't ask the file
//! system. FreeBSD's `vfs_cache.c` in miniature.
//!
//! Entries don't reference their vnodes: `vgone` purges every entry naming a vnode, as directory
//! or as target, before the vnode can go, so an entry never dangles. `remove`, `rmdir`, `rename`
//! and creating a name purge what they change. The cache is bounded (twice `kern.maxvnodes`);
//! past that the oldest entry goes.
//!
//! The reverse index (vnode -> the names it's cached under) also answers `getcwd(3)`'s question,
//! "what is this directory called in its parent", without reading the parent (FreeBSD's
//! `vn_fullpath`); a directory the cache has forgotten falls back to looking itself up in `..`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;
use vfs_if::Vnode;

/// What a lookup found: the vnode, or that the name is known not to exist.
#[derive(Clone, Copy)]
pub(crate) enum Hit {
    Found(*mut Vnode),
    Missing,
}

struct Cache {
    /// `(directory, name) -> (vnode, or 0 for a negative entry; age)`.
    entries: BTreeMap<(usize, Vec<u8>), (usize, u64)>,
    /// `age -> key`, to drop the oldest.
    by_age: BTreeMap<u64, (usize, Vec<u8>)>,
    /// `vnode -> keys naming it` (positive entries only).
    names_of: BTreeMap<usize, Vec<(usize, Vec<u8>)>>,
    next_age: u64,
    /// `vnode -> (directory, name)` it was last opened through (`note_opened`): for `fullpath` of a
    /// file the cache keeps nothing for (devfs's, procfs's) or has forgotten. Never a lookup answer.
    opened: BTreeMap<usize, (usize, Vec<u8>)>,
}

static CACHE: Mutex<Cache> =
    Mutex::new(Cache {
        entries: BTreeMap::new(),
        by_age: BTreeMap::new(),
        names_of: BTreeMap::new(),
        next_age: 0,
        opened: BTreeMap::new(),
    });

/// `vfs.cache.numentries` and lookup counters (`vfs.cache.hits`, `vfs.cache.misses`).
static HITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MISSES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub(crate) fn stats() -> (u64, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (CACHE.lock().entries.len() as u64, HITS.load(Relaxed), MISSES.load(Relaxed))
}

fn limit() -> usize {
    (crate::kern::vfs_subr::maxvnodes() * 2) as usize
}

impl Cache {
    fn remove_key(&mut self, key: &(usize, Vec<u8>)) {
        let Some((vp, age)) = self.entries.remove(key) else { return };
        self.by_age.remove(&age);
        if vp != 0 {
            if let Some(names) = self.names_of.get_mut(&vp) {
                names.retain(|k| k != key);
                if names.is_empty() {
                    self.names_of.remove(&vp);
                }
            }
        }
    }
}

/// `cache_lookup`: what the cache knows about `name` in `dvp`.
pub(crate) fn lookup(dvp: *mut Vnode, name: &[u8]) -> Option<Hit> {
    use core::sync::atomic::Ordering::Relaxed;
    let cache = CACHE.lock();
    match cache.entries.get(&(dvp as usize, name.to_vec())) {
        Some(&(0, _)) => {
            HITS.fetch_add(1, Relaxed);
            Some(Hit::Missing)
        }
        Some(&(vp, _)) => {
            HITS.fetch_add(1, Relaxed);
            Some(Hit::Found(vp as *mut Vnode))
        }
        None => {
            MISSES.fetch_add(1, Relaxed);
            None
        }
    }
}

/// `cache_enter`: `name` in `dvp` is `vp` (null: known missing).
pub(crate) fn enter(dvp: *mut Vnode, name: &[u8], vp: *mut Vnode) {
    if name == b"." || name == b".." {
        return;
    }
    let mut cache = CACHE.lock();
    let key = (dvp as usize, name.to_vec());
    cache.remove_key(&key);
    while cache.entries.len() >= limit() {
        let Some(oldest) = cache.by_age.values().next().cloned() else { break };
        cache.remove_key(&oldest);
    }
    cache.next_age += 1;
    let age = cache.next_age;
    cache.entries.insert(key.clone(), (vp as usize, age));
    cache.by_age.insert(age, key.clone());
    if !vp.is_null() {
        cache.names_of.entry(vp as usize).or_default().push(key);
    }
}

/// Forgets `name` in `dvp` (`cache_purge_name`: a remove, a rename's source or target, a create
/// over a negative entry).
pub(crate) fn purge_name(dvp: *mut Vnode, name: &[u8]) {
    CACHE.lock().remove_key(&(dvp as usize, name.to_vec()));
}

/// Forgets everything naming `vp` and everything in it if it's a directory (`cache_purge`: before
/// `vgone`, a `rmdir`, a rename of a directory).
pub(crate) fn purge(vp: *mut Vnode) {
    let mut cache = CACHE.lock();
    let as_target = cache.names_of.get(&(vp as usize)).cloned().unwrap_or_default();
    for key in as_target {
        cache.remove_key(&key);
    }
    let as_dir: Vec<(usize, Vec<u8>)> = cache
        .entries
        .range((vp as usize, Vec::new())..)
        .take_while(|((d, _), _)| *d == vp as usize)
        .map(|(k, _)| k.clone())
        .collect();
    for key in as_dir {
        cache.remove_key(&key);
    }
    cache.opened.remove(&(vp as usize));
    cache.opened.retain(|_, (d, _)| *d != vp as usize);
}

/// Remembers that `vp` was opened as `name` in `dvp`, for `fullpath` (`/proc/<pid>/fd/<n>`,
/// `ttyname`).
pub(crate) fn note_opened(dvp: *mut Vnode, name: &[u8], vp: *mut Vnode) {
    CACHE.lock().opened.insert(vp as usize, (dvp as usize, name.to_vec()));
}

/// Forgets every negative entry in `dvp` (a create in it: cheaper than knowing which name).
pub(crate) fn purge_negative(dvp: *mut Vnode) {
    let mut cache = CACHE.lock();
    let negative: Vec<(usize, Vec<u8>)> = cache
        .entries
        .range((dvp as usize, Vec::new())..)
        .take_while(|((d, _), _)| *d == dvp as usize)
        .filter(|(_, (v, _))| *v == 0)
        .map(|(k, _)| k.clone())
        .collect();
    for key in negative {
        cache.remove_key(&key);
    }
}

/// A name `vp` is cached under and the directory it's in, for `getcwd`.
pub(crate) fn name_of(vp: *mut Vnode) -> Option<(*mut Vnode, Vec<u8>)> {
    let cache = CACHE.lock();
    let (dvp, name) = match cache.names_of.get(&(vp as usize)).and_then(|n| n.last()) {
        Some(k) => k.clone(),
        None => cache.opened.get(&(vp as usize))?.clone(),
    };
    Some((dvp as *mut Vnode, name))
}
