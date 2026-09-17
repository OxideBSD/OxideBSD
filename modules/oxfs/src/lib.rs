//! `oxfs`: a small, real Unix-shaped filesystem (inodes with direct + single-indirect block
//! pointers, directories as ordinary inodes holding fixed-size records, real multi-component path
//! resolution, real per-process current-working-directory) -- replacing `modules/fat32` as the
//! filesystem `stsh`/BusyBox actually run on. See `CLAUDE.md`'s oxfs section for the full design
//! rationale; `modules/fat32` is kept in the workspace, still building and self-checking on every
//! `cargo build`, but is no longer loaded at boot.
//!
//! Like `modules/fat32`, this is in-memory only -- no real block device exists yet, so nothing
//! persists across reboot. Unlike FAT32, there's no on-disk *format* to invent or generate at
//! build time at all: `module_init` below populates the inode table directly via ordinary function
//! calls, using content `build.rs` hands this crate's own `include_bytes!(env!(...))` calls (each
//! already-built userland/BusyBox ELF gets its own env var, the same `extra_env` mechanism
//! `FAT32_IMAGE_PATH` already used) or, for the two small text files, a literal and the same
//! `b'A' + i % 26` formula `modules/fat32`'s own self-check already used.
//!
//! **What this fixes relative to FAT32** (see CLAUDE.md's FAT32 section for the full list of
//! limitations this replaces): 8.3 short names -> real names up to `NAME_MAX` bytes; one path
//! component per syscall call -> real multi-component `a/b/c`/`../x`/`/a/b` resolution in one call
//! (`resolve_path`/`resolve_parent` below); a directory that can never grow past its first
//! cluster -> a directory's own inode grows additional blocks like any other file; a fixed
//! per-open-file read cap (`MAX_FILE_BUFFER`, raised three times) -> real files stream straight
//! from their own block chain on each `read()`, capped only by the block pool itself; one
//! kernel-wide current directory shared by every process -> real per-process cwd
//! (`Process::cwd` in `src/process.rs`, via `oxidebsd_get_cwd`/`oxidebsd_set_cwd`); no
//! `unlink`/`rmdir`/`rename` at all -> all three now exist.
//!
//! **Storage**, all fixed-size `static mut` arrays (modules can't use `alloc`/`Vec`/`BTreeMap` --
//! see CLAUDE.md's module-loading section): a flat pool of `NUM_BLOCKS` `BLOCK_SIZE`-byte blocks
//! (`BLOCKS`/`BLOCK_USED`), and a flat table of `MAX_INODES` inodes (`INODES`). An inode holds up
//! to `DIRECT_BLOCKS` block numbers directly plus one single-indirect block (another
//! `BLOCK_SIZE / 4` pointers) -- max file size is bounded only by the block pool, not by an
//! arbitrary per-file cap.
//!
//! **Directories are ordinary inodes** whose data blocks hold fixed 32-byte records
//! (`{ used: u8, name_len: u8, inode: u32, name: [u8; NAME_MAX] }`, `NAME_MAX = 26`) --
//! `RECORDS_PER_BLOCK = BLOCK_SIZE / 32 = 128` entries per block. A directory that fills its
//! current blocks grows another one via the same `inode_ensure_block_at` every other file write
//! uses, rather than failing outright the way FAT32's own `DirectoryFull` did. `unlink`/`rmdir`
//! just clear a record's `used` byte -- the underlying inode/blocks are never freed, matching this
//! codebase's blanket "no deallocation anywhere" policy (`do_munmap`, module unload, etc.).
//!
//! **Root is a fixed inode number (`ROOT_INODE = 0`)**, self-referencing `.`/`..` (root's `..`
//! points at itself) -- no FAT32-style "`0` means root" special-casing needed, since there's no
//! on-disk format to stay compatible with. `ROOT_INODE`'s value (`0`) deliberately coincides with
//! `Process::cwd`'s own default (`0`, "unset") -- a freshly spawned process's cwd is root with no
//! translation needed.
//!
//! **Syscalls registered at the exact numbers `modules/fat32` used** (so nothing else in the ABI
//! changes): `SYS_OPEN = 5`, `SYS_CLOSE = 6`, `SYS_CHDIR = 12`, `SYS_MKDIR = 136`,
//! `SYS_GETCWD = 108`. Plus three new ones, OxideBSD-own-invented numbers continuing from `108`
//! (per this project's own established convention -- syscalls added after the musl/BusyBox port
//! invent their own numbers rather than copying FreeBSD's, see `SYS_GETPPID`/`SYS_GETCWD`/
//! `SYS_PIPE`/`SYS_DUP2`): `SYS_UNLINK = 109`, `SYS_RMDIR = 110`,
//! `SYS_RENAME = 111` (`(old_ptr, old_len, new_ptr, new_len)` -- uses all four of this ABI's
//! argument registers, the same precedent `execve`'s `envp_ptr` set for needing `R10`). Plus
//! `SYS_FSTAT = 126`, `SYS_STAT = 127`, `SYS_LSTAT = 128` (continuing past `SYS_DUP = 125`, the
//! highest number any module had claimed) -- see `write_stat`'s own doc comment for the wire
//! format and what's synthesized vs. real. Plus `SYS_GETDENTS = 129` -- real `readdir()`'s own
//! syscall, see `oxfs_getdents`'s own doc comment for the wire format.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_alloc_fd() -> u64;
    fn oxidebsd_register_fd_ops(
        fd: u64,
        read: extern "C" fn(u64, u64, u64) -> i64,
        write: extern "C" fn(u64, u64, u64) -> i64,
        close: extern "C" fn(u64) -> i64,
    ) -> i32;
    fn oxidebsd_close_fd(fd: u64) -> i32;
    fn oxidebsd_get_cwd() -> u64;
    fn oxidebsd_set_cwd(inode: u64);
    fn oxidebsd_get_root() -> u64;
    fn oxidebsd_set_root(inode: u64);
    fn oxidebsd_real_fd_of(fd: u64) -> i64;
    fn oxidebsd_proc_exists(pid: u64) -> i32;
    fn oxidebsd_proc_pid_at(index: u64) -> i64;
    fn oxidebsd_proc_stat_line(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_cmdline(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_status(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_meminfo(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_uptime(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_stat_global(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_modules(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_fd_at(pid: u64, index: u64) -> i64;
    fn oxidebsd_random_bytes(ptr: u64, len: u64) -> i64;
    fn oxidebsd_current_uid() -> u64;
    fn oxidebsd_current_gid() -> u64;
    /// `1`/`0` -- whether `src/ata.rs`'s fixed data-disk channel/drive responded to `IDENTIFY` at
    /// boot. `false` (`0`) means every mutation stays purely in-memory this boot, same as before
    /// this pass existed at all -- see `module_init`'s own doc comment.
    fn oxidebsd_block_device_present() -> i64;
    /// Reads/writes one `BLOCK_SIZE`-byte oxfs block (`block_no`, this module's own block-number
    /// space -- NOT a raw disk LBA) from/to `buf_ptr`, an already-allocated `BLOCK_SIZE`-byte
    /// buffer in this module's own memory. `0` on success, `-1` on any failure (no device,
    /// timeout, device error). See `src/ata.rs`'s own doc comment for the real sector-level I/O
    /// this translates into.
    fn oxidebsd_block_read(block_no: u64, buf_ptr: u64) -> i64;
    fn oxidebsd_block_write(block_no: u64, buf_ptr: u64) -> i64;
}

const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
/// Real x86_64 Linux's own `__NR_lseek` value -- confirmed against
/// `third_party/musl/arch/x86_64/bits/syscall.h.in` still at its inert value (no prior pass ever
/// needed it), and musl's own `lseek()` (`src/unistd/lseek.c`) already issues a plain
/// `syscall(SYS_lseek, fd, offset, whence)` with no `SYS__llseek` fallback on this arch -- no
/// musl-side patch needed at all, unlike almost every other syscall this ABI has added. Found live
/// via TinyCC (see CLAUDE.md's TinyCC section): its own object-file loader needs a real file size
/// upfront (`fseek(f, 0, SEEK_END)`/`ftell`) to read `crt1.o`/`libc.a` whole into memory before
/// parsing their real ELF/ar headers -- without this registered, that `fseek` silently failed
/// (`[boot] unrecognized syscall number 8`), and tcc's own file-loading code doesn't check the
/// return value, so it went on to read a garbage/zero-length buffer and reported `invalid object
/// file` for every crt/lib file it opened, not just "not found".
const SYS_LSEEK: u64 = 8;
/// Real x86_64 Linux's own `__NR_access` value -- like `SYS_LSEEK` above, still at its inert
/// value in `third_party/musl/arch/x86_64/bits/syscall.h.in` (confirmed unclaimed by grepping
/// every already-registered syscall number in this codebase), so no remap was needed, only the
/// argument-convention patch every path-taking syscall needs (see `oxfs_access`'s own doc
/// comment). Found live: `[boot] unrecognized syscall number 21` whenever real `access(2)` (PATH
/// search via `execvp`, `test -e`/`-r`/`-w`/`-x`, ...) was reached.
const SYS_ACCESS: u64 = 21;
const SYS_CHDIR: u64 = 12;
const SYS_MKDIR: u64 = 136;
const SYS_GETCWD: u64 = 108;
const SYS_UNLINK: u64 = 109;
const SYS_RMDIR: u64 = 110;
const SYS_RENAME: u64 = 111;
const SYS_FSTAT: u64 = 126;
const SYS_STAT: u64 = 127;
const SYS_LSTAT: u64 = 128;
const SYS_GETDENTS: u64 = 129;
/// Next two syscall numbers after `SYS_READV=153` (`src/syscall.rs`'s own highest at the time this
/// was added) -- real POSIX `readlink(2)`/`symlink(2)`, backing `modules/oxfs`'s new general
/// `InodeKind::Symlink` support (see `resolve_path_impl`'s own doc comment).
const SYS_READLINK: u64 = 154;
const SYS_SYMLINK: u64 = 155;
/// Next two after `modules/posix_compat`'s own `SYS_GETGROUPS = 164` (`src/syscall.rs`'s highest
/// at the time this was added) -- real `chmod(2)`/`chown(2)`, backing this module's new per-inode
/// `mode`/`uid`/`gid` fields. Filesystem-owned data, so these live here rather than in
/// `posix_compat` (same reasoning `SYS_STAT`/`SYS_FSTAT`/`SYS_LSTAT` already established).
const SYS_CHMOD: u64 = 165;
const SYS_CHOWN: u64 = 166;
/// Real Linux's own `__NR_fchmod` value, used directly rather than an invented number -- see
/// `oxfs_fchmod`'s own doc comment for why.
const SYS_FCHMOD: u64 = 91;
/// Next after `SYS_CHOWN=166` -- see `oxfs_utimensat`'s own doc comment for what this actually
/// does (a real existence check, no real timestamp storage) and why that's enough to unblock
/// BusyBox's `touch.c`.
const SYS_UTIMENSAT: u64 = 167;
/// The mount table (see this module's own "Mount table" section above `MAX_MOUNTS`). Real
/// `mount(2)` takes 5 conceptual args (`special, dir, fstype, flags, data`), which doesn't fit
/// this ABI's 4 registers -- rather than force one idealized shape, this splits into the two
/// concrete shapes BusyBox's own `mount.c` actually needs (`--bind`/`-t tmpfs`), matching the
/// existing precedent of patching the musl call site instead (`open`/`execve`/`rename`/`chown`
/// already do this; see `third_party/musl/src/linux/mount.c`'s own patch, which dispatches to
/// whichever of these two applies based on its own real `fstype` argument). **Not** the next three
/// numbers after `SYS_UTIMENSAT=167` (168/169/170), despite every recent addition otherwise just
/// continuing that sequence: those three real-Linux slots are `swapoff`/`reboot`/`sethostname`,
/// all three already-seeded, already-built BusyBox applets in this port's roster that currently
/// `ENOSYS` cleanly -- claiming those numbers would have silently misrouted a real call from any
/// of them into the mount table instead. Landed on 174-176 instead (real Linux
/// `create_module`/`init_module`/`delete_module` -- long-obsolete even on real Linux, and `insmod`/
/// `rmmod`/`modprobe` never became build candidates in this port at all, see
/// `docs/BUSYBOX_APPLETS.md`'s own note on `lsmod`), matching the musl-side patch's own explanation
/// (`third_party/musl/arch/x86_64/bits/syscall.h.in`).
const SYS_MOUNT_BIND: u64 = 174;
const SYS_MOUNT_TMPFS: u64 = 175;
/// Real `umount2(2)`'s own wire format fits this ABI's 4 registers whole (just the length-prefixed
/// path convention added, same as every other path-taking syscall here) -- no shape change needed,
/// unlike `mount` above.
const SYS_UMOUNT2: u64 = 176;

/// `SYS_FSYNC=471` through `SYS_FSTATFS=477` (continuing with `SYS_PRLIMIT64=478` through
/// `SYS_REBOOT=486` in `modules/posix_compat`) are the NEEDS_SYSCALL gap-table pass's own
/// filesystem-owned half. All seven landed at 471-486, not a continuation of this ABI's existing
/// 105-178 invented sequence -- a first attempt at continuing that sequence collided with a
/// *second* set of real, still-inert Linux syscalls sharing those same low numbers further down
/// `third_party/musl/arch/x86_64/bits/syscall.h.in` (e.g. real `__NR_gettid=186`, which has a live
/// caller inside musl itself, `src/thread/synccall.c`) -- see that file's own comment on
/// `__NR_flock` (right near `__NR_fsync`) for the full story on why 471-486 is provably
/// collision-free instead. `SYS_FSYNC`/`SYS_SYNC` force-commit a still-open fd's pending write
/// buffer to its real inode (oxfs's write model otherwise only commits at `close()`, see
/// `OpenFile::Write`'s own doc comment) -- `oxfs_fsync` for one fd, `oxfs_sync` for every
/// currently-open write fd at once. `SYS_FTRUNCATE`/`SYS_FALLOCATE` resize a file's real content
/// directly at the block level (`resize_inode_data`, not `write_inode_data` -- materializing a
/// whole file's content into one stack buffer first would risk overflowing this kernel's 128 KiB
/// kernel-stack floor for anything near this filesystem's ~4 MiB per-file cap).
/// `SYS_FLOCK` is a real per-inode `LOCK_SH`/`LOCK_EX`/`LOCK_UN` advisory-lock table
/// (`FLOCKS`) -- but a request that would conflict fails `EAGAIN` immediately even without
/// `LOCK_NB`, rather than genuinely blocking: this module has no scheduler-yield primitive
/// reachable from a syscall handler, and a real spin-wait here would permanently deadlock this
/// single-core, non-preemptive kernel against a lock holder that could never run to release it.
/// `SYS_STATFS`/`SYS_FSTATFS` report a real `struct statfs` built from this filesystem's own live
/// block/inode-usage counts (separately for the real vs. tmpfs pool, `write_statfs`), backing
/// `df`'s real `statvfs(3)` call.
const SYS_FSYNC: u64 = 471;
const SYS_SYNC: u64 = 472;
const SYS_FTRUNCATE: u64 = 473;
const SYS_FALLOCATE: u64 = 474;
const SYS_FLOCK: u64 = 475;
const SYS_STATFS: u64 = 476;
const SYS_FSTATFS: u64 = 477;

/// Continues past `SYS_UMASK = 487` (the highest number assigned anywhere in this ABI before this
/// pass -- see `modules/posix_compat`), not the `471`-`477` batch above -- confirmed via the same
/// "grep every still-inert real Linux `__NR_*` value in `bits/syscall.h.in`" audit those numbers
/// needed: none of real Linux's own `link`/`mknod`/`mknodat`/`chroot`/`getrusage` values (86/133/
/// 259/161/98) land anywhere near 488-491. `SYS_LINK`/`SYS_MKNOD` implement real hard links and
/// device-node creation (see `oxfs_link`/`oxfs_mknod`'s own doc comments -- neither existed before
/// this pass, since `Inode` had no link count and this filesystem had no device-node concept
/// distinct from `dev_open`'s own magic-path interception). `SYS_CHROOT` gives each process a real,
/// per-process root inode (`Process::root_inode` in `src/process.rs`).
const SYS_LINK: u64 = 488;
const SYS_MKNOD: u64 = 489;
const SYS_CHROOT: u64 = 490;

/// Same real POSIX value FAT32's own `O_CREAT` already uses (`0o100`, not an arbitrary bit) --
/// see `modules/fat32`'s own doc comment for why matching the real bit matters (musl's real
/// `open()` passes real POSIX flag values).
const O_CREAT: u64 = 0o100;

/// Real generic (this target has no x86_64-specific override, see `third_party/musl/arch/
/// generic/bits/fcntl.h`) POSIX values, backing real write-to-an-existing-file support in
/// `oxfs_open` -- see that function's own doc comment for why these matter now (they didn't
/// before: every open of an existing path used to always end up read-only regardless of what the
/// caller actually asked for).
const O_ACCMODE: u64 = 0o3;
const O_APPEND: u64 = 0o2000;

/// Real POSIX `st_mode` file-type bits (`S_IFREG`/`S_IFDIR`/`S_IFLNK`) -- these are the type bits
/// only, ORed with an inode's own real `mode` field (permission bits) when building a `stat`
/// result. `FIXED_PERM` remains the default *value* every fresh inode's `mode` starts at
/// (`0o755`), not a hardcoded stand-in for permissions any more -- see `SYS_CHMOD`'s own doc
/// comment (`oxfs_chmod`) for how it actually changes now.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
/// Real POSIX value, no Linux/BSD divergence -- backs `InodeKind::Symlink`.
const S_IFLNK: u32 = 0o120000;
/// Real POSIX values, no Linux/BSD divergence -- back `InodeKind::Device`'s two flavors (see
/// `oxfs_mknod`'s own doc comment).
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
/// Real POSIX mask isolating the type bits above out of a raw `mode_t` -- used by `oxfs_mknod` to
/// read the caller's requested node type back out of its own `mode` argument.
const S_IFMT: u32 = 0o170000;
const FIXED_PERM: u32 = 0o755;

/// Real `d_type` values (`include/dirent.h` on the `oxidebsd` musl branch) for `SYS_GETDENTS`'s
/// own wire format -- see `write_dirent_record`'s own doc comment.
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
/// Real value, no Linux/BSD divergence -- reported for an `InodeKind::Symlink` entry.
const DT_LNK: u8 = 10;
/// Real values, no Linux/BSD divergence -- reported for an `InodeKind::Device` entry (see
/// `oxfs_mknod`'s own doc comment).
const DT_CHR: u8 = 2;
const DT_BLK: u8 = 6;

const EBADF: i64 = 9;
const ENOENT: i64 = 2;
const EBUSY: i64 = 16;
const EEXIST: i64 = 17;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EMFILE: i64 = 24;
const ENOSPC: i64 = 28;
const EIO: i64 = 5;
const EINVAL: i64 = 22;
const ERANGE: i64 = 34;
/// musl's real compiled value (`third_party/musl/arch/generic/bits/errno.h`, `29` -- same on
/// FreeBSD, no divergence to worry about here). Returned by `oxfs_lseek` for a fd this filesystem
/// has no real position to seek within (an in-progress `Write`, or a synthetic `/dev/*` node).
const ESPIPE: i64 = 29;
/// FreeBSD's value (`66`), not Linux's (`39`) -- matching this codebase's established convention
/// of using FreeBSD errno values where they diverge (see `src/syscall.rs`'s own `ENOSYS`).
const ENOTEMPTY: i64 = 66;
/// Real value (`3`, same on FreeBSD/Linux) -- returned when a `/proc/<pid>/...` path's `pid`
/// vanishes between `proc_open`'s own existence check and the kernel accessor call that follows it.
const ESRCH: i64 = 3;
/// musl's real *compiled* value (`third_party/musl/arch/generic/bits/errno.h:40`) -- **not**
/// FreeBSD's `62`, which would repeat exactly the errno-divergence bug class `CLAUDE.md`'s
/// syscall-ABI section already documents at length (a real-BSD-nod value that doesn't match what
/// musl's own header actually defines the symbolic name as). Returned when `resolve_path_impl`'s
/// own symlink-following recursion exceeds `MAX_SYMLINK_DEPTH`.
const ELOOP: i64 = 40;
/// Real value, no Linux/BSD divergence -- returned by any mutating real-filesystem operation
/// (`mkdir`/`unlink`/`rmdir`/`rename`) attempted relative to a synthetic `/proc` cwd (see
/// `real_cwd_for_mutation`'s own doc comment).
const EROFS: i64 = 30;
/// Real value, no Linux/BSD divergence -- returned by `oxfs_chmod`/`oxfs_chown` when the caller
/// isn't allowed to perform the requested ownership/permission change (see `check_owner_access`'s
/// own doc comment), and by `oxfs_open`/the create-new-file path when `check_access` denies real
/// read/write permission.
const EPERM: i64 = 1;
const EACCES: i64 = 13;
/// musl's real *compiled* value (`third_party/musl/arch/generic/bits/errno.h:11`) -- `EWOULDBLOCK`
/// is a bare alias of this same value in musl (`#define EWOULDBLOCK EAGAIN`), not a distinct
/// number, so this one constant covers both real POSIX names. Returned by `oxfs_flock` for any
/// conflicting request, `LOCK_NB` or not -- see `SYS_FLOCK`'s own doc comment for why a genuinely
/// blocking wait isn't attempted.
const EAGAIN: i64 = 11;
/// Real value, no Linux/BSD divergence. Returned by `oxfs_flock` only if `FLOCKS`'s own fixed
/// table is completely full of *non-conflicting* locks on other inodes -- `MAX_FLOCKS` is sized
/// generously past any real concurrent use this port's roster exercises, so this is a defensive
/// bound, not an expected outcome.
const ENOLCK: i64 = 37;
/// Real value, no Linux/BSD divergence. Returned by `oxfs_link` when a `File`/`Device` inode's
/// `nlink` is already at `u16::MAX` -- effectively unreachable in practice, a defensive bound like
/// `ENOLCK` above, not an expected outcome.
const EMLINK: i64 = 31;
/// musl's real *compiled* value (`third_party/musl/arch/generic/bits/errno.h:19`). Returned by
/// `oxfs_link` when `existing` and the new parent directory fall in different inode pools (the
/// real, disk-persisted pool vs. a tmpfs mount's own in-memory-only pool) -- real POSIX "different
/// filesystem" behavior, and load-bearing here specifically to stop a tmpfs-pool inode from
/// gaining a real, disk-persisted name that points at content never actually written through (see
/// `alloc_inode_in`'s own doc comment for the same real/tmpfs-pool concern elsewhere).
const EXDEV: i64 = 18;
/// musl's real *compiled* value (`third_party/musl/arch/generic/bits/errno.h:6`). Returned by
/// `oxfs_open` when a real `InodeKind::Device` entry's major:minor doesn't match one of the four
/// synthetic devices this kernel can actually service -- see `known_device`'s own doc comment for
/// the deliberately small, honestly documented scope boundary this represents.
const ENXIO: i64 = 6;

const BLOCK_SIZE: usize = 4096;
/// 32 MiB pool (raised from 4 MiB once the BusyBox roster grew from 24 applets to ~300 -- see
/// CLAUDE.md's BusyBox section -- whose combined embedded ELF bytes alone run to ~18 MiB), with
/// real headroom left over for runtime-created files (`stsh`'s `write` built-in, BusyBox's own
/// file creation). `src/memory.rs`'s frame allocator and this module's own eager, non-paged
/// mapping mean this whole pool becomes a real physical-memory commitment the moment the module
/// loads (see `Cargo.toml`'s `[package.metadata.bootimage]` `-m` bump, made at the same time as
/// this).
const NUM_BLOCKS: usize = 8192;
/// Raised from 64 alongside `NUM_BLOCKS` above, same reason -- ~300 applets plus root/`hello.txt`/
/// `big.txt`/the self-check's own `/gdtest` fixtures need comfortably more than 64 inode slots.
/// Raised again, 512 -> 1024, once TinyCC (`third_party/tinycc`, see CLAUDE.md's TinyCC section)
/// needed musl's entire real header tree seeded under `/usr/include` at runtime -- measured
/// exactly against the real built `target/musl-sysroot`, not estimated: 217 header files (plus
/// ~7 subdirectories) + ~9 `/usr/lib` crt/lib files + tcc's own `libtcc1.a` + 5 bundled headers +
/// the `tcc` binary itself is ~250 new inodes, overflowing the ~180 that were free at 512.
const MAX_INODES: usize = 1024;
const DIRECT_BLOCKS: usize = 12;
const PTRS_PER_INDIRECT: usize = BLOCK_SIZE / 4;
/// Sentinel for "no block"/"no indirect block" -- block numbers are plain indices into `BLOCKS`
/// starting at `0` (unlike FAT32's cluster numbering, which reserves `0`/`1`), so `0` itself can't
/// double as the sentinel the way it does there.
const NO_BLOCK: u32 = u32::MAX;

const ROOT_INODE: u32 = 0;

/// A second, purely in-memory pool reserved for tmpfs mounts (see `MountKind::Tmpfs`) -- 4 MiB,
/// modest on purpose (scratch space, not a real persisted store). Block/inode numbers `>=
/// NUM_BLOCKS`/`>= MAX_INODES` fall in this range; `BLOCKS`/`BLOCK_USED`/`INODES` below are simply
/// extended to cover it, so every existing accessor (`read_block`/`write_block`/`read_inode`/
/// `write_inode`/`dir_lookup`/`dir_insert`/`resolve_path_impl`/...) keeps working unmodified over
/// the unified index space -- only `inode_ensure_block_at` (the sole allocation chokepoint, see its
/// own doc comment) and the disk-persistence hooks (`persist_data_block_if_ready`/
/// `persist_inode_block_if_ready`) need to know this range exists at all. Every whole-pool disk
/// loop (format/mount-from-disk/the three persist hooks) already iterates `0..NUM_BLOCKS`/
/// `0..MAX_INODES` by the named constant rather than `BLOCKS.len()`/`INODES.len()` -- verified
/// before this was added -- so none of that code needs to change to stay correctly bounded to the
/// real, persisted range only. Deliberately never reclaimed when a tmpfs mount is unmounted (its
/// inodes/blocks stay marked used forever) -- matches this module's existing "no deallocation
/// anywhere" stance (`unlink`/`rmdir` already only clear a directory record's `used` byte).
const TMPFS_NUM_BLOCKS: usize = 1024;
const TMPFS_MAX_INODES: usize = 128;

// --- Real disk persistence (see src/ata.rs) --------------------------------------------------
//
// Physical disk block layout: block `0` is the superblock, `[INODE_TABLE_START,
// INODE_TABLE_START + INODE_TABLE_BLOCKS)` is the packed inode table, `BITMAP_BLOCK` is the
// block-used bitmap, and real data starts at `DATA_BLOCK_OFFSET` -- this module's own in-memory
// block number `i` maps to physical disk block `DATA_BLOCK_OFFSET + i`. Sizing: 512 inodes at a
// fixed 128-byte stride (real content is 74 bytes -- 1 tag + 4 size + 48 direct + 4 indirect + 2
// mode + 4 uid + 4 gid + 2 nlink + 4 rdev + 1 device_char -- rounded up to a power-of-two stride
// that divides BLOCK_SIZE evenly,
// leaving headroom for future fields) is exactly 16 4096-byte blocks; `NUM_BLOCKS` (8192) bits is
// exactly 1. Total metadata region: 18 blocks.

/// Marks a real, formatted oxfs disk. Absence/mismatch (an unformatted/all-zero disk, or one some
/// other filesystem wrote) means the same thing either way: format fresh rather than try to
/// interpret unknown content -- see `mount_from_disk`.
const SUPERBLOCK_MAGIC: [u8; 4] = *b"OXFS";
const SUPERBLOCK_VERSION: u32 = 1;

const INODE_TABLE_START: u32 = 1;
/// Real packed size (see the section doc comment above) -- **never** a raw transmute/memcpy of
/// `Inode` itself, since it isn't `#[repr(C)]` and `InodeKind` has no explicit discriminant, so its
/// true in-memory layout isn't guaranteed across compiler versions/profiles. `pack_inode`/
/// `unpack_inode` do this by hand instead, the same raw-byte-offset idiom `write_dir_record`/
/// `dir_record_inode` already established for directory records.
const INODE_STRIDE: usize = 128;
const INODES_PER_BLOCK: usize = BLOCK_SIZE / INODE_STRIDE;
const INODE_TABLE_BLOCKS: u32 = ((MAX_INODES * INODE_STRIDE + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32;
const BITMAP_BLOCK: u32 = INODE_TABLE_START + INODE_TABLE_BLOCKS;
const DATA_BLOCK_OFFSET: u32 = BITMAP_BLOCK + 1;

/// Gates `write_block`/`write_inode`/`set_block_used`'s own write-through persistence (see those
/// functions below). Deliberately `false` for the *entire* duration of `format_fresh_filesystem`
/// and `mount_from_disk`, even though both call those same three functions heavily -- without this,
/// formatting (~300 applets' worth of block/inode/bitmap churn) and mounting (reading data back
/// into these exact same in-memory structures) would each trigger thousands of redundant
/// block-sized disk writes: data already correct on disk, or not yet meant to be there at all.
/// `module_init` sets this to `true` exactly once, right after its own mount-or-format branch
/// completes (`flush_all_to_disk` having just performed the real, one-time bulk write formatting
/// needs, or `mount_from_disk` having confirmed the disk already matches memory) and before any
/// real syscall becomes reachable -- from that point on, every further write really is a live
/// mutation from a running process, and belongs on disk immediately.
static mut PERSISTENCE_READY: bool = false;

fn persistence_ready() -> bool {
    unsafe { *core::ptr::addr_of!(PERSISTENCE_READY) }
}

fn set_persistence_ready(ready: bool) {
    unsafe { *core::ptr::addr_of_mut!(PERSISTENCE_READY) = ready };
}

/// Whether a real data disk is attached this boot at all -- the outer gate `persist_*_if_present`
/// (below) checks alongside `persistence_ready()`. A plain wrapper around the kernel-exported probe
/// result so call sites read naturally.
fn block_device_present() -> bool {
    unsafe { oxidebsd_block_device_present() != 0 }
}

const DIR_RECORD_SIZE: usize = 32;
const NAME_MAX: usize = 26;
const RECORDS_PER_BLOCK: usize = BLOCK_SIZE / DIR_RECORD_SIZE;

/// Synthetic `/proc/<pid>/{stat,cmdline,status}` content buffer -- comfortably covers any of the
/// three for this kernel's simple, single-threaded processes; longer content silently truncates
/// (accepted simplification for this tier, not indefinite-length-safe).
const PROC_BUFFER: usize = 1024;
/// Base for synthetic `d_ino` values `/proc`'s own `getdents` records report -- nothing
/// dereferences these as real inodes (there's no real inode backing any `/proc` entry), they only
/// need to be distinct and non-zero. Clear of `MAX_INODES`'s real range by a wide margin.
const PROC_INODE_BASE: u64 = 0x7000_0000;

/// Sentinel tag marking `Process::cwd` (see `src/process.rs`'s own doc comment -- a `u64`, fully
/// opaque to the kernel) as a synthetic `/proc` location rather than a real inode number. Real
/// inodes are bounded by `MAX_INODES` (~9 bits), so the top bit is always free.
///
/// **Load-bearing detail**: `current_cwd()`/`set_current_cwd()` used to truncate this value to
/// `u32` immediately (`oxidebsd_get_cwd() as u32`) before this pass -- entirely fine when `cwd`
/// only ever held a small real inode index, but it would silently discard this tag (and any
/// pid encoded in the high bits) if that truncation weren't also removed. See `Cwd`/`decode_cwd`
/// below, which replace that pair wholesale.
const CWD_PROC_TAG: u64 = 1 << 63;
const CWD_PROC_KIND_SHIFT: u32 = 32;
const CWD_PROC_KIND_MASK: u64 = 0xF << CWD_PROC_KIND_SHIFT;
const CWD_PROC_KIND_ROOT: u64 = 0 << CWD_PROC_KIND_SHIFT;
const CWD_PROC_KIND_PIDFILES: u64 = 1 << CWD_PROC_KIND_SHIFT;
const CWD_PROC_KIND_TASKLIST: u64 = 2 << CWD_PROC_KIND_SHIFT;
const CWD_PROC_KIND_FDLIST: u64 = 3 << CWD_PROC_KIND_SHIFT;
const CWD_PROC_PID_MASK: u64 = 0xFFFF_FFFF;

const MAX_OPEN_FILES: usize = 8;
/// Write-side accumulator cap (see `OpenFile::Write`'s own doc comment) -- comfortably past
/// today's largest embedded binary (`sh.elf`, ~102 KB). Matches `modules/fat32`'s own final,
/// proven-sufficient `MAX_FILE_BUFFER` value exactly (rather than something bigger): `OpenFile`'s
/// `Write` variant is the largest in the enum, so every `OPEN_FILES` slot reserves this much
/// space regardless of what it actually holds -- no reason to size it past what's actually needed.
const MAX_WRITE_BUFFER: usize = 131072;
const DIR_LISTING_BUFFER: usize = 4096;

const MAX_CWD_PATH: usize = 256;
const MAX_CWD_DEPTH: usize = 32;

const BIG_FILE_LEN: usize = 5000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum InodeKind {
    Free,
    File,
    Dir,
    /// A real symlink -- its target path string is stored exactly like a regular file's content
    /// (`write_inode_data`/`read_inode_at`, `inode.size` = target byte length), no separate
    /// storage mechanism needed. See `resolve_path_impl`'s own doc comment for how this is
    /// followed during path resolution.
    Symlink,
    /// A real, listable device node (`SYS_MKNOD`) -- unlike `/dev/{random,urandom,null,zero}`'s
    /// existing magic-path interception in `dev_open` (not backed by any inode at all), this is a
    /// genuine directory entry reporting `S_IFCHR`/`S_IFBLK` and a real `st_rdev` via `stat`. See
    /// `oxfs_mknod`'s own doc comment for the (deliberately small) set of major:minor pairs that
    /// actually work when opened.
    Device,
}

#[derive(Clone, Copy)]
struct Inode {
    kind: InodeKind,
    size: u32,
    direct: [u32; DIRECT_BLOCKS],
    indirect: u32,
    /// Real per-inode permission bits (12 bits would cover setuid/setgid/sticky too, but nothing
    /// in this port's roster sets or checks those, so only the low 9 POSIX rwxrwxrwx bits are ever
    /// written -- `oxfs_chmod` masks its input to `0o777`). Defaults to `FIXED_PERM` (`0o755`),
    /// the same fixed value every inode used to report unconditionally before this field existed
    /// -- so a freshly seeded/created file behaves identically to the old hardcoded-everywhere
    /// scheme until something actually calls `chmod`.
    mode: u16,
    /// Real per-inode ownership -- `0` (root) by default, matching every seeded boot file (there's
    /// no login mechanism, so root is the only uid that has ever created anything on this
    /// filesystem so far). See `check_access`'s own doc comment for how these two fields, plus the
    /// caller's own uid/gid (via `oxidebsd_current_uid`/`_gid`), combine into an actual permission
    /// decision.
    uid: u32,
    gid: u32,
    /// Real hard-link count -- meaningful only for `File`/`Device` (see `SYS_LINK`'s own doc
    /// comment); `Dir`/`Symlink` keep reporting their existing hardcoded `write_stat` values
    /// unchanged (real subdirectory-count-based `Dir` nlink stays a documented, separate gap).
    /// `Inode::new` seeds this to `1` (the one directory entry about to be inserted for it);
    /// `write_stat` floors a decoded `0` (an on-disk inode written before this field existed, whose
    /// zero-padded stride tail decodes as `0`) back up to `1` rather than reporting a bogus
    /// zero-link count.
    nlink: u16,
    /// Packed major/minor for an `InodeKind::Device` entry (`0` for everything else) -- decoded
    /// from the caller's raw `dev` argument using the same formula musl's own
    /// `makedev()`/`major()`/`minor()` macros use. See `oxfs_mknod`'s own doc comment.
    rdev: u32,
    /// `true` for a character device, `false` for a block device -- only meaningful for
    /// `InodeKind::Device`.
    device_char: bool,
}

impl Inode {
    const FREE: Inode = Inode {
        kind: InodeKind::Free,
        size: 0,
        direct: [NO_BLOCK; DIRECT_BLOCKS],
        indirect: NO_BLOCK,
        mode: FIXED_PERM as u16,
        uid: 0,
        gid: 0,
        nlink: 0,
        rdev: 0,
        device_char: false,
    };

    fn new(kind: InodeKind) -> Inode {
        Inode {
            kind,
            size: 0,
            direct: [NO_BLOCK; DIRECT_BLOCKS],
            indirect: NO_BLOCK,
            mode: FIXED_PERM as u16,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            device_char: false,
        }
    }
}

/// `static mut`, not `static` -- same requirement `modules/fat32`'s own `DISK`/`OPEN_FILES` have
/// (see that module's doc comment): every read happens from within this module's own exported,
/// syscall-reachable functions, whose results feed observably into `oxidebsd_log`/syscall return
/// values, so the optimizer can't treat any write as an unobservable dead store. All-zero initial
/// values place these in `.bss` (not baked into the merged object's own size).
const TOTAL_BLOCKS: usize = NUM_BLOCKS + TMPFS_NUM_BLOCKS;
const TOTAL_INODES: usize = MAX_INODES + TMPFS_MAX_INODES;

static mut BLOCKS: [[u8; BLOCK_SIZE]; TOTAL_BLOCKS] = [[0; BLOCK_SIZE]; TOTAL_BLOCKS];
static mut BLOCK_USED: [bool; TOTAL_BLOCKS] = [false; TOTAL_BLOCKS];
static mut INODES: [Inode; TOTAL_INODES] = [Inode::FREE; TOTAL_INODES];
static mut OPEN_FILES: [Option<(u64, OpenFile)>; MAX_OPEN_FILES] = [None; MAX_OPEN_FILES];

const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;
/// Sized past any real concurrent `flock()` use this port's roster exercises (a handful of
/// scripts serializing themselves through one lock file at a time) -- see `ENOLCK`'s own doc
/// comment for what happens if it's ever actually exhausted.
const MAX_FLOCKS: usize = 16;
/// `(inode, holder_real_fd, exclusive)` -- one real-`flock()`-table entry per currently-held lock.
/// Keyed by `real_fd` (an open file description, matching real `flock()`'s own "released when any
/// fd referring to this open file description closes" semantics), not by inode alone, since a
/// shared (`LOCK_SH`) lock can have multiple simultaneous holders. `static mut`, not `static` --
/// same requirement as `OPEN_FILES` above (see that field's own doc comment): every write is
/// observable only through `oxfs_flock`'s own syscall-reachable return value, so the optimizer
/// can't treat a write here as dead.
static mut FLOCKS: [Option<(u32, u64, bool)>; MAX_FLOCKS] = [None; MAX_FLOCKS];

fn flocks() -> &'static mut [Option<(u32, u64, bool)>; MAX_FLOCKS] {
    // SAFETY: same reasoning as `find_open_file`'s own access to `OPEN_FILES` -- single-core,
    // no concurrent access (a syscall handler runs to completion before another can start).
    unsafe { &mut *core::ptr::addr_of_mut!(FLOCKS) }
}

/// Releases every lock `real_fd` itself holds -- called from `oxfs_close` (real `flock()`
/// semantics: closing *any* fd referencing the locked open file description releases its locks,
/// and this filesystem has no `dup()`-shared open-file-description concept beyond the fd itself,
/// so "this one real_fd" is the complete, correct scope).
fn release_flocks_for(real_fd: u64) {
    for slot in flocks().iter_mut() {
        if matches!(slot, Some((_, fd, _)) if *fd == real_fd) {
            *slot = None;
        }
    }
}

fn read_block(n: u32) -> [u8; BLOCK_SIZE] {
    // SAFETY: see BLOCKS's own doc comment -- single-core, syscall-serialized access only. Copies
    // the whole block out by value rather than returning a reference, so no borrow of the static
    // ever outlives this call -- deliberately simple over clever, see the module doc comment.
    unsafe { (*core::ptr::addr_of!(BLOCKS))[n as usize] }
}

fn write_block(n: u32, data: &[u8; BLOCK_SIZE]) {
    unsafe { (*core::ptr::addr_of_mut!(BLOCKS))[n as usize] = *data };
    persist_data_block_if_ready(n, data);
}

fn block_used(n: u32) -> bool {
    unsafe { (*core::ptr::addr_of!(BLOCK_USED))[n as usize] }
}

fn set_block_used(n: u32, used: bool) {
    unsafe { (*core::ptr::addr_of_mut!(BLOCK_USED))[n as usize] = used };
    persist_bitmap_if_ready();
}

fn read_inode(n: u32) -> Inode {
    unsafe { (*core::ptr::addr_of!(INODES))[n as usize] }
}

fn write_inode(n: u32, inode: Inode) {
    unsafe { (*core::ptr::addr_of_mut!(INODES))[n as usize] = inode };
    persist_inode_block_if_ready(n);
}

/// Linear scan for the first free block -- fine at this module's scale (`NUM_BLOCKS = 1024`), same
/// "simplicity over a free list" choice `modules/fat32`'s own `allocate_cluster` already makes.
fn alloc_block() -> Option<u32> {
    for i in 0..NUM_BLOCKS as u32 {
        if !block_used(i) {
            set_block_used(i, true);
            write_block(i, &[0u8; BLOCK_SIZE]);
            return Some(i);
        }
    }
    None
}

/// Like `alloc_block`, but fills the fresh block with `0xFF` bytes, not zero -- required for an
/// indirect block specifically: each 4-byte slot is a block-number pointer, and a plain
/// zero-filled block would decode every slot as block `0` (a real, valid block), not `NO_BLOCK`
/// ("no pointer here yet").
fn alloc_indirect_block() -> Option<u32> {
    let n = alloc_block()?;
    write_block(n, &[0xFFu8; BLOCK_SIZE]);
    Some(n)
}

fn alloc_inode() -> Option<u32> {
    (0..MAX_INODES as u32).find(|&i| read_inode(i).kind == InodeKind::Free)
}

/// `alloc_block`'s tmpfs-pool counterpart -- same linear scan, over the tail range reserved by
/// `TMPFS_NUM_BLOCKS` instead of `0..NUM_BLOCKS`. Only ever called from `inode_ensure_block_at`,
/// which picks this over `alloc_block` based on which pool `inode_num` falls in -- see that
/// function's own doc comment for why it's the sole call site that needs to know this pool exists.
fn alloc_tmpfs_block() -> Option<u32> {
    for i in NUM_BLOCKS as u32..TOTAL_BLOCKS as u32 {
        if !block_used(i) {
            set_block_used(i, true);
            write_block(i, &[0u8; BLOCK_SIZE]);
            return Some(i);
        }
    }
    None
}

fn alloc_tmpfs_indirect_block() -> Option<u32> {
    let n = alloc_tmpfs_block()?;
    write_block(n, &[0xFFu8; BLOCK_SIZE]);
    Some(n)
}

/// `alloc_inode`'s tmpfs-pool counterpart -- see `alloc_tmpfs_block`'s own doc comment. Called
/// directly by the tmpfs-mount-creation path (`oxfs_mount_tmpfs`, which has no parent directory to
/// check -- it's creating the mount's own root) and by `alloc_inode_in` below for everything else.
fn alloc_tmpfs_inode() -> Option<u32> {
    (MAX_INODES as u32..TOTAL_INODES as u32).find(|&i| read_inode(i).kind == InodeKind::Free)
}

/// Picks `alloc_inode`/`alloc_tmpfs_inode` based on which pool `parent` (the directory the new
/// entry is being created in) belongs to -- a new file/dir/symlink created inside a tmpfs-mounted
/// directory must itself come from the tmpfs pool, or it would silently end up persisted (real
/// pool inodes are write-through to disk) and report the wrong `st_dev`. The shared chokepoint for
/// all three "create a new named entry" sites (`oxfs_mkdir`, `oxfs_open`'s `O_CREAT`-via-`oxfs_close`
/// commit, `oxfs_symlink`) -- found missing via `tests/mount_syscall_smoke.rs`, which caught the
/// `O_CREAT` case specifically (a file created inside a tmpfs mount reported the real filesystem's
/// `st_dev` instead of the tmpfs one).
fn alloc_inode_in(parent: u32) -> Option<u32> {
    if parent >= MAX_INODES as u32 {
        alloc_tmpfs_inode()
    } else {
        alloc_inode()
    }
}

/// Reads the block number backing `inode`'s logical block `index` (direct or, past
/// `DIRECT_BLOCKS`, via the single-indirect block), or `None` if that block was never allocated.
fn inode_block_at(inode: &Inode, index: usize) -> Option<u32> {
    if index < DIRECT_BLOCKS {
        let b = inode.direct[index];
        (b != NO_BLOCK).then_some(b)
    } else {
        let indirect_index = index - DIRECT_BLOCKS;
        if inode.indirect == NO_BLOCK || indirect_index >= PTRS_PER_INDIRECT {
            return None;
        }
        let ib = read_block(inode.indirect);
        let off = indirect_index * 4;
        let b = u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]]);
        (b != NO_BLOCK).then_some(b)
    }
}

/// Like `inode_block_at`, but allocates a fresh block (and, if needed, a fresh indirect block)
/// when `index` isn't backed by one yet -- used by both real file writes and directory growth.
/// Takes an inode *number*, not `&mut Inode`: every access to `INODES`/`BLOCKS` in this module
/// goes through the copy-in/copy-out helpers above, so no reference to either static is ever held
/// across a nested call (`alloc_block` here) that itself touches them.
///
/// **The one place block allocation needs to know about the tmpfs pool** (see `TMPFS_NUM_BLOCKS`'s
/// own doc comment): `dir_insert`'s directory-growth path and every real file write both funnel
/// through this single function (confirmed by grep -- `alloc_block`/`alloc_indirect_block` have no
/// other caller), so picking the allocator by whether `inode_num` falls in the tmpfs range here is
/// sufficient to make a tmpfs file/directory's own growth land in the tmpfs pool, with no other
/// call site needing to change.
fn inode_ensure_block_at(inode_num: u32, index: usize) -> Option<u32> {
    let tmpfs = inode_num >= MAX_INODES as u32;
    let mut inode = read_inode(inode_num);
    let result = if index < DIRECT_BLOCKS {
        if inode.direct[index] == NO_BLOCK {
            inode.direct[index] = if tmpfs {
                alloc_tmpfs_block()?
            } else {
                alloc_block()?
            };
        }
        Some(inode.direct[index])
    } else {
        let indirect_index = index - DIRECT_BLOCKS;
        if indirect_index >= PTRS_PER_INDIRECT {
            return None;
        }
        if inode.indirect == NO_BLOCK {
            inode.indirect = if tmpfs {
                alloc_tmpfs_indirect_block()?
            } else {
                alloc_indirect_block()?
            };
        }
        let mut ib = read_block(inode.indirect);
        let off = indirect_index * 4;
        let existing = u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]]);
        if existing == NO_BLOCK {
            let nb = if tmpfs {
                alloc_tmpfs_block()?
            } else {
                alloc_block()?
            };
            ib[off..off + 4].copy_from_slice(&nb.to_le_bytes());
            write_block(inode.indirect, &ib);
            Some(nb)
        } else {
            Some(existing)
        }
    };
    write_inode(inode_num, inode);
    result
}

/// Reads up to `out.len()` bytes starting at `position` within `inode_num`'s data, honoring its
/// stored `size` (real files only -- directories never call this, they walk raw records instead).
/// Returns the number of bytes actually read (`0` at or past EOF).
fn read_inode_at(inode_num: u32, position: usize, out: &mut [u8]) -> usize {
    let inode = read_inode(inode_num);
    let size = inode.size as usize;
    if position >= size {
        return 0;
    }
    let n = out.len().min(size - position);
    let mut written = 0;
    while written < n {
        let file_off = position + written;
        let block_index = file_off / BLOCK_SIZE;
        let in_block_off = file_off % BLOCK_SIZE;
        let Some(blk) = inode_block_at(&inode, block_index) else {
            break;
        };
        let block = read_block(blk);
        let chunk = (n - written).min(BLOCK_SIZE - in_block_off);
        out[written..written + chunk].copy_from_slice(&block[in_block_off..in_block_off + chunk]);
        written += chunk;
    }
    written
}

/// Writes `content` as `inode_num`'s complete contents, allocating whatever blocks are needed and
/// setting `size` -- the only write primitive this module has (matching `modules/fat32`'s own
/// "writes only ever create/replace a file's complete contents in one operation" simplification).
fn write_inode_data(inode_num: u32, content: &[u8]) -> bool {
    let block_count = content.len().div_ceil(BLOCK_SIZE);
    for i in 0..block_count {
        let Some(blk) = inode_ensure_block_at(inode_num, i) else {
            return false;
        };
        let start = i * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(content.len());
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..end - start].copy_from_slice(&content[start..end]);
        write_block(blk, &buf);
    }
    let mut inode = read_inode(inode_num);
    inode.size = content.len() as u32;
    write_inode(inode_num, inode);
    true
}

/// `SYS_FTRUNCATE`/`SYS_FALLOCATE`'s real logic -- resizes `inode_num`'s content to exactly
/// `new_size` bytes without ever materializing the file's complete old-or-new content in one
/// buffer the way `write_inode_data` does: growing zero-fills only the newly-added region,
/// block by block, via the same `inode_ensure_block_at`/`write_block` primitives
/// `write_inode_data` itself uses internally; shrinking touches no block content at all (bytes
/// past the new `size` simply become unreachable -- `read_inode_at` already never reads past
/// `inode.size`, and a later grow back past the old size would zero-fill over them again, matching
/// real POSIX "grow into a hole reads as zero" semantics either way). Load-bearing for staying
/// off the stack: this filesystem's per-file cap is ~4 MiB (see `Inode`'s own doc comment), far
/// past what this kernel's 128 KiB kernel-stack floor could ever hold as one local buffer.
fn resize_inode_data(inode_num: u32, new_size: usize) -> bool {
    let old_size = read_inode(inode_num).size as usize;
    if new_size > old_size {
        let mut pos = old_size;
        while pos < new_size {
            let block_index = pos / BLOCK_SIZE;
            let in_block_off = pos % BLOCK_SIZE;
            let Some(blk) = inode_ensure_block_at(inode_num, block_index) else {
                return false;
            };
            let mut block = read_block(blk);
            let chunk = (new_size - pos).min(BLOCK_SIZE - in_block_off);
            for b in &mut block[in_block_off..in_block_off + chunk] {
                *b = 0;
            }
            write_block(blk, &block);
            pos += chunk;
        }
    }
    let mut inode = read_inode(inode_num);
    inode.size = new_size as u32;
    write_inode(inode_num, inode);
    true
}

/// Byte-exact mirror of musl's `struct stat` for x86_64 (`arch/x86_64/bits/stat.h` in
/// `third_party/musl`) -- `dev_t`/`ino_t`/`nlink_t`/`off_t`/`blksize_t`/`blkcnt_t` are all 64-bit
/// on this target, and `struct timespec`'s `{tv_sec, tv_nsec}` is bit-identical to two raw `i64`s
/// here, so this `repr(C)` struct's natural layout already matches the real one field-for-field --
/// no manual padding needed beyond `__pad0` (which upstream also has explicitly, between the
/// `u32` id fields and the next `u64`). `src/stat/{stat,fstat,lstat}.c` on the `oxidebsd` musl
/// branch write straight into this shape, bypassing musl's usual `fstatat`/`kstat` indirection
/// entirely (same "patch the entry point, not the generic multiplexer" pattern `open()`/`chdir()`/
/// `mkdir()` already established -- see `CLAUDE.md`'s musl section).
#[repr(C)]
struct MuslStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime_sec: i64,
    st_atime_nsec: i64,
    st_mtime_sec: i64,
    st_mtime_nsec: i64,
    st_ctime_sec: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

const _: () = assert!(core::mem::size_of::<MuslStat>() == 144);

/// Builds a `MuslStat` for `inode_num` and writes it into the caller's buffer at `buf_ptr` --
/// shared by `oxfs_stat`/`oxfs_lstat` (path-based) and `oxfs_fstat` (fd-based). `st_uid`/`st_gid`
/// and `st_mode`'s permission bits are now real, backed by the inode's own `uid`/`gid`/`mode`
/// fields (see `Inode`'s own doc comment) -- everything else this filesystem still doesn't model
/// stays a fixed, honestly-fake value: timestamps are all `0` (no clock/RTC source exists yet --
/// see the same gap table's "clock + nanosleep" row). `st_dev` is `1` for the one real, persisted
/// filesystem and `2` for anything in the tmpfs pool (`inode_num >= MAX_INODES`, see
/// `TMPFS_NUM_BLOCKS`'s own doc comment) -- derivable from the inode number alone, and just enough
/// for `mountpoint`'s real `st_dev(path) != st_dev(parent)` check to detect a tmpfs mount. A bind
/// mount deliberately keeps `st_dev == 1` (same underlying superblock, matching real Linux's own
/// same-filesystem bind-mount behavior), so `mountpoint` can't distinguish a bind-mounted directory
/// from an ordinary one -- a known, honest limitation, not something this field could fix without a
/// real per-mount identity this design doesn't build.
///
/// `st_nlink` is `2` for a directory (`.` plus its parent's entry for it)
/// and `1` for a file -- this filesystem doesn't track hard links, so a directory's real
/// subdirectory count (which would also bump its parent's linked-from count) isn't reflected
/// either. `st_ino`/`st_size`/`st_blocks` are the only other fields backed by something real.
/// `write_unaligned` since a userland `struct stat*` has no alignment guarantee this kernel can
/// rely on (same trust boundary as every other raw user pointer here -- see the module doc
/// comment).
fn write_stat(inode_num: u32, buf_ptr: u64) -> i64 {
    let inode = read_inode(inode_num);
    // `File`/`Device` report a real, tracked link count (floored at `1` -- see `Inode::nlink`'s
    // own doc comment for why a decoded `0` means "written before this field existed", not "no
    // links at all"). `Dir`/`Symlink` keep their existing hardcoded values.
    let (type_bits, nlink) = match inode.kind {
        InodeKind::Dir => (S_IFDIR, 2u64),
        InodeKind::Symlink => (S_IFLNK, 1u64),
        InodeKind::Device => (
            if inode.device_char { S_IFCHR } else { S_IFBLK },
            inode.nlink.max(1) as u64,
        ),
        _ => (S_IFREG, inode.nlink.max(1) as u64),
    };
    let mode = type_bits | inode.mode as u32;
    let size = inode.size as i64;
    let dev = if inode_num >= MAX_INODES as u32 { 2 } else { 1 };
    let rdev = if inode.kind == InodeKind::Device {
        inode.rdev as u64
    } else {
        0
    };
    let stat = MuslStat {
        st_dev: dev,
        st_ino: inode_num as u64,
        st_nlink: nlink,
        st_mode: mode,
        st_uid: inode.uid,
        st_gid: inode.gid,
        __pad0: 0,
        st_rdev: rdev,
        st_size: size,
        st_blksize: BLOCK_SIZE as i64,
        st_blocks: (size + 511) / 512,
        st_atime_sec: 0,
        st_atime_nsec: 0,
        st_mtime_sec: 0,
        st_mtime_nsec: 0,
        st_ctime_sec: 0,
        st_ctime_nsec: 0,
        __unused: [0; 3],
    };
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer, sized by the caller's own
    // `sizeof(struct stat)` (144 bytes, matching `MuslStat` exactly, checked above).
    unsafe { (buf_ptr as *mut MuslStat).write_unaligned(stat) };
    0
}

/// Real POSIX `F_OK`/`X_OK`/`W_OK`/`R_OK` `amode` bits — the exact values musl's own `<unistd.h>`
/// (and every other libc) defines them as, so real `access(2)`'s own `amode` argument needs no
/// translation at this kernel boundary; `check_access`'s own `want` parameter uses this same
/// encoding directly.
const X_OK: u8 = 1;
const W_OK: u8 = 2;
const R_OK: u8 = 4;

/// Real POSIX permission check: `uid == 0` (root) bypasses every bit entirely, same as every real
/// Unix — this kernel's own single-user reality (root is the only uid that has ever existed so
/// far, see `Process::uid`'s own doc comment in `src/process.rs`) means this always evaluates to
/// `true` today, but the logic is real, not a stub — it'll start mattering the moment `setuid`
/// actually gets used to drop privilege. Otherwise picks the owner/group/other rwx triplet by
/// comparing against the inode's own `uid`/`gid` (first match wins, real Unix semantics: being in
/// the owning group doesn't fall through to "other" just because the group bits happen to deny
/// it), then requires every bit in `want` (`R_OK`/`W_OK`/`X_OK`, singly or combined — real
/// `access(2)`'s own encoding, see the constants above) to be set. `oxfs_open`'s own existing
/// callers only ever pass a single bit (`R_OK` or `W_OK`); `oxfs_access` below is the one caller
/// that can pass a real combination.
fn check_access(inode: &Inode, uid: u64, gid: u64, want: u8) -> bool {
    if uid == 0 {
        return true;
    }
    let mode = inode.mode;
    let bits = if uid == inode.uid as u64 {
        (mode >> 6) & 0o7
    } else if gid == inode.gid as u64 {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    bits & want as u16 == want as u16
}

/// `write_stat`'s counterpart for a synthetic `/proc` entry -- no real inode to read, so every
/// field is a fixed placeholder except `st_mode` (the one thing callers actually branch on, e.g.
/// `ls`/`pstree`'s own `stat()`-before-`opendir()` checks). `st_size` is always `0` rather than a
/// leaf file's real content length -- no target applet for this tier checks it, and computing a
/// real one would mean generating that content a second time just to measure it.
fn write_proc_stat(is_dir: bool, buf_ptr: u64) -> i64 {
    let (mode, nlink) = if is_dir {
        (S_IFDIR | FIXED_PERM, 2u64)
    } else {
        (S_IFREG | FIXED_PERM, 1u64)
    };
    let stat = MuslStat {
        st_dev: 1,
        st_ino: PROC_INODE_BASE,
        st_nlink: nlink,
        st_mode: mode,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: BLOCK_SIZE as i64,
        st_blocks: 0,
        st_atime_sec: 0,
        st_atime_nsec: 0,
        st_mtime_sec: 0,
        st_mtime_nsec: 0,
        st_ctime_sec: 0,
        st_ctime_nsec: 0,
        __unused: [0; 3],
    };
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer, sized by the caller's own
    // `sizeof(struct stat)` (144 bytes, matching `MuslStat` exactly, checked above).
    unsafe { (buf_ptr as *mut MuslStat).write_unaligned(stat) };
    0
}

/// Looks up the inode number backing an already-open real fd -- `oxfs_fstat`'s own lookup, since
/// `OPEN_FILES` is keyed by `real_fd` (see `oxidebsd_real_fd_of`'s own doc comment for why a
/// syscall-number-registered handler has to resolve that itself rather than getting it for free
/// the way `SYS_READ`/`SYS_WRITE` do). `None` for a `Write`-in-progress fd (`open(O_CREAT)` before
/// `close`) -- this filesystem doesn't allocate a real inode until close (see `OpenFile::Write`'s
/// own doc comment), so there's genuinely nothing to report yet.
fn inode_of_open_file(real_fd: u64) -> Option<u32> {
    match find_open_file(real_fd)? {
        OpenFile::FileRead { inode, .. } => Some(*inode),
        OpenFile::DirListing { inode, .. } => Some(*inode),
        OpenFile::Write { .. } => None,
        // No real inode backs a synthetic /proc or /dev entry -- fstat on one of these fds fails
        // as -EBADF, a documented known gap for this tier (no target applet needs it).
        OpenFile::ProcRead { .. } | OpenFile::ProcDir { .. } => None,
        OpenFile::DevRandom | OpenFile::DevNull | OpenFile::DevZero => None,
    }
}

/// The on-wire byte size of one `SYS_GETDENTS` record for a name of `name_len` bytes -- real
/// Linux `dirent64` layout (`d_ino: u64, d_off: i64, d_reclen: u16, d_type: u8, d_name: [u8; N]`,
/// `N` bytes wide including a NUL terminator), padded up to the next 8-byte boundary the same way
/// real Linux does (musl's `struct dirent` -- `arch/generic/bits/dirent.h` on the `oxidebsd` musl
/// branch, since `x86_64` doesn't override it -- assumes 8-byte-aligned records when it casts a
/// raw syscall buffer straight into `struct dirent*`).
fn dirent_record_len(name_len: usize) -> usize {
    let unpadded = 8 + 8 + 2 + 1 + name_len + 1;
    (unpadded + 7) & !7
}

/// Writes one `SYS_GETDENTS` record into `out`, whose length must already be exactly
/// `dirent_record_len(name.len())` (`oxfs_getdents` slices its output buffer to that size before
/// calling this). `off_cookie` becomes `d_off` -- real Linux uses this as an opaque seek cookie
/// for `telldir`/`seekdir`; nothing in this port's ported applets calls either, so a monotonic
/// counter (`oxfs_getdents`'s own `dirent_pos`, one-past the record just written) is honest enough
/// without pretending to support real seeking. Padding bytes past the NUL terminator are zeroed,
/// not left as whatever `out` already held -- `out` is caller-owned userland memory, reused across
/// `SYS_GETDENTS` calls at the same address in `hush`/coreutils' own DIR buffer.
fn write_dirent_record(out: &mut [u8], ino: u64, off_cookie: i64, dtype: u8, name: &[u8]) {
    let reclen = out.len();
    out[0..8].copy_from_slice(&ino.to_le_bytes());
    out[8..16].copy_from_slice(&off_cookie.to_le_bytes());
    out[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    out[18] = dtype;
    let name_start = 19;
    out[name_start..name_start + name.len()].copy_from_slice(name);
    for b in &mut out[name_start + name.len()..reclen] {
        *b = 0;
    }
}

fn dir_record_used(block: &[u8; BLOCK_SIZE], idx: usize) -> bool {
    block[idx * DIR_RECORD_SIZE] != 0
}

fn dir_record_name_len(block: &[u8; BLOCK_SIZE], idx: usize) -> usize {
    block[idx * DIR_RECORD_SIZE + 1] as usize
}

fn dir_record_name(block: &[u8; BLOCK_SIZE], idx: usize) -> &[u8] {
    let len = dir_record_name_len(block, idx);
    let start = idx * DIR_RECORD_SIZE + 6;
    &block[start..start + len]
}

fn dir_record_inode(block: &[u8; BLOCK_SIZE], idx: usize) -> u32 {
    let off = idx * DIR_RECORD_SIZE + 2;
    u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]])
}

fn write_dir_record(block: &mut [u8; BLOCK_SIZE], idx: usize, name: &[u8], inode: u32) {
    let off = idx * DIR_RECORD_SIZE;
    block[off] = 1;
    block[off + 1] = name.len() as u8;
    block[off + 2..off + 6].copy_from_slice(&inode.to_le_bytes());
    block[off + 6..off + 6 + name.len()].copy_from_slice(name);
}

fn clear_dir_record(block: &mut [u8; BLOCK_SIZE], idx: usize) {
    block[idx * DIR_RECORD_SIZE] = 0;
}

/// Looks `name` up directly inside `dir_inode` (no path walking -- see `resolve_path`/
/// `resolve_parent` for that). `name` may be `.`/`..`, both stored as real records like any other
/// (seeded by `oxfs_mkdir`/`module_init`, self-referencing for root).
fn dir_lookup(dir_inode: u32, name: &[u8]) -> Option<u32> {
    let inode = read_inode(dir_inode);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                return Some(dir_record_inode(&block, r));
            }
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum OxfsError {
    NotFound,
    NotADirectory,
    InvalidPath,
    DiskFull,
    /// `resolve_path_impl`'s own symlink-following recursion exceeded `MAX_SYMLINK_DEPTH` -- a
    /// symlink loop (or just a chain too long to be a real mistake), never actually exercised by
    /// this kernel's own seed data.
    TooManyLinks,
}

fn errno_for(e: OxfsError) -> i64 {
    -match e {
        OxfsError::NotFound => ENOENT,
        OxfsError::NotADirectory => ENOTDIR,
        OxfsError::InvalidPath => EINVAL,
        OxfsError::DiskFull => ENOSPC,
        OxfsError::TooManyLinks => ELOOP,
    }
}

/// Inserts a new `(name, target_inode)` record into `dir_inode`, reusing the first free (cleared
/// by a previous `dir_remove`) or never-yet-used record slot -- growing `dir_inode` with a fresh
/// block via `inode_ensure_block_at` if every existing block is full. This is the "a directory can
/// grow past its first cluster" fix over `modules/fat32`'s own `DirectoryFull`/`ENOSPC` dead end.
fn dir_insert(dir_inode: u32, name: &[u8], target_inode: u32) -> Result<(), OxfsError> {
    if name.len() > NAME_MAX {
        return Err(OxfsError::InvalidPath);
    }
    let inode = read_inode(dir_inode);
    let mut i = 0;
    loop {
        match inode_block_at(&inode, i) {
            Some(blk) => {
                let mut block = read_block(blk);
                for r in 0..RECORDS_PER_BLOCK {
                    if !dir_record_used(&block, r) {
                        write_dir_record(&mut block, r, name, target_inode);
                        write_block(blk, &block);
                        return Ok(());
                    }
                }
                i += 1;
            }
            None => {
                let Some(blk) = inode_ensure_block_at(dir_inode, i) else {
                    return Err(OxfsError::DiskFull);
                };
                // inode_ensure_block_at hands back a freshly zeroed block (record 0 is free) --
                // no need to scan it first.
                let mut block = [0u8; BLOCK_SIZE];
                write_dir_record(&mut block, 0, name, target_inode);
                write_block(blk, &block);
                return Ok(());
            }
        }
    }
}

/// Clears the record named `name` inside `dir_inode` -- the underlying inode/blocks are *not*
/// freed (see the module doc comment). `Err(NotFound)` if no such record exists (callers normally
/// check via `dir_lookup` first, so this mostly can't fail in practice).
fn dir_remove(dir_inode: u32, name: &[u8]) -> Result<(), OxfsError> {
    let inode = read_inode(dir_inode);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let mut block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                clear_dir_record(&mut block, r);
                write_block(blk, &block);
                return Ok(());
            }
        }
        i += 1;
    }
    Err(OxfsError::NotFound)
}

/// Counts live records in `dir_inode`, `.`/`..` included -- an otherwise-empty directory always
/// has exactly `2` (used by `oxfs_rmdir`).
fn dir_entry_count(dir_inode: u32) -> usize {
    let inode = read_inode(dir_inode);
    let mut count = 0;
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

/// Returns the `n`th (0-indexed) used record inside `dir_inode`, walking blocks in the same
/// order `dir_lookup`/`dir_entry_count` do -- `.`/`..` included, unlike `open_dir_listing`'s own
/// pretty-printed summary, since `SYS_GETDENTS`'s real callers (`opendir`/`readdir`) expect every
/// real record. `None` once `n` reaches the record count -- `oxfs_getdents`'s own EOF signal.
fn dir_nth_used_record(dir_inode: u32, n: usize) -> Option<(u32, [u8; NAME_MAX], u8)> {
    let inode = read_inode(dir_inode);
    let mut seen = 0usize;
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) {
                if seen == n {
                    let name = dir_record_name(&block, r);
                    let mut buf = [0u8; NAME_MAX];
                    buf[..name.len()].copy_from_slice(name);
                    return Some((dir_record_inode(&block, r), buf, name.len() as u8));
                }
                seen += 1;
            }
        }
        i += 1;
    }
    None
}

/// How many nested symlinks `resolve_path_impl` will transparently follow before giving up with
/// `ELOOP` -- generous headroom for any real chain, bounded so a symlink loop (`a -> b -> a`)
/// can't recurse this kernel into a stack overflow.
const MAX_SYMLINK_DEPTH: usize = 8;

// --- Mount table -------------------------------------------------------------------------------
//
// A real, but deliberately scoped, mount table: `mount --bind`/`mount -t tmpfs` only, no general
// pluggable-filesystem-type VFS (there is exactly one real block device and one real filesystem in
// this kernel, and modules can't call each other directly -- nothing else exists to plug in). See
// CLAUDE.md's own "Mount table" section for the full design and its known limitations.

const MAX_MOUNTS: usize = 8;
const MAX_MOUNT_PATH: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum MountKind {
    Bind,
    Tmpfs,
}

#[derive(Clone, Copy)]
struct MountEntry {
    used: bool,
    /// The real inode `dir_lookup` would otherwise have returned for this mountpoint -- shadowed
    /// by `active_mount_for` while this entry is active. Recovered directly (bypassing the
    /// redirect) by `oxfs_umount2` to find which entry to remove.
    mountpoint_inode: u32,
    /// Where a lookup reaching `mountpoint_inode` redirects to instead: the source directory's own
    /// inode for a bind mount, or a freshly allocated tmpfs root directory for a tmpfs mount.
    target_root_inode: u32,
    kind: MountKind,
    /// Display only (`/proc/mounts`) -- matching by inode, not by this string, is what
    /// `oxfs_umount2` actually uses to find the entry to remove.
    path: [u8; MAX_MOUNT_PATH],
    path_len: u8,
    source: [u8; MAX_MOUNT_PATH],
    source_len: u8,
}

impl MountEntry {
    const EMPTY: MountEntry = MountEntry {
        used: false,
        mountpoint_inode: 0,
        target_root_inode: 0,
        kind: MountKind::Bind,
        path: [0; MAX_MOUNT_PATH],
        path_len: 0,
        source: [0; MAX_MOUNT_PATH],
        source_len: 0,
    };
}

static mut MOUNTS: [MountEntry; MAX_MOUNTS] = [MountEntry::EMPTY; MAX_MOUNTS];

fn mounts() -> &'static mut [MountEntry; MAX_MOUNTS] {
    // SAFETY: same single-core, syscall-serialized access as every other `static mut` in this
    // module (see BLOCKS's own doc comment).
    unsafe { &mut *core::ptr::addr_of_mut!(MOUNTS) }
}

/// Returns the currently active mount shadowing `inode`, if any -- scanned from the end so a mount
/// stacked on top of an already-mounted directory wins (real Unix LIFO stacking), and so
/// `oxfs_umount2` removing the most recent one exposes whatever was mounted there before it.
fn active_mount_for(inode: u32) -> Option<MountEntry> {
    mounts()
        .iter()
        .rev()
        .find(|m| m.used && m.mountpoint_inode == inode)
        .copied()
}

/// `Process::root_inode` (`src/process.rs`), decoded the same "opaque `u64`, oxfs-owned meaning"
/// way `current_cwd()` already decodes `Process::cwd` -- `0` doubles as both oxfs's real root inode
/// number and "never chrooted", so no separate sentinel handling is needed here.
fn effective_root_inode() -> u32 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_get_root() as u32 }
}

/// Resolves `path` to a single inode number, starting from `cwd_inode` (or `root_inode`, if `path`
/// starts with `/`) and walking every `/`-separated component (`.`/`..`/empty components handled
/// along the way) -- real multi-component resolution, replacing `modules/fat32`'s
/// single-component-only `to_short_name`. Every *intermediate* component is transparently followed
/// if it's itself a symlink (real Unix behavior -- an intermediate component must resolve to a
/// directory one way or another). The *final* component is followed too when `follow_last` is set;
/// when it isn't, a symlink final component is returned as-is (its own inode, not its target's) --
/// the one difference between `stat(2)`/`open(2)` (follow) and `lstat(2)`/`readlink(2)` (don't).
/// Recursion depth is bounded by `MAX_SYMLINK_DEPTH` -- see `resolve_path`/
/// `resolve_path_nofollow_last` for the two callable wrappers over this (both fetch
/// `effective_root_inode()` themselves; every other call site in this file only ever goes through
/// one of those two, or `resolve_parent`, which itself calls `resolve_path`).
///
/// `root_inode` is also the real `SYS_CHROOT` containment mechanism: when a `..` component would
/// otherwise walk out of it (`current == root_inode`), it's treated as staying put instead of
/// following that directory's own genuine, real `..` record -- without this, `cd ..` from a
/// chrooted process's own root would walk straight back into the real tree via that directory's
/// real parent. Fully backward compatible for the un-chrooted case: the real root (`ROOT_INODE =
/// 0`) already self-references `..` (see the module doc comment), so this check is a no-op there.
fn resolve_path_impl(
    root_inode: u32,
    cwd_inode: u32,
    path: &[u8],
    follow_last: bool,
    depth: usize,
) -> Result<u32, OxfsError> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(OxfsError::TooManyLinks);
    }
    let mut current = if path.first() == Some(&b'/') {
        root_inode
    } else {
        cwd_inode
    };
    let mut iter = path
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .peekable();
    while let Some(component) = iter.next() {
        let is_last = iter.peek().is_none();
        if component == b"." {
            continue;
        }
        if component == b".." && current == root_inode {
            continue;
        }
        let next = dir_lookup(current, component).ok_or(OxfsError::NotFound)?;
        // A mounted directory shadows whatever real inode was already there -- applies to every
        // component, not just the last, matching real Unix (`stat`ing a mountpoint itself reports
        // the mounted fs's root). See MountEntry's own doc comment for `..`'s behavior from inside
        // each mount kind.
        let next = active_mount_for(next).map_or(next, |m| m.target_root_inode);
        let kind = read_inode(next).kind;
        if kind == InodeKind::Symlink && (!is_last || follow_last) {
            let mut target = [0u8; MAX_CWD_PATH];
            let n = read_inode_at(next, 0, &mut target);
            let start = if target.first() == Some(&b'/') {
                root_inode
            } else {
                current
            };
            current = resolve_path_impl(root_inode, start, &target[..n], true, depth + 1)?;
            if !is_last && read_inode(current).kind != InodeKind::Dir {
                return Err(OxfsError::NotADirectory);
            }
            continue;
        }
        if !is_last && kind != InodeKind::Dir {
            return Err(OxfsError::NotADirectory);
        }
        current = next;
    }
    Ok(current)
}

/// Always follows a symlink final component -- used by `chdir`/`stat`/the parent-prefix half of
/// `resolve_parent` (real Unix: an intermediate path component is always followed regardless of
/// caller).
fn resolve_path(cwd_inode: u32, path: &[u8]) -> Result<u32, OxfsError> {
    resolve_path_impl(effective_root_inode(), cwd_inode, path, true, 0)
}

/// Never follows a symlink final component (still follows every intermediate one) -- used by
/// `lstat(2)`/`readlink(2)`, the two real Unix calls that must see the link itself.
fn resolve_path_nofollow_last(cwd_inode: u32, path: &[u8]) -> Result<u32, OxfsError> {
    resolve_path_impl(effective_root_inode(), cwd_inode, path, false, 0)
}

/// Resolves `path` to its *parent* directory's inode number plus the final path component's raw
/// name bytes (still borrowed from `path`) -- used by every operation that creates, removes, or
/// renames a name (`open` with `O_CREAT`, `mkdir`, `unlink`, `rmdir`, `rename`), since those need
/// to mutate the parent's own directory records rather than just look the target up.
fn resolve_parent(cwd_inode: u32, path: &[u8]) -> Result<(u32, &[u8]), OxfsError> {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        // "" / "/" / "///" -- no leaf component to create, remove, or rename.
        return Err(OxfsError::InvalidPath);
    }
    let head = &path[..end];
    let leaf_start = head.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    let leaf = &head[leaf_start..];
    if leaf == b"." || leaf == b".." || leaf.len() > NAME_MAX {
        return Err(OxfsError::InvalidPath);
    }
    // Includes the trailing '/' when leaf_start > 0 (e.g. head = "/foo" -> parent_path = "/",
    // head = "sub/foo" -> parent_path = "sub/") -- harmless, resolve_path treats a trailing
    // separator as no extra component. When leaf_start == 0 (a bare name, no directory prefix)
    // this is "", which resolve_path already resolves to cwd_inode directly.
    let parent_path = &head[..leaf_start];
    let parent_inode = resolve_path(cwd_inode, parent_path)?;
    if read_inode(parent_inode).kind != InodeKind::Dir {
        return Err(OxfsError::NotADirectory);
    }
    Ok((parent_inode, leaf))
}

/// The calling process's current-working-directory location: either a real inode number, or a
/// synthetic `/proc` directory (`ProcDirKind` reused directly -- it already enumerates exactly the
/// shapes a `/proc` cwd can be: `Root`/`PidFiles`/`TaskList`/`FdList`). See `CWD_PROC_TAG`'s own
/// doc comment for the encoding this decodes/encodes.
enum Cwd {
    Real(u32),
    Proc(ProcDirKind),
}

fn decode_cwd(raw: u64) -> Cwd {
    if raw & CWD_PROC_TAG == 0 {
        return Cwd::Real(raw as u32);
    }
    let pid = (raw & CWD_PROC_PID_MASK) as u32;
    match raw & CWD_PROC_KIND_MASK {
        CWD_PROC_KIND_PIDFILES => Cwd::Proc(ProcDirKind::PidFiles(pid)),
        CWD_PROC_KIND_TASKLIST => Cwd::Proc(ProcDirKind::TaskList(pid)),
        CWD_PROC_KIND_FDLIST => Cwd::Proc(ProcDirKind::FdList(pid)),
        _ => Cwd::Proc(ProcDirKind::Root),
    }
}

fn encode_proc_cwd(kind: ProcDirKind) -> u64 {
    match kind {
        ProcDirKind::Root => CWD_PROC_TAG | CWD_PROC_KIND_ROOT,
        ProcDirKind::PidFiles(pid) => CWD_PROC_TAG | CWD_PROC_KIND_PIDFILES | pid as u64,
        ProcDirKind::TaskList(pid) => CWD_PROC_TAG | CWD_PROC_KIND_TASKLIST | pid as u64,
        ProcDirKind::FdList(pid) => CWD_PROC_TAG | CWD_PROC_KIND_FDLIST | pid as u64,
    }
}

fn current_cwd() -> Cwd {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    decode_cwd(unsafe { oxidebsd_get_cwd() })
}

fn set_current_cwd_real(inode: u32) {
    unsafe { oxidebsd_set_cwd(inode as u64) };
}

fn set_current_cwd_proc(kind: ProcDirKind) {
    unsafe { oxidebsd_set_cwd(encode_proc_cwd(kind)) };
}

/// `kind`'s own parent, as a `ProcDirKind` -- `None` only for `Root`, whose parent is the *real*
/// filesystem root, not expressible as a `ProcDirKind` at all (see `proc_relative_chdir`'s own
/// handling of that transition).
fn proc_parent_kind(kind: ProcDirKind) -> Option<ProcDirKind> {
    match kind {
        ProcDirKind::Root => None,
        ProcDirKind::PidFiles(_) => Some(ProcDirKind::Root),
        ProcDirKind::TaskList(pid) | ProcDirKind::FdList(pid) => Some(ProcDirKind::PidFiles(pid)),
    }
}

/// Opens `kind` itself as a directory listing -- the cwd-relative counterpart of `proc_open`
/// dispatching on a full suffix string, used once a caller already has a `ProcDirKind` in hand
/// (no suffix string to re-parse).
fn open_proc_dir_kind(kind: ProcDirKind) -> i64 {
    match kind {
        ProcDirKind::Root => open_proc_root_dir(),
        ProcDirKind::PidFiles(pid) => open_proc_pid_dir(pid),
        ProcDirKind::TaskList(pid) => open_task_dir(pid),
        ProcDirKind::FdList(pid) => open_fd_dir(pid),
    }
}

/// Builds `kind`'s own `/proc`-relative suffix (`""`/`"/3"`/`"/3/task"`/`"/3/fd"`) -- the same
/// grammar `proc_open`/`proc_kind` parse, used in reverse to let a relative operation performed
/// while cwd'd inside `/proc` delegate straight back into those two functions.
fn proc_dir_suffix(kind: ProcDirKind, out: &mut [u8; MAX_CWD_PATH]) -> usize {
    let mut buf = ByteBuf { buf: out, len: 0 };
    match kind {
        ProcDirKind::Root => {}
        ProcDirKind::PidFiles(pid) => {
            buf.push_bytes(b"/");
            buf.push_decimal(pid);
        }
        ProcDirKind::TaskList(pid) => {
            buf.push_bytes(b"/");
            buf.push_decimal(pid);
            buf.push_bytes(b"/task");
        }
        ProcDirKind::FdList(pid) => {
            buf.push_bytes(b"/");
            buf.push_decimal(pid);
            buf.push_bytes(b"/fd");
        }
    }
    buf.len
}

/// Writes `/proc` + `kind`'s own suffix into `out` -- `oxfs_getcwd`'s own counterpart of
/// `build_cwd_path` for a synthetic cwd.
fn build_proc_cwd_path(kind: ProcDirKind, out: &mut [u8; MAX_CWD_PATH]) -> usize {
    let mut suffix = [0u8; MAX_CWD_PATH];
    let suffix_len = proc_dir_suffix(kind, &mut suffix);
    out[..5].copy_from_slice(b"/proc");
    out[5..5 + suffix_len].copy_from_slice(&suffix[..suffix_len]);
    5 + suffix_len
}

/// The inverse of `proc_dir_suffix` for an arbitrary suffix string (same grammar `proc_kind`
/// parses) -- returns the concrete `ProcDirKind` a directory-shaped suffix names, or `None` if it
/// names a leaf file (or nothing at all). A small, near-duplicate, single-purpose parser rather
/// than a generalized one shared with `proc_open`/`proc_kind` -- matching this file's own existing
/// precedent for that pair (see their own doc comments).
fn proc_dir_kind_for(suffix: &[u8]) -> Option<ProcDirKind> {
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let Some(pid_str) = comps.next() else {
        return Some(ProcDirKind::Root);
    };
    let pid = parse_pid(pid_str)?;
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    if unsafe { oxidebsd_proc_exists(pid as u64) } == 0 {
        return None;
    }
    match comps.next() {
        None => Some(ProcDirKind::PidFiles(pid)),
        Some(b"fd") if comps.next().is_none() => Some(ProcDirKind::FdList(pid)),
        Some(b"task") => match comps.next() {
            None => Some(ProcDirKind::TaskList(pid)),
            // /proc/<pid>/task/<tid> (tid == pid only) behaves like /proc/<pid> itself -- see
            // ProcDirKind::TaskList's own doc comment.
            Some(tid_str) if comps.next().is_none() => {
                let tid = parse_pid(tid_str)?;
                (tid == pid).then_some(ProcDirKind::PidFiles(pid))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Concatenates `kind`'s own suffix with a relative `path` into a single `/proc`-suffix buffer,
/// for delegating a relative operation back into `proc_open`/`proc_kind`/`proc_dir_kind_for` --
/// the shared plumbing every `proc_relative_*` function below uses. Returns `None` if the combined
/// suffix wouldn't fit `MAX_CWD_PATH` (a real path this deep is not a realistic case this tier
/// needs to support, not a silent truncation).
fn proc_join_suffix(kind: ProcDirKind, path: &[u8], out: &mut [u8; MAX_CWD_PATH]) -> Option<usize> {
    let mut len = proc_dir_suffix(kind, out);
    if len + 1 + path.len() > out.len() {
        return None;
    }
    out[len] = b'/';
    len += 1;
    out[len..len + path.len()].copy_from_slice(path);
    len += path.len();
    Some(len)
}

/// `oxfs_open`'s own cwd-relative delegate once cwd is a synthetic `/proc` location (`kind`) and
/// `path` is itself relative (an absolute path -- `/proc/...`, `/dev/...`, or a real absolute path
/// -- is already handled by `oxfs_open` before this is ever called, exactly like today's real-cwd
/// case). `create` is rejected outright (`-EROFS`) -- nothing under `/proc` can ever be created.
fn proc_relative_open(kind: ProcDirKind, path: &[u8], create: bool) -> i64 {
    if create {
        return -EROFS;
    }
    if path.is_empty() || path == b"." {
        return open_proc_dir_kind(kind);
    }
    if path == b".." {
        return match proc_parent_kind(kind) {
            Some(parent) => open_proc_dir_kind(parent),
            None => open_dir_listing(ROOT_INODE),
        };
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    match proc_join_suffix(kind, path, &mut suffix) {
        Some(len) => proc_open(&suffix[..len]),
        None => -ENOENT,
    }
}

/// `oxfs_chdir`'s own cwd-relative delegate, same shape as `proc_relative_open`. A non-`/proc`
/// absolute target (e.g. `"/"`, `"/etc"`) is handled by `oxfs_chdir` itself before this is called,
/// exactly like an absolute `/proc/...` target -- this function only ever sees a relative `path`.
fn proc_relative_chdir(kind: ProcDirKind, path: &[u8]) -> i64 {
    if path.is_empty() || path == b"." {
        set_current_cwd_proc(kind);
        return 0;
    }
    if path == b".." {
        match proc_parent_kind(kind) {
            Some(parent) => set_current_cwd_proc(parent),
            None => set_current_cwd_real(ROOT_INODE),
        }
        return 0;
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    let Some(len) = proc_join_suffix(kind, path, &mut suffix) else {
        return -ENOENT;
    };
    match proc_dir_kind_for(&suffix[..len]) {
        Some(target) => {
            set_current_cwd_proc(target);
            0
        }
        None => match proc_kind(&suffix[..len]) {
            Some(false) => -ENOTDIR, // a real leaf file (stat/cmdline/status/a numeric fd entry)
            _ => -ENOENT,
        },
    }
}

/// `oxfs_stat`/`oxfs_lstat`'s own cwd-relative delegate -- `/proc` has no real symlinks (see
/// `resolve_path_impl`'s own doc comment), so there's no `stat`-vs-`lstat` divergence to make here
/// the way there is in real inode space; both call this the same way.
fn proc_relative_stat(kind: ProcDirKind, path: &[u8], buf_ptr: u64) -> i64 {
    if path.is_empty() || path == b"." {
        return write_proc_stat(true, buf_ptr);
    }
    if path == b".." {
        return match proc_parent_kind(kind) {
            Some(_) => write_proc_stat(true, buf_ptr),
            None => write_stat(ROOT_INODE, buf_ptr), // a real stat of the real root
        };
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    let Some(len) = proc_join_suffix(kind, path, &mut suffix) else {
        return -ENOENT;
    };
    match proc_kind(&suffix[..len]) {
        Some(is_dir) => write_proc_stat(is_dir, buf_ptr),
        None => -ENOENT,
    }
}

/// `oxfs_access`'s own cwd-relative delegate -- `/proc` has no real permission bits (see
/// `oxfs_access`'s own doc comment), so this is existence-only, the same shape
/// `proc_relative_readlink` below already uses for its own "exists or not" question.
fn proc_relative_access(kind: ProcDirKind, path: &[u8]) -> i64 {
    if path.is_empty() || path == b"." {
        return 0;
    }
    if path == b".." {
        return 0;
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    let Some(len) = proc_join_suffix(kind, path, &mut suffix) else {
        return -ENOENT;
    };
    match proc_kind(&suffix[..len]) {
        Some(_) => 0,
        None => -ENOENT,
    }
}

/// `oxfs_readlink`'s own cwd-relative delegate -- nothing under `/proc` is ever a real symlink in
/// this design (see `ProcDirKind::FdList`'s own doc comment), so a path that resolves to *anything*
/// existing is `-EINVAL` ("exists, but isn't a symlink"), matching real `readlink(2)`.
fn proc_relative_readlink(kind: ProcDirKind, path: &[u8]) -> i64 {
    if path.is_empty() || path == b"." || path == b".." {
        return -EINVAL;
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    let Some(len) = proc_join_suffix(kind, path, &mut suffix) else {
        return -ENOENT;
    };
    match proc_kind(&suffix[..len]) {
        Some(_) => -EINVAL,
        None => -ENOENT,
    }
}

/// The shared guard every mutating real-filesystem operation (`mkdir`/`unlink`/`rmdir`/`rename`)
/// needs now that `cwd` can be a synthetic `/proc` location: an absolute `path` is unaffected
/// (resolves against the real root exactly like it always has, regardless of cwd); a *relative*
/// `path` while cwd is inside `/proc` has no real directory to mutate at all, and must be rejected
/// outright (`-EROFS`) rather than silently falling through to whatever the raw sentinel bits
/// would decode to as a bogus real inode index.
fn real_cwd_for_mutation(path: &[u8]) -> Result<u32, i64> {
    match current_cwd() {
        Cwd::Real(inode) => Ok(inode),
        Cwd::Proc(_) => {
            if path.first() == Some(&b'/') {
                Ok(ROOT_INODE)
            } else {
                Err(-EROFS)
            }
        }
    }
}

/// Finds `target`'s own name as recorded in `parent`'s listing (`.`/`..` excluded) -- a directory
/// never stores its own name, only its parent's records do, so recovering one always means
/// searching the parent. Used by `build_cwd_path`.
fn find_name_of_inode_in_dir(parent: u32, target: u32) -> Option<([u8; NAME_MAX], u8)> {
    let inode = read_inode(parent);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) {
                let name = dir_record_name(&block, r);
                if name != b"." && name != b".." && dir_record_inode(&block, r) == target {
                    let mut buf = [0u8; NAME_MAX];
                    buf[..name.len()].copy_from_slice(name);
                    return Some((buf, name.len() as u8));
                }
            }
        }
        i += 1;
    }
    None
}

/// Reconstructs an absolute path for `inode_num` by walking `..` links up to the caller's own
/// effective root (`effective_root_inode()` -- real root unless chrooted, see `SYS_CHROOT`'s own
/// doc comment) and, at each level, recovering that level's own name from its parent's listing --
/// there's no stored path anywhere, only inode numbers, so every call re-derives it from scratch
/// (same approach `modules/fat32`'s own `build_cwd_path` already used for cluster numbers). The
/// effective root itself is always `"/"`, matching real `getcwd(2)` inside a chroot (a contained
/// process has no way to name anything above its own root, so nothing above it should ever appear
/// in the reconstructed path either -- otherwise `pwd` would visibly contradict
/// `resolve_path_impl`'s own `cd ..` containment).
fn build_cwd_path(inode_num: u32, out: &mut [u8; MAX_CWD_PATH]) -> usize {
    let root_inode = effective_root_inode();
    let mut chain = [0u32; MAX_CWD_DEPTH];
    let mut depth = 0;
    let mut cur = inode_num;
    while cur != root_inode && depth < MAX_CWD_DEPTH {
        chain[depth] = cur;
        depth += 1;
        cur = dir_lookup(cur, b"..").unwrap_or(root_inode);
    }

    if depth == 0 {
        out[0] = b'/';
        return 1;
    }

    let mut len = 0;
    for i in (0..depth).rev() {
        let child = chain[i];
        let parent = if i + 1 < depth {
            chain[i + 1]
        } else {
            root_inode
        };
        let Some((name, name_len)) = find_name_of_inode_in_dir(parent, child) else {
            break;
        };
        out[len] = b'/';
        len += 1;
        let name_len = name_len as usize;
        out[len..len + name_len].copy_from_slice(&name[..name_len]);
        len += name_len;
    }
    len
}

/// An open file's own state, keyed by fd in `OPEN_FILES`. `Write`'s buffer dwarfs the other two
/// variants -- deliberate, not overlooked: modules can't use `alloc`/`Box`, so every `OPEN_FILES`
/// slot has to be sized for the worst case regardless (the same "no allocator, so every slot pays
/// the largest variant's cost" shape `modules/fat32`'s own `OpenFile` already has, just with more
/// size variance here since `FileRead` no longer carries a buffer at all).
#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)]
enum OpenFile {
    /// A real file, opened for reading -- streams straight from `inode`'s own block chain on each
    /// `read()` call via `read_inode_at` rather than caching the whole file at `open` time (unlike
    /// `modules/fat32`'s own `OpenFile::Read`), so file size is bounded only by the block pool,
    /// not by a fixed per-fd buffer.
    FileRead { inode: u32, position: usize },
    /// A directory listing, formatted into a fixed buffer at `open` time -- listings stay small,
    /// so caching one is simpler than streaming it record-by-record, and this mirrors
    /// `modules/fat32`'s existing "open a directory, read back a formatted listing" trick for
    /// `ls`. `inode` is the directory's own inode number -- used by `inode_of_open_file`
    /// (`oxfs_fstat` on a directory fd) and by `oxfs_getdents`, which walks `inode`'s *live*
    /// records directly rather than this variant's own pre-formatted `content` (real
    /// `readdir()`/`getdents()` must see every record, `.`/`..` included, not the human-readable
    /// summary `content` holds). `dirent_pos` is `oxfs_getdents`'s own resume cursor -- see that
    /// function's own doc comment.
    DirListing {
        inode: u32,
        content: [u8; DIR_LISTING_BUFFER],
        len: usize,
        position: usize,
        dirent_pos: usize,
    },
    /// A file opened for writing -- accumulates across possibly-multiple `write` calls, committed
    /// only at `close` time (same all-at-once-on-close model `modules/fat32` already uses).
    Write {
        parent_inode: u32,
        name: [u8; NAME_MAX],
        name_len: u8,
        buffer: [u8; MAX_WRITE_BUFFER],
        len: usize,
        /// The caller's own uid at `open(O_CREAT)` time -- real Unix ownership semantics (a
        /// freshly created file is owned by its creator, not always root) -- captured here rather
        /// than re-queried at `close` time since a real program can `open` in one process and
        /// (via a shared fd, e.g. across `fork`) close in another. Unused (but still populated,
        /// for a fresh file) when `existing_inode` is `Some` -- overwriting/appending to a file
        /// that already exists never changes its owner, matching real POSIX `open()`/`write()`.
        owner_uid: u32,
        /// `None`: no inode exists yet for `name` -- `close` allocates a fresh one and inserts it
        /// (the original, only-ever-create behavior this filesystem had before real O_TRUNC/
        /// O_APPEND/O_WRONLY support on an *existing* path existed). `Some(inode)`: `name` already
        /// resolves to `inode` -- `close` overwrites that inode's own content in place via
        /// `write_inode_data` instead of allocating a second inode and re-inserting the directory
        /// entry (which would either collide with or orphan the original). Real POSIX overwrite/
        /// append semantics for an existing file need this distinction: same inode number, same
        /// owner/mode, same directory entry, just new content.
        existing_inode: Option<u32>,
        /// Set by a successful `SYS_FTRUNCATE`/`SYS_FALLOCATE` on this fd, cleared by any `write()`
        /// call that actually buffers real bytes -- tells `commit_write_buffer` whether the real
        /// resize `resize_inode_data` already performed should be left alone at `close()`/`fsync()`
        /// time, or overwritten by this fd's own write buffer as usual. Found live: real BusyBox
        /// `truncate FILE` (`open(O_CREAT) -> ftruncate(fd, size) -> close(fd)`, no `write()` call
        /// at all) had its real resize silently undone the instant `close()` ran -- `commit_write_
        /// buffer`'s existing-inode branch unconditionally re-committed `buffer[..len]`, and `len`
        /// was still `0` (no `write()` ever happened), truncating the file straight back to empty.
        /// A later `write()` on the same fd still wins over an earlier `ftruncate()`, matching real
        /// Unix's own ordering (see `oxfs_ftruncate`'s own doc comment) -- this flag only guards
        /// the specific case of `close()`/`fsync()` running with *zero* real `write()` calls ever
        /// having happened on this fd.
        resized_directly: bool,
        /// Set by `oxfs_unlink` when it finds *no* directory entry for the target path but does
        /// find this exact fd still mid-`open(O_CREAT)` (`existing_inode` still `None`) against
        /// that same `(parent_inode, name)` -- real POSIX: `unlink()` racing ahead of a
        /// not-yet-`close()`d `creat()` on the same path must still make the name unreachable the
        /// moment the create eventually commits (the classic "open, unlink, keep writing" temp-file
        /// idiom). Without this, `oxfs_unlink` found nothing (`ENOENT`) and a later commit (e.g. an
        /// explicit `ftruncate()`/`fsync()`, or the final `close()`) went ahead and inserted the
        /// directory entry anyway, silently resurrecting a name real POSIX says must stay gone.
        /// `commit_write_buffer` checks this and skips the `dir_insert` call when set, while still
        /// allocating a real inode and writing real content to it -- matches real Unix: an
        /// unlinked-but-still-open file keeps working through this fd, it just can never be found
        /// by path again. Backported from master's `5d2e1dd` (found there via `mmap/12-1.c`, a
        /// POSIX-pilot test this branch doesn't carry, but the underlying oxfs bug is identical).
        unlinked: bool,
        /// The real requested creation mode (`open(O_CREAT, mode)`'s own `mode` argument, masked
        /// to `0o777`) -- only meaningful when `existing_inode` is still `None` at `commit_write_
        /// buffer` time (a brand-new inode is being allocated, and this is what its own `mode`
        /// field gets initialized to); ignored when overwriting/appending to an already-existing
        /// inode, which keeps whatever real mode it already has. See `oxfs_open`'s own `mode`
        /// parameter doc comment for why this exists at all.
        mode: u16,
    },
    /// A synthetic `/proc/<pid>/{stat,cmdline,status}` file's content, generated once at `open`
    /// time by calling into `src/process.rs`'s kernel-exported accessors (see `open_proc_leaf`) --
    /// no real inode backs this, mirroring `DirListing`'s own "format once, stream on read" shape.
    ProcRead {
        content: [u8; PROC_BUFFER],
        len: usize,
        position: usize,
    },
    /// A synthetic `/proc` directory listing -- see `ProcDirKind` for what each variant lists.
    /// `content`/`position` back a human-readable read (`cat /proc`, mirroring `DirListing`'s dual
    /// read/getdents purpose); `dirent_pos` is `oxfs_getdents`'s own resume cursor, same role as
    /// `DirListing::dirent_pos`.
    ProcDir {
        kind: ProcDirKind,
        content: [u8; DIR_LISTING_BUFFER],
        len: usize,
        position: usize,
        dirent_pos: usize,
    },
    /// A synthetic `/dev/random` or `/dev/urandom` fd -- see `dev_open`'s own doc comment for why
    /// both device nodes share this one variant. Reads delegate to `oxidebsd_random_bytes`
    /// (`src/random.rs` in the kernel tree); writes are accepted and discarded (matching real
    /// Linux's own behavior for these two nodes, though real entropy-pool mixing from a write
    /// isn't modeled here at all).
    DevRandom,
    /// A synthetic `/dev/null` fd -- every read is an immediate EOF, every write succeeds and
    /// discards its input.
    DevNull,
    /// A synthetic `/dev/zero` fd -- every read fills the caller's buffer with zero bytes (never
    /// EOF), every write succeeds and discards its input, same as `DevNull`.
    DevZero,
}

/// What a synthetic `/proc` directory fd lists -- see `oxfs_getdents`'s own `ProcDir` handling.
#[derive(Clone, Copy)]
enum ProcDirKind {
    /// `/proc` itself: one entry per live pid (`oxidebsd_proc_pid_at`).
    Root,
    /// `/proc/<pid>`: the fixed three leaf names (`stat`/`cmdline`/`status`).
    PidFiles(u32),
    /// `/proc/<pid>/task`: exactly one entry, `<pid>`'s own decimal string -- this kernel has no
    /// real threading, so a process's only "task" is itself. See this file's own module doc
    /// comment / `CLAUDE.md`'s /proc section for why this exists at all: `pstree` (a target applet
    /// for this tier) unconditionally `opendir()`s this path and silently skips a pid entirely if
    /// it's missing, rather than falling back to treating the pid as single-threaded itself.
    TaskList(u32),
    /// `/proc/<pid>/fd`: one entry per fd this process currently has open (`oxidebsd_fd_at`).
    /// Closes the *enumeration* gap for `lsof`/`fuser` -- each entry is a plain `DT_REG`
    /// placeholder (no real fd-target content, since there's no `readlink`-able target to back it
    /// with: oxfs doesn't know what a pipe/socket fd actually is, only `src/pipe.rs`/`src/net/*`
    /// do). A real per-fd target (making these genuine symlinks to the fd's actual resource) needs
    /// a separate, cross-module "describe this fd" mechanism -- a known, deliberate limitation of
    /// this pass, not solved by guessing.
    FdList(u32),
}

fn register_open_file(open_file: OpenFile) -> i64 {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    let Some(slot) = slots.iter_mut().find(|s| s.is_none()) else {
        return -EMFILE;
    };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let fd = unsafe { oxidebsd_alloc_fd() };
    *slot = Some((fd, open_file));
    // SAFETY: oxfs_read/oxfs_write/oxfs_close are this module's own functions, already relocated
    // by the time module_init (which makes this function reachable) runs.
    unsafe { oxidebsd_register_fd_ops(fd, oxfs_read, oxfs_write, oxfs_close) };
    fd as i64
}

fn find_open_file(fd: u64) -> Option<&'static mut OpenFile> {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    for (slot_fd, file) in slots.iter_mut().flatten() {
        if *slot_fd == fd {
            return Some(file);
        }
    }
    None
}

/// Formats `dir_inode`'s listing (one name per line, `<DIR>` or a byte count) into a fresh
/// `OpenFile::DirListing` and registers a fd for it -- see the module doc comment's note on `ls`.
/// `.`/`..` are hidden, matching plain `ls`'s default.
fn open_dir_listing(dir_inode: u32) -> i64 {
    let mut content = [0u8; DIR_LISTING_BUFFER];
    let len = {
        let mut out = ByteBuf {
            buf: &mut content,
            len: 0,
        };
        let inode = read_inode(dir_inode);
        let mut i = 0;
        while let Some(blk) = inode_block_at(&inode, i) {
            let block = read_block(blk);
            for r in 0..RECORDS_PER_BLOCK {
                if !dir_record_used(&block, r) {
                    continue;
                }
                let name = dir_record_name(&block, r);
                if name == b"." || name == b".." {
                    continue;
                }
                let child_inode = read_inode(dir_record_inode(&block, r));
                out.push_bytes(name);
                if child_inode.kind == InodeKind::Dir {
                    out.push_bytes(b"  <DIR>\n");
                } else {
                    out.push_bytes(b"  ");
                    out.push_decimal(child_inode.size);
                    out.push_bytes(b"\n");
                }
            }
            i += 1;
        }
        out.len
    };
    register_open_file(OpenFile::DirListing {
        inode: dir_inode,
        content,
        len,
        position: 0,
        dirent_pos: 0,
    })
}

/// Which synthetic `/proc/<pid>/*` leaf a call to `open_proc_leaf` should generate.
#[derive(Clone, Copy)]
enum ProcLeaf {
    Stat,
    Cmdline,
    Status,
}

/// All-ASCII-digit, non-empty, fits in `u32` -- a real pid never needs more, and this doubles as
/// the "not a valid pid component" rejection every unrecognized `/proc/<garbage>` path needs.
fn parse_pid(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(value)
}

/// `/proc` itself: one live pid per line (`oxidebsd_proc_pid_at`, ascending, `-1`-terminated),
/// mirroring `open_dir_listing`'s own human-readable style.
fn open_proc_root_dir() -> i64 {
    let mut content = [0u8; DIR_LISTING_BUFFER];
    let len = {
        let mut out = ByteBuf {
            buf: &mut content,
            len: 0,
        };
        let mut i = 0u64;
        loop {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let pid = unsafe { oxidebsd_proc_pid_at(i) };
            if pid < 0 {
                break;
            }
            out.push_decimal(pid as u32);
            out.push_bytes(b"\n");
            i += 1;
        }
        out.push_bytes(b"meminfo\nuptime\nstat\nmodules\n");
        out.len
    };
    register_open_file(OpenFile::ProcDir {
        kind: ProcDirKind::Root,
        content,
        len,
        position: 0,
        dirent_pos: 0,
    })
}

/// `/proc/<pid>`: the fixed three leaf names.
fn open_proc_pid_dir(pid: u32) -> i64 {
    let mut content = [0u8; DIR_LISTING_BUFFER];
    let len = {
        let mut out = ByteBuf {
            buf: &mut content,
            len: 0,
        };
        out.push_bytes(b"stat\ncmdline\nstatus\n");
        out.len
    };
    register_open_file(OpenFile::ProcDir {
        kind: ProcDirKind::PidFiles(pid),
        content,
        len,
        position: 0,
        dirent_pos: 0,
    })
}

/// `/proc/<pid>/task`: exactly one entry, `pid`'s own decimal string -- see `ProcDirKind::TaskList`'s
/// own doc comment for why this exists at all.
fn open_task_dir(pid: u32) -> i64 {
    let mut content = [0u8; DIR_LISTING_BUFFER];
    let len = {
        let mut out = ByteBuf {
            buf: &mut content,
            len: 0,
        };
        out.push_decimal(pid);
        out.push_bytes(b"\n");
        out.len
    };
    register_open_file(OpenFile::ProcDir {
        kind: ProcDirKind::TaskList(pid),
        content,
        len,
        position: 0,
        dirent_pos: 0,
    })
}

/// `/proc/<pid>/fd`: one entry per real fd this process has open -- see `ProcDirKind::FdList`'s
/// own doc comment for why each entry is a plain placeholder rather than a real target-bearing
/// symlink.
fn open_fd_dir(pid: u32) -> i64 {
    let mut content = [0u8; DIR_LISTING_BUFFER];
    let len = {
        let mut out = ByteBuf {
            buf: &mut content,
            len: 0,
        };
        let mut i = 0u64;
        loop {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let fd = unsafe { oxidebsd_fd_at(pid as u64, i) };
            if fd < 0 {
                break;
            }
            out.push_decimal(fd as u32);
            out.push_bytes(b"\n");
            i += 1;
        }
        out.len
    };
    register_open_file(OpenFile::ProcDir {
        kind: ProcDirKind::FdList(pid),
        content,
        len,
        position: 0,
        dirent_pos: 0,
    })
}

/// Which system-wide (not per-pid) synthetic `/proc` file a call to `open_proc_sysfile` should
/// generate -- siblings of the numeric pid entries at `/proc`'s own top level.
#[derive(Clone, Copy)]
enum ProcSysFile {
    Meminfo,
    Uptime,
    Stat,
    Modules,
    Mounts,
}

/// Formats `MOUNTS` as standard mtab-shaped lines (`<source> <target> <fstype> <opts> 0 0`) for
/// `/proc/mounts` -- unlike the other `ProcSysFile` variants, this needs no kernel FFI accessor:
/// the mount table is this module's own state. A fixed `oxfs / oxfs rw 0 0` line always comes
/// first (the one real, always-mounted filesystem), followed by one line per active `MountEntry`.
/// Read by BusyBox's own `mount.c` (with no arguments) and `mountpoint`/`umount`'s own mtab
/// lookups -- the same "prefer /proc/mounts when present" convention real Linux userland follows.
fn format_mounts(buf: &mut [u8; PROC_BUFFER]) -> usize {
    let mut n = 0;
    let mut push = |bytes: &[u8]| {
        let room = buf.len() - n;
        let take = bytes.len().min(room);
        buf[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
    };
    push(b"oxfs / oxfs rw 0 0\n");
    for m in mounts().iter().filter(|m| m.used) {
        push(&m.source[..m.source_len as usize]);
        push(b" ");
        push(&m.path[..m.path_len as usize]);
        match m.kind {
            MountKind::Bind => push(b" none rw,bind 0 0\n"),
            MountKind::Tmpfs => push(b" tmpfs rw 0 0\n"),
        }
    }
    n
}

/// `/proc/{meminfo,uptime,stat,modules,mounts}`: same "format once at open time into a fixed
/// buffer" shape `open_proc_leaf` uses for the per-pid leaves, just backed by the system-wide
/// kernel accessors (or, for `Mounts`, this module's own state) instead of a per-pid one. Unlike
/// `open_proc_leaf`, there's no pid to vanish out from under this call -- none of these ever fail.
fn open_proc_sysfile(kind: ProcSysFile) -> i64 {
    let mut content = [0u8; PROC_BUFFER];
    let n = match kind {
        ProcSysFile::Mounts => format_mounts(&mut content) as i64,
        // SAFETY: FFI calls to kernel-exported functions, matching their declared signatures;
        // each writes at most PROC_BUFFER bytes into content, sized to match.
        _ => unsafe {
            match kind {
                ProcSysFile::Meminfo => {
                    oxidebsd_proc_meminfo(content.as_mut_ptr(), PROC_BUFFER as u64)
                }
                ProcSysFile::Uptime => {
                    oxidebsd_proc_uptime(content.as_mut_ptr(), PROC_BUFFER as u64)
                }
                ProcSysFile::Stat => {
                    oxidebsd_proc_stat_global(content.as_mut_ptr(), PROC_BUFFER as u64)
                }
                ProcSysFile::Modules => {
                    oxidebsd_proc_modules(content.as_mut_ptr(), PROC_BUFFER as u64)
                }
                ProcSysFile::Mounts => unreachable!(),
            }
        },
    };
    register_open_file(OpenFile::ProcRead {
        content,
        len: n as usize,
        position: 0,
    })
}

/// `/proc/<pid>/{stat,cmdline,status}`: calls the matching kernel accessor once, at `open` time,
/// into a fresh fixed buffer -- same "format once, stream on read" shape `open_dir_listing` uses.
fn open_proc_leaf(pid: u32, leaf: ProcLeaf) -> i64 {
    let mut content = [0u8; PROC_BUFFER];
    // SAFETY: FFI calls to kernel-exported functions, matching their declared signatures; each
    // writes at most PROC_BUFFER bytes into content, sized to match.
    let n = unsafe {
        match leaf {
            ProcLeaf::Stat => {
                oxidebsd_proc_stat_line(pid as u64, content.as_mut_ptr(), PROC_BUFFER as u64)
            }
            ProcLeaf::Cmdline => {
                oxidebsd_proc_cmdline(pid as u64, content.as_mut_ptr(), PROC_BUFFER as u64)
            }
            ProcLeaf::Status => {
                oxidebsd_proc_status(pid as u64, content.as_mut_ptr(), PROC_BUFFER as u64)
            }
        }
    };
    if n < 0 {
        // The pid existed at proc_open's own check but is gone now (exited between that check and
        // this call) -- ESRCH is the honest answer, not EBADF/ENOENT.
        return -ESRCH;
    }
    register_open_file(OpenFile::ProcRead {
        content,
        len: n as usize,
        position: 0,
    })
}

/// Dispatches every `/proc/...` path `oxfs_open` hands off to it (`suffix` is the path *after*
/// `/proc`, e.g. `""`, `"/3"`, `"/3/stat"`, `"/3/task/3/status"`). No real inode/path resolution
/// involved -- every case here is synthesized directly from the live process table via the
/// `oxidebsd_proc_*` kernel accessors.
fn proc_open(suffix: &[u8]) -> i64 {
    // System-wide files, siblings of the numeric pid entries at /proc's own top level -- checked
    // before any pid parsing (safe: none of these three names is ever a valid pid, so today they
    // already fall through to -ENOENT; no regression).
    match suffix {
        b"/meminfo" => return open_proc_sysfile(ProcSysFile::Meminfo),
        b"/uptime" => return open_proc_sysfile(ProcSysFile::Uptime),
        b"/stat" => return open_proc_sysfile(ProcSysFile::Stat),
        b"/modules" => return open_proc_sysfile(ProcSysFile::Modules),
        b"/mounts" => return open_proc_sysfile(ProcSysFile::Mounts),
        _ => {}
    }
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let Some(pid_str) = comps.next() else {
        return open_proc_root_dir();
    };
    let Some(pid) = parse_pid(pid_str) else {
        return -ENOENT;
    };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    if unsafe { oxidebsd_proc_exists(pid as u64) } == 0 {
        return -ENOENT;
    }
    match comps.next() {
        None => open_proc_pid_dir(pid),
        Some(b"stat") if comps.next().is_none() => open_proc_leaf(pid, ProcLeaf::Stat),
        Some(b"cmdline") if comps.next().is_none() => open_proc_leaf(pid, ProcLeaf::Cmdline),
        Some(b"status") if comps.next().is_none() => open_proc_leaf(pid, ProcLeaf::Status),
        Some(b"fd") if comps.next().is_none() => open_fd_dir(pid),
        // /proc/<pid>/task[/<tid>[/stat|cmdline|status]] -- see ProcDirKind::TaskList's doc
        // comment for why this redirect exists. Only tid == pid is ever valid: this kernel has no
        // real threading, so a process's only "task" is itself.
        Some(b"task") => match comps.next() {
            None => open_task_dir(pid),
            Some(tid_str) => {
                let Some(tid) = parse_pid(tid_str) else {
                    return -ENOENT;
                };
                if tid != pid {
                    return -ENOENT;
                }
                match comps.next() {
                    None => open_proc_pid_dir(pid),
                    Some(b"stat") if comps.next().is_none() => open_proc_leaf(pid, ProcLeaf::Stat),
                    Some(b"cmdline") if comps.next().is_none() => {
                        open_proc_leaf(pid, ProcLeaf::Cmdline)
                    }
                    Some(b"status") if comps.next().is_none() => {
                        open_proc_leaf(pid, ProcLeaf::Status)
                    }
                    _ => -ENOENT,
                }
            }
        },
        _ => -ENOENT,
    }
}

/// Resolves a `/proc` suffix (same grammar as `proc_open`, see its own doc comment) to whether it
/// names a directory, without generating any real content -- shared by `oxfs_stat`/`oxfs_lstat`'s
/// own `/proc` handling, which only needs the file type to fill in `st_mode`. `None` means no such
/// entry (`-ENOENT`). A separate, smaller match from `proc_open`'s own -- that one additionally has
/// to pick which specific kernel accessor to call for a leaf file's real content, which this
/// doesn't need.
fn proc_kind(suffix: &[u8]) -> Option<bool> {
    match suffix {
        b"/meminfo" | b"/uptime" | b"/stat" | b"/modules" | b"/mounts" => return Some(false),
        _ => {}
    }
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let Some(pid_str) = comps.next() else {
        return Some(true); // /proc itself
    };
    let pid = parse_pid(pid_str)?;
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    if unsafe { oxidebsd_proc_exists(pid as u64) } == 0 {
        return None;
    }
    match comps.next() {
        None => Some(true), // /proc/<pid>
        Some(b"stat" | b"cmdline" | b"status") if comps.next().is_none() => Some(false),
        Some(b"fd") if comps.next().is_none() => Some(true),
        Some(b"task") => match comps.next() {
            None => Some(true), // /proc/<pid>/task
            Some(tid_str) => {
                let tid = parse_pid(tid_str)?;
                if tid != pid {
                    return None;
                }
                match comps.next() {
                    None => Some(true), // /proc/<pid>/task/<tid>
                    Some(b"stat" | b"cmdline" | b"status") if comps.next().is_none() => Some(false),
                    _ => None,
                }
            }
        },
        _ => None,
    }
}

/// `/dev/{random,urandom,null,zero}` -- a second special-cased path prefix alongside `/proc`
/// (`proc_open`'s own doc comment), added specifically once BusyBox's own vendored TLS code
/// (`networking/tls.c`'s `tls_get_random`) turned out to need real `/dev/urandom` (see
/// CLAUDE.md's "Real networking" known-gaps entry on `wget` HTTPS) -- previously `open()` on any
/// of these just fell through to `-ENOENT` like any other nonexistent path, since no real inode
/// backed them and nothing intercepted the prefix.
///
/// Unlike `/proc`, there's no directory-listing/`stat` support here at all -- nothing in this
/// port's roster calls `opendir("/dev")`/`stat("/dev/...")`, only plain `open()`+`read()`/
/// `write()`+`close()`, so that's all this implements. A known, documented gap, the same
/// incremental-rollout shape `/proc` itself went through.
///
/// `random` and `urandom` share one variant (`OpenFile::DevRandom`) -- this kernel has no real
/// entropy-pool concept, so there's no meaningful difference between "blocks until enough entropy"
/// and "doesn't" the way real Linux's two device nodes historically differed (and barely still do,
/// post-5.6). See `src/random.rs`'s own module doc comment for where the actual bytes come from.
fn dev_open(suffix: &[u8]) -> i64 {
    match suffix {
        b"random" | b"urandom" => register_open_file(OpenFile::DevRandom),
        b"null" => register_open_file(OpenFile::DevNull),
        b"zero" => register_open_file(OpenFile::DevZero),
        _ => -ENOENT,
    }
}

/// Splits a raw `dev_t` register value into `(major, minor)` the same way musl's own
/// `major()`/`minor()` macros do (`third_party/musl/include/sys/sysmacros.h`) for any major <
/// 4096 / minor < 256 -- musl's full macro folds in extra bits past that range, but every value
/// this filesystem's own device support actually needs to round-trip (the four devices below, and
/// anything BusyBox's own `makedevs` default table passes) stays well inside it, so this reduced
/// form is bit-for-bit identical to the real one there. `Inode::rdev` stores the caller's raw
/// `dev` argument verbatim (truncated to `u32`, already exactly this packed shape for a realistic
/// value) -- so encoding back out for `write_stat`'s own `st_rdev` needs no separate step, only
/// this same split for the `oxfs_open` dispatch below.
fn dev_major_minor(dev: u32) -> (u32, u32) {
    ((dev >> 8) & 0xfff, dev & 0xff)
}

/// The only major:minor pairs an `InodeKind::Device` node's `open()` can actually service -- real
/// Linux's own standard values for `/dev/null`(1,3)/`zero`(1,5)/`random`(1,8)/`urandom`(1,9), so a
/// real `mknod /dev/null c 1 3` genuinely works. No general device-driver framework exists (mirrors
/// `dev_open`'s own scope, just reached via a real inode instead of magic-path interception) --
/// anything else is a real, listable, stat-able device node whose `open()` honestly fails `-ENXIO`,
/// matching real Linux's own behavior for a device number with no bound driver.
fn known_device(rdev: u32, device_char: bool) -> Option<OpenFile> {
    if !device_char {
        return None;
    }
    match dev_major_minor(rdev) {
        (1, 3) => Some(OpenFile::DevNull),
        (1, 5) => Some(OpenFile::DevZero),
        (1, 8) | (1, 9) => Some(OpenFile::DevRandom),
        _ => None,
    }
}

/// Registered for `SYS_OPEN`. `/proc/...` (absolute only -- a *relative* path reached while cwd is
/// already inside `/proc` is `proc_relative_open`'s job, below) is intercepted before any of the
/// real, cwd-relative special-casing below, since it isn't backed by a real inode at all -- see
/// `proc_open`. `/dev/...` gets the same treatment right after -- see `dev_open`.
///
/// `mode` (the 4th real syscall argument, `R10`) is `open(2)`'s own real creation-mode argument --
/// only meaningful (and only ever read) when `O_CREAT` actually creates a brand-new inode (the
/// `None if create` arm below); ignored for every other arm, the same way real `open(2)` ignores
/// it for an existing path. **Found live, a real bug, not a deliberate simplification**: this
/// ABI's own `SYS_OPEN` used to carry no mode argument at all (`third_party/musl/src/fcntl/
/// open.c`'s own old comment: "this filesystem doesn't model permissions" -- stale the moment the
/// real per-inode `mode`/`uid`/`gid` permission model landed, but never revisited), so every
/// `open(O_CREAT, mode)` silently got `FIXED_PERM` (`0o755`) regardless of what the caller
/// actually asked for -- a real permission/security gap for anything expecting a restrictive
/// creation mode (e.g. `open(path, O_CREAT|O_WRONLY, 0600)`). Fixed by extending `open(2)`'s own
/// wire format to a real 4-arg `(path_ptr, path_len, flags, mode)` -- `third_party/musl/src/
/// fcntl/open.c` and `src/internal/syscall.h`'s own `__sys_open3`/`__sys_open_cp3` (the internal
/// stdio-callers' path) now pass it through via `__syscall4`/`__syscall_cp4` instead of discarding
/// it. Backported from master's `aeeac6f`/musl's `fac4d9c` (found there via `sem_open/3-1.c`, a
/// POSIX-pilot test this branch doesn't carry, but the underlying bug is identical). **No umask
/// consultation here** -- `Process::umask` is still real, tracked-but-unconsulted state everywhere
/// else oxfs creates an inode, unchanged by this fix.
/// `""`/`"."`/`".."`/`"/"` are special-cased next (mirroring `modules/fat32`'s own handling of
/// them) before falling into `resolve_parent`, which -- unlike FAT32's single-component
/// `to_short_name` -- handles an arbitrarily deep path (`sub/inner/file.txt`) in this one call.
extern "C" fn oxfs_open(path_ptr: u64, path_len: u64, flags: u64, mode: u64) -> i64 {
    // SAFETY: same trust boundary as sys_write's own documented pointer-validation gap in
    // src/syscall.rs -- the caller (ultimately userland, via SYS_OPEN) owns this pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let create = flags & O_CREAT != 0;

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return proc_open(&path[5..]);
    }
    if path.starts_with(b"/dev/") {
        return dev_open(&path[5..]);
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_open(kind, path, create);
            }
        }
    };

    if path.is_empty() || path == b"." {
        return open_dir_listing(cwd);
    }
    if path == b"/" {
        return open_dir_listing(ROOT_INODE);
    }
    if path == b".." {
        return match dir_lookup(cwd, b"..") {
            Some(parent) => open_dir_listing(parent),
            None => -ENOENT,
        };
    }

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };

    match dir_lookup(parent, leaf) {
        Some(inode_num) => {
            // `dir_lookup` is a bare lookup -- unlike `resolve_path`, it doesn't apply the mount
            // redirect `resolve_path_impl`'s own loop does for every *intermediate* component.
            // That's correct when `leaf` is being checked for an EEXIST-style presence test
            // (`oxfs_mkdir`/`oxfs_symlink`), but here `leaf` is the thing actually being opened --
            // if it's itself an active mountpoint (e.g. `open("/mnttest")`, not
            // `open("/mnttest/f")`, where "mnttest" is an *intermediate* component `resolve_path`
            // inside `resolve_parent` already redirected), it needs the same redirect or a plain
            // `open`/`getdents` on the mountpoint's own path would see the real, shadowed
            // directory instead of the mounted one. Found live via `tests/mount_syscall_smoke.rs`.
            let inode_num = active_mount_for(inode_num).map_or(inode_num, |m| m.target_root_inode);
            // Real open() follows a final symlink component by default (no O_NOFOLLOW in this
            // ABI to opt out) -- resolve_path already knows how, so hand it the symlink's own
            // stored target relative to its own parent directory. A dangling target surfaces as
            // the same -ENOENT any other failed resolve_path call already returns.
            let resolved = if read_inode(inode_num).kind == InodeKind::Symlink {
                let mut target = [0u8; MAX_CWD_PATH];
                let n = read_inode_at(inode_num, 0, &mut target);
                match resolve_path(parent, &target[..n]) {
                    Ok(v) => v,
                    Err(e) => return errno_for(e),
                }
            } else {
                inode_num
            };
            // Real permission check -- see check_access's own doc comment. `want_write` is real
            // now (see this function's own doc comment for the history: every open of an existing
            // path used to always end up read-only regardless of O_WRONLY/O_RDWR); do_execve's own
            // ELF-loading read (see src/process.rs) always opens read-only, so its own approximate
            // execute-permission-via-read-bit check (a known, documented simplification, harmless
            // while every seeded file's default mode 0o755 sets both bits identically) is
            // unaffected by this.
            let inode = read_inode(resolved);
            let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
            // Real O_RDONLY is 0 -- "anything but that" in the low two bits means O_WRONLY/O_RDWR.
            let want_write = flags & O_ACCMODE != 0;
            if !check_access(&inode, uid, gid, if want_write { W_OK } else { R_OK }) {
                return -EACCES;
            }
            match inode.kind {
                InodeKind::Dir if want_write => -EISDIR,
                InodeKind::Dir => open_dir_listing(resolved),
                InodeKind::Device => match known_device(inode.rdev, inode.device_char) {
                    Some(open_file) => register_open_file(open_file),
                    None => -ENXIO,
                },
                _ if want_write => {
                    let mut name = [0u8; NAME_MAX];
                    name[..leaf.len()].copy_from_slice(leaf);
                    let mut buffer = [0u8; MAX_WRITE_BUFFER];
                    let mut len = 0;
                    // O_APPEND: start from the file's real existing content, so subsequent writes
                    // land after it rather than replacing it -- otherwise (plain O_WRONLY/O_RDWR,
                    // with or without an explicit O_TRUNC) start empty, real POSIX truncate-on-
                    // write-open semantics (this filesystem has no way to write only *part* of a
                    // file in place -- see write_inode_data's own doc comment -- so there's no
                    // separate "O_WRONLY without O_TRUNC" case to support here; the last real
                    // difference O_TRUNC would make, leaving the old content until the write
                    // actually happens, doesn't matter for any caller in this port's roster).
                    if flags & O_APPEND != 0 {
                        len = read_inode_at(resolved, 0, &mut buffer);
                    }
                    register_open_file(OpenFile::Write {
                        parent_inode: parent,
                        name,
                        name_len: leaf.len() as u8,
                        buffer,
                        len,
                        owner_uid: inode.uid,
                        existing_inode: Some(resolved),
                        resized_directly: false,
                        unlinked: false,
                        // Unused: `commit_write_buffer`'s `existing_inode: Some(_)` branch never
                        // touches `inode.mode` -- overwriting/appending to a file that already
                        // exists never changes its own real, already-stored permission bits.
                        mode: inode.mode,
                    })
                }
                _ => register_open_file(OpenFile::FileRead {
                    inode: resolved,
                    position: 0,
                }),
            }
        }
        None if create => {
            let parent_inode = read_inode(parent);
            let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
            if !check_access(&parent_inode, uid, gid, W_OK) {
                return -EACCES;
            }
            let mut name = [0u8; NAME_MAX];
            name[..leaf.len()].copy_from_slice(leaf);
            register_open_file(OpenFile::Write {
                parent_inode: parent,
                name,
                name_len: leaf.len() as u8,
                buffer: [0; MAX_WRITE_BUFFER],
                len: 0,
                owner_uid: uid as u32,
                existing_inode: None,
                resized_directly: false,
                unlinked: false,
                // Real requested creation mode -- see `oxfs_open`'s own `mode` parameter doc
                // comment for the wire-format history (this ABI's `open(2)` used to have no way
                // to carry `mode` at all, so every `O_CREAT` file silently got `FIXED_PERM`
                // regardless of what the caller actually asked for). No umask consultation here --
                // `Process::umask` is still real, tracked-but-unconsulted state everywhere else
                // oxfs creates an inode, not something this fix's own scope extends to.
                mode: (mode & 0o777) as u16,
            })
        }
        None => -ENOENT,
    }
}

extern "C" fn oxfs_read(fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(file) = find_open_file(fd) else {
        return -EBADF;
    };
    match file {
        OpenFile::FileRead { inode, position } => {
            // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
            let n = read_inode_at(*inode, *position, out);
            *position += n;
            n as i64
        }
        OpenFile::DirListing {
            content,
            len: total,
            position,
            ..
        } => {
            let remaining = *total - *position;
            let n = remaining.min(len as usize);
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, n) };
            out.copy_from_slice(&content[*position..*position + n]);
            *position += n;
            n as i64
        }
        OpenFile::Write { .. } => -EBADF,
        OpenFile::ProcRead {
            content,
            len: total,
            position,
        } => {
            let remaining = *total - *position;
            let n = remaining.min(len as usize);
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, n) };
            out.copy_from_slice(&content[*position..*position + n]);
            *position += n;
            n as i64
        }
        OpenFile::ProcDir {
            content,
            len: total,
            position,
            ..
        } => {
            let remaining = *total - *position;
            let n = remaining.min(len as usize);
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, n) };
            out.copy_from_slice(&content[*position..*position + n]);
            *position += n;
            n as i64
        }
        OpenFile::DevRandom => {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            unsafe { oxidebsd_random_bytes(ptr, len) }
        }
        OpenFile::DevNull => 0, // immediate EOF, matching real /dev/null's own read behavior
        OpenFile::DevZero => {
            // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
            out.fill(0);
            len as i64
        }
    }
}

extern "C" fn oxfs_write(fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(file) = find_open_file(fd) else {
        return -EBADF;
    };
    match file {
        OpenFile::Write {
            buffer,
            len: buf_len,
            resized_directly,
            ..
        } => {
            let available = MAX_WRITE_BUFFER - *buf_len;
            let n = available.min(len as usize);
            if n == 0 && len > 0 {
                return -ENOSPC;
            }
            // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
            let src = unsafe { core::slice::from_raw_parts(ptr as *const u8, n) };
            buffer[*buf_len..*buf_len + n].copy_from_slice(src);
            *buf_len += n;
            // A real write() reasserts the normal buffer-wins-at-close behavior -- matches real
            // Unix's own "whichever happens last" ordering between ftruncate() and write() (see
            // `resized_directly`'s own doc comment).
            if n > 0 {
                *resized_directly = false;
            }
            n as i64
        }
        // Matches real /dev/null's and /dev/zero's own write behavior (accept and discard); real
        // /dev/urandom also accepts writes (mixing them into the entropy pool) -- this kernel has
        // no such pool to mix into, so accept-and-discard is the honest simplification here too.
        OpenFile::DevRandom | OpenFile::DevNull | OpenFile::DevZero => len as i64,
        _ => -EBADF,
    }
}

/// Shared by `oxfs_close` (which then discards the slot entirely) and `oxfs_fsync`/`oxfs_sync`
/// (which force this same commit early, without closing the fd -- see `SYS_FSYNC`'s own doc
/// comment for why this filesystem's normal commit-only-at-close write model otherwise makes
/// `fsync()` a lie). A no-op (`0`) for any non-`Write` variant -- nothing to flush for a read or
/// directory-listing fd. For a brand-new file (`existing_inode` still `None`), allocates the real
/// inode and inserts its directory entry *now*, then records that new inode back into
/// `existing_inode` -- idempotent: a second `commit_write_buffer` call on the same still-open fd
/// (a `write()` then another `fsync()`, or `fsync()` then `close()`) takes the `Some(inode_num)`
/// branch instead of re-allocating and double-inserting.
fn commit_write_buffer(file: &mut OpenFile) -> i64 {
    let OpenFile::Write {
        parent_inode,
        name,
        name_len,
        buffer,
        len,
        owner_uid,
        existing_inode,
        resized_directly,
        unlinked,
        mode,
    } = file
    else {
        return 0;
    };
    // Overwriting/appending to a file that already exists: write the new content into its own
    // existing inode -- same inode number, same directory entry, same owner/mode -- rather
    // than allocating a second inode and re-inserting the name (which would either collide
    // with or orphan the original entry; see OpenFile::Write's own doc comment).
    //
    // Skipped entirely when `resized_directly` is still set (a `SYS_FTRUNCATE`/`SYS_FALLOCATE`
    // already resized this same inode for real, and no `write()` has happened since to justify
    // overwriting it with -- ordinarily empty -- buffer content) -- see that field's own doc
    // comment for the real bug this guards against.
    if let Some(inode_num) = *existing_inode {
        if *resized_directly {
            return 0;
        }
        return if write_inode_data(inode_num, &buffer[..*len]) {
            0
        } else {
            -EIO
        };
    }
    // A new file created inside a tmpfs-mounted directory must itself come from the tmpfs
    // pool -- see `alloc_inode_in` below for why this is the one call site of the three
    // "create a new named entry" ones (mkdir/open-O_CREAT/symlink) that had a live bug here
    // (found via `tests/mount_syscall_smoke.rs`): the other two check `parent`/`cwd` directly,
    // but this one only learns `parent_inode` this late, at commit time.
    let Some(new_inode) = alloc_inode_in(*parent_inode) else {
        return -ENOSPC;
    };
    let mut inode = Inode::new(InodeKind::File);
    inode.uid = *owner_uid;
    inode.mode = *mode;
    write_inode(new_inode, inode);
    if !write_inode_data(new_inode, &buffer[..*len]) {
        return -EIO;
    }
    // Real Unix semantics: this fd's own name was already unlinked before it ever got the chance
    // to name anything (see `unlinked`'s own doc comment) -- a real inode still gets allocated and
    // populated, so the fd (and any mmap of it) keeps working, but no directory entry is ever
    // inserted for it.
    if *unlinked {
        *existing_inode = Some(new_inode);
        return 0;
    }
    match dir_insert(*parent_inode, &name[..*name_len as usize], new_inode) {
        Ok(()) => {
            *existing_inode = Some(new_inode);
            0
        }
        Err(e) => errno_for(e),
    }
}

/// Registered as `fd`'s close callback via `oxidebsd_register_fd_ops`. For a file opened for
/// writing, this is (ordinarily) the point its accumulated buffer is actually committed to a real
/// inode, via `commit_write_buffer` above -- unless `SYS_FSYNC`/`SYS_SYNC` already did so earlier
/// on this same still-open fd, in which case this is a cheap idempotent no-op re-commit of
/// unchanged content. Also releases any `flock()` locks `fd` still holds -- real `flock()`
/// semantics: closing the locked fd releases its locks.
extern "C" fn oxfs_close(fd: u64) -> i64 {
    release_flocks_for(fd);
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    let Some(slot) = slots
        .iter_mut()
        .find(|s| matches!(s, Some((slot_fd, _)) if *slot_fd == fd))
    else {
        return -EBADF;
    };
    let (_, mut file) = slot.take().expect("just matched Some above");
    commit_write_buffer(&mut file)
}

/// Registered for `SYS_CLOSE`. Delegates to the kernel's own `oxidebsd_close_fd`, which removes
/// `fd` from its registry and invokes `oxfs_close` above -- not a direct call, so a closed fd is
/// also no longer reachable via `SYS_READ`/`SYS_WRITE` afterward.
extern "C" fn sys_close(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_close_fd(fd) as i64 }
}

/// Registered for `SYS_FSYNC`. See `SYS_FSYNC`'s own doc comment (up near its number's
/// definition) for why this filesystem's normal commit-only-at-close write model otherwise makes
/// `fsync()` a lie for anything opened for writing. A no-op success for a read/directory fd --
/// real Unix `fsync()` on a read-only fd is also a harmless no-op.
extern "C" fn oxfs_fsync(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    match find_open_file(real_fd as u64) {
        Some(file) => commit_write_buffer(file),
        None => -EBADF,
    }
}

/// Registered for `SYS_SYNC`. Real `sync(2)` takes no arguments and (per POSIX) has no failure
/// return at all -- best-effort force-commits every currently-open write fd's pending buffer, the
/// whole-filesystem counterpart of `oxfs_fsync`'s single-fd version, and always reports success.
extern "C" fn oxfs_sync(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    for (_, file) in slots.iter_mut().flatten() {
        commit_write_buffer(file);
    }
    0
}

/// Shared fd-to-inode resolution for `SYS_FTRUNCATE`/`SYS_FALLOCATE`/`SYS_FSTAT`: `inode_of_open_
/// file` alone (see its own doc comment) reports `None` for *every* `OpenFile::Write` fd, even one
/// that already refers to a real, pre-existing inode (`O_WRONLY` on an existing path, not a fresh
/// `O_CREAT`) -- exactly BusyBox `truncate`'s own common case (`open()` an existing file, then
/// `ftruncate()` it). This falls through to that case specifically before giving up.
///
/// **Also handles a freshly-`O_CREAT`'d file that hasn't been `close()`d yet** (`existing_inode`
/// still `None` -- no real inode allocated at all until commit, see `OpenFile::Write`'s own doc
/// comment). Found live twice, both real, common cases, not edge cases: (1) BusyBox `truncate
/// FILE` on a *nonexistent* `FILE` does exactly `open(path, O_CREAT|O_WRONLY) ->
/// ftruncate(fd, size)`, so this fd is always still `existing_inode: None` at the moment
/// `ftruncate()` runs; (2) BusyBox `tar cf`/`ar rc` (once this build's own `FEATURE_TAR_CREATE`/
/// `FEATURE_AR_CREATE` Kconfig gap closed -- see `build.rs`'s own doc comment) both `fstat()` their
/// freshly-`O_CREAT`'d output fd before ever writing to it, to confirm it's a real file. Previously
/// a flat `EBADF` in both cases, since neither match arm above covered it. Forces the same
/// early-commit `commit_write_buffer` already does for `fsync()`/`sync()` (real inode + directory
/// entry created *now*, not deferred to `close()`) so there's something real to resize/report on.
fn resolve_write_fd_inode(real_fd: u64) -> Option<u32> {
    if let Some(inode_num) = inode_of_open_file(real_fd) {
        return Some(inode_num);
    }
    let file = find_open_file(real_fd)?;
    if let OpenFile::Write {
        existing_inode: None,
        ..
    } = file
    {
        if commit_write_buffer(file) != 0 {
            return None;
        }
    }
    match file {
        OpenFile::Write {
            existing_inode: Some(inode_num),
            ..
        } => Some(*inode_num),
        _ => None,
    }
}

/// Registered for `SYS_FTRUNCATE`. Resizes the fd's real inode directly (`resize_inode_data`) --
/// if this fd is also still mid-write (an existing file opened `O_WRONLY`, not yet `close()`d),
/// a later `write()`/`close()` on it will still overwrite this content again as usual, matching
/// real Unix's own "whichever happens last wins" ordering between `ftruncate()` and `write()`.
/// Marks the fd's own `resized_directly` (if it's a `Write` fd at all -- `resolve_write_fd_inode`
/// also resolves plain read fds via `inode_of_open_file`, which have no such flag to set) so a
/// later `close()`/`fsync()` with no intervening `write()` doesn't undo this resize -- see that
/// field's own doc comment for the real bug this closes.
extern "C" fn oxfs_ftruncate(fd: u64, len: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd as u64) else {
        return -EBADF;
    };
    if read_inode(inode_num).kind == InodeKind::Dir {
        return -EISDIR;
    }
    if !resize_inode_data(inode_num, len as usize) {
        return -ENOSPC;
    }
    if let Some(OpenFile::Write {
        resized_directly, ..
    }) = find_open_file(real_fd as u64)
    {
        *resized_directly = true;
    }
    0
}

/// Registered for `SYS_FALLOCATE`. `mode` is ignored -- always behaves like the default (no
/// `FALLOC_FL_KEEP_SIZE`/`FALLOC_FL_PUNCH_HOLE`/... flag support, a known simplification no
/// applet in this port's roster needs past). Zero-extends the file to `offset + len` if it's
/// currently shorter; otherwise a real no-op (real `fallocate()` never shrinks a file). Marks the
/// fd's own `resized_directly` on an actual resize -- see `oxfs_ftruncate`'s own doc comment for
/// why (same real bug, same fix, shared with that syscall).
extern "C" fn oxfs_fallocate(fd: u64, _mode: u64, offset: u64, len: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd as u64) else {
        return -EBADF;
    };
    let inode = read_inode(inode_num);
    if inode.kind == InodeKind::Dir {
        return -EISDIR;
    }
    let target = offset.saturating_add(len) as usize;
    if inode.size as usize >= target {
        return 0;
    }
    if !resize_inode_data(inode_num, target) {
        return -ENOSPC;
    }
    if let Some(OpenFile::Write {
        resized_directly, ..
    }) = find_open_file(real_fd as u64)
    {
        *resized_directly = true;
    }
    0
}

/// Registered for `SYS_FLOCK`. See `SYS_FLOCK`'s own doc comment (up near its number's
/// definition) for the real `LOCK_SH`/`LOCK_EX`/`LOCK_UN` semantics this implements, and why a
/// request that would conflict fails `EAGAIN` immediately rather than genuinely blocking even
/// without `LOCK_NB`.
extern "C" fn oxfs_flock(fd: u64, op: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    let Some(inode_num) = inode_of_open_file(real_fd) else {
        return -EBADF;
    };

    if op & LOCK_UN != 0 {
        release_flocks_for(real_fd);
        return 0;
    }
    let exclusive = op & LOCK_EX != 0;
    if !exclusive && op & LOCK_SH == 0 {
        return -EINVAL;
    }
    let table = flocks();
    let conflict = table.iter().any(|s| {
        matches!(s, Some((i, holder_fd, ex))
            if *i == inode_num && *holder_fd != real_fd && (exclusive || *ex))
    });
    if conflict {
        return -EAGAIN;
    }
    if let Some(slot) = table
        .iter_mut()
        .find(|s| matches!(s, Some((i, holder_fd, _)) if *i == inode_num && *holder_fd == real_fd))
    {
        *slot = Some((inode_num, real_fd, exclusive));
        return 0;
    }
    match table.iter_mut().find(|s| s.is_none()) {
        Some(slot) => {
            *slot = Some((inode_num, real_fd, exclusive));
            0
        }
        None => -ENOLCK,
    }
}

/// musl's real generic `struct statfs` (`arch/generic/bits/statfs.h` in `third_party/musl` -- this
/// target has no x86_64-specific override, and no separate `statfs64` syscall exists on a 64-bit
/// arch, so this is the one and only shape `src/stat/statvfs.c`'s `__statfs`/`__fstatfs` ever
/// build). All eight `unsigned long`/`fsblkcnt_t`/`fsfilcnt_t` fields are 8 bytes wide on this
/// target, `fsid_t` is a 2-element `int` array -- `f_spare` pads the real kernel-reserved tail.
#[repr(C)]
struct MuslStatfs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<MuslStatfs>() == 120);

/// An arbitrary but recognizable magic (`"OXFS"` as big-endian ASCII bytes) -- no applet in this
/// port's roster branches on `f_type`'s specific value, so any fixed constant would do.
const OXFS_STATFS_MAGIC: u64 = 0x4f584653;

/// Builds a real `struct statfs` from this filesystem's own live usage counts and writes it into
/// the caller's buffer -- shared by `oxfs_statfs` (path-based) and `oxfs_fstatfs` (fd-based).
/// `is_tmpfs` picks which of the two block/inode pools to report on (see `TMPFS_NUM_BLOCKS`'s own
/// doc comment) -- free counts are computed by scanning that pool's own slice of `BLOCK_USED`/
/// `INODES` fresh on every call (no cached running total exists to go stale). `f_bavail` is set
/// equal to `f_bfree` -- this filesystem has no reserved-for-root-only block reservation to make
/// the two diverge, unlike a real ext-family filesystem's own `statfs()`.
fn write_statfs(is_tmpfs: bool, buf_ptr: u64) -> i64 {
    let (blocks_lo, blocks_hi, inodes_lo, inodes_hi) = if is_tmpfs {
        (NUM_BLOCKS, TOTAL_BLOCKS, MAX_INODES, TOTAL_INODES)
    } else {
        (0, NUM_BLOCKS, 0, MAX_INODES)
    };
    let used = unsafe { &*core::ptr::addr_of!(BLOCK_USED) };
    let free_blocks = (blocks_lo..blocks_hi).filter(|&i| !used[i]).count() as u64;
    let inodes = unsafe { &*core::ptr::addr_of!(INODES) };
    let free_inodes = (inodes_lo..inodes_hi)
        .filter(|&i| inodes[i].kind == InodeKind::Free)
        .count() as u64;
    let statfs = MuslStatfs {
        f_type: OXFS_STATFS_MAGIC,
        f_bsize: BLOCK_SIZE as u64,
        f_blocks: (blocks_hi - blocks_lo) as u64,
        f_bfree: free_blocks,
        f_bavail: free_blocks,
        f_files: (inodes_hi - inodes_lo) as u64,
        f_ffree: free_inodes,
        f_fsid: [0, 0],
        f_namelen: NAME_MAX as u64,
        f_frsize: BLOCK_SIZE as u64,
        f_flags: 0,
        f_spare: [0; 4],
    };
    // SAFETY: same trust boundary as `write_stat` -- caller-owned pointer, sized by the caller's
    // own `sizeof(struct statfs)` (120 bytes, matching `MuslStatfs` exactly, checked above).
    unsafe { (buf_ptr as *mut MuslStatfs).write_unaligned(statfs) };
    0
}

/// Registered for `SYS_STATFS`. No `/proc` interception (unlike `oxfs_stat`) -- `/proc` isn't a
/// real, statfs-able mount in this design, and no target applet's own `df`/`statvfs()` call ever
/// targets it. A synthetic-`/proc` cwd falls back to resolving from the real root for an absolute
/// path, same as `oxfs_stat`'s own handling of that case.
extern "C" fn oxfs_statfs(path_ptr: u64, path_len: u64, buf_ptr: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(_) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return -ENOENT;
            }
        }
    };
    match resolve_path(cwd, path) {
        Ok(inode_num) => write_statfs(inode_num >= MAX_INODES as u32, buf_ptr),
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_FSTATFS`. `oxfs_statfs`'s fd-based counterpart -- same fd-to-inode
/// resolution `oxfs_fstat` already uses.
extern "C" fn oxfs_fstatfs(fd: u64, buf_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    match inode_of_open_file(real_fd as u64) {
        Some(inode_num) => write_statfs(inode_num >= MAX_INODES as u32, buf_ptr),
        None => -EBADF,
    }
}

/// Registered for `SYS_CHDIR`. An absolute `/proc/...` target is intercepted first (via
/// `proc_dir_kind_for`, same shape `oxfs_open` uses for `proc_open`) -- it isn't backed by a real
/// inode at all, so `resolve_path` can't resolve it. Otherwise `resolve_path` already handles every
/// real-filesystem case `chdir` needs (`""`/`"."`/`".."`/`"/"`/a multi-component path) uniformly --
/// no separate resolver needed the way `modules/fat32`'s own single-component-only grammar
/// required. A *relative* target while cwd is already inside `/proc` is `proc_relative_chdir`'s
/// job.
extern "C" fn oxfs_chdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return match proc_dir_kind_for(&path[5..]) {
            Some(kind) => {
                set_current_cwd_proc(kind);
                0
            }
            None => match proc_kind(&path[5..]) {
                Some(false) => -ENOTDIR,
                _ => -ENOENT,
            },
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_chdir(kind, path);
            }
        }
    };
    match resolve_path(cwd, path) {
        Ok(inode_num) if read_inode(inode_num).kind == InodeKind::Dir => {
            set_current_cwd_real(inode_num);
            0
        }
        Ok(_) => -ENOTDIR,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_CHROOT`. `path` is resolved exactly like any other path -- against the
/// caller's current cwd *and* its own already-live root (`effective_root_inode()`, consulted
/// automatically inside `resolve_path`), so a nested chroot resolves relative to whatever root is
/// already active, matching real `chroot(2)`. Root-only (`-EPERM` otherwise, real `chroot(2)`'s own
/// `CAP_SYS_CHROOT` requirement -- same genuine-root-only tier as `oxfs_chown`, not the older
/// "no capability model, so always allow" precedent predating the permission-model pass).
/// Deliberately does **not** also `chdir` to the new root -- real `chroot(2)` doesn't either;
/// BusyBox's own `chroot` applet calls `chdir("/")` itself right afterward, the normal real-world
/// pattern. See `resolve_path_impl`'s own doc comment for the actual `cd ..` containment mechanism
/// this enables.
extern "C" fn oxfs_chroot(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let caller_uid = unsafe { oxidebsd_current_uid() };
    if caller_uid != 0 {
        return -EPERM;
    }
    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        // cwd inside /proc, and a *relative* (non-`/`-leading) target: no real caller in this
        // port's roster does this (BusyBox's own `chroot` applet always operates on a real
        // filesystem path), same "honest ENOENT, not a dedicated proc-relative-resolution helper"
        // reasoning `oxfs_utimensat` above already established for the identical edge case.
        Cwd::Proc(_) if path.first() != Some(&b'/') => return -ENOENT,
        Cwd::Proc(_) => ROOT_INODE,
    };
    match resolve_path(cwd, path) {
        Ok(inode_num) if read_inode(inode_num).kind == InodeKind::Dir => {
            unsafe { oxidebsd_set_root(inode_num as u64) };
            0
        }
        Ok(_) => -ENOTDIR,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_GETCWD`. Same wire format as `modules/fat32`'s own `sys_getcwd` (a
/// NUL-terminated string written into `buf`, byte count including the NUL on success, `-ERANGE`
/// if `buf_len` is too small).
extern "C" fn oxfs_getcwd(buf_ptr: u64, buf_len: u64, _a2: u64, _a3: u64) -> i64 {
    let mut path = [0u8; MAX_CWD_PATH];
    let len = match current_cwd() {
        Cwd::Real(inode) => build_cwd_path(inode, &mut path),
        Cwd::Proc(kind) => build_proc_cwd_path(kind, &mut path),
    };

    if buf_len == 0 || (len as u64) + 1 > buf_len {
        return -ERANGE;
    }

    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let out = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    out[..len].copy_from_slice(&path[..len]);
    out[len] = 0;
    (len + 1) as i64
}

/// Registered for `SYS_MKDIR`. `path` may now be multi-component (`sub/nested`, as long as `sub`
/// already exists) -- `resolve_parent` handles that the same way it does for `open`'s `O_CREAT`
/// case.
///
/// **`mkdir("/")` (or any path with no leaf component after stripping trailing slashes) needs its
/// own real `EEXIST`, not `resolve_parent`'s generic `EINVAL`.** Found live: BusyBox's own
/// `mkdir -p` walks and creates every leading component of an *absolute* path, including
/// attempting `mkdir("/")` itself as the very first step -- its own EEXIST-tolerant loop treats
/// any other errno as a hard failure, so a real `mkdir -p /some/absolute/path` aborted outright.
/// `resolve_parent` can't just be changed generically (`rmdir`/`rename`/`symlink`/`mknod` share it
/// and have their own, different correct answers for "no leaf" -- real `rmdir("/")` is `EBUSY`,
/// not `EEXIST`), so this is handled here, specific to `mkdir`'s own real semantics: create-target-
/// already-exists is always `EEXIST`, regardless of whether that target happens to be the root.
extern "C" fn oxfs_mkdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(OxfsError::InvalidPath) if resolve_path(cwd, path).is_ok() => return -EEXIST,
        Err(e) => return errno_for(e),
    };
    if dir_lookup(parent, leaf).is_some() {
        return -EEXIST;
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return -ENOSPC;
    };
    write_inode(new_inode, Inode::new(InodeKind::Dir));
    if dir_insert(new_inode, b".", new_inode).is_err()
        || dir_insert(new_inode, b"..", parent).is_err()
    {
        return -ENOSPC;
    }
    match dir_insert(parent, leaf, new_inode) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_UNLINK`. Refuses to unlink a directory (`EISDIR` -- use `SYS_RMDIR`
/// instead, matching real Unix convention). The removed record's inode/blocks are still never
/// freed (see the module doc comment) -- what's real now is `nlink` itself: a `File`/`Device`
/// inode's own link count is decremented before the record is cleared, so a still-linked file's
/// other name(s) keep reporting the right count via `write_stat` (see `SYS_LINK`'s own doc
/// comment). Reaching `0` isn't a dealloc trigger, just "the last name is gone."
extern "C" fn oxfs_unlink(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(target) = dir_lookup(parent, leaf) else {
        // No directory entry exists yet -- real ENOENT, *unless* some still-open fd is mid-`open
        // (O_CREAT)` against this exact (parent, name) and hasn't committed (inserted its own
        // directory entry) yet. Real POSIX: `unlink()` racing ahead of a not-yet-`close()`d
        // `creat()` on the same path must still make the name unreachable the moment the create
        // eventually commits -- see `OpenFile::Write::unlinked`'s own doc comment.
        let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
        for slot in slots.iter_mut().flatten() {
            if let (
                _,
                OpenFile::Write {
                    parent_inode,
                    name,
                    name_len,
                    existing_inode: None,
                    unlinked,
                    ..
                },
            ) = slot
                && *parent_inode == parent
                && &name[..*name_len as usize] == leaf
            {
                *unlinked = true;
                return 0;
            }
        }
        return -ENOENT;
    };
    let mut target_inode = read_inode(target);
    if target_inode.kind == InodeKind::Dir {
        return -EISDIR;
    }
    if matches!(target_inode.kind, InodeKind::File | InodeKind::Device) {
        target_inode.nlink = target_inode.nlink.saturating_sub(1);
        write_inode(target, target_inode);
    }
    match dir_remove(parent, leaf) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_LINK`. `(existing_ptr, existing_len, new_ptr, new_len)` -- same 4-register
/// two-path shape `SYS_RENAME`/`SYS_SYMLINK` already use (see
/// `third_party/musl/src/unistd/link.c`'s own patch for why `existing`/`new` need explicit lengths
/// where real `link(2)` doesn't). `existing` is resolved via the normal, symlink-following
/// `resolve_path` -- same as `stat`/`open` already do -- so linking a symlink *path* links its
/// real target, not the symlink entry itself (this filesystem doesn't support hard-linking a
/// symlink directly, a documented simplification; POSIX itself leaves this implementation-defined).
/// Only `File`/`Device` inodes can be linked (`EPERM` for a directory, real Unix's own
/// hard-link-to-a-directory prohibition). Rejects linking across the real/tmpfs inode-pool
/// boundary with `EXDEV` -- see that constant's own doc comment for why (a tmpfs-pool inode must
/// never gain a real, disk-persisted name).
extern "C" fn oxfs_link(existing_ptr: u64, existing_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let existing_path =
        unsafe { core::slice::from_raw_parts(existing_ptr as *const u8, existing_len as usize) };
    let new_path = unsafe { core::slice::from_raw_parts(new_ptr as *const u8, new_len as usize) };
    let existing_cwd = match real_cwd_for_mutation(existing_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_cwd = match real_cwd_for_mutation(new_path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let existing_inode = match resolve_path(existing_cwd, existing_path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let mut inode = read_inode(existing_inode);
    if !matches!(inode.kind, InodeKind::File | InodeKind::Device) {
        return -EPERM;
    }

    let (new_parent, new_leaf) = match resolve_parent(new_cwd, new_path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if dir_lookup(new_parent, new_leaf).is_some() {
        return -EEXIST;
    }
    let existing_pool_tmpfs = existing_inode >= MAX_INODES as u32;
    let new_pool_tmpfs = new_parent >= MAX_INODES as u32;
    if existing_pool_tmpfs != new_pool_tmpfs {
        return -EXDEV;
    }
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if !check_access(&read_inode(new_parent), uid, gid, W_OK) {
        return -EACCES;
    }
    if inode.nlink == u16::MAX {
        return -EMLINK;
    }
    match dir_insert(new_parent, new_leaf, existing_inode) {
        Ok(()) => {
            inode.nlink += 1;
            write_inode(existing_inode, inode);
            0
        }
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_MKNOD`. `(path_ptr, path_len, mode, dev)` -- real `mknod(2)`'s own
/// `(path, mode, dev)` shape plus the length-prefixed path convention every other path-taking
/// syscall here uses (see `third_party/musl/src/stat/mknod.c`'s own patch). Creates a real,
/// listable inode reporting `S_IFCHR`/`S_IFBLK` and a real `st_rdev` via `stat`/`getdents` --
/// unlike `/dev/{random,urandom,null,zero}`'s existing magic-path interception in `dev_open` (not
/// backed by any inode at all). See `known_device`'s own doc comment for the deliberately small
/// set of major:minor pairs `open()` actually services. Also supports `S_IFREG` (an immediately
/// committed empty regular file, unlike `O_CREAT`'s deferred-to-`close()` commit -- matches
/// `oxfs_symlink`'s eager-allocate shape instead). `S_IFIFO`/`S_IFSOCK`/anything else in `mode`'s
/// type bits is `-EINVAL` -- real named-pipe persistence is a distinct, unstarted gap. Creating a
/// device node is root-only (`-EPERM` otherwise, real `mknod(2)`'s own `CAP_MKNOD` requirement,
/// same genuine-root-only tier as `oxfs_chown`); `S_IFREG` only needs ordinary write permission on
/// the parent, same as any other create.
extern "C" fn oxfs_mknod(path_ptr: u64, path_len: u64, mode: u64, dev: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if dir_lookup(parent, leaf).is_some() {
        return -EEXIST;
    }
    let (kind, device_char) = match (mode as u32) & S_IFMT {
        S_IFREG => (InodeKind::File, false),
        S_IFCHR => (InodeKind::Device, true),
        S_IFBLK => (InodeKind::Device, false),
        _ => return -EINVAL,
    };
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if kind == InodeKind::Device && uid != 0 {
        return -EPERM;
    }
    if !check_access(&read_inode(parent), uid, gid, W_OK) {
        return -EACCES;
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return -ENOSPC;
    };
    let mut inode = Inode::new(kind);
    inode.mode = (mode & 0o777) as u16;
    inode.uid = uid as u32;
    inode.gid = gid as u32;
    if kind == InodeKind::Device {
        inode.rdev = dev as u32;
        inode.device_char = device_char;
    }
    write_inode(new_inode, inode);
    match dir_insert(parent, leaf, new_inode) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_RMDIR`. Only succeeds on an empty directory (`.`/`..` excepted, via
/// `dir_entry_count`).
extern "C" fn oxfs_rmdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(raw_target) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    if read_inode(raw_target).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    // `dir_lookup` is a bare lookup -- doesn't apply the mount redirect `resolve_path_impl`'s own
    // loop does for intermediate components. `leaf` here is the thing actually being removed, so
    // if it's itself an active mountpoint, emptiness must be checked against the *mounted* root,
    // not the real, shadowed attachment-point directory underneath it (which is always trivially
    // empty) -- otherwise `rmdir` on a non-empty mount silently deletes the mountpoint's name,
    // orphaning its content permanently (unreachable by path, no longer even `umount2`-able).
    // Same fix shape as `oxfs_open`'s existing mount-redirect handling above.
    if active_mount_for(raw_target).is_some() {
        return -EBUSY;
    }
    if dir_entry_count(raw_target) > 2 {
        return -ENOTEMPTY;
    }
    match dir_remove(parent, leaf) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_RENAME`. `(old_ptr, old_len, new_ptr, new_len)` -- uses all four of this
/// ABI's argument registers (see the module doc comment). Overwriting an existing plain file at
/// `new` is allowed (its old record is cleared first, its inode leaked like every other removal
/// here); overwriting an existing directory is refused (`EISDIR`, kept simple rather than
/// implementing real directory-replace semantics).
extern "C" fn oxfs_rename(old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let old_path = unsafe { core::slice::from_raw_parts(old_ptr as *const u8, old_len as usize) };
    let new_path = unsafe { core::slice::from_raw_parts(new_ptr as *const u8, new_len as usize) };
    // Checked independently -- old/new can have different relativity (e.g. renaming a relative
    // name to an absolute destination while cwd is inside /proc must still reject the relative
    // half).
    let old_cwd = match real_cwd_for_mutation(old_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_cwd = match real_cwd_for_mutation(new_path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (old_parent, old_leaf) = match resolve_parent(old_cwd, old_path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(target) = dir_lookup(old_parent, old_leaf) else {
        return -ENOENT;
    };
    let (new_parent, new_leaf) = match resolve_parent(new_cwd, new_path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if let Some(existing) = dir_lookup(new_parent, new_leaf) {
        if read_inode(existing).kind == InodeKind::Dir {
            return -EISDIR;
        }
        let _ = dir_remove(new_parent, new_leaf);
    }
    if dir_remove(old_parent, old_leaf).is_err() {
        return -EIO;
    }
    match dir_insert(new_parent, new_leaf, target) {
        Ok(()) => 0,
        Err(e) => {
            // Best-effort rollback so a failed rename doesn't just lose the entry outright.
            let _ = dir_insert(old_parent, old_leaf, target);
            errno_for(e)
        }
    }
}

/// Registered for `SYS_ACCESS`, kept at real Linux's own inert value (`21`) rather than one of
/// this ABI's own invented numbers -- `third_party/musl/arch/x86_64/bits/syscall.h.in` never
/// remapped `__NR_access`, and nothing else in this ABI claims `21` (confirmed by grep across
/// every registered syscall number here), the same "leave it where musl already emits it" call
/// already made for `SYS_WRITEV`/`SYS_PIPE` in that same header. `(path_ptr, path_len, amode)` --
/// real `access(2)`'s own `(path, amode)` shape plus the length-prefixed path convention every
/// other path-taking syscall here uses (see `third_party/musl/src/unistd/access.c`'s own patch).
/// `amode == F_OK` (`0`) is existence-only; otherwise every requested `R_OK`/`W_OK`/`X_OK` bit
/// (singly or combined) must be granted, checked against the caller's real uid/gid via
/// `check_access` (this kernel has no separate effective uid to diverge from -- see `Process::
/// uid`'s own doc comment in `src/process.rs`). `/proc` entries have no real permission bits (see
/// `write_proc_stat`'s own fixed-placeholder stance) -- existence alone is treated as access,
/// matching this codebase's "don't pretend to model what isn't there" approach elsewhere.
extern "C" fn oxfs_access(path_ptr: u64, path_len: u64, amode: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return match proc_kind(&path[5..]) {
            Some(_) => 0,
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_access(kind, path);
            }
        }
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let amode = amode as u8;
    if amode == 0 {
        return 0;
    }
    let inode = read_inode(inode_num);
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if check_access(&inode, uid, gid, amode) {
        0
    } else {
        -EACCES
    }
}

/// Registered for `SYS_STAT`. Follows a final symlink component (`resolve_path`'s own default) --
/// `oxfs_lstat` below no longer just aliases this, now that real symlinks exist (see
/// `resolve_path_impl`'s own doc comment for the two functions' actual difference). `/proc/...` is
/// intercepted the same way `oxfs_open` does (see `proc_kind`) -- needed for `ls`/`pstree`, both of
/// which `stat()` a path before deciding whether to list it. A relative path while cwd is inside
/// `/proc` delegates to `proc_relative_stat`.
extern "C" fn oxfs_stat(path_ptr: u64, path_len: u64, buf_ptr: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return match proc_kind(&path[5..]) {
            Some(is_dir) => write_proc_stat(is_dir, buf_ptr),
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_stat(kind, path, buf_ptr);
            }
        }
    };
    match resolve_path(cwd, path) {
        Ok(inode_num) => write_stat(inode_num, buf_ptr),
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_LSTAT`. Unlike `oxfs_stat`, never follows a final symlink component --
/// reports the link itself (`S_IFLNK`, `st_size` = target length), the one real difference between
/// the two now that symlinks exist. `/proc` has none, so its own interception is identical to
/// `oxfs_stat`'s.
extern "C" fn oxfs_lstat(path_ptr: u64, path_len: u64, buf_ptr: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return match proc_kind(&path[5..]) {
            Some(is_dir) => write_proc_stat(is_dir, buf_ptr),
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_stat(kind, path, buf_ptr);
            }
        }
    };
    match resolve_path_nofollow_last(cwd, path) {
        Ok(inode_num) => write_stat(inode_num, buf_ptr),
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_READLINK`. `(path_ptr, path_len, buf_ptr, bufsize)` -- real `readlink(2)`'s
/// own two non-string args plus the length-prefixed path shape every other path-taking syscall
/// here uses (see `third_party/musl/src/unistd/readlink.c`'s own patch). Never NUL-terminates the
/// output (real `readlink(2)` semantics) -- returns the byte count actually copied.
extern "C" fn oxfs_readlink(path_ptr: u64, path_len: u64, buf_ptr: u64, buf_cap: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        // Nothing under /proc is a real symlink in this design (see ProcDirKind::FdList's own
        // doc comment) -- an existing path is "exists, but isn't a symlink", not "no such file".
        return match proc_kind(&path[5..]) {
            Some(_) => -EINVAL,
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_readlink(kind, path);
            }
        }
    };
    let inode_num = match resolve_path_nofollow_last(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let inode = read_inode(inode_num);
    if inode.kind != InodeKind::Symlink {
        return -EINVAL;
    }
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let out = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_cap as usize) };
    read_inode_at(inode_num, 0, out) as i64
}

/// Registered for `SYS_SYMLINK`. `(target_ptr, target_len, linkpath_ptr, linkpath_len)` -- mirrors
/// `oxfs_rename`'s own 4-register shape exactly (two path strings, no other args); see
/// `third_party/musl/src/unistd/symlink.c`'s own patch for why `target`/`linkpath` need explicit
/// lengths where real `symlink(2)` doesn't. `target` is stored verbatim, unvalidated and
/// unresolved (matching real `symlink(2)`: a dangling or even syntactically-nonsensical target is
/// perfectly legal to create, only resolving it later can fail).
extern "C" fn oxfs_symlink(
    target_ptr: u64,
    target_len: u64,
    linkpath_ptr: u64,
    linkpath_len: u64,
) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };
    let linkpath =
        unsafe { core::slice::from_raw_parts(linkpath_ptr as *const u8, linkpath_len as usize) };
    let cwd = match real_cwd_for_mutation(linkpath) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, linkpath) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if dir_lookup(parent, leaf).is_some() {
        return -EEXIST;
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return -ENOSPC;
    };
    write_inode(new_inode, Inode::new(InodeKind::Symlink));
    if !write_inode_data(new_inode, target) {
        return -EIO;
    }
    match dir_insert(parent, leaf, new_inode) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// Registered for `SYS_CHMOD`. `(path_ptr, path_len, mode)` -- real `chmod(2)`'s own `(path, mode)`
/// shape plus the length-prefixed path convention every other path-taking syscall here uses (see
/// `third_party/musl/src/stat/chmod.c`'s own patch). Follows a final symlink component (real
/// `chmod(2)` semantics -- there's no `lchmod` in POSIX at all, unlike `chown`/`lchown` below).
/// Only the inode's own owner or root may change its permission bits (`EPERM` otherwise, matching
/// real Unix); `mode` is masked to `0o777` -- setuid/setgid/sticky bits aren't modeled (see
/// `Inode::mode`'s own doc comment), so a caller trying to set them just has those bits silently
/// dropped rather than rejected, the same "don't pretend to model what isn't there" reasoning
/// `write_stat`'s own fixed placeholders already follow.
extern "C" fn oxfs_chmod(path_ptr: u64, path_len: u64, mode: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let mut inode = read_inode(inode_num);
    let caller_uid = unsafe { oxidebsd_current_uid() };
    if caller_uid != 0 && caller_uid != inode.uid as u64 {
        return -EPERM;
    }
    inode.mode = (mode & 0o777) as u16;
    write_inode(inode_num, inode);
    0
}

/// Registered for `SYS_CHOWN`. `(path_ptr, path_len, uid, gid)` -- real `chown(2)`'s own
/// `(path, uid, gid)` shape, using all four of this ABI's argument registers the same way
/// `SYS_RENAME`/`SYS_SYMLINK` already do (see `third_party/musl/src/unistd/chown.c`'s own patch).
/// Follows a final symlink component, matching real `chown(2)` (unlike `lchown(2)`, not
/// implemented this pass -- no target applet in the current roster calls it). Real POSIX
/// `(uid_t)-1`/`(gid_t)-1` "leave this field unchanged" convention (`u32::MAX` once truncated
/// through this ABI's `u64` register), so a caller can change just one of the two. **Root-only**,
/// unlike `chmod` above -- this kernel has no group-membership concept at all, so there's no way
/// to support real Unix's narrower "owner may change the group to one they belong to" case; any
/// non-root caller gets a flat `EPERM`, matching real behavior for the *ownership*-changing case
/// specifically (real Unix restricts that to root unconditionally too).
extern "C" fn oxfs_chown(path_ptr: u64, path_len: u64, uid: u64, gid: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let caller_uid = unsafe { oxidebsd_current_uid() };
    if caller_uid != 0 {
        return -EPERM;
    }
    let mut inode = read_inode(inode_num);
    if uid != u32::MAX as u64 {
        inode.uid = uid as u32;
    }
    if gid != u32::MAX as u64 {
        inode.gid = gid as u32;
    }
    write_inode(inode_num, inode);
    0
}

/// Registered for `SYS_FCHMOD` at real Linux's own `__NR_fchmod = 91` -- unlike every other
/// syscall in this module, this one needed no invented number and no musl-side remap at all:
/// `third_party/musl/arch/x86_64/bits/syscall.h.in` never touches `__NR_fchmod`, so musl's
/// `fchmod(2)` wrapper already calls `syscall(91, fd, mode)` directly, and `91` was still
/// completely unassigned in this ABI's own registry (checked against every `SYS_*` constant in
/// `src/`/`modules/` before landing here -- same collision-avoidance discipline as inventing a new
/// number, just confirming the reverse: that using the real value directly doesn't collide with an
/// already-invented one). Found live: BusyBox's `uudecode` restores the encoded file's mode via
/// `fchmod(fd, mode)` on its still-open output fd, not a path-based `chmod()` -- previously a
/// silent `ENOSYS` (uudecode ignores the return value, so the roundtrip test still passed on
/// content alone; the restored mode was just silently wrong).
///
/// Uses `resolve_write_fd_inode`, not the narrower `inode_of_open_file` -- same reasoning as
/// `oxfs_fstat`'s own doc comment: a still-open `OpenFile::Write` fd (pre-existing or freshly
/// `O_CREAT`'d) needs to resolve to a real inode here too. Same owner-or-root permission check and
/// `0o777` mode mask as `oxfs_chmod` above (see that function's own doc comment for why).
extern "C" fn oxfs_fchmod(fd: u64, mode: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd as u64) else {
        return -EBADF;
    };
    let mut inode = read_inode(inode_num);
    let caller_uid = unsafe { oxidebsd_current_uid() };
    if caller_uid != 0 && caller_uid != inode.uid as u64 {
        return -EPERM;
    }
    inode.mode = (mode & 0o777) as u16;
    write_inode(inode_num, inode);
    0
}

/// Registered for `SYS_UTIMENSAT`. `(path_ptr, path_len, _times_ptr, _flags)` -- see
/// `third_party/musl/src/stat/utimensat.c`'s own patch comment for the real wire-format story
/// (dropped the always-`AT_FDCWD` `fd` argument, computed `path_len` explicitly). This filesystem
/// has no real per-inode timestamp fields at all yet (`write_stat`'s own `st_*time*` fields are
/// still fixed placeholders) -- so this is a real existence check (`ENOENT` for a path that
/// doesn't resolve, matching real `utimensat(2)`) with a no-op success otherwise, not a real
/// timestamp update. That's the one thing BusyBox's `touch.c` actually needs from this call
/// working correctly: it treats `ENOENT` specifically as "the file doesn't exist yet" and falls
/// back to `open(O_CREAT)` to create it (already fully working) -- an unconditional success here
/// (with no existence check at all) would have broken that fallback by making `touch newfile`
/// silently do nothing instead of creating `newfile`. `_times_ptr`/`_flags` are read by nothing
/// here (no timestamps to set), but still accepted in the wire format for a future real
/// implementation to use.
extern "C" fn oxfs_utimensat(path_ptr: u64, path_len: u64, _times_ptr: u64, _flags: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return match proc_kind(&path[5..]) {
            Some(_) => 0,
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        // cwd inside /proc, and a *relative* (non-`/`-leading) target: no real caller in this
        // port's roster does this (touch.c always operates on a real filesystem path), so this
        // deliberately doesn't grow a dedicated proc-relative-existence helper just for it --
        // ENOENT is the honest, real POSIX answer for "this doesn't resolve to anything," not a
        // dodge for something the ELF-loading-relevant paths above still handle for real.
        Cwd::Proc(_) if path.first() != Some(&b'/') => return -ENOENT,
        Cwd::Proc(_) => ROOT_INODE,
    };
    match resolve_path(cwd, path) {
        Ok(_) => 0,
        Err(e) => errno_for(e),
    }
}

/// Copies `src` into a fixed `[u8; MAX_MOUNT_PATH]` for `MountEntry`'s own display-only `path`/
/// `source` fields, truncating if `src` is longer -- these are never compared against (matching by
/// inode, see `oxfs_umount2`), only ever formatted back out for `/proc/mounts`, so silent
/// truncation of a pathologically long path is a cosmetic degradation, not a correctness bug.
fn copy_mount_path(src: &[u8]) -> ([u8; MAX_MOUNT_PATH], u8) {
    let mut buf = [0u8; MAX_MOUNT_PATH];
    let n = src.len().min(MAX_MOUNT_PATH);
    buf[..n].copy_from_slice(&src[..n]);
    (buf, n as u8)
}

/// Finds the first free `MountEntry` slot, or `None` if `MAX_MOUNTS` are all active.
fn free_mount_slot() -> Option<usize> {
    mounts().iter().position(|m| !m.used)
}

/// Registered for `SYS_MOUNT_BIND`. `(source_ptr, source_len, target_ptr, target_len)` -- see
/// `SYS_MOUNT_BIND`'s own doc comment for why `mount(2)` splits into two syscalls here. `target`
/// must already exist and be a real directory (the thing being shadowed); `source` is resolved
/// through any mount already active on it (real behavior: binding from inside another mount binds
/// the *effective* view, not the raw underlying inode) and must also be a directory -- this design
/// only supports directory bind mounts, matching what every applet in this port's roster actually
/// does with `--bind`.
extern "C" fn oxfs_mount_bind(
    source_ptr: u64,
    source_len: u64,
    target_ptr: u64,
    target_len: u64,
) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let source =
        unsafe { core::slice::from_raw_parts(source_ptr as *const u8, source_len as usize) };
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };

    let source_cwd = match real_cwd_for_mutation(source) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target_cwd = match real_cwd_for_mutation(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let source_inode = match resolve_path(source_cwd, source) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if read_inode(source_inode).kind != InodeKind::Dir {
        return -ENOTDIR;
    }

    let (parent, leaf) = match resolve_parent(target_cwd, target) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(mountpoint_inode) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    if read_inode(mountpoint_inode).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    let Some(slot) = free_mount_slot() else {
        return -ENOSPC;
    };
    let (path, path_len) = copy_mount_path(target);
    let (src_buf, src_len) = copy_mount_path(source);
    mounts()[slot] = MountEntry {
        used: true,
        mountpoint_inode,
        target_root_inode: source_inode,
        kind: MountKind::Bind,
        path,
        path_len,
        source: src_buf,
        source_len: src_len,
    };
    0
}

/// Registered for `SYS_MOUNT_TMPFS`. `(target_ptr, target_len, _, _)` -- `target` must already
/// exist and be a real directory, same requirement as the bind-mount case above. Allocates a fresh
/// directory from the tmpfs pool (`alloc_tmpfs_inode`, see `TMPFS_NUM_BLOCKS`'s own doc comment)
/// and gives it real `.`/`..` records the same way `oxfs_mkdir` does -- `..` points at the
/// mountpoint's own real parent, so `cd ..` from inside this tmpfs mount escapes back to the real
/// tree with no special-casing anywhere else in this file.
extern "C" fn oxfs_mount_tmpfs(target_ptr: u64, target_len: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };

    let target_cwd = match real_cwd_for_mutation(target) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent, leaf) = match resolve_parent(target_cwd, target) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(mountpoint_inode) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    if read_inode(mountpoint_inode).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    let Some(slot) = free_mount_slot() else {
        return -ENOSPC;
    };
    let Some(new_root) = alloc_tmpfs_inode() else {
        return -ENOSPC;
    };
    write_inode(new_root, Inode::new(InodeKind::Dir));
    if dir_insert(new_root, b".", new_root).is_err() || dir_insert(new_root, b"..", parent).is_err()
    {
        return -EIO;
    }
    let (path, path_len) = copy_mount_path(target);
    let (source, source_len) = copy_mount_path(b"tmpfs");
    mounts()[slot] = MountEntry {
        used: true,
        mountpoint_inode,
        target_root_inode: new_root,
        kind: MountKind::Tmpfs,
        path,
        path_len,
        source,
        source_len,
    };
    0
}

/// Registered for `SYS_UMOUNT2`. `(target_ptr, target_len, flags, _)` -- `flags` accepted but
/// ignored, matching `TIOCSWINSZ`'s existing "accepted but not enforced" precedent (no
/// `MNT_FORCE`/`MNT_DETACH` distinction). Recovers the *raw* shadowed inode at `target` via a bare
/// `dir_lookup` (deliberately not `resolve_path`, which would apply the mount redirect and hand
/// back the mounted target's own root instead of the mountpoint itself), then finds and clears
/// whichever `MountEntry` was shadowing it -- searched from the end, so unmounting removes the most
/// recently stacked mount first (real LIFO stacking). `EINVAL` if `target` isn't a currently active
/// mountpoint, matching real `umount2(2)`.
extern "C" fn oxfs_umount2(target_ptr: u64, target_len: u64, _flags: u64, _r10: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };

    let target_cwd = match real_cwd_for_mutation(target) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent, leaf) = match resolve_parent(target_cwd, target) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let Some(raw_inode) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    match mounts()
        .iter_mut()
        .rev()
        .find(|m| m.used && m.mountpoint_inode == raw_inode)
    {
        Some(entry) => {
            entry.used = false;
            0
        }
        None => -EINVAL,
    }
}

/// Registered for `SYS_FSTAT`. `fd` here is the calling *process's* own fd number, not this
/// module's `real_fd` -- `oxidebsd_real_fd_of` (see its own doc comment in `src/fd.rs`) resolves
/// that first, the same way `SYS_READ`/`SYS_WRITE` get it resolved for them automatically by
/// `crate::fd::read`/`write` before ever reaching a registered callback.
///
/// **Uses `resolve_write_fd_inode`, not the narrower `inode_of_open_file`** -- see that function's
/// own doc comment: a still-open `OpenFile::Write` fd (whether against a pre-existing inode or a
/// freshly-`O_CREAT`'d one not yet committed) used to report a flat `EBADF` here, which is exactly
/// what broke real BusyBox `tar cf`/`ar rc` (both `fstat()` their freshly-created output fd before
/// writing anything to it, to confirm it's a real file) once this build's own archive-creation
/// Kconfig gap closed.
extern "C" fn oxfs_fstat(fd: u64, buf_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    match resolve_write_fd_inode(real_fd as u64) {
        Some(inode_num) => write_stat(inode_num, buf_ptr),
        None => -EBADF,
    }
}

/// Registered for `SYS_LSEEK` -- see that constant's own doc comment for why this exists at all
/// (found live via TinyCC needing a real file size upfront to load `crt1.o`/`libc.a` whole).
/// `offset`/`whence` arrive as real `u64` register values -- `offset` is reinterpreted as `i64`
/// (real `lseek(2)`'s own signed-offset convention; musl's `off_t` is 64-bit on this arch, so no
/// truncation). Real `SEEK_SET=0`/`SEEK_CUR=1`/`SEEK_END=2` -- no divergence to remap. Only the
/// `{FileRead,DirListing,ProcRead,ProcDir}` variants have a real `position`/size to seek within;
/// `Write` (an in-progress accumulate-then-commit buffer, not a real random-access file -- see
/// `OpenFile::Write`'s own doc comment) and the synthetic `/dev/*` variants report `ESPIPE`, the
/// real POSIX answer for "this fd has no seekable position", rather than silently accepting a seek
/// that would never actually change what a later `read`/`write` sees.
extern "C" fn oxfs_lseek(fd: u64, offset: u64, whence: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(open_file) = find_open_file(real_fd as u64) else {
        return -EBADF;
    };
    let offset = offset as i64;
    let (position, size): (&mut usize, i64) = match open_file {
        OpenFile::FileRead { inode, position } => {
            (position, read_inode(*inode).size as i64)
        }
        OpenFile::DirListing { content: _, len, position, .. } => (position, *len as i64),
        OpenFile::ProcRead { len, position, .. } => (position, *len as i64),
        OpenFile::ProcDir { len, position, .. } => (position, *len as i64),
        OpenFile::Write { .. } | OpenFile::DevRandom | OpenFile::DevNull | OpenFile::DevZero => {
            return -ESPIPE;
        }
    };
    let new_pos = match whence {
        0 => offset,                     // SEEK_SET
        1 => *position as i64 + offset,  // SEEK_CUR
        2 => size + offset,              // SEEK_END
        _ => return -EINVAL,
    };
    if new_pos < 0 {
        return -EINVAL;
    }
    *position = new_pos as usize;
    new_pos
}

/// Writes `value`'s decimal digits (no leading zeros; `0` prints as `"0"`) into `buf`, returning
/// the byte count -- module-side equivalent of `src/process.rs`'s own `push_decimal`, duplicated
/// rather than shared for the same reason: modules can't depend on kernel-crate internals.
fn decimal_into(buf: &mut [u8], value: u64) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
    }
    n
}

/// The `n`-th entry of a synthetic `/proc` directory (`kind`) -- `(d_ino, name, name_len, d_type)`,
/// mirroring `dir_nth_used_record`'s shape for a real directory (plus a `d_type`, since a synthetic
/// directory has no inode to derive one from). `None` once every entry has been emitted.
fn proc_dir_nth_entry(kind: ProcDirKind, n: usize) -> Option<(u64, [u8; NAME_MAX], u8, u8)> {
    match kind {
        ProcDirKind::Root => {
            // The system-wide files come first (indices 0..SYS_NAMES.len()), so no live-pid count
            // needs computing up front -- pid entries simply start right after them.
            const SYS_NAMES: [&[u8]; 4] = [b"meminfo", b"uptime", b"stat", b"modules"];
            if let Some(name_bytes) = SYS_NAMES.get(n) {
                let mut name = [0u8; NAME_MAX];
                name[..name_bytes.len()].copy_from_slice(name_bytes);
                // Distinct, cosmetic-only d_ino (see PROC_INODE_BASE's own doc comment) -- clear
                // of both MAX_INODES's real range and every pid-derived d_ino below it.
                return Some((
                    PROC_INODE_BASE - 1 - n as u64,
                    name,
                    name_bytes.len() as u8,
                    DT_REG,
                ));
            }
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let pid = unsafe { oxidebsd_proc_pid_at((n - SYS_NAMES.len()) as u64) };
            if pid < 0 {
                return None;
            }
            let mut name = [0u8; NAME_MAX];
            let name_len = decimal_into(&mut name, pid as u64);
            Some((PROC_INODE_BASE + pid as u64, name, name_len as u8, DT_DIR))
        }
        ProcDirKind::PidFiles(pid) => {
            const NAMES: [&[u8]; 3] = [b"stat", b"cmdline", b"status"];
            let name_bytes = *NAMES.get(n)?;
            let mut name = [0u8; NAME_MAX];
            name[..name_bytes.len()].copy_from_slice(name_bytes);
            Some((
                PROC_INODE_BASE + (pid as u64) * 8 + n as u64 + 1,
                name,
                name_bytes.len() as u8,
                DT_REG,
            ))
        }
        ProcDirKind::TaskList(pid) => {
            if n != 0 {
                return None;
            }
            let mut name = [0u8; NAME_MAX];
            let name_len = decimal_into(&mut name, pid as u64);
            Some((PROC_INODE_BASE + pid as u64, name, name_len as u8, DT_DIR))
        }
        ProcDirKind::FdList(pid) => {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let fd = unsafe { oxidebsd_fd_at(pid as u64, n as u64) };
            if fd < 0 {
                return None;
            }
            let mut name = [0u8; NAME_MAX];
            let name_len = decimal_into(&mut name, fd as u64);
            // Disjoint from PidFiles' own `* 8` stride -- cosmetic only, see PROC_INODE_BASE's doc.
            Some((
                PROC_INODE_BASE + (pid as u64) * 1024 + fd as u64 + 1,
                name,
                name_len as u8,
                DT_REG,
            ))
        }
    }
}

/// Registered for `SYS_GETDENTS`. `fd` is the calling process's own fd number, resolved to this
/// module's `real_fd` the same way `oxfs_fstat` does (see its own doc comment). Fills as many
/// whole records as fit in `buf_len` starting from the open directory's own resume cursor
/// (`OpenFile::DirListing::dirent_pos`/`ProcDir::dirent_pos`), returns the byte count actually
/// written (`0` once every record has already been emitted -- real `getdents(2)`'s own EOF
/// convention, which `readdir()` relies on to stop looping). A record that doesn't fully fit is
/// left for the next call rather than truncated -- matching real Linux, which never splits a
/// record across two `getdents` calls.
extern "C" fn oxfs_getdents(fd: u64, buf_ptr: u64, buf_len: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(file) = find_open_file(real_fd as u64) else {
        return -EBADF;
    };
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let out = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    match file {
        OpenFile::DirListing {
            inode: dir_inode,
            dirent_pos,
            ..
        } => {
            let dir_inode = *dir_inode;
            let mut written = 0usize;
            while let Some((child_inode, name, name_len)) =
                dir_nth_used_record(dir_inode, *dirent_pos)
            {
                let name = &name[..name_len as usize];
                let reclen = dirent_record_len(name.len());
                if written + reclen > out.len() {
                    break;
                }
                let child = read_inode(child_inode);
                let dtype = match child.kind {
                    InodeKind::Dir => DT_DIR,
                    InodeKind::Symlink => DT_LNK,
                    InodeKind::Device if child.device_char => DT_CHR,
                    InodeKind::Device => DT_BLK,
                    _ => DT_REG,
                };
                write_dirent_record(
                    &mut out[written..written + reclen],
                    child_inode as u64,
                    (*dirent_pos + 1) as i64,
                    dtype,
                    name,
                );
                written += reclen;
                *dirent_pos += 1;
            }
            written as i64
        }
        OpenFile::ProcDir {
            kind, dirent_pos, ..
        } => {
            let kind = *kind;
            let mut written = 0usize;
            while let Some((ino, name, name_len, dtype)) = proc_dir_nth_entry(kind, *dirent_pos) {
                let name = &name[..name_len as usize];
                let reclen = dirent_record_len(name.len());
                if written + reclen > out.len() {
                    break;
                }
                write_dirent_record(
                    &mut out[written..written + reclen],
                    ino,
                    (*dirent_pos + 1) as i64,
                    dtype,
                    name,
                );
                written += reclen;
                *dirent_pos += 1;
            }
            written as i64
        }
        _ => -ENOTDIR,
    }
}

fn log_bytes(bytes: &[u8]) {
    unsafe { oxidebsd_log(bytes.as_ptr(), bytes.len() as u64) };
}

fn log(message: &str) {
    log_bytes(message.as_bytes());
}

/// A minimal, `core::fmt`-free byte-buffer builder -- see `modules/fat32`'s own doc comment for
/// why module code avoids `core::fmt::Write`/`write!` entirely (it reintroduces `GOTPCREL`
/// relocations and pulls in a large fraction of `core::fmt`'s tables).
struct ByteBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl ByteBuf<'_> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.buf.len() - self.len;
        let n = bytes.len().min(available);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn push_decimal(&mut self, value: u32) {
        if value == 0 {
            self.push_bytes(b"0");
            return;
        }
        let mut digits = [0u8; 10];
        let mut count = 0;
        let mut remaining = value;
        while remaining > 0 {
            digits[count] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            count += 1;
        }
        digits[..count].reverse();
        self.push_bytes(&digits[..count]);
    }
}

// --- Real disk persistence: on-disk (de)serialization, mount, format-flush, write-through ------
//
// See this file's own "Real disk persistence" constants section (near `ROOT_INODE`) for the
// physical block layout these functions read/write.

/// Packs one `Inode` into `out` (exactly `INODE_STRIDE` bytes) using explicit byte offsets, the
/// same idiom `write_dir_record` already established for directory records -- see
/// `INODE_STRIDE`'s own doc comment for why this can't be a raw transmute/memcpy.
fn pack_inode(inode: &Inode, out: &mut [u8]) {
    out[0] = match inode.kind {
        InodeKind::Free => 0,
        InodeKind::File => 1,
        InodeKind::Dir => 2,
        InodeKind::Symlink => 3,
        InodeKind::Device => 4,
    };
    out[1..5].copy_from_slice(&inode.size.to_le_bytes());
    for (i, d) in inode.direct.iter().enumerate() {
        let off = 5 + i * 4;
        out[off..off + 4].copy_from_slice(&d.to_le_bytes());
    }
    let indirect_off = 5 + DIRECT_BLOCKS * 4;
    out[indirect_off..indirect_off + 4].copy_from_slice(&inode.indirect.to_le_bytes());
    let mode_off = indirect_off + 4;
    out[mode_off..mode_off + 2].copy_from_slice(&inode.mode.to_le_bytes());
    let uid_off = mode_off + 2;
    out[uid_off..uid_off + 4].copy_from_slice(&inode.uid.to_le_bytes());
    let gid_off = uid_off + 4;
    out[gid_off..gid_off + 4].copy_from_slice(&inode.gid.to_le_bytes());
    let nlink_off = gid_off + 4;
    out[nlink_off..nlink_off + 2].copy_from_slice(&inode.nlink.to_le_bytes());
    let rdev_off = nlink_off + 2;
    out[rdev_off..rdev_off + 4].copy_from_slice(&inode.rdev.to_le_bytes());
    let device_char_off = rdev_off + 4;
    out[device_char_off] = inode.device_char as u8;
    for b in &mut out[device_char_off + 1..] {
        *b = 0;
    }
}

/// `pack_inode`'s inverse.
fn unpack_inode(data: &[u8]) -> Inode {
    let kind = match data[0] {
        1 => InodeKind::File,
        2 => InodeKind::Dir,
        3 => InodeKind::Symlink,
        4 => InodeKind::Device,
        _ => InodeKind::Free,
    };
    let size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let mut direct = [NO_BLOCK; DIRECT_BLOCKS];
    for (i, d) in direct.iter_mut().enumerate() {
        let off = 5 + i * 4;
        *d = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    }
    let indirect_off = 5 + DIRECT_BLOCKS * 4;
    let indirect = u32::from_le_bytes([
        data[indirect_off],
        data[indirect_off + 1],
        data[indirect_off + 2],
        data[indirect_off + 3],
    ]);
    let mode_off = indirect_off + 4;
    let mode = u16::from_le_bytes([data[mode_off], data[mode_off + 1]]);
    let uid_off = mode_off + 2;
    let uid = u32::from_le_bytes([
        data[uid_off],
        data[uid_off + 1],
        data[uid_off + 2],
        data[uid_off + 3],
    ]);
    let gid_off = uid_off + 4;
    let gid = u32::from_le_bytes([
        data[gid_off],
        data[gid_off + 1],
        data[gid_off + 2],
        data[gid_off + 3],
    ]);
    let nlink_off = gid_off + 4;
    let nlink = u16::from_le_bytes([data[nlink_off], data[nlink_off + 1]]);
    let rdev_off = nlink_off + 2;
    let rdev = u32::from_le_bytes([
        data[rdev_off],
        data[rdev_off + 1],
        data[rdev_off + 2],
        data[rdev_off + 3],
    ]);
    let device_char_off = rdev_off + 4;
    let device_char = data[device_char_off] != 0;
    Inode {
        kind,
        size,
        direct,
        indirect,
        mode,
        uid,
        gid,
        nlink,
        rdev,
        device_char,
    }
}

/// Write-through hook for `write_block` -- persists the single physical data block `n` maps to,
/// gated on both a disk being attached and `persistence_ready()` (see that flag's own doc comment
/// for why format/mount themselves must not trigger this).
fn persist_data_block_if_ready(n: u32, data: &[u8; BLOCK_SIZE]) {
    // Tmpfs-pool blocks (see TMPFS_NUM_BLOCKS's own doc comment) are never persisted -- they have
    // no physical counterpart in the on-disk layout, which is sized to NUM_BLOCKS exactly.
    if n >= NUM_BLOCKS as u32 || !persistence_ready() || !block_device_present() {
        return;
    }
    let phys = DATA_BLOCK_OFFSET as u64 + n as u64;
    unsafe {
        oxidebsd_block_write(phys, data.as_ptr() as u64);
    }
}

/// Write-through hook for `write_inode` -- repacks the *entire* physical inode-table block `n`
/// belongs to from the in-memory `INODES` array (which already holds the correct value for every
/// inode in that block, `n` included, by the time this runs) and writes it whole. No
/// read-before-write needed: memory is always the complete source of truth here, unlike a real
/// on-disk filesystem recovering from a crash mid-write.
fn persist_inode_block_if_ready(n: u32) {
    // Tmpfs-pool inodes are never persisted, same reasoning as persist_data_block_if_ready above
    // -- without this, `block_idx` below would be computed from a bogus, out-of-range `n` and
    // corrupt some unrelated physical inode-table block.
    if n >= MAX_INODES as u32 || !persistence_ready() || !block_device_present() {
        return;
    }
    let block_idx = n as usize / INODES_PER_BLOCK;
    let mut block = [0u8; BLOCK_SIZE];
    for slot in 0..INODES_PER_BLOCK {
        let ino = block_idx * INODES_PER_BLOCK + slot;
        if ino >= MAX_INODES {
            break;
        }
        let inode = read_inode(ino as u32);
        pack_inode(
            &inode,
            &mut block[slot * INODE_STRIDE..(slot + 1) * INODE_STRIDE],
        );
    }
    let phys = INODE_TABLE_START as u64 + block_idx as u64;
    unsafe {
        oxidebsd_block_write(phys, block.as_ptr() as u64);
    }
}

/// Write-through hook for `set_block_used` -- repacks the *entire* bitmap from the in-memory
/// `BLOCK_USED` array and writes it whole, same "memory is the complete source of truth, no
/// read-modify-write needed" reasoning as `persist_inode_block_if_ready`.
fn persist_bitmap_if_ready() {
    if !persistence_ready() || !block_device_present() {
        return;
    }
    let mut block = [0u8; BLOCK_SIZE];
    for i in 0..NUM_BLOCKS {
        if block_used(i as u32) {
            block[i / 8] |= 1 << (i % 8);
        }
    }
    unsafe {
        oxidebsd_block_write(BITMAP_BLOCK as u64, block.as_ptr() as u64);
    }
}

fn write_superblock() {
    let mut block = [0u8; BLOCK_SIZE];
    block[0..4].copy_from_slice(&SUPERBLOCK_MAGIC);
    block[4..8].copy_from_slice(&SUPERBLOCK_VERSION.to_le_bytes());
    block[8..12].copy_from_slice(&(NUM_BLOCKS as u32).to_le_bytes());
    block[12..16].copy_from_slice(&(MAX_INODES as u32).to_le_bytes());
    block[16..20].copy_from_slice(&ROOT_INODE.to_le_bytes());
    unsafe {
        oxidebsd_block_write(0, block.as_ptr() as u64);
    }
}

/// Resets the *real* (non-tmpfs) block-used bitmap and inode table back to a pristine, all-free
/// state -- `0..NUM_BLOCKS`/`0..MAX_INODES` by the named constants, never touching the separate
/// tmpfs pool above them (which `mount_from_disk` never populates in the first place, and which
/// `module_init` never touches at this stage either). Must run before `format_fresh_filesystem` on
/// *any* path that might have already partially populated this state -- concretely, a failed
/// `mount_from_disk` call.
///
/// **Found live, the hard way**: `mount_from_disk`'s own bitmap-load and inode-table-load loops
/// (both, below) run to completion *before* its own subsequent per-block data-read loop, which is
/// where a real failure (`oxidebsd_block_read` returning nonzero partway through) actually gets
/// detected and turned into a `return false`. A stale disk image predating a real layout change --
/// concretely, the very case this fix was found from: `MAX_INODES` doubling (512 -> 1024, see
/// CLAUDE.md's TinyCC section) shifts `INODE_TABLE_BLOCKS`/`DATA_BLOCK_OFFSET` forward, so an
/// already-existing disk image written under the old, smaller layout has real, physically
/// different bytes at every "data block" location the new layout expects -- mounted cleanly enough
/// to load a bitmap marking most of the *old* install's blocks used (a fully-packed ~300-applet
/// roster, close to the old pool's own capacity), then failed partway through the actual data read.
/// Without this reset, `format_fresh_filesystem`'s own fresh allocations (`alloc_block`/
/// `alloc_inode`, both plain linear scans for the first *unmarked* slot) inherited that stale
/// "mostly full" bitmap from a filesystem that no longer exists in memory at all -- confirmed live:
/// a fresh format, on a completely empty in-memory pool, panicked `DiskFull` seeding `/etc`'s own
/// `.` entry (one of the very first real block allocations *after* `/bin`'s ~300+ applets), not
/// because the real content genuinely didn't fit, but because most of the pool was falsely marked
/// used before formatting had allocated anything of its own.
fn reset_real_pool_for_fresh_format() {
    for i in 0..NUM_BLOCKS as u32 {
        set_block_used(i, false);
    }
    for i in 0..MAX_INODES as u32 {
        write_inode(i, Inode::FREE);
    }
}

/// Attempts to mount an already-formatted disk: reads the superblock, and if its magic matches,
/// loads the bitmap and inode table wholesale, then eager-loads only the data blocks the bitmap
/// marks used (not an unconditional full sweep of `NUM_BLOCKS` -- see this file's own
/// `PERSISTENCE_READY` doc comment and CLAUDE.md's own notes on this class of PIO-under-emulation
/// cost). Returns `false` on a missing/mismatched superblock (an unformatted disk -- the expected,
/// common first-boot case) or on any real read failure partway through, in which case the caller
/// falls back to `format_fresh_filesystem` (after first calling
/// `reset_real_pool_for_fresh_format` -- see its own doc comment for why that's required, not
/// optional) -- a partially-readable disk gets cleanly reformatted rather than the kernel trying to
/// recover a partial mount, a deliberate simplification for this phase (see the implementation
/// plan's own "known limitations" list).
fn mount_from_disk() -> bool {
    let mut sb = [0u8; BLOCK_SIZE];
    if unsafe { oxidebsd_block_read(0, sb.as_mut_ptr() as u64) } != 0 {
        return false;
    }
    if sb[0..4] != SUPERBLOCK_MAGIC {
        return false;
    }

    // Layout check, not just a magic check -- a disk formatted under a previous `NUM_BLOCKS`/
    // `MAX_INODES`/`SUPERBLOCK_VERSION` has the right magic but real, physically different bytes
    // at every block-offset this build's own `INODE_TABLE_START`/`BITMAP_BLOCK`/
    // `DATA_BLOCK_OFFSET` expect (all derived from these same constants -- see this file's own
    // "Real disk persistence" section). Before this check, a stale disk merely *usually* failed
    // loudly partway through the loops below (see `reset_real_pool_for_fresh_format`'s own doc
    // comment for the real, live case this was found from) -- that was incidental, not a real
    // safety guarantee, since a layout change can just as easily leave every read in-bounds and
    // silently misinterpret stale bytes as this build's own inode table/bitmap/data.
    let stored_version = u32::from_le_bytes(sb[4..8].try_into().unwrap());
    let stored_num_blocks = u32::from_le_bytes(sb[8..12].try_into().unwrap());
    let stored_max_inodes = u32::from_le_bytes(sb[12..16].try_into().unwrap());
    if stored_version != SUPERBLOCK_VERSION
        || stored_num_blocks as usize != NUM_BLOCKS
        || stored_max_inodes as usize != MAX_INODES
    {
        log("[oxfs] mount: on-disk layout doesn't match this build -- falling back to format\n");
        return false;
    }

    let mut bitmap_block = [0u8; BLOCK_SIZE];
    if unsafe { oxidebsd_block_read(BITMAP_BLOCK as u64, bitmap_block.as_mut_ptr() as u64) } != 0 {
        log("[oxfs] mount: failed to read block-used bitmap -- falling back to format\n");
        return false;
    }
    for i in 0..NUM_BLOCKS {
        let used = (bitmap_block[i / 8] >> (i % 8)) & 1 != 0;
        set_block_used(i as u32, used);
    }

    for block_idx in 0..INODE_TABLE_BLOCKS as usize {
        let mut block = [0u8; BLOCK_SIZE];
        let phys = INODE_TABLE_START as u64 + block_idx as u64;
        if unsafe { oxidebsd_block_read(phys, block.as_mut_ptr() as u64) } != 0 {
            log("[oxfs] mount: failed to read an inode table block -- falling back to format\n");
            return false;
        }
        for slot in 0..INODES_PER_BLOCK {
            let ino = block_idx * INODES_PER_BLOCK + slot;
            if ino >= MAX_INODES {
                break;
            }
            let off = slot * INODE_STRIDE;
            write_inode(ino as u32, unpack_inode(&block[off..off + INODE_STRIDE]));
        }
    }

    let mut loaded: u32 = 0;
    for i in 0..NUM_BLOCKS as u32 {
        if block_used(i) {
            let mut data = [0u8; BLOCK_SIZE];
            let phys = DATA_BLOCK_OFFSET as u64 + i as u64;
            if unsafe { oxidebsd_block_read(phys, data.as_mut_ptr() as u64) } != 0 {
                log("[oxfs] mount: failed to read a data block -- falling back to format\n");
                return false;
            }
            write_block(i, &data);
            loaded += 1;
        }
    }

    let mut msg_buf = [0u8; 96];
    let mut msg = ByteBuf {
        buf: &mut msg_buf,
        len: 0,
    };
    msg.push_bytes(b"[oxfs] mounted existing filesystem from disk (");
    msg.push_decimal(loaded);
    msg.push_bytes(b" data blocks loaded)\n");
    let len = msg.len;
    log_bytes(&msg_buf[..len]);
    true
}

/// Performs the one-time bulk write a freshly formatted filesystem needs: superblock, the full
/// bitmap, the full inode table, and every block the bitmap marks used. Called once, right after
/// `format_fresh_filesystem` completes, while `PERSISTENCE_READY` is still `false` (see that flag's
/// own doc comment for why the format pass itself doesn't write through block-by-block) -- so every
/// subsequent boot mounts this disk instead of reformatting it.
fn flush_all_to_disk() {
    write_superblock();

    let mut bitmap_block = [0u8; BLOCK_SIZE];
    for i in 0..NUM_BLOCKS {
        if block_used(i as u32) {
            bitmap_block[i / 8] |= 1 << (i % 8);
        }
    }
    unsafe {
        oxidebsd_block_write(BITMAP_BLOCK as u64, bitmap_block.as_ptr() as u64);
    }

    for block_idx in 0..INODE_TABLE_BLOCKS as usize {
        let mut block = [0u8; BLOCK_SIZE];
        for slot in 0..INODES_PER_BLOCK {
            let ino = block_idx * INODES_PER_BLOCK + slot;
            if ino >= MAX_INODES {
                break;
            }
            let inode = read_inode(ino as u32);
            pack_inode(
                &inode,
                &mut block[slot * INODE_STRIDE..(slot + 1) * INODE_STRIDE],
            );
        }
        let phys = INODE_TABLE_START as u64 + block_idx as u64;
        unsafe {
            oxidebsd_block_write(phys, block.as_ptr() as u64);
        }
    }

    let mut flushed: u32 = 0;
    for i in 0..NUM_BLOCKS as u32 {
        if block_used(i) {
            let data = read_block(i);
            let phys = DATA_BLOCK_OFFSET as u64 + i as u64;
            unsafe {
                oxidebsd_block_write(phys, data.as_ptr() as u64);
            }
            flushed += 1;
        }
    }

    let mut msg_buf = [0u8; 96];
    let mut msg = ByteBuf {
        buf: &mut msg_buf,
        len: 0,
    };
    msg.push_bytes(b"[oxfs] formatted fresh filesystem and flushed to disk (");
    msg.push_decimal(flushed);
    msg.push_bytes(b" data blocks)\n");
    let len = msg.len;
    log_bytes(&msg_buf[..len]);
}

/// Allocates a fresh file inode under `parent` named `name` with `content` as its complete
/// contents -- the `module_init`-time equivalent of `open(O_CREAT)` + `write` + `close`, used to
/// seed every embedded file without going through the fd/syscall machinery.
fn seed_file(parent: u32, name: &[u8], content: &[u8]) -> bool {
    let Some(inode) = alloc_inode() else {
        return false;
    };
    write_inode(inode, Inode::new(InodeKind::File));
    write_inode_data(inode, content) && dir_insert(parent, name, inode).is_ok()
}

/// `seed_file`'s symlink counterpart -- allocates a fresh `InodeKind::Symlink` inode under
/// `parent` named `name`, pointing at `target` (stored verbatim, exactly like `oxfs_symlink`
/// itself stores a real caller's target -- see that function's own doc comment). Used to seed
/// `/bin/lsmod` as an alias of `/bin/lsoxmod` without needing two copies of the same binary.
fn seed_symlink(parent: u32, name: &[u8], target: &[u8]) -> bool {
    let Some(inode) = alloc_inode() else {
        return false;
    };
    write_inode(inode, Inode::new(InodeKind::Symlink));
    write_inode_data(inode, target) && dir_insert(parent, name, inode).is_ok()
}

/// Idempotent directory creation -- looks up an existing child named `name` under `parent` first,
/// only allocating and wiring a fresh `.`/`..`-seeded directory inode when one doesn't already
/// exist. Factors out the same 5-statement pattern every other directory in this file hand-inlines
/// once each (`/bin`, `/etc`, `/home`, `/home/user`, root itself) -- `seed_tree` below is the first
/// caller that needs to create directories in a loop, re-entering the same parent many times (once
/// per sibling file under it), where hand-inlining stops being reasonable.
fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    if let Some(existing) = dir_lookup(parent, name) {
        return existing;
    }
    let inode = alloc_inode().expect("oxfs: failed to allocate a directory inode");
    write_inode(inode, Inode::new(InodeKind::Dir));
    dir_insert(inode, b".", inode).expect("oxfs: failed to seed a directory's . entry");
    dir_insert(inode, b"..", parent).expect("oxfs: failed to seed a directory's .. entry");
    dir_insert(parent, name, inode)
        .expect("oxfs: failed to insert a new directory into its parent");
    inode
}

/// Seeds a whole manifest of `(relative_path, content)` pairs (each `relative_path` real,
/// `/`-separated, e.g. `"bits/alltypes.h"`) under `root`, creating any missing intermediate
/// directories via `ensure_dir` along the way. Used for TinyCC's own on-target runtime tree
/// (`/usr/include`, `/usr/lib`, `/usr/lib/tcc` -- see `format_fresh_filesystem`'s own call sites
/// and CLAUDE.md's TinyCC section) -- the first content this filesystem seeds shaped like a real
/// nested directory tree (musl's own `include/bits`, `include/sys`, ...) rather than a small fixed
/// set of top-level files.
fn seed_tree(root: u32, files: &[(&str, &[u8])]) -> bool {
    let mut ok = true;
    for (rel_path, content) in files {
        let (dir_path, file_name) = match rel_path.rsplit_once('/') {
            Some((dir, name)) => (dir, name),
            None => ("", *rel_path),
        };
        let mut dir = root;
        if !dir_path.is_empty() {
            for component in dir_path.split('/') {
                dir = ensure_dir(dir, component.as_bytes());
            }
        }
        ok &= seed_file(dir, file_name.as_bytes(), content);
    }
    ok
}

/// `MUSL_INCLUDE_FILES`/`MUSL_LIB_FILES`/`TCC_RUNTIME_FILES` -- generated by build.rs's
/// `write_tcc_runtime_manifest` (see its own doc comment for why this is a generated `include!`
/// rather than the `env!()`-per-file pattern every other embedded ELF in this file uses). Declared
/// at module scope since it defines real top-level `pub static` items, consumed by
/// `format_fresh_filesystem`'s own `/usr` seeding below.
include!(env!("TCC_RUNTIME_MANIFEST_PATH"));

/// Populates a completely fresh (never-before-formatted) in-memory filesystem: root/`bin`/`etc`,
/// every seed file/BusyBox applet, and the self-check. Runs unconditionally when no data disk is
/// attached; runs once, the first time a real disk is attached with no valid superblock on it yet
/// (see `module_init`, below, for the mount-or-format decision and `flush_all_to_disk`, which
/// follows a successful run of this function so every *subsequent* boot mounts instead of
/// reformatting). Returns whether the self-check passed.
fn format_fresh_filesystem() -> bool {
    let root = alloc_inode().expect("oxfs: failed to allocate root inode");
    debug_assert_eq!(
        root, ROOT_INODE,
        "oxfs: root must be the first inode allocated"
    );
    write_inode(root, Inode::new(InodeKind::Dir));
    dir_insert(root, b".", root).expect("oxfs: failed to seed root's . entry");
    dir_insert(root, b"..", root).expect("oxfs: failed to seed root's .. entry");

    let mut ok = true;

    ok &= seed_file(
        root,
        b"hello.txt",
        b"Hello from OxideBSD's own filesystem!\n",
    );

    // Formula-derived, not a literal -- so the self-check below can independently recompute the
    // expected bytes, same idiom modules/fat32's own self-check already established.
    let mut big = [0u8; BIG_FILE_LEN];
    for (i, b) in big.iter_mut().enumerate() {
        *b = b'A' + (i % 26) as u8;
    }
    ok &= seed_file(root, b"big.txt", &big);

    // A real applet self-test, meant to be run by hand at the hush prompt (`sh /test_busybox.sh`)
    // -- see that file's own header comment for why it's written the way it is: this kernel's
    // actual `sh` build has HUSH_IF/HUSH_LOOPS/HUSH_CASE/HUSH_FUNCTIONS/HUSH_TICK all off (checked
    // against the real generated target/busybox-sh/.config, not assumed from BusyBox's own
    // Kconfig defaults), so it's a flat sequence of real applet invocations using only
    // redirection/pipes/`&&`/`||`, not an if/for-based test harness.
    ok &= seed_file(root, b"test_busybox.sh", include_bytes!("test_busybox.sh"));

    // All executables live under /bin, not root -- matches `src/process.rs`'s pid-1 `PATH=/bin`
    // envp, so a bare command name (`ls`, not `/ls`) resolves via musl's real `execvp` search.
    let bin = alloc_inode().expect("oxfs: failed to allocate /bin inode");
    write_inode(bin, Inode::new(InodeKind::Dir));
    dir_insert(bin, b".", bin).expect("oxfs: failed to seed /bin's . entry");
    dir_insert(bin, b"..", root).expect("oxfs: failed to seed /bin's .. entry");
    dir_insert(root, b"bin", bin).expect("oxfs: failed to insert /bin into root");

    ok &= seed_file(bin, b"smoke", include_bytes!(env!("OXFS_SMOKE_ELF_PATH")));
    ok &= seed_file(bin, b"musl", include_bytes!(env!("OXFS_MUSL_ELF_PATH")));
    // lsoxmod: a real standalone Rust userland ELF (userland/lsoxmod/, same "freestanding,
    // raw-SYSCALL, no musl/BusyBox involved" category as smoke/musl above), not a BusyBox applet
    // -- lists OxideBSD's own dynamically loaded kernel modules by reading the real /proc/modules
    // this pass added, the same "port real format, read real data" approach the rest of this
    // filesystem's /proc support already uses. `lsmod` is seeded as a real symlink to it rather
    // than a second copy of the same bytes -- real BusyBox has its own `lsmod` (see CLAUDE.md's
    // BusyBox gap analysis), but that one reads Linux's own `/proc/modules` format expecting real
    // Linux kernel modules, not this kernel's own module system, so the name is intentionally
    // pointed at the OxideBSD-native tool instead of BusyBox's applet of the same name.
    ok &= seed_file(
        bin,
        b"lsoxmod",
        include_bytes!(env!("OXFS_LSOXMOD_ELF_PATH")),
    );
    ok &= seed_symlink(bin, b"lsmod", b"lsoxmod");
    // tcc: OxideBSD's first on-target C compiler -- real upstream TinyCC (`third_party/tinycc`,
    // see CLAUDE.md's TinyCC section and `build_tinycc`'s own doc comment in build.rs), cross-built
    // against this same musl sysroot with `--config-musl`. Milestone A only: the binary launches
    // and its own `-v`/`--help` work (no filesystem access needed for those). It can't yet actually
    // compile/link a real C file -- that needs musl's header tree, crt objects, `libc.a`, and tcc's
    // own `libtcc1.a` seeded under `/usr`, wired in separately once that milestone lands.
    ok &= seed_file(bin, b"tcc", include_bytes!(env!("OXFS_TCC_ELF_PATH")));
    ok &= seed_file(bin, b"true", include_bytes!(env!("OXFS_TRUE_ELF_PATH")));
    ok &= seed_file(bin, b"echo", include_bytes!(env!("OXFS_ECHO_ELF_PATH")));
    ok &= seed_file(bin, b"cat", include_bytes!(env!("OXFS_CAT_ELF_PATH")));
    ok &= seed_file(bin, b"sh", include_bytes!(env!("OXFS_HUSH_ELF_PATH")));
    ok &= seed_file(bin, b"false", include_bytes!(env!("OXFS_FALSE_ELF_PATH")));
    ok &= seed_file(bin, b"yes", include_bytes!(env!("OXFS_YES_ELF_PATH")));
    ok &= seed_file(bin, b"more", include_bytes!(env!("OXFS_MORE_ELF_PATH")));
    ok &= seed_file(bin, b"mkdir", include_bytes!(env!("OXFS_MKDIR_ELF_PATH")));
    ok &= seed_file(bin, b"rmdir", include_bytes!(env!("OXFS_RMDIR_ELF_PATH")));
    ok &= seed_file(bin, b"rm", include_bytes!(env!("OXFS_RM_ELF_PATH")));
    ok &= seed_file(bin, b"mv", include_bytes!(env!("OXFS_MV_ELF_PATH")));
    ok &= seed_file(bin, b"cp", include_bytes!(env!("OXFS_CP_ELF_PATH")));
    ok &= seed_file(bin, b"touch", include_bytes!(env!("OXFS_TOUCH_ELF_PATH")));
    ok &= seed_file(bin, b"head", include_bytes!(env!("OXFS_HEAD_ELF_PATH")));
    ok &= seed_file(bin, b"tail", include_bytes!(env!("OXFS_TAIL_ELF_PATH")));
    ok &= seed_file(bin, b"wc", include_bytes!(env!("OXFS_WC_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"basename",
        include_bytes!(env!("OXFS_BASENAME_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"dirname",
        include_bytes!(env!("OXFS_DIRNAME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"printf", include_bytes!(env!("OXFS_PRINTF_ELF_PATH")));
    ok &= seed_file(bin, b"seq", include_bytes!(env!("OXFS_SEQ_ELF_PATH")));
    ok &= seed_file(bin, b"cut", include_bytes!(env!("OXFS_CUT_ELF_PATH")));
    ok &= seed_file(bin, b"sort", include_bytes!(env!("OXFS_SORT_ELF_PATH")));
    ok &= seed_file(bin, b"uniq", include_bytes!(env!("OXFS_UNIQ_ELF_PATH")));
    ok &= seed_file(bin, b"kill", include_bytes!(env!("OXFS_KILL_ELF_PATH")));

    // Second pass: every applet build.rs's own second-pass probe found buildable against this
    // musl port (see build.rs's own BUSYBOX_APPLETS_PASS2 comment and docs/BUSYBOX_APPLETS.md for
    // what each one actually needs at runtime -- most need something OxideBSD doesn't implement
    // yet; "builds" was the bar this pass used, not "works"). One-liner form (not the multi-line
    // seed_file(...) call the first 24 applets above use) purely because there are ~300 of these --
    // no behavioral difference.
    ok &= seed_file(
        bin,
        b"addgroup",
        include_bytes!(env!("OXFS_ADDGROUP_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"adduser",
        include_bytes!(env!("OXFS_ADDUSER_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"adjtimex",
        include_bytes!(env!("OXFS_ADJTIMEX_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ar", include_bytes!(env!("OXFS_AR_ELF_PATH")));
    ok &= seed_file(bin, b"arp", include_bytes!(env!("OXFS_ARP_ELF_PATH")));
    ok &= seed_file(bin, b"arping", include_bytes!(env!("OXFS_ARPING_ELF_PATH")));
    ok &= seed_file(bin, b"ascii", include_bytes!(env!("OXFS_ASCII_ELF_PATH")));
    ok &= seed_file(bin, b"ash", include_bytes!(env!("OXFS_ASH_ELF_PATH")));
    ok &= seed_file(bin, b"awk", include_bytes!(env!("OXFS_AWK_ELF_PATH")));
    ok &= seed_file(bin, b"base32", include_bytes!(env!("OXFS_BASE32_ELF_PATH")));
    ok &= seed_file(bin, b"base64", include_bytes!(env!("OXFS_BASE64_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"bash_ash",
        include_bytes!(env!("OXFS_BASH_ASH_ELF_PATH")),
    );
    ok &= seed_file(bin, b"bash", include_bytes!(env!("OXFS_BASH_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"bbconfig",
        include_bytes!(env!("OXFS_BBCONFIG_ELF_PATH")),
    );
    ok &= seed_file(bin, b"arch", include_bytes!(env!("OXFS_ARCH_ELF_PATH")));
    ok &= seed_file(bin, b"sysctl", include_bytes!(env!("OXFS_SYSCTL_ELF_PATH")));
    ok &= seed_file(bin, b"bc", include_bytes!(env!("OXFS_BC_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"bootchartd",
        include_bytes!(env!("OXFS_BOOTCHARTD_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"bunzip2",
        include_bytes!(env!("OXFS_BUNZIP2_ELF_PATH")),
    );
    ok &= seed_file(bin, b"bzcat", include_bytes!(env!("OXFS_BZCAT_ELF_PATH")));
    ok &= seed_file(bin, b"bzip2", include_bytes!(env!("OXFS_BZIP2_ELF_PATH")));
    ok &= seed_file(bin, b"cal", include_bytes!(env!("OXFS_CAL_ELF_PATH")));
    ok &= seed_file(bin, b"chat", include_bytes!(env!("OXFS_CHAT_ELF_PATH")));
    ok &= seed_file(bin, b"chgrp", include_bytes!(env!("OXFS_CHGRP_ELF_PATH")));
    ok &= seed_file(bin, b"chmod", include_bytes!(env!("OXFS_CHMOD_ELF_PATH")));
    ok &= seed_file(bin, b"chown", include_bytes!(env!("OXFS_CHOWN_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"chpasswd",
        include_bytes!(env!("OXFS_CHPASSWD_ELF_PATH")),
    );
    ok &= seed_file(bin, b"chroot", include_bytes!(env!("OXFS_CHROOT_ELF_PATH")));
    ok &= seed_file(bin, b"chrt", include_bytes!(env!("OXFS_CHRT_ELF_PATH")));
    ok &= seed_file(bin, b"cksum", include_bytes!(env!("OXFS_CKSUM_ELF_PATH")));
    ok &= seed_file(bin, b"clear", include_bytes!(env!("OXFS_CLEAR_ELF_PATH")));
    ok &= seed_file(bin, b"cmp", include_bytes!(env!("OXFS_CMP_ELF_PATH")));
    ok &= seed_file(bin, b"comm", include_bytes!(env!("OXFS_COMM_ELF_PATH")));
    ok &= seed_file(bin, b"cpio", include_bytes!(env!("OXFS_CPIO_ELF_PATH")));
    ok &= seed_file(bin, b"crc32", include_bytes!(env!("OXFS_CRC32_ELF_PATH")));
    ok &= seed_file(bin, b"crond", include_bytes!(env!("OXFS_CROND_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"crontab",
        include_bytes!(env!("OXFS_CRONTAB_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"cryptpw",
        include_bytes!(env!("OXFS_CRYPTPW_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"cttyhack",
        include_bytes!(env!("OXFS_CTTYHACK_ELF_PATH")),
    );
    ok &= seed_file(bin, b"date", include_bytes!(env!("OXFS_DATE_ELF_PATH")));
    ok &= seed_file(bin, b"dc", include_bytes!(env!("OXFS_DC_ELF_PATH")));
    ok &= seed_file(bin, b"dd", include_bytes!(env!("OXFS_DD_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"delgroup",
        include_bytes!(env!("OXFS_DELGROUP_ELF_PATH")),
    );
    ok &= seed_file(bin, b"df", include_bytes!(env!("OXFS_DF_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"dhcprelay",
        include_bytes!(env!("OXFS_DHCPRELAY_ELF_PATH")),
    );
    ok &= seed_file(bin, b"diff", include_bytes!(env!("OXFS_DIFF_ELF_PATH")));
    ok &= seed_file(bin, b"dmesg", include_bytes!(env!("OXFS_DMESG_ELF_PATH")));
    ok &= seed_file(bin, b"dnsd", include_bytes!(env!("OXFS_DNSD_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"dnsdomainname",
        include_bytes!(env!("OXFS_DNSDOMAINNAME_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"dos2unix",
        include_bytes!(env!("OXFS_DOS2UNIX_ELF_PATH")),
    );
    ok &= seed_file(bin, b"dpkg", include_bytes!(env!("OXFS_DPKG_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"dpkg_deb",
        include_bytes!(env!("OXFS_DPKG_DEB_ELF_PATH")),
    );
    ok &= seed_file(bin, b"du", include_bytes!(env!("OXFS_DU_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"dumpleases",
        include_bytes!(env!("OXFS_DUMPLEASES_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ed", include_bytes!(env!("OXFS_ED_ELF_PATH")));
    ok &= seed_file(bin, b"egrep", include_bytes!(env!("OXFS_EGREP_ELF_PATH")));
    ok &= seed_file(bin, b"env", include_bytes!(env!("OXFS_ENV_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"envuidgid",
        include_bytes!(env!("OXFS_ENVUIDGID_ELF_PATH")),
    );
    ok &= seed_file(bin, b"expand", include_bytes!(env!("OXFS_EXPAND_ELF_PATH")));
    ok &= seed_file(bin, b"expr", include_bytes!(env!("OXFS_EXPR_ELF_PATH")));
    ok &= seed_file(bin, b"factor", include_bytes!(env!("OXFS_FACTOR_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"fakeidentd",
        include_bytes!(env!("OXFS_FAKEIDENTD_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"fallocate",
        include_bytes!(env!("OXFS_FALLOCATE_ELF_PATH")),
    );
    ok &= seed_file(bin, b"fgrep", include_bytes!(env!("OXFS_FGREP_ELF_PATH")));
    ok &= seed_file(bin, b"find", include_bytes!(env!("OXFS_FIND_ELF_PATH")));
    ok &= seed_file(bin, b"flock", include_bytes!(env!("OXFS_FLOCK_ELF_PATH")));
    ok &= seed_file(bin, b"fold", include_bytes!(env!("OXFS_FOLD_ELF_PATH")));
    ok &= seed_file(bin, b"free", include_bytes!(env!("OXFS_FREE_ELF_PATH")));
    ok &= seed_file(bin, b"fsync", include_bytes!(env!("OXFS_FSYNC_ELF_PATH")));
    ok &= seed_file(bin, b"ftpd", include_bytes!(env!("OXFS_FTPD_ELF_PATH")));
    ok &= seed_file(bin, b"ftpget", include_bytes!(env!("OXFS_FTPGET_ELF_PATH")));
    ok &= seed_file(bin, b"ftpput", include_bytes!(env!("OXFS_FTPPUT_ELF_PATH")));
    ok &= seed_file(bin, b"fuser", include_bytes!(env!("OXFS_FUSER_ELF_PATH")));
    ok &= seed_file(bin, b"getopt", include_bytes!(env!("OXFS_GETOPT_ELF_PATH")));
    ok &= seed_file(bin, b"getty", include_bytes!(env!("OXFS_GETTY_ELF_PATH")));
    ok &= seed_file(bin, b"grep", include_bytes!(env!("OXFS_GREP_ELF_PATH")));
    ok &= seed_file(bin, b"groups", include_bytes!(env!("OXFS_GROUPS_ELF_PATH")));
    ok &= seed_file(bin, b"gunzip", include_bytes!(env!("OXFS_GUNZIP_ELF_PATH")));
    ok &= seed_file(bin, b"gzip", include_bytes!(env!("OXFS_GZIP_ELF_PATH")));
    ok &= seed_file(bin, b"halt", include_bytes!(env!("OXFS_HALT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"hexdump",
        include_bytes!(env!("OXFS_HEXDUMP_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"hexedit",
        include_bytes!(env!("OXFS_HEXEDIT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"hostid", include_bytes!(env!("OXFS_HOSTID_ELF_PATH")));
    ok &= seed_file(bin, b"httpd", include_bytes!(env!("OXFS_HTTPD_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"hwclock",
        include_bytes!(env!("OXFS_HWCLOCK_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"ifconfig",
        include_bytes!(env!("OXFS_IFCONFIG_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ifdown", include_bytes!(env!("OXFS_IFDOWN_ELF_PATH")));
    ok &= seed_file(bin, b"inetd", include_bytes!(env!("OXFS_INETD_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"install",
        include_bytes!(env!("OXFS_INSTALL_ELF_PATH")),
    );
    ok &= seed_file(bin, b"iostat", include_bytes!(env!("OXFS_IOSTAT_ELF_PATH")));
    ok &= seed_file(bin, b"ipcalc", include_bytes!(env!("OXFS_IPCALC_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"killall5",
        include_bytes!(env!("OXFS_KILLALL5_ELF_PATH")),
    );
    ok &= seed_file(bin, b"less", include_bytes!(env!("OXFS_LESS_ELF_PATH")));
    ok &= seed_file(bin, b"link", include_bytes!(env!("OXFS_LINK_ELF_PATH")));
    ok &= seed_file(bin, b"ln", include_bytes!(env!("OXFS_LN_ELF_PATH")));
    ok &= seed_file(bin, b"login", include_bytes!(env!("OXFS_LOGIN_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"logname",
        include_bytes!(env!("OXFS_LOGNAME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"lpd", include_bytes!(env!("OXFS_LPD_ELF_PATH")));
    ok &= seed_file(bin, b"lpq", include_bytes!(env!("OXFS_LPQ_ELF_PATH")));
    ok &= seed_file(bin, b"lpr", include_bytes!(env!("OXFS_LPR_ELF_PATH")));
    ok &= seed_file(bin, b"ls", include_bytes!(env!("OXFS_LS_ELF_PATH")));
    ok &= seed_file(bin, b"lsof", include_bytes!(env!("OXFS_LSOF_ELF_PATH")));
    ok &= seed_file(bin, b"lspci", include_bytes!(env!("OXFS_LSPCI_ELF_PATH")));
    ok &= seed_file(bin, b"lsscsi", include_bytes!(env!("OXFS_LSSCSI_ELF_PATH")));
    ok &= seed_file(bin, b"lsusb", include_bytes!(env!("OXFS_LSUSB_ELF_PATH")));
    ok &= seed_file(bin, b"lzcat", include_bytes!(env!("OXFS_LZCAT_ELF_PATH")));
    ok &= seed_file(bin, b"lzop", include_bytes!(env!("OXFS_LZOP_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"makedevs",
        include_bytes!(env!("OXFS_MAKEDEVS_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"makemime",
        include_bytes!(env!("OXFS_MAKEMIME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"man", include_bytes!(env!("OXFS_MAN_ELF_PATH")));
    ok &= seed_file(bin, b"md5sum", include_bytes!(env!("OXFS_MD5SUM_ELF_PATH")));
    ok &= seed_file(bin, b"minips", include_bytes!(env!("OXFS_MINIPS_ELF_PATH")));
    ok &= seed_file(bin, b"mknod", include_bytes!(env!("OXFS_MKNOD_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"mkpasswd",
        include_bytes!(env!("OXFS_MKPASSWD_ELF_PATH")),
    );
    ok &= seed_file(bin, b"mktemp", include_bytes!(env!("OXFS_MKTEMP_ELF_PATH")));
    ok &= seed_file(bin, b"mount", include_bytes!(env!("OXFS_MOUNT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"mountpoint",
        include_bytes!(env!("OXFS_MOUNTPOINT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"mpstat", include_bytes!(env!("OXFS_MPSTAT_ELF_PATH")));
    ok &= seed_file(bin, b"nc", include_bytes!(env!("OXFS_NC_ELF_PATH")));
    ok &= seed_file(bin, b"netcat", include_bytes!(env!("OXFS_NETCAT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"netstat",
        include_bytes!(env!("OXFS_NETSTAT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"nice", include_bytes!(env!("OXFS_NICE_ELF_PATH")));
    ok &= seed_file(bin, b"nl", include_bytes!(env!("OXFS_NL_ELF_PATH")));
    ok &= seed_file(bin, b"nmeter", include_bytes!(env!("OXFS_NMETER_ELF_PATH")));
    ok &= seed_file(bin, b"nohup", include_bytes!(env!("OXFS_NOHUP_ELF_PATH")));
    ok &= seed_file(bin, b"nproc", include_bytes!(env!("OXFS_NPROC_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"nslookup",
        include_bytes!(env!("OXFS_NSLOOKUP_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ntpd", include_bytes!(env!("OXFS_NTPD_ELF_PATH")));
    ok &= seed_file(bin, b"nuke", include_bytes!(env!("OXFS_NUKE_ELF_PATH")));
    ok &= seed_file(bin, b"od", include_bytes!(env!("OXFS_OD_ELF_PATH")));
    ok &= seed_file(bin, b"passwd", include_bytes!(env!("OXFS_PASSWD_ELF_PATH")));
    ok &= seed_file(bin, b"paste", include_bytes!(env!("OXFS_PASTE_ELF_PATH")));
    ok &= seed_file(bin, b"patch", include_bytes!(env!("OXFS_PATCH_ELF_PATH")));
    ok &= seed_file(bin, b"pgrep", include_bytes!(env!("OXFS_PGREP_ELF_PATH")));
    ok &= seed_file(bin, b"pidof", include_bytes!(env!("OXFS_PIDOF_ELF_PATH")));
    ok &= seed_file(bin, b"ping", include_bytes!(env!("OXFS_PING_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"pipe_progress",
        include_bytes!(env!("OXFS_PIPE_PROGRESS_ELF_PATH")),
    );
    ok &= seed_file(bin, b"pkill", include_bytes!(env!("OXFS_PKILL_ELF_PATH")));
    ok &= seed_file(bin, b"pmap", include_bytes!(env!("OXFS_PMAP_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"popmaildir",
        include_bytes!(env!("OXFS_POPMAILDIR_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"poweroff",
        include_bytes!(env!("OXFS_POWEROFF_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"powertop",
        include_bytes!(env!("OXFS_POWERTOP_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"printenv",
        include_bytes!(env!("OXFS_PRINTENV_ELF_PATH")),
    );
    ok &= seed_file(bin, b"pscan", include_bytes!(env!("OXFS_PSCAN_ELF_PATH")));
    ok &= seed_file(bin, b"pstree", include_bytes!(env!("OXFS_PSTREE_ELF_PATH")));
    ok &= seed_file(bin, b"pwd", include_bytes!(env!("OXFS_PWD_ELF_PATH")));
    ok &= seed_file(bin, b"pwdx", include_bytes!(env!("OXFS_PWDX_ELF_PATH")));
    ok &= seed_file(bin, b"rdate", include_bytes!(env!("OXFS_RDATE_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"readlink",
        include_bytes!(env!("OXFS_READLINK_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"realpath",
        include_bytes!(env!("OXFS_REALPATH_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"reformime",
        include_bytes!(env!("OXFS_REFORMIME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"remove", include_bytes!(env!("OXFS_REMOVE_ELF_PATH")));
    ok &= seed_file(bin, b"renice", include_bytes!(env!("OXFS_RENICE_ELF_PATH")));
    ok &= seed_file(bin, b"reset", include_bytes!(env!("OXFS_RESET_ELF_PATH")));
    ok &= seed_file(bin, b"resize", include_bytes!(env!("OXFS_RESIZE_ELF_PATH")));
    ok &= seed_file(bin, b"rev", include_bytes!(env!("OXFS_REV_ELF_PATH")));
    ok &= seed_file(bin, b"route", include_bytes!(env!("OXFS_ROUTE_ELF_PATH")));
    ok &= seed_file(bin, b"rpm", include_bytes!(env!("OXFS_RPM_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"rpm2cpio",
        include_bytes!(env!("OXFS_RPM2CPIO_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"rtcwake",
        include_bytes!(env!("OXFS_RTCWAKE_ELF_PATH")),
    );
    ok &= seed_file(bin, b"run", include_bytes!(env!("OXFS_RUN_ELF_PATH")));
    ok &= seed_file(bin, b"sed", include_bytes!(env!("OXFS_SED_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"sendmail",
        include_bytes!(env!("OXFS_SENDMAIL_ELF_PATH")),
    );
    ok &= seed_file(bin, b"setsid", include_bytes!(env!("OXFS_SETSID_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"setuidgid",
        include_bytes!(env!("OXFS_SETUIDGID_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"sha1sum",
        include_bytes!(env!("OXFS_SHA1SUM_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"sha256sum",
        include_bytes!(env!("OXFS_SHA256SUM_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"sha3sum",
        include_bytes!(env!("OXFS_SHA3SUM_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"sha512sum",
        include_bytes!(env!("OXFS_SHA512SUM_ELF_PATH")),
    );
    ok &= seed_file(bin, b"shred", include_bytes!(env!("OXFS_SHRED_ELF_PATH")));
    ok &= seed_file(bin, b"shuf", include_bytes!(env!("OXFS_SHUF_ELF_PATH")));
    ok &= seed_file(bin, b"sleep", include_bytes!(env!("OXFS_SLEEP_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"smemcap",
        include_bytes!(env!("OXFS_SMEMCAP_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"softlimit",
        include_bytes!(env!("OXFS_SOFTLIMIT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"split", include_bytes!(env!("OXFS_SPLIT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"ssl_client",
        include_bytes!(env!("OXFS_SSL_CLIENT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"start", include_bytes!(env!("OXFS_START_ELF_PATH")));
    ok &= seed_file(bin, b"stat", include_bytes!(env!("OXFS_STAT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"strings",
        include_bytes!(env!("OXFS_STRINGS_ELF_PATH")),
    );
    ok &= seed_file(bin, b"stty", include_bytes!(env!("OXFS_STTY_ELF_PATH")));
    ok &= seed_file(bin, b"su", include_bytes!(env!("OXFS_SU_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"sulogin",
        include_bytes!(env!("OXFS_SULOGIN_ELF_PATH")),
    );
    ok &= seed_file(bin, b"sum", include_bytes!(env!("OXFS_SUM_ELF_PATH")));
    ok &= seed_file(bin, b"sync", include_bytes!(env!("OXFS_SYNC_ELF_PATH")));
    ok &= seed_file(bin, b"tac", include_bytes!(env!("OXFS_TAC_ELF_PATH")));
    ok &= seed_file(bin, b"tar", include_bytes!(env!("OXFS_TAR_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"taskset",
        include_bytes!(env!("OXFS_TASKSET_ELF_PATH")),
    );
    ok &= seed_file(bin, b"tcpsvd", include_bytes!(env!("OXFS_TCPSVD_ELF_PATH")));
    ok &= seed_file(bin, b"tee", include_bytes!(env!("OXFS_TEE_ELF_PATH")));
    ok &= seed_file(bin, b"telnet", include_bytes!(env!("OXFS_TELNET_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"telnetd",
        include_bytes!(env!("OXFS_TELNETD_ELF_PATH")),
    );
    ok &= seed_file(bin, b"test", include_bytes!(env!("OXFS_TEST_ELF_PATH")));
    ok &= seed_file(bin, b"time", include_bytes!(env!("OXFS_TIME_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"timeout",
        include_bytes!(env!("OXFS_TIMEOUT_ELF_PATH")),
    );
    ok &= seed_file(bin, b"top", include_bytes!(env!("OXFS_TOP_ELF_PATH")));
    ok &= seed_file(bin, b"tr", include_bytes!(env!("OXFS_TR_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"traceroute",
        include_bytes!(env!("OXFS_TRACEROUTE_ELF_PATH")),
    );
    ok &= seed_file(bin, b"tree", include_bytes!(env!("OXFS_TREE_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"truncate",
        include_bytes!(env!("OXFS_TRUNCATE_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ts", include_bytes!(env!("OXFS_TS_ELF_PATH")));
    ok &= seed_file(bin, b"tsort", include_bytes!(env!("OXFS_TSORT_ELF_PATH")));
    ok &= seed_file(bin, b"tty", include_bytes!(env!("OXFS_TTY_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"ttysize",
        include_bytes!(env!("OXFS_TTYSIZE_ELF_PATH")),
    );
    ok &= seed_file(bin, b"udhcpd", include_bytes!(env!("OXFS_UDHCPD_ELF_PATH")));
    ok &= seed_file(bin, b"udpsvd", include_bytes!(env!("OXFS_UDPSVD_ELF_PATH")));
    ok &= seed_file(bin, b"umount", include_bytes!(env!("OXFS_UMOUNT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"uncompress",
        include_bytes!(env!("OXFS_UNCOMPRESS_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"unexpand",
        include_bytes!(env!("OXFS_UNEXPAND_ELF_PATH")),
    );
    ok &= seed_file(bin, b"unit", include_bytes!(env!("OXFS_UNIT_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"unix2dos",
        include_bytes!(env!("OXFS_UNIX2DOS_ELF_PATH")),
    );
    ok &= seed_file(bin, b"unlink", include_bytes!(env!("OXFS_UNLINK_ELF_PATH")));
    ok &= seed_file(bin, b"unlzma", include_bytes!(env!("OXFS_UNLZMA_ELF_PATH")));
    ok &= seed_file(bin, b"unxz", include_bytes!(env!("OXFS_UNXZ_ELF_PATH")));
    ok &= seed_file(bin, b"unzip", include_bytes!(env!("OXFS_UNZIP_ELF_PATH")));
    ok &= seed_file(bin, b"uptime", include_bytes!(env!("OXFS_UPTIME_ELF_PATH")));
    ok &= seed_file(bin, b"usleep", include_bytes!(env!("OXFS_USLEEP_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"uudecode",
        include_bytes!(env!("OXFS_UUDECODE_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"uuencode",
        include_bytes!(env!("OXFS_UUENCODE_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"vconfig",
        include_bytes!(env!("OXFS_VCONFIG_ELF_PATH")),
    );
    ok &= seed_file(bin, b"vi", include_bytes!(env!("OXFS_VI_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"volname",
        include_bytes!(env!("OXFS_VOLNAME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"watch", include_bytes!(env!("OXFS_WATCH_ELF_PATH")));
    ok &= seed_file(bin, b"wget", include_bytes!(env!("OXFS_WGET_ELF_PATH")));
    ok &= seed_file(bin, b"which", include_bytes!(env!("OXFS_WHICH_ELF_PATH")));
    ok &= seed_file(bin, b"whoami", include_bytes!(env!("OXFS_WHOAMI_ELF_PATH")));
    ok &= seed_file(bin, b"whois", include_bytes!(env!("OXFS_WHOIS_ELF_PATH")));
    ok &= seed_file(bin, b"xargs", include_bytes!(env!("OXFS_XARGS_ELF_PATH")));
    ok &= seed_file(bin, b"xxd", include_bytes!(env!("OXFS_XXD_ELF_PATH")));
    ok &= seed_file(bin, b"xzcat", include_bytes!(env!("OXFS_XZCAT_ELF_PATH")));
    ok &= seed_file(bin, b"zcat", include_bytes!(env!("OXFS_ZCAT_ELF_PATH")));
    // Appended out of alphabetical order, added after SYS_UNAME existed -- see build.rs's own
    // BUSYBOX_APPLETS_PASS2 comment.
    ok &= seed_file(bin, b"uname", include_bytes!(env!("OXFS_UNAME_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"hostname",
        include_bytes!(env!("OXFS_HOSTNAME_ELF_PATH")),
    );

    // /etc/resolv.conf, for musl's own real DNS stub resolver (third_party/musl/src/network/) --
    // no DNS logic lives in this kernel; musl's resolver is a real UDP client already built on
    // socket/sendto/recvfrom/poll (see src/net/mod.rs's oxidebsd_sys_poll doc comment), it just
    // needs a nameserver address to send queries to. 10.0.2.3 is QEMU SLIRP's own built-in DNS
    // relay (must stay in sync with src/net/ipv4.rs's own DNS_SERVER_IP -- this crate can't import
    // that constant directly, it's a separate no_std module build, see CLAUDE.md's module-loading
    // section).
    let etc = alloc_inode().expect("oxfs: failed to allocate /etc inode");
    write_inode(etc, Inode::new(InodeKind::Dir));
    dir_insert(etc, b".", etc).expect("oxfs: failed to seed /etc's . entry");
    dir_insert(etc, b"..", root).expect("oxfs: failed to seed /etc's .. entry");
    dir_insert(root, b"etc", etc).expect("oxfs: failed to insert /etc into root");
    ok &= seed_file(etc, b"resolv.conf", b"nameserver 10.0.2.3\n");
    // /etc/passwd + /etc/group -- musl's own getpwnam/getpwuid/getgrnam/getgrgid
    // (third_party/musl/src/passwd/*.c) parse these directly via plain fopen/fgets, no syscall of
    // their own beyond the open/read/readv this filesystem already supports -- same "port libc's
    // real code, don't reimplement its logic kernel-side" philosophy CLAUDE.md's musl-port section
    // already documents for DNS resolution. Two real accounts now, not just root -- a second,
    // non-root `user` (uid/gid 1000) exists specifically so `su`/`login` have something real to
    // exercise: root calling either always skips the password check entirely (see busybox's own
    // su.c), so a root-only passwd file could never demonstrate real authentication at all.
    ok &= seed_file(
        etc,
        b"passwd",
        b"root:x:0:0:root:/:/bin/sh\nuser:x:1000:1000:User:/home/user:/bin/sh\n",
    );
    ok &= seed_file(etc, b"group", b"root:x:0:\nuser:x:1000:\n");

    // /etc/shadow: real crypt(3) password hashes (SHA-512, `$6$`) -- musl's own getspnam
    // (third_party/musl/src/passwd/getspnam*.c) parses this the same way it parses /etc/passwd.
    // Both passwords equal the account's own username (`root`/`user`) -- fine for a kernel with no
    // external network exposure and no real multi-user threat model, but real enough that `su`/
    // `login`'s own crypt() comparison genuinely succeeds or fails on the actual input, not a
    // hardcoded stub. Locked to 0600 immediately after seeding, since `seed_file` always creates at
    // the default `FIXED_PERM=0o755` and a real shadow file must not be world-readable.
    ok &= seed_file(
        etc,
        b"shadow",
        b"root:$6$rootsalt1$LPAGSn9wp5B5UT8Za.dDLpjIX7Iesb2cmVG/FkZsCpAaVTYOv5MM2tNq6/FtrWiSFSRAXC/JM.vP6j727dx63.:19000:0:99999:7:::\nuser:$6$usersalt1$K3nFr1EkyUio7bqA5yHH406lM.gYiQIJraJUwV47yxP/3fF.Sa4wdmFXIsT//WSUp5YDYkRnpOAFIjJqbtQXA.:19000:0:99999:7:::\n",
    );
    if let Some(shadow_inode) = dir_lookup(etc, b"shadow") {
        let mut inode = read_inode(shadow_inode);
        inode.mode = 0o600;
        write_inode(shadow_inode, inode);
    } else {
        ok = false;
    }

    // /home/user -- real, owned by uid/gid 1000 -- so `su -`/`login`'s own real chdir-to-home
    // lands somewhere that's actually theirs (permission-checked, not just root's own `/`).
    let home = alloc_inode().expect("oxfs: failed to allocate /home inode");
    write_inode(home, Inode::new(InodeKind::Dir));
    dir_insert(home, b".", home).expect("oxfs: failed to seed /home's . entry");
    dir_insert(home, b"..", root).expect("oxfs: failed to seed /home's .. entry");
    dir_insert(root, b"home", home).expect("oxfs: failed to insert /home into root");

    let user_home = alloc_inode().expect("oxfs: failed to allocate /home/user inode");
    write_inode(user_home, Inode::new(InodeKind::Dir));
    dir_insert(user_home, b".", user_home).expect("oxfs: failed to seed /home/user's . entry");
    dir_insert(user_home, b"..", home).expect("oxfs: failed to seed /home/user's .. entry");
    dir_insert(home, b"user", user_home).expect("oxfs: failed to insert /home/user into /home");
    {
        let mut inode = read_inode(user_home);
        inode.mode = 0o700;
        inode.uid = 1000;
        inode.gid = 1000;
        write_inode(user_home, inode);
    }

    // TinyCC's own on-target runtime tree -- see CLAUDE.md's TinyCC section. `/usr/include`,
    // `/usr/lib`, `/usr/lib/tcc` exactly match tcc's own compiled-in defaults (`CONFIG_TCCDIR`/
    // `CONFIG_TCC_CRTPREFIX`/`CONFIG_TCC_SYSINCLUDEPATHS`, baked in via build.rs's
    // `--prefix=/usr` configure flag), so no extra `-B`/`-I`/`-L` flags are needed to invoke `tcc`
    // on target.
    let usr = ensure_dir(root, b"usr");
    let usr_include = ensure_dir(usr, b"include");
    ok &= seed_tree(usr_include, MUSL_INCLUDE_FILES);
    let usr_lib = ensure_dir(usr, b"lib");
    ok &= seed_tree(usr_lib, MUSL_LIB_FILES);
    let usr_lib_tcc = ensure_dir(usr_lib, b"tcc");
    ok &= seed_tree(usr_lib_tcc, TCC_RUNTIME_FILES);

    // A real fixture for exercising the compiler end to end (`tcc -static -o hello.elf hello.c`,
    // by hand at the hush prompt or via `tests/tcc_syscall_smoke.rs`) -- a real `printf`, not a
    // bare `return`, so it exercises musl's stdio/writev path, not just process exit.
    ok &= seed_file(
        root,
        b"hello.c",
        b"#include <stdio.h>\nint main(void) {\n    printf(\"hello from tcc\\n\");\n    return 0;\n}\n",
    );

    if !ok {
        log("[oxfs] self-check FAILED: seeding embedded files failed\n");
    }

    // --- Round-trip check: hello.txt/big.txt read back correctly. ---
    if let Some(hello) = dir_lookup(root, b"hello.txt") {
        let mut buf = [0u8; 64];
        let n = read_inode_at(hello, 0, &mut buf);
        if &buf[..n] != b"Hello from OxideBSD's own filesystem!\n" {
            ok = false;
            log("[oxfs] self-check FAILED: hello.txt contents mismatch\n");
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found\n");
    }
    if let Some(big_inode) = dir_lookup(root, b"big.txt") {
        let mut buf = [0u8; BIG_FILE_LEN];
        let n = read_inode_at(big_inode, 0, &mut buf);
        let matches = n == BIG_FILE_LEN
            && buf[..n]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == b'A' + (i % 26) as u8);
        if !matches {
            ok = false;
            log("[oxfs] self-check FAILED: big.txt contents mismatch (multi-block read)\n");
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: big.txt not found\n");
    }

    // --- stat/fstat/lstat round trip, through the real registered handlers. ---
    if let Some(hello) = dir_lookup(root, b"hello.txt") {
        let expected_size = read_inode(hello).size as i64;
        let path = b"hello.txt";
        let mut stat_buf = [0u8; 144];
        if oxfs_stat(
            path.as_ptr() as u64,
            path.len() as u64,
            stat_buf.as_mut_ptr() as u64,
            0,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: stat hello.txt failed\n");
        } else {
            let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
            if st.st_ino != hello as u64 || st.st_size != expected_size || st.st_mode & S_IFREG == 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: stat hello.txt field mismatch\n");
            }
        }

        let mut lstat_buf = [0u8; 144];
        if oxfs_lstat(
            path.as_ptr() as u64,
            path.len() as u64,
            lstat_buf.as_mut_ptr() as u64,
            0,
        ) != 0
            || lstat_buf != stat_buf
        {
            ok = false;
            log("[oxfs] self-check FAILED: lstat hello.txt disagreed with stat\n");
        }

        let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
        if fd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: open hello.txt for fstat check failed\n");
        } else {
            let mut fstat_buf = [0u8; 144];
            if oxfs_fstat(fd as u64, fstat_buf.as_mut_ptr() as u64, 0, 0) != 0
                || fstat_buf != stat_buf
            {
                ok = false;
                log("[oxfs] self-check FAILED: fstat hello.txt disagreed with stat\n");
            }
            oxfs_close(fd as u64);
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found for stat check\n");
    }

    // --- getdents round trip, through the real registered handler. ---
    let gdtest = b"/gdtest";
    if oxfs_mkdir(gdtest.as_ptr() as u64, gdtest.len() as u64, 0, 0) != 0 {
        ok = false;
        log("[oxfs] self-check FAILED: mkdir /gdtest failed\n");
    } else {
        let mut seeded = true;
        for name in [&b"/gdtest/a"[..], &b"/gdtest/b"[..]] {
            let fd = oxfs_open(name.as_ptr() as u64, name.len() as u64, O_CREAT, 0);
            if fd < 0 {
                seeded = false;
            } else {
                oxfs_close(fd as u64);
            }
        }
        if !seeded {
            ok = false;
            log("[oxfs] self-check FAILED: seeding /gdtest/{a,b} failed\n");
        }

        let dfd = oxfs_open(gdtest.as_ptr() as u64, gdtest.len() as u64, 0, 0);
        if dfd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: open /gdtest for getdents failed\n");
        } else {
            let dfd = dfd as u64;
            let mut buf = [0u8; 512];
            let n = oxfs_getdents(dfd, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
            if n <= 0 {
                ok = false;
                log("[oxfs] self-check FAILED: getdents /gdtest returned nothing\n");
            } else {
                let (mut seen_dot, mut seen_dotdot, mut seen_a, mut seen_b) =
                    (false, false, false, false);
                let mut off = 0usize;
                let mut count = 0;
                while off < n as usize {
                    let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
                    if reclen == 0 || off + reclen > n as usize {
                        break;
                    }
                    let name_start = off + 19;
                    let name_end = buf[name_start..off + reclen]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(off + reclen, |p| name_start + p);
                    match &buf[name_start..name_end] {
                        b"." => seen_dot = true,
                        b".." => seen_dotdot = true,
                        b"a" => seen_a = true,
                        b"b" => seen_b = true,
                        _ => {}
                    }
                    count += 1;
                    off += reclen;
                }
                if count != 4 || !seen_dot || !seen_dotdot || !seen_a || !seen_b {
                    ok = false;
                    log("[oxfs] self-check FAILED: getdents /gdtest entries mismatch\n");
                }
                // Every record already consumed -- a second call must report EOF (0), the signal
                // readdir() relies on to stop looping.
                let n2 = oxfs_getdents(dfd, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
                if n2 != 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: getdents /gdtest didn't reach EOF\n");
                }
            }
            oxfs_close(dfd);
        }
    }

    // --- mkdir/chdir/open(O_CREAT)/write/close/read, through the real registered handlers. ---
    if oxfs_mkdir(b"sub".as_ptr() as u64, 3, 0, 0) != 0 {
        ok = false;
        log("[oxfs] self-check FAILED: mkdir sub failed\n");
    } else if oxfs_chdir(b"sub".as_ptr() as u64, 3, 0, 0) != 0 {
        ok = false;
        log("[oxfs] self-check FAILED: chdir into sub failed\n");
    } else {
        let content = b"inside a subdirectory\n";
        let fd = oxfs_open(b"in.txt".as_ptr() as u64, 6, O_CREAT, 0);
        if fd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: open(O_CREAT) sub/in.txt failed\n");
        } else {
            let fd = fd as u64;
            if oxfs_write(fd, content.as_ptr() as u64, content.len() as u64) != content.len() as i64
            {
                ok = false;
                log("[oxfs] self-check FAILED: write sub/in.txt failed\n");
            }
            oxfs_close(fd);

            // getcwd inside sub -> "/sub".
            let mut cwd_buf = [0u8; 64];
            let n = oxfs_getcwd(cwd_buf.as_mut_ptr() as u64, cwd_buf.len() as u64, 0, 0);
            if n <= 0 || &cwd_buf[..(n as usize - 1)] != b"/sub" {
                ok = false;
                log("[oxfs] self-check FAILED: getcwd inside sub mismatch\n");
            }

            // Multi-component resolution: open "/sub/in.txt" in one call from root's own cwd.
            oxfs_chdir(b"/".as_ptr() as u64, 1, 0, 0);
            let path = b"/sub/in.txt";
            let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
            if fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: multi-component open /sub/in.txt failed\n");
            } else {
                let fd = fd as u64;
                let mut buf = [0u8; 64];
                let n = oxfs_read(fd, buf.as_mut_ptr() as u64, buf.len() as u64);
                oxfs_close(fd);
                if n < 0 || &buf[..n as usize] != content {
                    ok = false;
                    log("[oxfs] self-check FAILED: /sub/in.txt contents mismatch\n");
                }
            }

            // rename /sub/in.txt -> /sub/renamed.txt.
            let old = b"/sub/in.txt";
            let new = b"/sub/renamed.txt";
            if oxfs_rename(
                old.as_ptr() as u64,
                old.len() as u64,
                new.as_ptr() as u64,
                new.len() as u64,
            ) != 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: rename /sub/in.txt failed\n");
            } else {
                let fd = oxfs_open(old.as_ptr() as u64, old.len() as u64, 0, 0);
                if fd >= 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: old name still openable after rename\n");
                }
                let fd = oxfs_open(new.as_ptr() as u64, new.len() as u64, 0, 0);
                if fd < 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: renamed.txt not openable after rename\n");
                } else {
                    oxfs_close(fd as u64);
                }
            }

            // unlink /sub/renamed.txt, mkdir /sub/nested (multi-component mkdir), rmdir checks.
            if oxfs_unlink(new.as_ptr() as u64, new.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: unlink /sub/renamed.txt failed\n");
            }
            let nested = b"/sub/nested";
            if oxfs_mkdir(nested.as_ptr() as u64, nested.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: mkdir /sub/nested failed\n");
            } else {
                let sub_path = b"/sub";
                if oxfs_rmdir(sub_path.as_ptr() as u64, sub_path.len() as u64, 0, 0) != -ENOTEMPTY {
                    ok = false;
                    log("[oxfs] self-check FAILED: rmdir /sub should have failed with ENOTEMPTY\n");
                }
                if oxfs_rmdir(nested.as_ptr() as u64, nested.len() as u64, 0, 0) != 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: rmdir /sub/nested failed\n");
                }
                if oxfs_rmdir(sub_path.as_ptr() as u64, sub_path.len() as u64, 0, 0) != 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: rmdir /sub failed\n");
                }
            }
        }
    }

    // --- Real write-to-an-existing-file support (O_WRONLY overwrite/truncate, O_APPEND, EISDIR
    // on a directory) -- see this pass's own CLAUDE.md entry for why this used to be impossible:
    // any open of an existing path always came back read-only, so a file could only ever be
    // written once, for its entire lifetime.
    {
        const O_WRONLY: u64 = 0o1;
        const O_APPEND: u64 = 0o2000;
        let path = b"/overwrite_test.txt";

        let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, O_CREAT, 0);
        if fd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: create overwrite_test.txt failed\n");
        } else {
            let fd = fd as u64;
            oxfs_write(fd, b"AAAAA".as_ptr() as u64, 5);
            oxfs_close(fd);

            // Plain O_WRONLY on an existing path: real overwrite-from-scratch, including a real
            // truncate (writing fewer bytes than before must not leave the old tail behind).
            let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, O_WRONLY, 0);
            if fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: O_WRONLY reopen of an existing file failed\n");
            } else {
                let fd = fd as u64;
                oxfs_write(fd, b"BB".as_ptr() as u64, 2);
                oxfs_close(fd);

                let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
                let mut buf = [0u8; 16];
                let n = oxfs_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                oxfs_close(fd as u64);
                if fd < 0 || n != 2 || &buf[..2] != b"BB" {
                    ok = false;
                    log(
                        "[oxfs] self-check FAILED: O_WRONLY overwrite did not truncate correctly\n",
                    );
                }
            }

            // O_APPEND: new writes land after the real existing content, not replacing it.
            let fd = oxfs_open(
                path.as_ptr() as u64,
                path.len() as u64,
                O_WRONLY | O_APPEND,
                0,
            );
            if fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: O_APPEND reopen of an existing file failed\n");
            } else {
                let fd = fd as u64;
                oxfs_write(fd, b"CC".as_ptr() as u64, 2);
                oxfs_close(fd);

                let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
                let mut buf = [0u8; 16];
                let n = oxfs_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                oxfs_close(fd as u64);
                if fd < 0 || n != 4 || &buf[..4] != b"BBCC" {
                    ok = false;
                    log("[oxfs] self-check FAILED: O_APPEND did not preserve existing content\n");
                }
            }

            oxfs_unlink(path.as_ptr() as u64, path.len() as u64, 0, 0);
        }

        // Opening a real directory (not the "/" special case) for writing is a real EISDIR now.
        let dir_path = b"/writetest_dir";
        if oxfs_mkdir(dir_path.as_ptr() as u64, dir_path.len() as u64, 0, 0) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: mkdir /writetest_dir failed\n");
        } else {
            if oxfs_open(dir_path.as_ptr() as u64, dir_path.len() as u64, O_WRONLY, 0) != -EISDIR {
                ok = false;
                log("[oxfs] self-check FAILED: O_WRONLY on a directory should be EISDIR\n");
            }
            oxfs_rmdir(dir_path.as_ptr() as u64, dir_path.len() as u64, 0, 0);
        }
    }

    // --- /proc system-wide files (meminfo/uptime/stat/modules), through the real registered
    // handlers. No real process exists yet at this point in boot, but these four don't need one
    // (unlike ProcDirKind::PidFiles/TaskList/FdList navigation, which does -- covered by tests/
    // proc_smoke.rs's own real-SYSCALL test instead, since it needs a real spawned process).
    // `/proc/modules` in particular can only be checked here for "oxfs is listed" -- src/
    // module.rs's `load()` records this module's own entry *before* calling `module_init` (this
    // very function), specifically so a module's own self-check can see itself already present,
    // matching real Linux's own "present in /proc/modules the instant relocation finishes" timing.
    for (path, needle) in [
        (b"/proc/meminfo".as_slice(), b"MemTotal".as_slice()),
        (b"/proc/uptime".as_slice(), b".".as_slice()),
        (b"/proc/stat".as_slice(), b"cpu".as_slice()),
        (b"/proc/modules".as_slice(), b"oxfs".as_slice()),
    ] {
        let mut buf = [0u8; PROC_BUFFER];
        let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
        if fd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: open /proc system file failed\n");
            continue;
        }
        let n = oxfs_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
        oxfs_close(fd as u64);
        if n <= 0 || !buf[..n as usize].windows(needle.len()).any(|w| w == needle) {
            ok = false;
            log("[oxfs] self-check FAILED: /proc system file content mismatch\n");
        }
    }

    // --- chdir into/out of /proc, through the real registered handlers (Part C). ---
    {
        let proc_path = b"/proc";
        if oxfs_chdir(proc_path.as_ptr() as u64, proc_path.len() as u64, 0, 0) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: chdir /proc failed\n");
        } else {
            // Relative "" (list cwd) should match the absolute /proc listing's own content.
            let empty = b"";
            let dfd = oxfs_open(empty.as_ptr() as u64, 0, 0, 0);
            if dfd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: relative open(\"\") inside /proc failed\n");
            } else {
                let mut buf = [0u8; DIR_LISTING_BUFFER];
                let n = oxfs_read(dfd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                oxfs_close(dfd as u64);
                if n <= 0 || !buf[..n as usize].windows(7).any(|w| w == b"meminfo") {
                    ok = false;
                    log("[oxfs] self-check FAILED: relative /proc listing missing meminfo\n");
                }
            }

            // Relative "meminfo" should match the absolute /proc/meminfo read.
            let rel = b"meminfo";
            let rfd = oxfs_open(rel.as_ptr() as u64, rel.len() as u64, 0, 0);
            let abs = b"/proc/meminfo";
            let afd = oxfs_open(abs.as_ptr() as u64, abs.len() as u64, 0, 0);
            if rfd < 0 || afd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: relative/absolute /proc/meminfo open failed\n");
            } else {
                let mut rbuf = [0u8; PROC_BUFFER];
                let mut abuf = [0u8; PROC_BUFFER];
                let rn = oxfs_read(rfd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64);
                let an = oxfs_read(afd as u64, abuf.as_mut_ptr() as u64, abuf.len() as u64);
                if rn != an || rbuf != abuf {
                    ok = false;
                    log("[oxfs] self-check FAILED: relative /proc/meminfo content mismatch\n");
                }
            }
            if rfd >= 0 {
                oxfs_close(rfd as u64);
            }
            if afd >= 0 {
                oxfs_close(afd as u64);
            }

            // EROFS guard: nothing can be created while cwd is inside /proc.
            let x = b"x";
            if oxfs_mkdir(x.as_ptr() as u64, x.len() as u64, 0, 0) != -EROFS {
                ok = false;
                log("[oxfs] self-check FAILED: mkdir inside /proc should have failed with EROFS\n");
            }

            // Back out to the real root -- getcwd must report "/", and a real op must still work.
            let dotdot = b"..";
            if oxfs_chdir(dotdot.as_ptr() as u64, dotdot.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: chdir .. out of /proc failed\n");
            }
            let mut cwd_buf = [0u8; 64];
            let n = oxfs_getcwd(cwd_buf.as_mut_ptr() as u64, cwd_buf.len() as u64, 0, 0);
            if n <= 0 || &cwd_buf[..(n as usize - 1)] != b"/" {
                ok = false;
                log("[oxfs] self-check FAILED: getcwd after leaving /proc mismatch\n");
            }
            let real_path = b"hello.txt";
            let real_fd = oxfs_open(real_path.as_ptr() as u64, real_path.len() as u64, 0, 0);
            if real_fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: real open after leaving /proc failed\n");
            } else {
                oxfs_close(real_fd as u64);
            }
        }
    }

    // --- Real symlinks, through the real registered handlers (Part D). ---
    if let Some(hello) = dir_lookup(ROOT_INODE, b"hello.txt") {
        let target = b"hello.txt";
        let linkpath = b"hello_link";
        if oxfs_symlink(
            target.as_ptr() as u64,
            target.len() as u64,
            linkpath.as_ptr() as u64,
            linkpath.len() as u64,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: symlink hello_link failed\n");
        } else {
            let mut rbuf = [0u8; 64];
            let n = oxfs_readlink(
                linkpath.as_ptr() as u64,
                linkpath.len() as u64,
                rbuf.as_mut_ptr() as u64,
                rbuf.len() as u64,
            );
            if n != target.len() as i64 || &rbuf[..n as usize] != target {
                ok = false;
                log("[oxfs] self-check FAILED: readlink hello_link mismatch\n");
            }

            let mut stat_buf = [0u8; 144];
            if oxfs_stat(
                linkpath.as_ptr() as u64,
                linkpath.len() as u64,
                stat_buf.as_mut_ptr() as u64,
                0,
            ) != 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: stat hello_link (follow) failed\n");
            } else {
                let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
                if st.st_mode & S_IFREG == 0 || st.st_ino != hello as u64 {
                    ok = false;
                    log("[oxfs] self-check FAILED: stat hello_link didn't follow to hello.txt\n");
                }
            }

            let mut lstat_buf = [0u8; 144];
            if oxfs_lstat(
                linkpath.as_ptr() as u64,
                linkpath.len() as u64,
                lstat_buf.as_mut_ptr() as u64,
                0,
            ) != 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: lstat hello_link failed\n");
            } else {
                let st = unsafe { (lstat_buf.as_ptr() as *const MuslStat).read_unaligned() };
                if st.st_mode & S_IFLNK != S_IFLNK || st.st_size != target.len() as i64 {
                    ok = false;
                    log("[oxfs] self-check FAILED: lstat hello_link should report S_IFLNK\n");
                }
            }

            // open() follows the link -- content must match hello.txt's own real content.
            let fd = oxfs_open(linkpath.as_ptr() as u64, linkpath.len() as u64, 0, 0);
            if fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: open hello_link (follow) failed\n");
            } else {
                let expected_size = read_inode(hello).size as usize;
                let mut buf = [0u8; 64];
                let n = oxfs_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                oxfs_close(fd as u64);
                if n < 0 || n as usize != expected_size {
                    ok = false;
                    log("[oxfs] self-check FAILED: open hello_link content length mismatch\n");
                }
            }

            if oxfs_unlink(linkpath.as_ptr() as u64, linkpath.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: unlink hello_link failed\n");
            }
            if dir_lookup(ROOT_INODE, b"hello_link").is_some() {
                ok = false;
                log("[oxfs] self-check FAILED: hello_link still present after unlink\n");
            }
            if dir_lookup(ROOT_INODE, b"hello.txt").is_none() {
                ok = false;
                log("[oxfs] self-check FAILED: hello.txt disappeared after unlinking its link\n");
            }
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found for symlink check\n");
    }

    // --- Real hard links, device nodes, and per-process chroot containment, through the real
    // registered handlers (Part D2). ---
    if let Some(hello) = dir_lookup(ROOT_INODE, b"hello.txt") {
        let hello_size = read_inode(hello).size;
        let hello_name = b"hello.txt";
        let link_name = b"hello_hardlink";
        if oxfs_link(
            hello_name.as_ptr() as u64,
            hello_name.len() as u64,
            link_name.as_ptr() as u64,
            link_name.len() as u64,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: link hello_hardlink failed\n");
        } else {
            let mut stat_buf = [0u8; 144];
            if oxfs_stat(
                link_name.as_ptr() as u64,
                link_name.len() as u64,
                stat_buf.as_mut_ptr() as u64,
                0,
            ) != 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: stat hello_hardlink failed\n");
            } else {
                let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
                if st.st_ino != hello as u64 || st.st_nlink != 2 || st.st_size != hello_size as i64
                {
                    ok = false;
                    log(
                        "[oxfs] self-check FAILED: hello_hardlink didn't report the real shared inode/nlink\n",
                    );
                }
            }
            if oxfs_unlink(link_name.as_ptr() as u64, link_name.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: unlink hello_hardlink failed\n");
            }
            if read_inode(hello).nlink != 1 {
                ok = false;
                log("[oxfs] self-check FAILED: hello.txt nlink didn't drop back to 1\n");
            }
            if dir_lookup(ROOT_INODE, b"hello.txt").is_none() {
                ok = false;
                log(
                    "[oxfs] self-check FAILED: hello.txt disappeared after unlinking its hard link\n",
                );
            }
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found for link check\n");
    }

    {
        let reg_path = b"mknodtest.reg";
        if oxfs_mknod(
            reg_path.as_ptr() as u64,
            reg_path.len() as u64,
            (S_IFREG | 0o644) as u64,
            0,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: mknod mknodtest.reg (S_IFREG) failed\n");
        } else if oxfs_unlink(reg_path.as_ptr() as u64, reg_path.len() as u64, 0, 0) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: unlink mknodtest.reg failed\n");
        }

        // Real Linux's own standard major:minor for /dev/null (1,3) -- see known_device's own doc
        // comment. Exercises the real create -> stat -> open -> write/read -> unlink round trip
        // through a genuine inode, distinct from dev_open's own magic-path /dev/null.
        let dev_path = b"mknodtest.null";
        let null_dev: u64 = (1 << 8) | 3;
        if oxfs_mknod(
            dev_path.as_ptr() as u64,
            dev_path.len() as u64,
            (S_IFCHR | 0o600) as u64,
            null_dev,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: mknod mknodtest.null (S_IFCHR 1,3) failed\n");
        } else {
            let mut stat_buf = [0u8; 144];
            if oxfs_stat(
                dev_path.as_ptr() as u64,
                dev_path.len() as u64,
                stat_buf.as_mut_ptr() as u64,
                0,
            ) != 0
            {
                ok = false;
                log("[oxfs] self-check FAILED: stat mknodtest.null failed\n");
            } else {
                let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
                if st.st_mode & S_IFMT != S_IFCHR || st.st_rdev != null_dev {
                    ok = false;
                    log(
                        "[oxfs] self-check FAILED: mknodtest.null didn't report S_IFCHR/real rdev\n",
                    );
                }
            }
            let fd = oxfs_open(dev_path.as_ptr() as u64, dev_path.len() as u64, 0o1, 0);
            if fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: open mknodtest.null failed\n");
            } else {
                let payload = b"x";
                let wrote = oxfs_write(fd as u64, payload.as_ptr() as u64, 1);
                let mut rbuf = [1u8; 8];
                let read = oxfs_read(fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64);
                oxfs_close(fd as u64);
                if wrote < 0 || read != 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: mknodtest.null didn't behave like /dev/null\n");
                }
            }
            if oxfs_unlink(dev_path.as_ptr() as u64, dev_path.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: unlink mknodtest.null failed\n");
            }
        }
    }

    // Real per-process chroot containment. Runs at pid 0 (module_init's own self-check), where
    // oxidebsd_current_uid always reports root -- see oxfs_chroot's own doc comment. Explicitly
    // resets BOOT_ROOT back to the real root (0) afterward regardless of outcome, via
    // oxidebsd_set_root directly rather than a path-based chroot back (once chrooted, an absolute
    // "/" no longer names the real root at all -- see resolve_path_impl's own containment logic),
    // so every check after this one in this same self-check still resolves against the real tree.
    {
        let dir_name = b"chroottest";
        if oxfs_mkdir(dir_name.as_ptr() as u64, dir_name.len() as u64, 0, 0) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: mkdir chroottest failed\n");
        } else {
            let chroot_inode = dir_lookup(ROOT_INODE, b"chroottest");
            let path = b"/chroottest";
            if oxfs_chroot(path.as_ptr() as u64, path.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: chroot /chroottest failed\n");
            } else {
                // Real chroot(2) doesn't move cwd -- BusyBox's own chroot applet chdir("/")s
                // right afterward, the normal real-world pattern this mirrors.
                let root_path = b"/";
                if oxfs_chdir(root_path.as_ptr() as u64, root_path.len() as u64, 0, 0) != 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: chdir / after chroot failed\n");
                }
                let mut cwd_buf = [0u8; 16];
                let n = oxfs_getcwd(cwd_buf.as_mut_ptr() as u64, cwd_buf.len() as u64, 0, 0);
                if n != 2 || &cwd_buf[..1] != b"/" {
                    ok = false;
                    log("[oxfs] self-check FAILED: getcwd inside chroot should report /\n");
                }
                let dotdot = b"..";
                if oxfs_chdir(dotdot.as_ptr() as u64, dotdot.len() as u64, 0, 0) != 0 {
                    ok = false;
                    log(
                        "[oxfs] self-check FAILED: chdir .. inside chroot should still succeed (contained, not escape)\n",
                    );
                }
                let after_dotdot = match current_cwd() {
                    Cwd::Real(inode) => Some(inode),
                    Cwd::Proc(_) => None,
                };
                if after_dotdot != chroot_inode {
                    ok = false;
                    log("[oxfs] self-check FAILED: chdir .. escaped the chroot\n");
                }
            }
            unsafe { oxidebsd_set_root(0) };
            set_current_cwd_real(ROOT_INODE);
        }
    }

    // --- Real chmod/chown, through the real registered handlers (Part E). This runs at pid 0
    // (module_init's own self-check, before any real process exists), where oxidebsd_current_uid
    // always reports root -- see oxfs_chmod/oxfs_chown's own doc comments for the real permission
    // rules this exercises only the always-allowed side of. ---
    if let Some(hello) = dir_lookup(ROOT_INODE, b"hello.txt") {
        let path = b"hello.txt";
        if oxfs_chmod(path.as_ptr() as u64, path.len() as u64, 0o600, 0) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: chmod hello.txt failed\n");
        } else if read_inode(hello).mode != 0o600 {
            ok = false;
            log("[oxfs] self-check FAILED: chmod hello.txt didn't stick\n");
        }
        if oxfs_chown(path.as_ptr() as u64, path.len() as u64, 7, u32::MAX as u64) != 0 {
            ok = false;
            log("[oxfs] self-check FAILED: chown hello.txt failed\n");
        } else {
            let after = read_inode(hello);
            // gid passed as u32::MAX ("leave unchanged") must not have moved off its seeded 0.
            if after.uid != 7 || after.gid != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: chown hello.txt field mismatch\n");
            }
        }
        let mut stat_buf = [0u8; 144];
        if oxfs_stat(
            path.as_ptr() as u64,
            path.len() as u64,
            stat_buf.as_mut_ptr() as u64,
            0,
        ) != 0
        {
            ok = false;
            log("[oxfs] self-check FAILED: stat hello.txt after chmod/chown failed\n");
        } else {
            let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
            if st.st_mode & 0o777 != 0o600 || st.st_uid != 7 || st.st_gid != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: stat hello.txt didn't reflect chmod/chown\n");
            }
        }
        // Restore hello.txt's original ownership/mode so later checks in this self-check (and any
        // real process that opens it after boot) see the same seeded state every other file has.
        let mut inode = read_inode(hello);
        inode.mode = FIXED_PERM as u16;
        inode.uid = 0;
        inode.gid = 0;
        write_inode(hello, inode);
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found for chmod/chown check\n");
    }

    if ok {
        log("[oxfs] self-check passed\n");
    }
    ok
}

/// Real module entry point (`#[unsafe(no_mangle)]`, discovered by `build.rs`'s relocatable-link
/// step and called by `src/module.rs::load`). Decides between mounting an already-formatted disk
/// and formatting a fresh one (or running purely in-memory, if no data disk is attached at all --
/// see `src/ata.rs`), then performs the state every path needs regardless: resetting the boot-time
/// cwd and registering every syscall this module owns. Must never early-return before that tail --
/// skipping syscall registration on any path would silently ship a filesystem no process could
/// actually use.
#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    let has_disk = block_device_present();

    let ok = if has_disk && mount_from_disk() {
        true
    } else {
        // A failed mount attempt can have already partially populated the real block-used
        // bitmap/inode table from the stale disk it just gave up on -- see
        // `reset_real_pool_for_fresh_format`'s own doc comment for the real, live bug this
        // guards against. Harmless (a no-op over already-pristine state) on the "no disk
        // attached at all" path, so this runs unconditionally rather than only when `has_disk`.
        reset_real_pool_for_fresh_format();
        let ok = format_fresh_filesystem();
        if has_disk {
            flush_all_to_disk();
        }
        ok
    };

    // Both the mount and the format-then-flush path above leave PERSISTENCE_READY false
    // throughout their own bulk work (see that flag's own doc comment) -- flipped here, once,
    // right before real syscalls become reachable, so every write a running process makes from
    // this point on is persisted immediately.
    set_persistence_ready(true);

    // Back to root, matching the state a booting kernel with no real process yet should leave
    // BOOT_CWD in (a real process's own cwd starts at Process::cwd's default, 0/root, regardless
    // of whatever format_fresh_filesystem's self-check did to BOOT_CWD -- see src/process.rs's own
    // doc comment -- but leaving this tidy avoids any confusion reading a boot log).
    set_current_cwd_real(ROOT_INODE);

    // SAFETY: FFI calls to kernel-exported functions, matching their declared signatures exactly.
    unsafe {
        oxidebsd_register_syscall(SYS_OPEN, oxfs_open);
        oxidebsd_register_syscall(SYS_ACCESS, oxfs_access);
        oxidebsd_register_syscall(SYS_CLOSE, sys_close);
        oxidebsd_register_syscall(SYS_CHDIR, oxfs_chdir);
        oxidebsd_register_syscall(SYS_CHROOT, oxfs_chroot);
        oxidebsd_register_syscall(SYS_MKDIR, oxfs_mkdir);
        oxidebsd_register_syscall(SYS_GETCWD, oxfs_getcwd);
        oxidebsd_register_syscall(SYS_UNLINK, oxfs_unlink);
        oxidebsd_register_syscall(SYS_LINK, oxfs_link);
        oxidebsd_register_syscall(SYS_MKNOD, oxfs_mknod);
        oxidebsd_register_syscall(SYS_RMDIR, oxfs_rmdir);
        oxidebsd_register_syscall(SYS_RENAME, oxfs_rename);
        oxidebsd_register_syscall(SYS_READLINK, oxfs_readlink);
        oxidebsd_register_syscall(SYS_SYMLINK, oxfs_symlink);
        oxidebsd_register_syscall(SYS_STAT, oxfs_stat);
        oxidebsd_register_syscall(SYS_LSTAT, oxfs_lstat);
        oxidebsd_register_syscall(SYS_FSTAT, oxfs_fstat);
        oxidebsd_register_syscall(SYS_LSEEK, oxfs_lseek);
        oxidebsd_register_syscall(SYS_GETDENTS, oxfs_getdents);
        oxidebsd_register_syscall(SYS_CHMOD, oxfs_chmod);
        oxidebsd_register_syscall(SYS_CHOWN, oxfs_chown);
        oxidebsd_register_syscall(SYS_FCHMOD, oxfs_fchmod);
        oxidebsd_register_syscall(SYS_UTIMENSAT, oxfs_utimensat);
        oxidebsd_register_syscall(SYS_MOUNT_BIND, oxfs_mount_bind);
        oxidebsd_register_syscall(SYS_MOUNT_TMPFS, oxfs_mount_tmpfs);
        oxidebsd_register_syscall(SYS_UMOUNT2, oxfs_umount2);
        oxidebsd_register_syscall(SYS_FSYNC, oxfs_fsync);
        oxidebsd_register_syscall(SYS_SYNC, oxfs_sync);
        oxidebsd_register_syscall(SYS_FTRUNCATE, oxfs_ftruncate);
        oxidebsd_register_syscall(SYS_FALLOCATE, oxfs_fallocate);
        oxidebsd_register_syscall(SYS_FLOCK, oxfs_flock);
        oxidebsd_register_syscall(SYS_STATFS, oxfs_statfs);
        oxidebsd_register_syscall(SYS_FSTATFS, oxfs_fstatfs);
    }

    if ok { 0 } else { -1 }
}
