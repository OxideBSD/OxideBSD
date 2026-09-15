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
//! (`BLOCKS`/`BLOCK_USED`), and a flat table of `MAX_INODES` inodes (`INODES`). An inode addresses
//! its data via `DIRECT_BLOCKS` direct block numbers, one single-indirect block, and one
//! double-indirect block (see `Inode::double_indirect`'s own doc comment) -- `MAX_FILE_SIZE` (~4.1
//! GiB) is a real architectural ceiling on any *one* file, distinct from the real pool's own total
//! free space (a much smaller, honest `ENOSPC` limit shared across every file combined).
//!
//! **Directories are ordinary inodes** whose data blocks hold fixed `DIR_RECORD_SIZE`-byte records
//! (`{ used: u8, name_len: u8, inode: u32, name: [u8; NAME_MAX] }`, `NAME_MAX = 40`,
//! `DIR_RECORD_SIZE = 6 + NAME_MAX = 46` -- raised from `26`/`32` once the full Open POSIX Test
//! Suite corpus (see `build.rs`'s `discover_posix_test_files`) needed real directory names up to
//! 32 bytes, e.g. `pthread_mutexattr_setprioceiling` -- found live as a real `module_init` panic,
//! `dir_insert`'s own `InvalidPath` rejection) -- `RECORDS_PER_BLOCK = BLOCK_SIZE / 46 = 89`
//! entries per block. A directory that fills its
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
    /// Same as `oxidebsd_register_fd_ops`, plus a `content_id` callback — see
    /// `crate::fs::fd::FdContentId`'s own doc comment (kernel tree) for why this exists: real
    /// fd-backed `MAP_SHARED` mmap (`crate::process::mm::do_mmap`) needs a live "what real inode
    /// does this fd resolve to right now" query, keyed by nothing this module already exposes
    /// generically. Only used for oxfs's own real file-backed `OpenFile` variants below
    /// (`register_open_file` calls this instead of the plain `oxidebsd_register_fd_ops`
    /// unconditionally — `oxfs_content_id` itself returns `-1` for every non-file variant).
    fn oxidebsd_register_fd_ops_with_content_id(
        fd: u64,
        read: extern "C" fn(u64, u64, u64) -> i64,
        write: extern "C" fn(u64, u64, u64) -> i64,
        close: extern "C" fn(u64) -> i64,
        content_id: extern "C" fn(u64) -> i64,
    ) -> i32;
    /// See `crate::fs::fd::ContentRead`/`ContentWrite`/`ContentSize`'s own doc comment (kernel
    /// tree) for why real fd-backed `MAP_SHARED` mmap needs this instead of the plain per-fd
    /// read/write callbacks. Called once, from this module's own `module_init`.
    fn oxidebsd_register_content_accessors(
        read: extern "C" fn(u64, u64, u64, u64) -> i64,
        write: extern "C" fn(u64, u64, u64) -> i64,
        size: extern "C" fn(u64) -> i64,
    );
    fn oxidebsd_close_fd(fd: u64) -> i32;
    /// Sets (`on != 0`) or clears real `FD_CLOEXEC` on `fd`, in the *current* process's own table
    /// -- see `crate::fs::fd::oxidebsd_set_fd_cloexec`'s own doc comment (kernel tree). `oxfs_open`
    /// is the one caller here, right after a successful real `O_CLOEXEC` open.
    fn oxidebsd_set_fd_cloexec(fd: u64, on: u64) -> i64;
    /// Overrides `fd`'s real `pread`/`pwrite` callbacks -- see
    /// `crate::fs::fd::oxidebsd_set_fd_pread_pwrite`'s own doc comment (kernel tree).
    /// `register_open_file` is the one caller here, right after every fresh fd's ordinary
    /// `read`/`write`/`close`/`content_id` registration.
    fn oxidebsd_set_fd_pread_pwrite(
        fd: u64,
        pread: extern "C" fn(u64, u64, u64, u64) -> i64,
        pwrite: extern "C" fn(u64, u64, u64, u64) -> i64,
    );
    /// Overrides `fd`'s real `access_mode` callback -- see
    /// `crate::fs::fd::oxidebsd_set_fd_access_mode`/`FdAccessMode`'s own doc comment (kernel tree).
    /// `register_open_file` is the one caller here, right alongside `oxidebsd_set_fd_pread_pwrite`.
    fn oxidebsd_set_fd_access_mode(fd: u64, access_mode: extern "C" fn(u64) -> i64);
    /// Overrides `fd`'s real `is_append` callback -- see
    /// `crate::fs::fd::oxidebsd_set_fd_append`/`FdIsAppend`'s own doc comment (kernel tree).
    /// `register_open_file` is the one caller here, right alongside `oxidebsd_set_fd_access_mode`.
    fn oxidebsd_set_fd_append(fd: u64, is_append: extern "C" fn(u64) -> i64);
    /// Overrides `fd`'s real `fb_geometry` callback -- see
    /// `crate::fs::fd::oxidebsd_set_fd_fb_geometry`/`FdFbGeometry`'s own doc comment (kernel tree).
    /// `register_open_file` is the one caller, unconditionally for every fd (the callback itself
    /// discriminates by `OpenFile` variant, same precedent `oxfs_access_mode`/`oxfs_content_id`
    /// already establish).
    fn oxidebsd_set_fd_fb_geometry(fd: u64, fb_geometry: extern "C" fn(u64, u64) -> i32);
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
    /// Real framebuffer geometry -- see `src/drivers/fbdev.rs`'s own doc comment (kernel tree).
    /// Writes a `RawFbGeometry` (this module's own local copy of that file's `FbGeometry` --
    /// modules can't depend on kernel-crate types directly, so this is duplicated, not shared;
    /// see this codebase's own "audit duplicated wire structs on kernel-side change" precedent)
    /// through `out`, returning `0` on success or `-1` if no usable (32bpp) framebuffer exists
    /// this boot. `known_device`'s `(29, 0)` arm is the one caller.
    fn oxidebsd_fb_geometry(out: u64) -> i32;
    fn oxidebsd_current_uid() -> u64;
    fn oxidebsd_current_gid() -> u64;
    fn oxidebsd_current_umask() -> u64;
    /// Real Unix epoch seconds, whole-second precision -- see `src/cpu/rtc.rs`'s own doc comment
    /// on `oxidebsd_unix_time`. Backs real `st_mtime`/`st_ctime` (`write_inode_data`/
    /// `resize_inode_data`).
    fn oxidebsd_unix_time() -> i64;
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
/// Real Linux's own `__NR_fchdir` value, used directly -- see `oxfs_fchdir`'s own doc comment.
const SYS_FCHDIR: u64 = 81;
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
/// `OxideBSD-doc/BUSYBOX_APPLETS.md`'s own note on `lsmod`), matching the musl-side patch's own explanation
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
/// Real, unremapped Linux `__NR_fdatasync=75` (confirmed unclaimed -- this ABI's own invented
/// numbers start at 100, and `third_party/musl/src/unistd/fdatasync.c` issues this exact number
/// directly, no OxideBSD-side remap needed, matching `SYS_PREAD`/`SYS_PWRITE`'s own precedent).
/// Registered straight at `oxfs_fsync` -- this filesystem's commit-only-at-close write model makes
/// no distinction between syncing data and syncing metadata (both happen atomically in the same
/// `commit_write_buffer` call), so `fdatasync(2)`'s real, POSIX-permitted "may skip metadata"
/// relaxation collapses to exactly `fsync(2)`'s own behavior here -- honest, not a stub.
const SYS_FDATASYNC: u64 = 75;
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
/// Real generic `open(2)` `O_RDWR` value -- see `OpenFile::Write`'s own `readwrite`/`position`
/// fields for what this actually unlocks (real bidirectional read/write/seek through one fd,
/// found missing live via the Open POSIX Test Suite's `aio_read`/`aio_write`/`lio_listio` pilot).
const O_RDWR: u64 = 0o2;
/// Real generic `open(2)` `O_EXCL` value -- combined with `O_CREAT`, real POSIX requires
/// `open()` to fail `EEXIST` when the target name already exists (regardless of what it resolves
/// to -- a symlink, a directory, an existing regular file all count), rather than transparently
/// opening it. Found live via `shm_open/22-1.c` (Open POSIX Test Suite pilot): `oxfs_open` used to
/// ignore this bit entirely and just open the pre-existing object.
const O_EXCL: u64 = 0o200;
/// Real generic `open(2)` `O_TRUNC` value -- see `oxfs_open`'s own `want_write` branch for where
/// this is consulted. Found live via `shm_open/25-1.c`: a reopen of an already-existing object
/// with `O_TRUNC` must make the truncation to zero length visible to an immediate `fstat()` on the
/// same fd, not merely defer it to whatever this filesystem's own write-buffer eventually commits
/// at `close()` (which never fires here at all, since the test never calls `write()`).
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
/// Real generic `open(2)` `O_CLOEXEC` value -- distinct from `fcntl(2)`'s own `FD_CLOEXEC` value
/// (`src/syscall/ffi.rs`'s `sys_fcntl` consults that one instead). Found live via `shm_open/
/// 11-1.c` (the Open POSIX Test Suite pilot): real `shm_open()` (`third_party/musl/src/mman/
/// shm_open.c`) always passes this to `open()` directly, not through a separate `fcntl()` call --
/// `oxfs_open`'s own tail (see below) is what actually marks the returned fd.
const O_CLOEXEC: u64 = 0o2000000;

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
/// Real value, no Linux/BSD divergence -- returned when a real, whole path argument exceeds
/// `OXFS_PATH_MAX` (see that constant's own doc comment). Distinct from `NAME_MAX`'s own
/// per-component `InvalidPath`/`EINVAL` check in `resolve_parent` below -- real POSIX uses
/// `ENAMETOOLONG` specifically for *this* case.
const ENAMETOOLONG: i64 = 36;
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
/// Raised again, 8192 -> 16384, once the Open POSIX Test Suite pilot (see CLAUDE.md's "POSIX
/// conformance pilot" sections and `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`) grew from its original
/// 68-file curated subset to several hundred files, adding real content on the order of the
/// existing BusyBox applet roster's own footprint -- the ~14 MiB of headroom left at 8192 blocks
/// (32 MiB total, minus BusyBox's own ~18 MiB) wasn't enough. 16384 blocks (64 MiB) leaves real
/// headroom again, not just enough to exactly fit.
///
/// **Raised again, 65536 -> 262144 (256 MiB -> 1 GiB), alongside the real per-file addressing fix**
/// (`Inode::double_indirect`, see that field's own doc comment): a per-file cap of ~4 MiB was the
/// binding constraint before, so the real pool's own size never mattered much past "bigger than
/// the seeded content." Once a single file can address up to ~4.1 GiB, the pool itself becomes the
/// real, honest ceiling on how big any file can actually get -- 1 GiB gives genuinely useful
/// headroom for that without exhausting this project's own hard `MODULE_REGION_CEILING` VA budget
/// (`src/module.rs`; ~1.5 GiB total, shared by *every* kernel module -- this module is already by
/// far the largest consumer of it, and the only one with any large static pools at all). A real 4
/// GiB file is structurally impossible regardless of this number: the whole pool is a fixed
/// `static mut` array baked directly into this module's own image, eagerly mapped as real physical
/// RAM the instant it loads (see this constant's own opening paragraph) -- it can never itself
/// reach anywhere near 4 GiB without either blowing the VA budget outright or costing more real
/// RAM than this kernel has ever assumed a single module would need. A file's real achievable size
/// is bounded by whatever of this pool is actually still free (an honest `ENOSPC` once it isn't),
/// exactly like any real filesystem whose maximum file size (a property of its own addressing
/// scheme) can exceed its disk's real free space.
///
/// **Found live alongside this bump, a real pre-existing bug**: `persist_bitmap_if_ready`/
/// `mount_from_disk`/`flush_all_to_disk` packed the *entire* block-used bitmap into a single
/// `BLOCK_SIZE`-byte buffer (`i / 8` indexing it directly) -- correct only while `NUM_BLOCKS` fits
/// in `BLOCK_SIZE * 8` bits (32768). This constant had already silently exceeded that bound at
/// 65536 blocks before this pass (a real, guaranteed out-of-bounds panic -- fatal to this module,
/// see `module::CURRENT_MODULE_FATAL` -- the moment any real write happened against a real,
/// persisted disk past boot), just never hit because this pass is what actually exercises real
/// disk persistence hard enough to surface it. Fixed by spreading the bitmap across
/// `BITMAP_BLOCKS` real blocks instead of a hardcoded one -- see that constant's own doc comment.
const NUM_BLOCKS: usize = 262144;
/// Raised from 64 alongside `NUM_BLOCKS` above, same reason -- ~300 applets plus root/`hello.txt`/
/// `big.txt`/the self-check's own `/gdtest` fixtures need comfortably more than 64 inode slots.
/// Raised again, 512 -> 1024, once TinyCC (`third_party/tinycc`, see CLAUDE.md's TinyCC section)
/// needed musl's entire real header tree seeded under `/usr/include` at runtime -- measured
/// exactly against the real built `target/musl-sysroot`, not estimated: 217 header files (plus
/// ~7 subdirectories) + ~9 `/usr/lib` crt/lib files + tcc's own `libtcc1.a` + 5 bundled headers +
/// the `tcc` binary itself is ~250 new inodes, overflowing the ~180 that were free at 512.
/// Raised again, 1024 -> 2048, alongside `NUM_BLOCKS` above -- the expanded POSIX pilot corpus
/// adds several hundred new files plus one subdirectory per interface under `/posix-tests/bin/`.
/// Raised again, 2048 -> 8192 (`NUM_BLOCKS` 16384 -> 65536 alongside it), once the pilot expanded
/// from a 488-file curated dedup to the full ~1700-file Open POSIX Test Suite corpus (see
/// `build.rs`'s `discover_posix_test_files`) -- both this constant and `build.rs`'s own mirrored
/// `OXFS_MAX_INODES`/`OXFS_NUM_BLOCKS` must be bumped together, or `mount_from_disk`'s own
/// layout-version check (see "Real disk persistence" in CLAUDE.md) forces a reformat instead of a
/// mount against any disk image already written with the old layout.
const MAX_INODES: usize = 8192;
const DIRECT_BLOCKS: usize = 12;
const PTRS_PER_INDIRECT: usize = BLOCK_SIZE / 4;
/// A double-indirect block's own fan-out: `PTRS_PER_INDIRECT` pointers to *index* blocks, each in
/// turn holding `PTRS_PER_INDIRECT` pointers to real data blocks -- `1024 * 1024 = 1,048,576` data
/// blocks reachable through one double-indirect pointer, i.e. exactly `1024^2 * BLOCK_SIZE` = 4
/// GiB. See `Inode::double_indirect`'s own doc comment for why this (and not a bigger, triple-
/// indirect scheme) is the right amount of addressing to add.
const PTRS_PER_DOUBLE_INDIRECT: usize = PTRS_PER_INDIRECT * PTRS_PER_INDIRECT;
/// Real per-file addressing ceiling once `Inode::double_indirect` is in play: `DIRECT_BLOCKS` +
/// one single-indirect block's worth + one double-indirect block's worth of data blocks, all
/// `BLOCK_SIZE` bytes each -- `(12 + 1024 + 1048576) * 4096` = 4,299,198,464 bytes, ~4.1 GiB.
/// Informational only (nothing indexes by it directly; `inode_block_at`/`inode_ensure_block_at`
/// derive the same three tiers from `DIRECT_BLOCKS`/`PTRS_PER_INDIRECT`/`PTRS_PER_DOUBLE_INDIRECT`
/// directly) -- kept as a single named place this file's own doc comments can point at.
#[allow(dead_code)]
const MAX_FILE_SIZE: usize =
    (DIRECT_BLOCKS + PTRS_PER_INDIRECT + PTRS_PER_DOUBLE_INDIRECT) * BLOCK_SIZE;
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
// INODE_TABLE_START + INODE_TABLE_BLOCKS)` is the packed inode table, `[BITMAP_START,
// BITMAP_START + BITMAP_BLOCKS)` is the block-used bitmap, and real data starts at
// `DATA_BLOCK_OFFSET` -- this module's own in-memory block number `i` maps to physical disk block
// `DATA_BLOCK_OFFSET + i`. Sizing (as of `SUPERBLOCK_VERSION = 2`): `MAX_INODES` inodes at a fixed
// 128-byte stride (real packed content is 106 bytes -- 1 tag + 8 size + 48 direct + 4 indirect + 4
// double_indirect + 2 mode + 4 uid + 4 gid + 2 nlink + 4 rdev + 1 device_char + 8 mtime + 8 ctime +
// 8 atime -- rounded up to a power-of-two stride that divides BLOCK_SIZE evenly, leaving headroom
// for future fields); `BITMAP_BLOCKS` bitmap blocks, one bit per real block (`NUM_BLOCKS`, no
// longer assumed to fit a single block -- see that constant's own doc comment for the real bug
// this fixed). `INODE_TABLE_BLOCKS`/`BITMAP_BLOCKS`/`DATA_BLOCK_OFFSET` are all real, derived
// consts, not hand-computed numbers -- see each one's own definition below.

/// Marks a real, formatted oxfs disk. Absence/mismatch (an unformatted/all-zero disk, or one some
/// other filesystem wrote) means the same thing either way: format fresh rather than try to
/// interpret unknown content -- see `mount_from_disk`.
const SUPERBLOCK_MAGIC: [u8; 4] = *b"OXFS";
/// Bumped 1 -> 2 for the real max-file-size redesign: `Inode`'s own packed on-disk shape changed
/// (`size` widened to 64-bit, a new `double_indirect` block pointer added -- see that field's own
/// doc comment), and the block-used bitmap's own on-disk span changed (`BITMAP_BLOCKS`, no longer
/// hardcoded to one block). A disk formatted under version 1 has the wrong bytes at every offset
/// this build now expects -- `mount_from_disk`'s own layout check (below) already treats any
/// mismatch here exactly like a `NUM_BLOCKS`/`MAX_INODES` change: a clean, automatic reformat, not
/// a crash or silent misread. Any content on an existing `target/oxfs_disk.img` besides the
/// seeded-at-boot roster (BusyBox/musl/TinyCC/POSIX corpus, all reseeded fresh on format) is lost.
const SUPERBLOCK_VERSION: u32 = 2;

const INODE_TABLE_START: u32 = 1;
/// Real packed size (see the section doc comment above) -- **never** a raw transmute/memcpy of
/// `Inode` itself, since it isn't `#[repr(C)]` and `InodeKind` has no explicit discriminant, so its
/// true in-memory layout isn't guaranteed across compiler versions/profiles. `pack_inode`/
/// `unpack_inode` do this by hand instead, the same raw-byte-offset idiom `write_dir_record`/
/// `dir_record_inode` already established for directory records.
const INODE_STRIDE: usize = 128;
const INODES_PER_BLOCK: usize = BLOCK_SIZE / INODE_STRIDE;
const INODE_TABLE_BLOCKS: u32 = ((MAX_INODES * INODE_STRIDE + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32;
/// How many physical blocks the block-used bitmap spans -- one bit per real (non-tmpfs) block,
/// `BLOCK_SIZE * 8` bits per physical block. **Must be a real, computed span, not a hardcoded
/// single block** -- see `NUM_BLOCKS`'s own doc comment for the real, previously-live bug this
/// fixes (a `NUM_BLOCKS` past `BLOCK_SIZE * 8` = 32768 already silently exceeded a single block's
/// worth of bits before this pass).
const BITMAP_BLOCKS: u32 = ((NUM_BLOCKS + BLOCK_SIZE * 8 - 1) / (BLOCK_SIZE * 8)) as u32;
const BITMAP_START: u32 = INODE_TABLE_START + INODE_TABLE_BLOCKS;
const DATA_BLOCK_OFFSET: u32 = BITMAP_START + BITMAP_BLOCKS;

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

// 26 -> 40 (`DIR_RECORD_SIZE` 32 -> 46 alongside it, `6 + NAME_MAX`): the full Open POSIX Test
// Suite corpus (see `build.rs`'s `discover_posix_test_files`) seeds real directory names up to 32
// bytes (`pthread_mutexattr_setprioceiling`/`pthread_mutexattr_getprioceiling`) -- found live as a
// real `module_init` panic when the pilot corpus expanded past the old 488-file curated subset
// (which happened to never include a name that long).
const NAME_MAX: usize = 40;
const DIR_RECORD_SIZE: usize = 6 + NAME_MAX;
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

/// **Bumped 8 -> 256 -> 2048 (2026-09-05)**. First bumped 8->256 chasing a pilot-run cascade: this
/// table is *global*, not per-process, and this kernel has no orphan-reaping mechanism (see
/// `do_wait4`'s own doc comment) -- a process whose real parent already exited (or that itself
/// gets stuck) leaves any fd it opened here permanently leaked. The POSIX pilot's own `shm_open/
/// 23-1.c` (up to 1000 processes x 1000 loop iterations, each a real `shm_open(..., O_CREAT|
/// O_EXCL, ...)` that never closes the fd until its own process exits) drove this straight to
/// exhaustion at just 8 slots -- and because the table is global, that exhaustion didn't just fail
/// `shm_open/23-1.c` itself, it made `hush` (pid 1) unable to open *its own* redirect file for
/// every single test that ran afterward, silently misclassifying hundreds of unrelated,
/// individually-correct tests as FAIL for the rest of the boot. At the time, each slot cost a full
/// `MAX_WRITE_BUFFER` regardless of use (`OpenFile::Write` was the enum's dominant variant), so 256
/// was chosen as "enough headroom to stop the cascade, cheap enough to afford" -- not enough to
/// let `shm_open/23-1.c` itself actually pass (it needs up to 1000 real objects live at once, one
/// per `shm_open`'d name, held open until each holding process's own loop finishes).
///
/// **Bumped again to 2048 once the real fix landed**: `OpenFile::Write`'s buffer moved out of the
/// enum entirely into its own separate, smaller `WRITE_BUFFERS` pool (see that pool's own doc
/// comment) -- a slot's cost is no longer `MAX_WRITE_BUFFER` regardless of use, just the enum's new
/// largest variant (`DirListing`/`ProcDir`'s `DIR_LISTING_BUFFER`, ~4 KiB). 2048 slots now costs
/// **less** total memory than the old 256 did (~8 MiB vs. ~32 MiB) while giving `shm_open/23-1.c`
/// real headroom past its own 1000-object peak.
const MAX_OPEN_FILES: usize = 2048;
/// Write-side flush-window size (see `OpenFile::Write`'s own doc comment). Raised 128 KiB -> 16
/// MiB alongside the real max-file-size redesign: this used to be a hard *whole-file* cap (every
/// `close()` replaced a file's complete content with exactly this buffer, see `commit_write_buffer`'s
/// pre-redesign doc comment) -- now it's just how much a `write()` loop can accumulate before this
/// module flushes it into the real inode's own block chain and keeps accepting more, so a real
/// file built via ordinary sequential `write()` calls is no longer capped at this number at all
/// (only by `MAX_FILE_SIZE`/the real pool's own free space). 16 MiB is chosen directly to satisfy
/// that flush-window requirement, not tuned against any specific real workload the way the old 128
/// KiB figure was.
const MAX_WRITE_BUFFER: usize = 16 * 1024 * 1024;
/// How many `WRITE_BUFFERS` slots exist -- **not** the same as `MAX_OPEN_FILES` any more (see that
/// constant's own doc comment for the split this enables). Lowered 256 -> 16 alongside
/// `MAX_WRITE_BUFFER`'s own 128x bump (128 KiB -> 16 MiB): holding the total pool cost
/// (`MAX_WRITE_BUFFERS * MAX_WRITE_BUFFER`) roughly flat, rather than multiplying it out to 4 GiB,
/// is required, not just frugal -- this pool, like `BLOCKS`, is a real, always-resident static
/// array inside this module's own image, sharing the same hard ~1.5 GiB `MODULE_REGION_CEILING`
/// VA budget every other kernel module draws from too (see `NUM_BLOCKS`'s own doc comment for the
/// same constraint on the block pool). 16 slots * 16 MiB = 256 MiB, comfortably inside what's left
/// after `NUM_BLOCKS`'s own 1 GiB bump, and still real headroom past the concurrent-*writer* count
/// (as opposed to total open-fd count, see this constant's own prior note) this kernel has ever
/// actually needed -- most concurrently-open fds across this whole codebase's own test corpus
/// never call `write()` at all (plain reads, directory listings, and any `O_CREAT`-but-never-
/// written object like `shm_open/23-1.c`'s own 1000 objects, real POSIX
/// `shm_open(O_RDONLY|O_CREAT, ...)` use).
const MAX_WRITE_BUFFERS: usize = 16;
const DIR_LISTING_BUFFER: usize = 4096;

const MAX_CWD_PATH: usize = 256;
const MAX_CWD_DEPTH: usize = 32;

/// Real POSIX `{PATH_MAX}` (musl's own compiled value, `third_party/musl/include/limits.h`) --
/// the real whole-path-length limit, real `ENAMETOOLONG` when exceeded. Distinct from `NAME_MAX`'s
/// own per-*component* check in `resolve_parent` below (`InvalidPath`/`EINVAL`) -- this is real
/// POSIX text for the *whole* path, not any one component of it. Bigger than `MAX_CWD_PATH` (256,
/// a real but much smaller internal buffer for formatting *this filesystem's own* absolute cwd
/// string) -- the two serve unrelated purposes and were never meant to be the same number.
///
/// **Does not close `shm_open/39-2.c`/`shm_unlink/10-2.c`** (Open POSIX Test Suite pilot), the two
/// tests that originally flagged this gap -- investigated, not a kernel bug: both construct a name
/// with *embedded* `/` characters to build a genuinely `PATH_MAX`-length string, but real, upstream
/// musl's own `__shm_mapname()` (`third_party/musl/src/mman/shm_open.c`) rejects any embedded `/`
/// as `EINVAL` *before* ever checking length -- real POSIX explicitly leaves embedded-slash
/// handling in a `shm_open()` name implementation-defined, so this is legitimate, spec-legal musl
/// behavior, not a bug to patch around. This check is still real and correct for what it actually
/// covers: an ordinary, non-shm path (a plain `open()`/`unlink()`/`mkdir()`/... on a genuinely
/// too-long path with no embedded weirdness) now gets the real `ENAMETOOLONG` POSIX requires,
/// where it previously fell through to whatever `resolve_parent`'s own component walk happened to
/// produce instead.
const OXFS_PATH_MAX: usize = 4096;

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
    /// Real content length in bytes. Widened `u32` -> `u64` alongside `double_indirect` below --
    /// `MAX_FILE_SIZE` (~4.1 GiB) exceeds `u32::MAX` by design (a 4 GiB file wouldn't otherwise be
    /// representable at all), so this has to grow with the addressing scheme it now needs to
    /// describe.
    size: u64,
    direct: [u32; DIRECT_BLOCKS],
    indirect: u32,
    /// Real double-indirect block pointer, added alongside `size`'s widening to close this
    /// filesystem's real max-file-size gap: `direct` + `indirect` alone address only
    /// `(DIRECT_BLOCKS + PTRS_PER_INDIRECT) * BLOCK_SIZE` ~= 4.04 MiB per file -- an arbitrary,
    /// far-too-low architectural cap unrelated to how much of the real block pool is actually
    /// free. One double-indirect pointer (an index block of `PTRS_PER_INDIRECT` pointers, each to
    /// its own index block of `PTRS_PER_INDIRECT` pointers to real data blocks) adds exactly
    /// `PTRS_PER_INDIRECT^2 * BLOCK_SIZE` = 4 GiB of further addressable space -- chosen
    /// specifically because `1024^2` (`PTRS_PER_INDIRECT` squared) lands on exactly 4 GiB with
    /// this filesystem's existing `BLOCK_SIZE`/4-byte-pointer shape, satisfying "at least 4 GiB"
    /// with one added tier rather than needing a third, triple-indirect one. See
    /// `inode_block_at`/`inode_ensure_block_at` for how the three tiers (direct, single-, double-
    /// indirect) are actually walked/allocated, and `MAX_FILE_SIZE`'s own doc comment for the real,
    /// combined total. `NO_BLOCK` until a file's own content actually reaches past the single-
    /// indirect tier -- the overwhelming majority of real files here never allocate this at all.
    double_indirect: u32,
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
    /// Real, whole-second Unix epoch `st_mtime`/`st_ctime` (`oxidebsd_unix_time`, see that
    /// import's own doc comment) -- previously both hardcoded `0` in `write_stat` (no clock/RTC
    /// source existed at the time). `write_inode_data`/`resize_inode_data` are this filesystem's
    /// only two real content-mutation choke points (every write -- a plain `write()`'s deferred
    /// commit, `fsync`/`close`, and a real fd-backed `MAP_SHARED` mapping's own `msync`/`munmap`/
    /// exit writeback via `oxfs_inode_content_write` -- ultimately goes through one of them), so
    /// bumping both there covers every real write path uniformly, mmap included (`mmap/14-1.c` in
    /// the POSIX conformance pilot). Real POSIX ties `st_mtime`/`st_ctime` to slightly different
    /// events (`st_ctime` also updates on a pure metadata change like `chmod`/`chown`, with no
    /// content write at all) -- not implemented here, a separate, narrower gap than what this field
    /// closes: nothing in this port's roster checks `st_ctime` after a metadata-only change.
    mtime: i64,
    ctime: i64,
    /// Real, whole-second Unix epoch `st_atime` -- previously a permanent `0` placeholder (see this
    /// field's own prior doc comment, now stale: "no test or real caller in this port needs it").
    /// `mmap/13-1.c` (Open POSIX Test Suite) is a genuine, real POSIX "shall" requirement this
    /// kernel was actually violating: "The initial read or write reference to a mapped region shall
    /// cause the file's st_atime field to be marked for update if it has not already been marked
    /// for update" (the same clause also explicitly permits marking it "at any time between the
    /// mmap() call and the corresponding munmap() call" -- this kernel doesn't do real demand
    /// paging for file-backed mmap (every covered page is eagerly populated at `mmap()` time, see
    /// `process::mm::do_mmap_file_backed`), so bumping atime at that one real population read,
    /// rather than tracking each page's own first-touch, is a spec-legal choice, not a shortcut).
    /// Bumped by `touch_atime` from two real read paths: `oxfs_read`'s own `OpenFile::FileRead` arm
    /// (a plain `read()`) and `oxfs_inode_content_read` (the `mmap` population/re-population read
    /// `process::mm::do_mmap_file_backed` calls by content identity, see that accessor's own doc
    /// comment) -- both real "read reference" events, not just this one pilot test's own narrow
    /// need. `touch_atime` skips the write-through if the whole-second value hasn't changed since
    /// the last touch (a real, common Unix optimization, not a fake pass condition -- POSIX only
    /// requires atime be "marked for update," not persisted with per-read precision).
    atime: i64,
}

impl Inode {
    const FREE: Inode = Inode {
        kind: InodeKind::Free,
        size: 0,
        direct: [NO_BLOCK; DIRECT_BLOCKS],
        indirect: NO_BLOCK,
        double_indirect: NO_BLOCK,
        mode: FIXED_PERM as u16,
        uid: 0,
        gid: 0,
        nlink: 0,
        rdev: 0,
        device_char: false,
        mtime: 0,
        ctime: 0,
        atime: 0,
    };

    fn new(kind: InodeKind) -> Inode {
        let now = unsafe { oxidebsd_unix_time() };
        Inode {
            kind,
            size: 0,
            direct: [NO_BLOCK; DIRECT_BLOCKS],
            indirect: NO_BLOCK,
            double_indirect: NO_BLOCK,
            mode: FIXED_PERM as u16,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            device_char: false,
            mtime: now,
            ctime: now,
            atime: now,
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

/// Real per-open-file write-accumulation buffers, pooled separately from `OPEN_FILES` itself --
/// see `MAX_WRITE_BUFFERS`'s own doc comment for why this split exists. `OpenFile::Write::buf_slot`
/// is `None` until the first real `write()` call (or, for `O_APPEND`, until `open()`'s own
/// preload -- see that call site) actually needs somewhere to put bytes; a fd that's opened but
/// never written to (a plain read, or a real POSIX `shm_open(O_RDONLY|O_CREAT, ...)`) never
/// touches this pool at all.
static mut WRITE_BUFFERS: [[u8; MAX_WRITE_BUFFER]; MAX_WRITE_BUFFERS] =
    [[0; MAX_WRITE_BUFFER]; MAX_WRITE_BUFFERS];
static mut WRITE_BUFFER_USED: [bool; MAX_WRITE_BUFFERS] = [false; MAX_WRITE_BUFFERS];

/// Claims a free `WRITE_BUFFERS` slot, `None` if the pool is exhausted (a real, if unlikely,
/// resource limit -- surfaces to a caller as `ENOSPC`, same errno `oxfs_write` already returns for
/// "this fd's own buffer is full").
fn alloc_write_buffer() -> Option<usize> {
    let used = unsafe { &mut *core::ptr::addr_of_mut!(WRITE_BUFFER_USED) };
    let idx = used.iter().position(|&u| !u)?;
    used[idx] = true;
    Some(idx)
}

/// Releases a `WRITE_BUFFERS` slot back to the pool -- called once, from `oxfs_close`, once a
/// fd's own final commit (if any) has already consumed its content. Doesn't zero the slot's old
/// content -- matches this module's existing "unlink/close never scrubs stale data" convention
/// (`BLOCKS`/`INODES` don't either); a later `alloc_write_buffer` caller always overwrites
/// `buffer[..len]` from its own fresh `len = 0` before ever reading any of it back.
fn free_write_buffer(idx: usize) {
    let used = unsafe { &mut *core::ptr::addr_of_mut!(WRITE_BUFFER_USED) };
    used[idx] = false;
}

/// Real, `'static` access to one `WRITE_BUFFERS` slot's full backing array -- callers slice it to
/// whatever length they actually need (`oxfs_write` writes into it; `commit_write_buffer` reads
/// `[..len]` back out).
fn write_buffer(idx: usize) -> &'static mut [u8; MAX_WRITE_BUFFER] {
    let bufs = unsafe { &mut *core::ptr::addr_of_mut!(WRITE_BUFFERS) };
    &mut bufs[idx]
}

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
    persist_bitmap_if_ready(n);
}

fn read_inode(n: u32) -> Inode {
    unsafe { (*core::ptr::addr_of!(INODES))[n as usize] }
}

fn write_inode(n: u32, inode: Inode) {
    unsafe { (*core::ptr::addr_of_mut!(INODES))[n as usize] = inode };
    persist_inode_block_if_ready(n);
}

/// Resume-scan cursor for `alloc_block` -- see that function's own doc comment for why a bare
/// linear-from-`0` scan (this module's original design) stopped being viable once `NUM_BLOCKS`
/// grew large enough for real big-file writes to actually matter.
static mut NEXT_FREE_BLOCK: u32 = 0;

/// Finds and claims the first free real (non-tmpfs) block, starting from `NEXT_FREE_BLOCK` rather
/// than always rescanning from `0` -- this module's blocks are **never freed** in normal operation
/// (`unlink`/`rmdir` only clear a directory record's `used` byte, matching this module's own
/// blanket "no deallocation anywhere" stance; the one exception, `reset_real_pool_for_fresh_format`,
/// resets this cursor back to `0` in the same pass, see that function's own doc comment) -- so once
/// this cursor passes a block, no future call can ever need to look at it again, making this a real
/// bump allocator in practice (the loop below only ever iterates more than once during whatever
/// startup seeding leaves a stale cursor behind, e.g. right after `mount_from_disk` loads a bitmap
/// with a real prefix already marked used). A bare rescan-from-`0` scan (this function's original
/// design, "fine at this module's scale" when `NUM_BLOCKS` was in the low thousands) becomes a real
/// `O(n^2)` cost filling the whole pool once `NUM_BLOCKS` is large enough for a genuinely big real
/// file to matter -- the same class of bug `memory::BootInfoFrameAllocator`'s own doc comment
/// already warns about for the physical frame allocator, fixed here the same way: cursor state, not
/// a rebuilt-each-call scan.
fn alloc_block() -> Option<u32> {
    let start = unsafe { *core::ptr::addr_of!(NEXT_FREE_BLOCK) };
    for i in start..NUM_BLOCKS as u32 {
        if !block_used(i) {
            set_block_used(i, true);
            write_block(i, &[0u8; BLOCK_SIZE]);
            unsafe { *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK) = i + 1 };
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

/// Reads a real block-number pointer out of index block `ib_num` at slot `slot` -- the same
/// 4-byte-little-endian-pointer decoding `inode_block_at`/`inode_ensure_block_at` need at every
/// indirection tier (a single-indirect block's own slots, and both levels of a double-indirect
/// block's own two-level slot chain), factored out once there were three call sites instead of one.
fn read_index_ptr(ib_num: u32, slot: usize) -> u32 {
    let ib = read_block(ib_num);
    let off = slot * 4;
    u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]])
}

/// Reads the block number backing `inode`'s logical block `index` -- direct, then (past
/// `DIRECT_BLOCKS`) via the single-indirect block, then (past that) via the double-indirect block
/// (see `Inode::double_indirect`'s own doc comment for the three-tier addressing scheme this
/// implements) -- or `None` if that block was never allocated.
fn inode_block_at(inode: &Inode, index: usize) -> Option<u32> {
    if index < DIRECT_BLOCKS {
        let b = inode.direct[index];
        return (b != NO_BLOCK).then_some(b);
    }
    let index = index - DIRECT_BLOCKS;
    if index < PTRS_PER_INDIRECT {
        if inode.indirect == NO_BLOCK {
            return None;
        }
        let b = read_index_ptr(inode.indirect, index);
        return (b != NO_BLOCK).then_some(b);
    }
    let index = index - PTRS_PER_INDIRECT;
    if inode.double_indirect == NO_BLOCK || index >= PTRS_PER_DOUBLE_INDIRECT {
        return None;
    }
    let outer_slot = index / PTRS_PER_INDIRECT;
    let inner_slot = index % PTRS_PER_INDIRECT;
    let inner_block = read_index_ptr(inode.double_indirect, outer_slot);
    if inner_block == NO_BLOCK {
        return None;
    }
    let b = read_index_ptr(inner_block, inner_slot);
    (b != NO_BLOCK).then_some(b)
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
    } else if index - DIRECT_BLOCKS < PTRS_PER_INDIRECT {
        let indirect_index = index - DIRECT_BLOCKS;
        if inode.indirect == NO_BLOCK {
            inode.indirect = if tmpfs {
                alloc_tmpfs_indirect_block()?
            } else {
                alloc_indirect_block()?
            };
        }
        ensure_index_slot(inode.indirect, indirect_index, tmpfs)
    } else {
        // Double-indirect tier -- see `Inode::double_indirect`'s own doc comment. `outer_slot`
        // picks (allocating if needed) the one inner index block covering `inner_slot`'s own
        // range, then `ensure_index_slot` does the same real-block allocation `inode_ensure_block_
        // at`'s single-indirect branch above already does, just one level deeper.
        let index = index - DIRECT_BLOCKS - PTRS_PER_INDIRECT;
        if index >= PTRS_PER_DOUBLE_INDIRECT {
            return None;
        }
        let outer_slot = index / PTRS_PER_INDIRECT;
        let inner_slot = index % PTRS_PER_INDIRECT;
        if inode.double_indirect == NO_BLOCK {
            inode.double_indirect = if tmpfs {
                alloc_tmpfs_indirect_block()?
            } else {
                alloc_indirect_block()?
            };
        }
        let mut outer = read_block(inode.double_indirect);
        let outer_off = outer_slot * 4;
        let mut inner_block = u32::from_le_bytes(
            outer[outer_off..outer_off + 4].try_into().unwrap(),
        );
        if inner_block == NO_BLOCK {
            inner_block = if tmpfs {
                alloc_tmpfs_indirect_block()?
            } else {
                alloc_indirect_block()?
            };
            outer[outer_off..outer_off + 4].copy_from_slice(&inner_block.to_le_bytes());
            write_block(inode.double_indirect, &outer);
        }
        ensure_index_slot(inner_block, inner_slot, tmpfs)
    };
    write_inode(inode_num, inode);
    result
}

/// Shared by `inode_ensure_block_at`'s single-indirect branch and its double-indirect branch's own
/// inner tier: reads index block `ib_num`'s pointer at `slot`, allocating (from the real or tmpfs
/// pool, per `tmpfs`) and writing back a fresh real data-block pointer if that slot is still
/// `NO_BLOCK`.
fn ensure_index_slot(ib_num: u32, slot: usize, tmpfs: bool) -> Option<u32> {
    let mut ib = read_block(ib_num);
    let off = slot * 4;
    let existing = u32::from_le_bytes(ib[off..off + 4].try_into().unwrap());
    if existing != NO_BLOCK {
        return Some(existing);
    }
    let nb = if tmpfs {
        alloc_tmpfs_block()?
    } else {
        alloc_block()?
    };
    ib[off..off + 4].copy_from_slice(&nb.to_le_bytes());
    write_block(ib_num, &ib);
    Some(nb)
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

/// Writes `content` as `inode_num`'s complete contents (replacing whatever was there before),
/// allocating whatever blocks are needed and setting `size`. **No longer `OpenFile::Write`'s own
/// commit primitive** (that path now flushes positionally/additively via `write_inode_at`, see
/// `commit_write_buffer`'s own doc comment) -- this whole-content-replace shape is still exactly
/// right for its one remaining real caller, `oxfs_inode_content_write` (real fd-backed `MAP_SHARED`
/// mmap writeback, which always supplies a mapping's complete current content).
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
    inode.size = content.len() as u64;
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
    write_inode(inode_num, inode);
    true
}

/// Real `st_atime` update -- see `Inode::atime`'s own doc comment for the POSIX text this
/// implements and why bumping it here (rather than tracking each mmap'd page's own first-touch)
/// is spec-legal. Skips the write-through entirely if the whole-second value hasn't changed since
/// the last touch -- a real, common Unix optimization (POSIX only requires atime be "marked for
/// update," not persisted with per-read precision), not a fake pass condition; keeps a tight read
/// loop from re-persisting the same inode-table block on every single call.
fn touch_atime(inode_num: u32) {
    let mut inode = read_inode(inode_num);
    let now = unsafe { oxidebsd_unix_time() };
    if inode.atime == now {
        return;
    }
    inode.atime = now;
    write_inode(inode_num, inode);
}

/// `SYS_FTRUNCATE`/`SYS_FALLOCATE`'s real logic -- resizes `inode_num`'s content to exactly
/// `new_size` bytes without ever materializing the file's complete old-or-new content in one
/// buffer the way `write_inode_data` does: growing zero-fills only the newly-added region,
/// block by block, via the same `inode_ensure_block_at`/`write_block` primitives
/// `write_inode_data` itself uses internally; shrinking touches no block content at all (bytes
/// past the new `size` simply become unreachable -- `read_inode_at` already never reads past
/// `inode.size`, and a later grow back past the old size would zero-fill over them again, matching
/// real POSIX "grow into a hole reads as zero" semantics either way). Load-bearing for staying
/// off the stack: this filesystem's real per-file addressing ceiling is `MAX_FILE_SIZE` (~4.1
/// GiB, see `Inode::double_indirect`'s own doc comment), far past what this kernel's 128 KiB
/// kernel-stack floor could ever hold as one local buffer.
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
    inode.size = new_size as u64;
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
    write_inode(inode_num, inode);
    true
}

/// Real `pwrite(2)`'s own logic: writes `data` directly into `inode_num`'s real blocks starting at
/// `position`, without ever materializing the file's complete old-or-new content in one buffer --
/// same block-by-block approach `resize_inode_data` already uses, extended to write real content
/// instead of zeros. A gap between the file's current real size and `position` (real POSIX: writing
/// past EOF creates a hole that reads back as zero) is zero-filled first via `resize_inode_data`
/// itself, reusing its own already-correct real "grow into a hole" logic rather than duplicating
/// it. Load-bearing for the same reason `resize_inode_data` is: this filesystem's real per-file
/// addressing ceiling is `MAX_FILE_SIZE` (~4.1 GiB), far past what a 128 KiB kernel stack could
/// hold as one local buffer -- and, unlike `OpenFile::Write`'s own `WRITE_BUFFERS` pool (a bounded
/// `MAX_WRITE_BUFFER`-sized flush window, not a whole-file cap any more -- see that constant's own
/// doc comment), this has no buffer-size ceiling at all short of the filesystem's own real
/// addressing/pool limits. See
/// `oxfs_pwrite`'s own doc comment for the real caller (`SYS_PWRITE`, found live via the Open POSIX
/// Test Suite's `aio_write`/`lio_listio` pilot -- `lio_listio/1-1.c` alone needs a real 1 MiB
/// `pwrite()`, far past what the pooled buffer could ever hold).
fn write_inode_at(inode_num: u32, position: usize, data: &[u8]) -> bool {
    let old_size = read_inode(inode_num).size as usize;
    if position > old_size && !resize_inode_data(inode_num, position) {
        return false;
    }
    let mut pos = position;
    let mut written = 0;
    while written < data.len() {
        let block_index = pos / BLOCK_SIZE;
        let in_block_off = pos % BLOCK_SIZE;
        let Some(blk) = inode_ensure_block_at(inode_num, block_index) else {
            return false;
        };
        let mut block = read_block(blk);
        let chunk = (data.len() - written).min(BLOCK_SIZE - in_block_off);
        block[in_block_off..in_block_off + chunk]
            .copy_from_slice(&data[written..written + chunk]);
        write_block(blk, &block);
        pos += chunk;
        written += chunk;
    }
    let mut inode = read_inode(inode_num);
    if pos > inode.size as usize {
        inode.size = pos as u64;
    }
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
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
/// fields (see `Inode`'s own doc comment) -- `st_atime`/`st_mtime`/`st_ctime` are real too (see
/// `Inode::atime`/`Inode::mtime`'s own doc comments), whole-second precision only (`*_nsec` fields
/// stay `0`). `st_dev` is `1` for the one real, persisted
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
/// either. `st_ino`/`st_size`/`st_blocks`/`st_atime`/`st_mtime`/`st_ctime` are the only other
/// fields backed by something real (see `Inode::atime`/`Inode::mtime`'s own doc comments).
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
        st_atime_sec: inode.atime,
        st_atime_nsec: 0,
        st_mtime_sec: inode.mtime,
        st_mtime_nsec: 0,
        st_ctime_sec: inode.ctime,
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
        // No real inode backs a /dev/fb0 fd either -- same reasoning as the /proc/dev arms above.
        OpenFile::Framebuffer { .. } => None,
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
    /// A real, whole path argument exceeded `OXFS_PATH_MAX` -- see that constant's own doc comment.
    NameTooLong,
}

fn errno_for(e: OxfsError) -> i64 {
    -match e {
        OxfsError::NotFound => ENOENT,
        OxfsError::NotADirectory => ENOTDIR,
        OxfsError::InvalidPath => EINVAL,
        OxfsError::DiskFull => ENOSPC,
        OxfsError::TooManyLinks => ELOOP,
        OxfsError::NameTooLong => ENAMETOOLONG,
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
    // Real POSIX `ENAMETOOLONG` -- see `OXFS_PATH_MAX`'s own doc comment. Only checked for the
    // real, outermost caller-supplied path (`depth == 0`) -- a symlink target's own recursive
    // resolution (`depth > 0`) is already bounded well under this by `MAX_CWD_PATH` (256) at the
    // read site just below, so re-checking there would be redundant, not more correct.
    if depth == 0 && path.len() > OXFS_PATH_MAX {
        return Err(OxfsError::NameTooLong);
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
        // See `force_commit_pending_create`'s own doc comment -- previously wired into `oxfs_open`
        // only, so a same-process `open(O_CREAT)` (still open, not yet closed/fsynced/ftruncated)
        // stayed genuinely invisible to any *other* syscall walking a path through this exact
        // resolver -- `stat`/`lstat`/`unlink`/`chdir`/... Found live via `mmap/13-1.c` (Open POSIX
        // Test Suite pilot): `open(O_CREAT) -> write() -> stat()` on the same still-open fd, no
        // close in between, real `ENOENT`'d the `stat()` even though the file plainly "exists" by
        // any real Unix's standard. Harmless to call for every component, not just the last: a
        // pending create can only ever be a leaf (an intermediate component must already be a
        // real, committed directory or this walk already fails `NotADirectory`/`NotFound`
        // regardless), and the `(parent, name)` match this scans for is exact either way.
        force_commit_pending_create(current, component);
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
    // Real POSIX `ENAMETOOLONG` -- see `OXFS_PATH_MAX`'s own doc comment. Checked against the
    // real, whole, original path (not the leaf-trimmed `head` computed below): `resolve_path`'s
    // own recursive call further down only ever sees the *parent* prefix, which could be under
    // this limit even when the full path (parent + leaf) isn't.
    if path.len() > OXFS_PATH_MAX {
        return Err(OxfsError::NameTooLong);
    }
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

/// An open file's own state, keyed by fd in `OPEN_FILES`. `DirListing`/`ProcDir`'s own
/// `DIR_LISTING_BUFFER` (4 KiB) is the largest embedded buffer here now that `Write`'s own
/// (formerly `OPEN_FILES`-dominating, `MAX_WRITE_BUFFER` = 128 KiB) content buffer lives in the
/// separate `WRITE_BUFFERS` pool instead (`buf_slot`, an index, not the content itself) -- see
/// that pool's own doc comment for why: modules can't use `alloc`/`Box`, so every `OPEN_FILES`
/// slot still has to be sized for its own worst case, but decoupling the one genuinely huge,
/// rarely-simultaneously-needed buffer from the fixed per-slot cost lets `MAX_OPEN_FILES` scale far
/// higher without a matching memory cost (see `MAX_OPEN_FILES`'s own doc comment for the concrete
/// before/after numbers).
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
    /// A file opened for writing. **Real streaming write-back, not a whole-file staging buffer**:
    /// `write()` accumulates into `WRITE_BUFFERS[buf_slot]` up to `MAX_WRITE_BUFFER` (a flush
    /// *window*, not a file-size cap any more), at which point (or at `close()`/`fsync()`/any
    /// forced early commit) `commit_write_buffer` appends whatever's buffered onto the real inode
    /// at `write_pos` and keeps going -- so a real file built via an ordinary sequential `write()`
    /// loop is bounded only by `MAX_FILE_SIZE`/the real pool's own free space, never by this
    /// buffer's own size. Replaces the old "buffer holds the file's *entire* content, replaced
    /// wholesale at `close()`" model (still `modules/fat32`'s own design), which is what capped a
    /// written-from-scratch file at `MAX_WRITE_BUFFER` no matter how it was written.
    Write {
        parent_inode: u32,
        name: [u8; NAME_MAX],
        name_len: u8,
        /// Index into the separate `WRITE_BUFFERS` pool holding this fd's *currently unflushed*
        /// content -- `None` until something actually needs to buffer real bytes (see
        /// `WRITE_BUFFERS`'s own doc comment for why this is pooled separately from `OpenFile`
        /// rather than embedded inline). Real invariant: `len == 0` whenever this is `None`. Once
        /// `commit_write_buffer` flushes `buffer[..len]` onto the real inode, `len` resets to `0`
        /// (the slot itself stays claimed until `close()` -- see `free_write_buffer`'s own call
        /// site) and more bytes can accumulate from there; the slot is never required to hold a
        /// whole file's content at once any more.
        buf_slot: Option<usize>,
        len: usize,
        /// Absolute file offset the *next* flush will write `buffer[..len]` at -- advances by
        /// `len` every time `commit_write_buffer` actually flushes something. Set once at `open()`
        /// time: `0` for a brand-new file or a plain overwrite (real POSIX: a write-mode open
        /// without `O_APPEND` starts at file position `0`, regardless of the file's own prior
        /// size), or the file's real current size for `O_APPEND` (so buffered writes land after
        /// existing content without ever having to copy that content through this buffer at all --
        /// see this field's own history: the old design *preloaded* `O_APPEND`'s existing bytes
        /// into the buffer itself, silently losing everything past the buffer's own then-128-KiB
        /// capacity for any append target bigger than that, since the old whole-file-replace
        /// commit only ever wrote back whatever fit).
        write_pos: u64,
        /// The caller's own uid at `open(O_CREAT)` time -- real Unix ownership semantics (a
        /// freshly created file is owned by its creator, not always root) -- captured here rather
        /// than re-queried at `close` time since a real program can `open` in one process and
        /// (via a shared fd, e.g. across `fork`) close in another. Unused (but still populated,
        /// for a fresh file) when `existing_inode` is `Some` -- overwriting/appending to a file
        /// that already exists never changes its owner, matching real POSIX `open()`/`write()`.
        owner_uid: u32,
        /// `None`: no inode exists yet for `name` -- the first real flush (a full buffer during
        /// `write()`, or `close()`/`fsync()`/any forced early commit) allocates a fresh one and
        /// inserts it (the original, only-ever-create behavior this filesystem had before real
        /// O_TRUNC/O_APPEND/O_WRONLY support on an *existing* path existed). `Some(inode)`: `name`
        /// already resolves to `inode` -- flushes write directly into that same inode's real
        /// blocks via `write_inode_at` (positional, additive -- see `write_pos`'s own doc comment),
        /// never allocating a second inode or re-inserting the directory entry.
        existing_inode: Option<u32>,
        /// Set by `oxfs_unlink` when it's called against `(parent_inode, name)` before this fd's
        /// first commit -- i.e. while `existing_inode` is still `None`, so there's no directory
        /// entry yet for `unlink` to actually remove. Found live via `mmap/12-1.c` (the POSIX
        /// conformance pilot): real `open(O_CREAT|O_EXCL) -> unlink() -> ftruncate() -> mmap() ->
        /// close()` unlinks the file *before* anything ever committed it, so `oxfs_unlink`'s normal
        /// `dir_lookup` found nothing and returned `ENOENT` -- then `ftruncate()`'s own forced early
        /// commit (`resolve_write_fd_inode`) went ahead and inserted a directory entry anyway,
        /// silently resurrecting a name real POSIX says must stay gone. `commit_write_buffer`
        /// checks this flag and skips the `dir_insert` call when set, while still allocating a real
        /// inode and writing real content to it -- matches real Unix: an unlinked-but-still-open
        /// file keeps working through this fd/any mapping of it, it just can never be found by path
        /// again.
        unlinked: bool,
        /// The caller's own real requested access mode at `open()` time (`true` for `O_RDONLY`,
        /// i.e. `flags & O_ACCMODE == 0`) -- **not** whether this variant is internally
        /// `Write`-shaped, which is unconditional for a brand-new `O_CREAT` file regardless of the
        /// caller's actual intent (a real inode still has to exist for the deferred-commit design
        /// to work, see `existing_inode`'s own doc comment). `oxfs_write`/`oxfs_ftruncate`/
        /// `oxfs_fallocate` all check this and refuse (`EBADF`/`EINVAL`) when set -- found live via
        /// `shm_open/13-1.c` (the Open POSIX Test Suite pilot): `shm_open(O_RDONLY|O_CREAT, ...)`
        /// on a brand-new object used to silently accept a later `ftruncate()`, since nothing
        /// re-checked the caller's original access mode once past `open()`'s own create-path
        /// (which never gated on it at all, unlike the existing-path branch's own `want_write`
        /// check).
        readonly: bool,
        /// Real `O_RDWR` (as opposed to `O_WRONLY`) at `open()` time -- unlocks real `read()`/
        /// `lseek()`/`pread()`/`pwrite()` support directly against this same fd's own pending (or
        /// already-committed, via `resolve_write_fd_inode`'s forced early commit) content, on top
        /// of the ordinary write-then-commit-at-close path every `Write` fd already has -- see
        /// `oxfs_read`/`oxfs_lseek`/`oxfs_pread`/`oxfs_pwrite`'s own doc comments. `false` (the
        /// existing, unchanged behavior: `read()`/`lseek()` are `EBADF`/`ESPIPE`) for a plain
        /// `O_WRONLY` fd -- found missing live via the Open POSIX Test Suite's `aio_read`/
        /// `aio_write`/`lio_listio` pilot, all three of which `open(O_CREAT|O_RDWR)` then read back
        /// through the very same fd they just wrote.
        readwrite: bool,
        /// Real `read()`/`lseek()` cursor -- meaningful only when `readwrite` is `true` (an
        /// ordinary `O_WRONLY` fd has no real seekable position at all, see `readonly`'s sibling
        /// `readwrite` field above). Distinct from `len` (this fd's own pending-write-buffer
        /// extent, still used exactly as before for the write side) since a real caller can
        /// `lseek()` this back to an earlier position without discarding what's already been
        /// written.
        position: usize,
        /// The real requested creation mode (`open(O_CREAT, mode)`'s own `mode` argument, masked
        /// to `0o777`) -- only meaningful when `existing_inode` is still `None` at `commit_write_
        /// buffer` time (a brand-new inode is being allocated, and this is what its own `mode`
        /// field gets initialized to); ignored when overwriting/appending to an already-existing
        /// inode, which keeps whatever real mode it already has. See `oxfs_open`'s own `mode`
        /// parameter doc comment for why this exists at all.
        mode: u16,
        /// Real `O_APPEND` at `open()` time -- reported back to userspace via `oxfs_is_append`/
        /// `oxidebsd_set_fd_append` (`src/fs/fd.rs`)'s `F_GETFL` support, distinct from
        /// `write_pos`'s own one-time-at-open use of this same bit (that field only ever needed
        /// the *initial* write offset, not this open file description's actual `O_APPEND` status
        /// for later querying). Found live via the Open POSIX Test Suite's `aio_write/2-1.c`: real,
        /// unmodified musl's own AIO implementation calls `fcntl(fd, F_GETFL) & O_APPEND` once per
        /// fd to decide whether queued writes must serialize behind each other -- `F_GETFL` used to
        /// never report this bit at all, so every `O_APPEND`-opened aio fd looked non-appending,
        /// letting three concurrent `aio_write()`s skip ordering *and* all target the same `pwrite`
        /// offset `0` (an all-zero `memset`'d `aiocb`), each overwriting the last.
        append: bool,
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
    /// A real `/dev/fb0` fd -- see `known_device`'s `(29, 0)` arm and `src/drivers/fbdev.rs`'s own
    /// module doc comment (kernel tree). Real pixel I/O happens only through `mmap()` (see
    /// `process::mm::do_mmap_fb`, kernel tree) -- `read`/`write`/`lseek` on this fd are all
    /// real, honest failures (`EBADF`/`ESPIPE`), matching real Linux's own `/dev/fb0` (which does
    /// support `write()`, but no target in this port's roster needs that path, so it's left
    /// unimplemented rather than half-modeled).
    Framebuffer {
        phys_base: u64,
        len: u64,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
    },
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
    // SAFETY: oxfs_read/oxfs_write/oxfs_close/oxfs_content_id are this module's own functions,
    // already relocated by the time module_init (which makes this function reachable) runs.
    // Always the `_with_content_id` variant, not just for `FileRead`/`Write` -- `oxfs_content_id`
    // itself already returns `-1` for every other variant, so there's no need to discriminate here.
    unsafe {
        oxidebsd_register_fd_ops_with_content_id(
            fd,
            oxfs_read,
            oxfs_write,
            oxfs_close,
            oxfs_content_id,
        );
        // Always registered, unconditionally -- same "the callback itself discriminates by
        // variant" reasoning `oxfs_content_id` above already established. See `oxfs_pread`/
        // `oxfs_pwrite`'s own doc comments for what each real variant actually supports.
        oxidebsd_set_fd_pread_pwrite(fd, oxfs_pread, oxfs_pwrite);
        oxidebsd_set_fd_access_mode(fd, oxfs_access_mode);
        oxidebsd_set_fd_append(fd, oxfs_is_append);
        oxidebsd_set_fd_fb_geometry(fd, oxfs_fb_geometry);
    };
    fd as i64
}

/// `access_mode` callback for `oxidebsd_set_fd_access_mode` -- see
/// `crate::fs::fd::FdAccessMode`'s own doc comment (kernel tree) for the return-bits shape. Only
/// `FileRead`/`Write` are ever real here (every other variant never reaches `do_mmap_file_backed`'s
/// check at all -- `oxfs_content_id` already returns `-1` for them, so this is never even called
/// against one, but the fallback is a harmless readable+writable default anyway):
/// `FileRead` only ever exists for a real `O_RDONLY` open of an existing file (see `oxfs_open`'s own
/// `want_write` branch) -- always readable, never writable. `Write` covers `O_WRONLY`/`O_RDWR`, and
/// (via the create-path branch) a plain `O_RDONLY|O_CREAT` too -- `readonly` (real `O_RDONLY`) and
/// `readwrite` (real `O_RDWR`) together already capture all three real access modes exactly:
/// `readonly` or `readwrite` true means readable; anything but `readonly` means writable.
extern "C" fn oxfs_access_mode(real_fd: u64) -> i64 {
    match find_open_file(real_fd) {
        Some(OpenFile::FileRead { .. }) => 0b01,
        Some(OpenFile::Write {
            readonly,
            readwrite,
            ..
        }) => {
            let mut bits = 0;
            if *readonly || *readwrite {
                bits |= 0b01;
            }
            if !*readonly {
                bits |= 0b10;
            }
            bits
        }
        _ => 0b11,
    }
}

/// `is_append` callback for `oxidebsd_set_fd_append` -- see `crate::fs::fd::FdIsAppend`'s own doc
/// comment (kernel tree) for the real bug this closes. `1` only for a `Write` fd actually opened
/// with `O_APPEND`; every other `OpenFile` variant (including a `Write` fd without it) reports `0`,
/// matching `oxfs_content_id`/`oxfs_access_mode`'s own "discriminates by variant, harmless default
/// for everything else" shape.
extern "C" fn oxfs_is_append(real_fd: u64) -> i64 {
    match find_open_file(real_fd) {
        Some(OpenFile::Write { append: true, .. }) => 1,
        _ => 0,
    }
}

/// `fb_geometry` callback for `oxidebsd_set_fd_fb_geometry` -- see that import's own doc comment.
/// `-1` for every `OpenFile` variant except `Framebuffer`, matching `oxfs_content_id`'s own
/// "discriminates by variant, harmless default for everything else" shape.
extern "C" fn oxfs_fb_geometry(real_fd: u64, out: u64) -> i32 {
    match find_open_file(real_fd) {
        Some(OpenFile::Framebuffer {
            phys_base,
            len,
            width,
            height,
            pitch,
            bpp,
        }) => {
            let geom = RawFbGeometry {
                phys_base: *phys_base,
                len: *len,
                width: *width,
                height: *height,
                pitch: *pitch,
                bpp: *bpp,
            };
            // SAFETY: same known pointer-validation gap every other module-boundary write in this
            // file already has -- `out` is always a kernel-owned stack buffer in practice (see
            // `fs::fd::framebuffer_geometry_of`, the only caller, kernel tree), never a raw
            // userland pointer.
            unsafe { *(out as *mut RawFbGeometry) = geom };
            0
        }
        _ => -1,
    }
}

/// `content_id` callback for `oxidebsd_register_fd_ops_with_content_id` — see that import's own
/// doc comment. Reuses `resolve_write_fd_inode` (the same helper `oxfs_ftruncate`/`oxfs_fstat`
/// already call) rather than only recognizing an *already*-committed inode -- found live:
/// `mmap/1-1.c` (the POSIX conformance pilot) calls `open(O_CREAT|O_RDWR|O_EXCL) -> write() ->
/// mmap()` with no intervening `ftruncate()`/`fstat()`, so a real caller's fd genuinely can still
/// be an uncommitted `Write { existing_inode: None, .. }` at `mmap()` time -- an earlier version
/// of this function returned `-1` for exactly that case, making every such `mmap()` fail outright
/// (`ENODEV`) rather than forcing the same early commit `ftruncate`/`fstat` already do on demand.
/// `-1` only for a fd `resolve_write_fd_inode` genuinely can't identify at all: any synthetic
/// variant (`DirListing`/`ProcRead`/`ProcDir`/`DevRandom`/`DevNull`/`DevZero`), or a commit that
/// itself failed (e.g. `ENOSPC`).
///
/// **Known, accepted quirk**: forcing early commit here calls the same `dir_insert` a real
/// `close()` would -- if the caller already `unlink()`d this exact path *before* ever committing
/// (nothing stops a real program from `open() -> unlink() -> write() -> mmap()`, and this pilot's
/// own `mmap/1-1.c`/`mmap/12-1.c` do exactly that), the name reappears in its parent directory,
/// where real POSIX would have kept it permanently anonymous (data preserved, but never
/// re-findable by path) once unlinked. Not fixed here: doing so needs oxfs's own pending-`Write`
/// state to track "this target name was already unlinked," a distinct, non-trivial gap in this
/// filesystem's write-commit model, not something real fd-backed mmap content resolution can or
/// should paper over. No test in this pilot's own manifest checks for the resurrected name itself
/// except `mmap/12-1.c`, which fails on exactly this pre-existing behavior regardless of mmap.
extern "C" fn oxfs_content_id(real_fd: u64) -> i64 {
    match resolve_write_fd_inode(real_fd) {
        Some(inode) => inode as i64,
        None => -1,
    }
}

/// `read` accessor for `oxidebsd_register_content_accessors` — reads directly from `inode`'s real,
/// committed block content via `read_inode_at`, bypassing any fd's own `OpenFile` state entirely.
/// See `crate::fs::fd::ContentRead`'s own doc comment (kernel tree) for why this exists instead of
/// reusing `oxfs_read`. Also the one real touch point for `mmap/13-1.c`'s own POSIX requirement
/// (see `Inode::atime`'s own doc comment): `process::mm::do_mmap_file_backed` calls this to
/// populate a real fd-backed mapping's covered pages, at `mmap()` call time -- a genuine "read
/// reference," and the spec text explicitly permits marking atime "at any time between the
/// mmap() call and the corresponding munmap() call," not just on each individual page's own first
/// touch (which this kernel's eager, non-demand-paged population has no way to distinguish anyway).
extern "C" fn oxfs_inode_content_read(inode: u64, offset: u64, ptr: u64, len: u64) -> i64 {
    // SAFETY: same trust boundary as elsewhere -- caller (crate::process::mm, kernel-core) owns
    // this pointer/length, always a page-aligned kernel staging buffer in practice.
    let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    let n = read_inode_at(inode as u32, offset as usize, out);
    if n > 0 {
        touch_atime(inode as u32);
    }
    n as i64
}

/// `write` accessor for `oxidebsd_register_content_accessors` -- replaces `inode`'s complete real
/// content with exactly `len` bytes via `write_inode_data`, same one-shot whole-content write
/// primitive every other real write in this module ultimately goes through (see `OpenFile::Write`'s
/// own doc comment). Reachable from kernel core without going through any fd's own
/// `OpenFile::Write` buffer/close machinery, which real fd-backed mmap writeback can't use anyway
/// -- see `crate::process::mm::do_mmap_file_backed`'s own doc comment.
extern "C" fn oxfs_inode_content_write(inode: u64, ptr: u64, len: u64) -> i64 {
    // SAFETY: same trust boundary as above.
    let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    if write_inode_data(inode as u32, data) {
        len as i64
    } else {
        -EIO
    }
}

/// `size` accessor for `oxidebsd_register_content_accessors` -- `inode`'s real current content
/// length in bytes.
extern "C" fn oxfs_inode_content_size(inode: u64) -> i64 {
    read_inode(inode as u32).size as i64
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
                    out.push_decimal_u64(child_inode.size);
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
        // Real Linux's own standard fbdev major:minor (29, 0) -- cosmetic here (no general
        // device-driver framework backs this number choice), but matches a real `mknod /dev/fb0 c
        // 29 0`. Queries the real, current framebuffer geometry at *open* time, not once at boot
        // -- harmless to re-query every open since Limine's response never changes across a boot.
        (29, 0) => framebuffer_open_file(),
        _ => None,
    }
}

/// This module's own local copy of `src/drivers/fbdev.rs`'s `FbGeometry` (kernel tree) -- modules
/// can't depend on kernel-crate types directly, only on the plain `u64`/`i32` FFI boundary, so the
/// wire layout is duplicated rather than shared. Any future change to the kernel-side struct needs
/// the identical change mirrored here (same "audit duplicated wire structs" precedent this
/// codebase already follows for userland smoke-test crates that hand-duplicate kernel structs).
#[repr(C)]
#[derive(Clone, Copy)]
struct RawFbGeometry {
    phys_base: u64,
    len: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
}

/// `known_device`'s `(29, 0)` arm -- `None` if no usable (32bpp) framebuffer exists this boot,
/// matching real Linux's own `-ENXIO` for a device number with no bound driver (the `known_device`
/// caller already turns a `None` here into exactly that).
fn framebuffer_open_file() -> Option<OpenFile> {
    let mut geom = RawFbGeometry {
        phys_base: 0,
        len: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bpp: 0,
    };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let ok = unsafe { oxidebsd_fb_geometry(&mut geom as *mut RawFbGeometry as u64) };
    if ok != 0 {
        return None;
    }
    Some(OpenFile::Framebuffer {
        phys_base: geom.phys_base,
        len: geom.len,
        width: geom.width,
        height: geom.height,
        pitch: geom.pitch,
        bpp: geom.bpp,
    })
}

/// Closes a real visibility gap in this filesystem's own deferred-commit `open(O_CREAT)` design
/// (see `OpenFile::Write::existing_inode`'s own doc comment): a still-open fd from an earlier
/// `open(O_CREAT)` against `(parent, name)` doesn't get a real inode/directory entry until
/// something forces an early commit (`fsync`/`ftruncate`/`close`/`resolve_write_fd_inode`'s own
/// fd-based fstat special-case) -- so a *second*, independent `open()` call against the exact same
/// path, in the same process, with no such intervening call on the first fd, used to see nothing
/// at all via `dir_lookup` (real `ENOENT`, or a silent second create). Real POSIX/Unix `open(2)`
/// has no such gap: the directory entry exists the instant the first `open(O_CREAT)` call returns.
/// Found live via `shm_open/22-1.c` (a same-process `open(O_CREAT) -> open(O_CREAT|O_EXCL)` pair
/// must see `EEXIST` on the second call) and `shm_open/32-1.c`/`34-1.c` (a same-process
/// `open(O_CREAT, mode) -> open()` pair, no `O_CREAT` on the second call, must find the first
/// call's own real, already-applied `mode` for a permission check to have anything real to deny
/// against). Scans the small, fixed `OPEN_FILES` table (`MAX_OPEN_FILES = 8`, cheap to walk) for
/// any other fd still mid-create against this exact `(parent, name)` and force-commits it right
/// now via the same `commit_write_buffer` every other early-commit call site already uses --
/// including `commit_write_buffer`'s own `unlinked` check, so a path that was `unlink()`d before
/// ever committing (see that field's own doc comment) still correctly ends up with no directory
/// entry inserted, matching real Unix "removed before ever named" semantics.
fn force_commit_pending_create(parent: u32, name: &[u8]) {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    for slot in slots.iter_mut().flatten() {
        // Checked via a plain immutable borrow first (dropped as soon as `matches!` finishes
        // evaluating) so the mutable reborrow just below is never in question -- simpler than
        // trying to thread one mutable borrow through both the match guard and the call.
        let is_match = matches!(
            &slot.1,
            OpenFile::Write {
                parent_inode,
                name: n,
                name_len,
                existing_inode: None,
                ..
            } if *parent_inode == parent && &n[..*name_len as usize] == name
        );
        if is_match {
            commit_write_buffer(&mut slot.1);
            return;
        }
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
/// it for an existing path. **Found live, a real bug, not a preemptive addition**: this ABI's own
/// `SYS_OPEN` used to carry no mode argument at all (`third_party/musl/src/fcntl/open.c`'s own old
/// comment: "this filesystem doesn't model permissions" -- stale the moment the real per-inode
/// `mode`/`uid`/`gid` permission model landed, see CLAUDE.md's own "Permission model" section, but
/// never revisited), so every `open(O_CREAT, mode)` silently got `FIXED_PERM` (`0o755`) regardless
/// of what the caller actually asked for -- `sem_open/3-1.c` (Open POSIX Test Suite pilot) expects
/// a semaphore created `0444` to make a later write-access re-open genuinely `EACCES`, which can
/// only happen if the requested `0444` really lands on the inode. Fixed by extending `open(2)`'s
/// own wire format to a real 4-arg `(path_ptr, path_len, flags, mode)` -- `third_party/musl/src/
/// fcntl/open.c` and `src/internal/syscall.h`'s own `__sys_open3`/`__sys_open_cp3` (the internal
/// stdio-callers' path, see that file's own doc comment for the argument-shape history) now pass
/// it through via `__syscall4`/`__syscall_cp4` instead of discarding it. **Real umask consultation**
/// (found live via `shm_open/18-1.c`, the Open POSIX Test Suite pilot -- a `shm_open()`'d object's
/// real permission bits must have the caller's own `umask` bits already cleared): the requested
/// `mode` is masked against `oxidebsd_current_umask()` (real, tracked-but-previously-unconsulted
/// `Process::umask` state, see CLAUDE.md's own umask section) before being stored on the fresh
/// inode, same real POSIX `mode & ~umask` rule every other Unix `open(O_CREAT)` applies.
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
    // Only the four magic device names are intercepted here -- anything else under `/dev/`
    // (`/dev/shm/...` for POSIX named shared memory/semaphores -- see `format_fresh_filesystem`'s
    // own `/dev/shm` seeding -- or a real `mknod`-created device node) falls through to ordinary
    // real path resolution below instead of an unconditional `ENOENT`, now that `/dev` is seeded
    // as a real directory rather than existing only as this prefix interception.
    if path.starts_with(b"/dev/") {
        let suffix = &path[5..];
        if matches!(suffix, b"random" | b"urandom" | b"null" | b"zero") {
            return dev_open(suffix);
        }
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

    // See `force_commit_pending_create`'s own doc comment: closes a real same-process visibility
    // gap where an earlier, still-uncommitted `open(O_CREAT)` against this exact path wouldn't be
    // seen by this call's own `dir_lookup` below.
    force_commit_pending_create(parent, leaf);

    let result = match dir_lookup(parent, leaf) {
        Some(inode_num) => {
            // Real `O_EXCL` (only meaningful combined with `O_CREAT`, per real POSIX): the target
            // already exists -- regardless of what it resolves to (symlink, directory, device,
            // ...) -- so `open()` must fail here rather than transparently opening it. Checked
            // before the mount-redirect/symlink-follow logic below, on the raw `dir_lookup` result,
            // matching real Unix's own "the name itself already exists" semantics. Found live via
            // `shm_open/22-1.c` (Open POSIX Test Suite pilot).
            if create && flags & O_EXCL != 0 {
                return -EEXIST;
            }
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
                    // O_APPEND: buffered writes flush after the file's real existing content --
                    // `write_pos` starts at the file's own real current size, with **no need to
                    // preload that content into the buffer at all** (real streaming flushes are
                    // positional/additive via `write_inode_at`, see `write_pos`'s own doc comment)
                    // -- fixes a real, previously-live bug: the old design preloaded existing
                    // content into the write buffer itself, silently losing everything past the
                    // buffer's own capacity (128 KiB at the time) for any append target bigger
                    // than that, since the old whole-file-replace commit only ever wrote back
                    // whatever fit.
                    //
                    // Plain O_WRONLY (no O_APPEND), or an explicit O_TRUNC regardless of access
                    // mode: this filesystem's own established, tested behavior (`module_init`'s
                    // self-check, "O_WRONLY overwrite did not truncate correctly") is that a plain
                    // O_WRONLY reopen of an existing file replaces its *entire* content with
                    // whatever gets written -- real POSIX would only overwrite the bytes actually
                    // touched, leaving any untouched tail alone, but a plain write-only fd can
                    // never observe that tail anyway (no real read-back path), and this matches
                    // `modules/fat32`'s own established precedent (see `write_inode_data`'s own
                    // doc comment). Resizes to `0` immediately, exactly like a real `O_TRUNC`
                    // (whether or not the caller actually passed one for the O_WRONLY case).
                    //
                    // Real O_RDWR *without* O_TRUNC is the one case that keeps existing content:
                    // a genuine read-modify-write fd needs to see what's already there via its own
                    // real `read()`/`pread()` support (see `readwrite`'s own doc comment) --
                    // buffered writes still flush positionally/additively from file offset `0`
                    // (this filesystem's only write primitive), so bytes never actually written
                    // keep their old content, matching real POSIX for this one case.
                    let write_pos = if flags & O_APPEND != 0 {
                        inode.size
                    } else if flags & O_ACCMODE != O_RDWR || flags & O_TRUNC != 0 {
                        resize_inode_data(resolved, 0);
                        0
                    } else {
                        0
                    };
                    register_open_file(OpenFile::Write {
                        parent_inode: parent,
                        name,
                        name_len: leaf.len() as u8,
                        buf_slot: None,
                        len: 0,
                        write_pos,
                        owner_uid: inode.uid,
                        existing_inode: Some(resolved),
                        unlinked: false,
                        readonly: false, // this whole arm only runs when want_write is true
                        readwrite: flags & O_ACCMODE == O_RDWR,
                        position: write_pos as usize,
                        // Unused: `commit_write_buffer`'s `existing_inode: Some(_)` branch never
                        // touches `inode.mode` -- overwriting/appending to a file that already
                        // exists never changes its own real, already-stored permission bits.
                        mode: inode.mode,
                        append: flags & O_APPEND != 0,
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
                buf_slot: None,
                len: 0,
                write_pos: 0,
                owner_uid: uid as u32,
                existing_inode: None,
                unlinked: false,
                // Real O_RDONLY is 0 -- "anything but that" in the low two bits means
                // O_WRONLY/O_RDWR, same real-access-mode convention the existing-path branch
                // above already uses via its own `want_write` -- this create-path branch never
                // gated on it before (see `readonly`'s own doc comment for the real bug this
                // closes).
                readonly: flags & O_ACCMODE == 0,
                readwrite: flags & O_ACCMODE == O_RDWR,
                position: 0,
                // Real requested creation mode -- see `oxfs_open`'s own `mode` parameter doc
                // comment for the wire-format history (this ABI's `open(2)` used to have no way
                // to carry `mode` at all, so every `O_CREAT` file silently got `FIXED_PERM`
                // regardless of what the caller actually asked for; found live via `sem_open/
                // 3-1.c`, the Open POSIX Test Suite pilot -- a semaphore created `0444` needs its
                // own restricted mode to actually take effect for a later `EACCES` to be possible
                // at all). Real `mode & ~umask` -- `Process::umask` (`oxidebsd_current_umask`) is
                // consulted here so a caller's own umask actually clears bits the way real
                // `open(O_CREAT)` always does; found live via `shm_open/18-1.c` (Open POSIX Test
                // Suite pilot), which sets a real, non-default umask and expects those exact bits
                // gone from the resulting object's permissions.
                mode: (mode as u16 & !(unsafe { oxidebsd_current_umask() } as u16)) & 0o777,
                append: flags & O_APPEND != 0,
            })
        }
        None => -ENOENT,
    };
    // Real O_CLOEXEC: musl's own shm_open() always passes this to open() directly (see
    // O_CLOEXEC's own doc comment) -- applied here, once, on the way out, rather than in every
    // branch above, since it's the same real fd-number regardless of which branch produced it.
    if result >= 0 && flags & O_CLOEXEC != 0 {
        unsafe { oxidebsd_set_fd_cloexec(result as u64, 1) };
    }
    result
}

extern "C" fn oxfs_read(fd: u64, ptr: u64, len: u64) -> i64 {
    // Real `O_RDWR` support: force an early real commit (if this fd hasn't already committed --
    // see `resolve_write_fd_inode`'s own doc comment) so this read sees whatever's been written so
    // far, then read from the real inode directly. A separate, sequential lookup rather than a
    // branch inside the match below: `resolve_write_fd_inode` does its own fresh `find_open_file`
    // call internally, which would alias the `&mut OpenFile` a single enclosing match already
    // holds (both ultimately borrow the same `static mut OPEN_FILES` slot).
    if matches!(find_open_file(fd), Some(OpenFile::Write { readwrite: true, .. })) {
        let Some(inode) = resolve_write_fd_inode(fd) else {
            return -EIO;
        };
        let Some(OpenFile::Write { position, .. }) = find_open_file(fd) else {
            return -EBADF;
        };
        // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
        let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
        let n = read_inode_at(inode, *position, out);
        *position += n;
        if n > 0 {
            touch_atime(inode);
        }
        return n as i64;
    }
    let Some(file) = find_open_file(fd) else {
        return -EBADF;
    };
    match file {
        OpenFile::FileRead { inode, position } => {
            // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
            let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
            let n = read_inode_at(*inode, *position, out);
            *position += n;
            // Real POSIX read(): a real data access, marked for st_atime update -- skipped for a
            // zero-byte read (at or past EOF), matching real Unix's own "no state change" behavior
            // for that case.
            if n > 0 {
                touch_atime(*inode);
            }
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
        // Real pixel I/O only ever happens through mmap() (process::mm::do_mmap_fb, kernel
        // tree) -- see OpenFile::Framebuffer's own doc comment.
        OpenFile::Framebuffer { .. } => -EBADF,
    }
}

/// Real streaming write: accumulates into the fd's own `WRITE_BUFFERS` window
/// (`MAX_WRITE_BUFFER` bytes), flushing to the real inode via `commit_write_buffer` whenever that
/// window fills up and continuing to accept more -- so a real file built via a sequential `write()`
/// loop is bounded only by `MAX_FILE_SIZE`/the real pool's own free space, never by the buffer's
/// own size (see `OpenFile::Write`'s own doc comment for the whole-file-replace model this
/// replaces). May flush more than once for one large `len`; each flush re-fetches `find_open_file`
/// immediately before/after rather than holding a field-level borrow across it, the same
/// aliasing-avoidance discipline `oxfs_read`'s own `readwrite` handling already establishes.
extern "C" fn oxfs_write(fd: u64, ptr: u64, len: u64) -> i64 {
    match find_open_file(fd) {
        Some(OpenFile::Write { readonly: true, .. }) => return -EBADF,
        Some(OpenFile::Write { .. }) => {}
        Some(OpenFile::DevRandom | OpenFile::DevNull | OpenFile::DevZero) => {
            // Matches real /dev/null's and /dev/zero's own write behavior (accept and discard);
            // real /dev/urandom also accepts writes (mixing them into the entropy pool) -- this
            // kernel has no such pool to mix into, so accept-and-discard is the honest
            // simplification here too.
            return len as i64;
        }
        _ => return -EBADF,
    }
    // Real POSIX zero-length write: succeeds trivially, no buffer needed -- checked before ever
    // touching `WRITE_BUFFERS` so a fd that only ever does zero-length writes never claims a slot.
    if len == 0 {
        return 0;
    }
    let requested = len as usize;
    let mut written = 0usize;
    while written < requested {
        let Some(file) = find_open_file(fd) else {
            break;
        };
        let full = matches!(
            file,
            OpenFile::Write { buf_slot: Some(_), len: l, .. } if *l >= MAX_WRITE_BUFFER
        );
        if full {
            if commit_write_buffer(file) != 0 {
                break;
            }
            continue;
        }
        let OpenFile::Write {
            buf_slot,
            len: buf_len,
            ..
        } = file
        else {
            break;
        };
        let idx = match *buf_slot {
            Some(idx) => idx,
            None => match alloc_write_buffer() {
                Some(idx) => {
                    *buf_slot = Some(idx);
                    idx
                }
                None => break,
            },
        };
        let available = MAX_WRITE_BUFFER - *buf_len;
        let n = available.min(requested - written);
        let buffer = write_buffer(idx);
        // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length, offset by what
        // this call has already consumed.
        let src = unsafe { core::slice::from_raw_parts((ptr as *const u8).add(written), n) };
        buffer[*buf_len..*buf_len + n].copy_from_slice(src);
        *buf_len += n;
        written += n;
    }
    if written > 0 {
        written as i64
    } else {
        -ENOSPC
    }
}

/// Shared by `oxfs_write` (once `buf_slot`'s window fills up), `oxfs_close` (which then discards
/// the slot entirely), and `oxfs_fsync`/`oxfs_sync`/`resolve_write_fd_inode`'s own forced-early-
/// commit call sites -- real streaming write-back, not a whole-file replace: flushes whatever's
/// currently buffered onto the real inode at `write_pos`, positionally and *additively*
/// (`write_inode_at`, the same primitive `pwrite(2)` uses) rather than replacing the file's
/// complete content the way this function used to (see `OpenFile::Write`'s own doc comment for why
/// that capped every written-from-scratch file at the buffer's own size). A no-op (`0`) for any
/// non-`Write` variant, or a `Write` fd with nothing currently buffered (`len == 0` -- covers a
/// never-written fd, and a fd whose buffer was already flushed and has nothing new since,
/// including the specific case `resized_directly` used to guard: a `SYS_FTRUNCATE`/`SYS_FALLOCATE`
/// resize with no `write()` since needs no flush at all to stay intact, since there's nothing
/// buffered to flush over it -- no separate flag needed under this design).
///
/// For a brand-new file (`existing_inode` still `None`), allocates the real inode and inserts its
/// directory entry *now*, then records that new inode back into `existing_inode` -- idempotent: a
/// second call on the same still-open fd (a `write()` then another `fsync()`, or `fsync()` then
/// `close()`) takes the `Some(inode_num)` branch instead of re-allocating and double-inserting.
/// This inode-allocation step happens even when there's nothing to flush yet (an empty-but-real
/// `open(O_CREAT)` forced to commit early by `SYS_FTRUNCATE`/`SYS_FSTAT`/mmap) -- only the actual
/// content flush below is skipped when the buffer is empty.
fn commit_write_buffer(file: &mut OpenFile) -> i64 {
    let OpenFile::Write {
        parent_inode,
        name,
        name_len,
        buf_slot,
        len,
        write_pos,
        owner_uid,
        existing_inode,
        unlinked,
        readonly: _,
        readwrite: _,
        position: _,
        mode,
        append: _,
    } = file
    else {
        return 0;
    };
    // Ensure a real inode exists for this fd, independent of whether there's anything to flush --
    // see this function's own doc comment.
    let inode_num = match *existing_inode {
        Some(inode_num) => inode_num,
        None => {
            // A new file created inside a tmpfs-mounted directory must itself come from the tmpfs
            // pool -- see `alloc_inode_in` below for why this is the one call site of the three
            // "create a new named entry" ones (mkdir/open-O_CREAT/symlink) that had a live bug
            // here (found via `tests/mount_syscall_smoke.rs`): the other two check `parent`/`cwd`
            // directly, but this one only learns `parent_inode` this late, at first-flush time.
            let Some(new_inode) = alloc_inode_in(*parent_inode) else {
                return -ENOSPC;
            };
            let mut inode = Inode::new(InodeKind::File);
            inode.uid = *owner_uid;
            inode.mode = *mode;
            write_inode(new_inode, inode);
            // Real Unix semantics: this fd's own name was already unlinked before it ever got the
            // chance to name anything (see `unlinked`'s own doc comment) -- a real inode still
            // gets allocated, so the fd (and any mmap of it) keeps working, but no directory entry
            // is ever inserted for it.
            if *unlinked {
                *existing_inode = Some(new_inode);
            } else if let Err(e) = dir_insert(*parent_inode, &name[..*name_len as usize], new_inode)
            {
                return errno_for(e);
            } else {
                *existing_inode = Some(new_inode);
            }
            new_inode
        }
    };
    // Flush whatever's currently buffered (if anything) -- `buf_slot: None` and `len == 0` are
    // both "nothing to flush" (the real invariant `len == 0` whenever `buf_slot` is `None` still
    // holds, see that field's own doc comment).
    let content: &[u8] = match *buf_slot {
        Some(idx) if *len > 0 => &write_buffer(idx)[..*len],
        _ => return 0,
    };
    if !write_inode_at(inode_num, *write_pos as usize, content) {
        return -EIO;
    }
    *write_pos += *len as u64;
    *len = 0;
    0
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
    let result = commit_write_buffer(&mut file);
    // Release this fd's own `WRITE_BUFFERS` slot back to the pool, if it ever claimed one --
    // safe only here (not in `commit_write_buffer` itself, also called by `fsync`/`sync` without
    // closing the fd): a still-open fd may see more `write()` calls after an `fsync()`, which need
    // the same slot (and its own `write_pos` bookkeeping) to keep flushing into, so it has to
    // survive until the fd is genuinely gone.
    if let OpenFile::Write {
        buf_slot: Some(idx),
        ..
    } = file
    {
        free_write_buffer(idx);
    }
    result
}

/// Registered for `SYS_CLOSE`. Delegates to the kernel's own `oxidebsd_close_fd`, which removes
/// `fd` from its registry and invokes `oxfs_close` above -- not a direct call, so a closed fd is
/// also no longer reachable via `SYS_READ`/`SYS_WRITE` afterward.
///
/// `oxidebsd_close_fd`'s own return is a plain C-style `0`/`-1` boolean, not a registered
/// handler's `-errno` wire format -- passing its literal `-1` straight through used to be
/// silently read as `-errno` with `errno=1` (`EPERM`) instead of real close(2)'s one documented
/// failure, `EBADF` (an already-closed/never-open fd -- `mq_close/3-1.c`, but really any
/// double-close on any fd kind). Translated here, the only call site for this function.
extern "C" fn sys_close(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    if unsafe { oxidebsd_close_fd(fd) } == 0 { 0 } else { -EBADF }
}

/// Registered for `SYS_FSYNC`. See `SYS_FSYNC`'s own doc comment (up near its number's
/// definition) for why this filesystem's normal commit-only-at-close write model otherwise makes
/// `fsync()` a lie for anything opened for writing. A no-op success for a read/directory fd --
/// real Unix `fsync()` on a read-only fd is also a harmless no-op.
///
/// A real, registered fd that just isn't one of *this* module's own (a pipe, socket, or mqueue
/// end) resolves fine via `oxidebsd_real_fd_of` but has no `find_open_file` entry -- real POSIX
/// `EINVAL` ("fildes does not refer to a file on which this operation is possible",
/// `fsync/7-1.c`, a pipe), not `EBADF` (reserved for a real "no such fd at all").
extern "C" fn oxfs_fsync(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    match find_open_file(real_fd as u64) {
        Some(file) => commit_write_buffer(file),
        None => -EINVAL,
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
    // Real, previously-live bug, found via the Open POSIX Test Suite's `aio_write/2-1.c`: this
    // used to only call `commit_write_buffer` the *first* time (gated on `existing_inode: None`,
    // i.e. "only if a real inode doesn't exist yet") -- correct for allocating the inode, but wrong
    // for flushing content, since a `Write` fd can keep accumulating *more* buffered bytes via
    // ordinary `write()` calls after that first commit. Any later `lseek()`/`read()`/`pread()` on
    // the same still-open `O_RDWR` fd would then never see that later-written content at all,
    // since nothing re-flushed it. `commit_write_buffer` is cheap to call unconditionally -- it
    // already no-ops (`return 0`) whenever there's nothing currently buffered (`len == 0`), the
    // same real invariant every other call site here relies on.
    if matches!(file, OpenFile::Write { .. }) && commit_write_buffer(file) != 0 {
        return None;
    }
    match file {
        OpenFile::Write {
            existing_inode: Some(inode_num),
            ..
        } => Some(*inode_num),
        _ => None,
    }
}

/// Real POSIX `ftruncate(2)`/`fallocate(2)`: `EINVAL` when `fd` isn't open for writing -- shared by
/// both callers below. Peeks the still-registered `OpenFile::Write` state directly (rather than
/// going through `resolve_write_fd_inode`, which only ever returns a bare inode number, with no
/// access-mode context left to check) -- see `OpenFile::Write::readonly`'s own doc comment.
fn ftruncate_blocked_readonly(real_fd: u64) -> bool {
    matches!(
        find_open_file(real_fd),
        Some(OpenFile::Write {
            readonly: true,
            ..
        })
    )
}

/// Registered for `SYS_FTRUNCATE`. Resizes the fd's real inode directly (`resize_inode_data`), via
/// `resolve_write_fd_inode`'s own forced early flush/commit -- by the time this resize runs, any
/// content already buffered on this fd (if it's also still mid-write, e.g. an existing file
/// opened `O_WRONLY`, not yet `close()`d) is already durably flushed onto the same inode this
/// resizes, and `commit_write_buffer` skips flushing anything more at `close()`/`fsync()` time
/// while the buffer stays empty (see that function's own doc comment) -- so this resize simply
/// sticks unless a genuinely new `write()` happens afterward, matching real Unix's own "whichever
/// happens last wins" ordering between `ftruncate()` and `write()` without needing a separate flag
/// to guard it (a real, previously-live bug this closes -- see `OpenFile::Write`'s own doc
/// comment's history for the old whole-file-replace design this flag used to compensate for).
extern "C" fn oxfs_ftruncate(fd: u64, len: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    if ftruncate_blocked_readonly(real_fd) {
        return -EINVAL;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd) else {
        return -EBADF;
    };
    if read_inode(inode_num).kind == InodeKind::Dir {
        return -EISDIR;
    }
    if !resize_inode_data(inode_num, len as usize) {
        return -ENOSPC;
    }
    0
}

/// Registered for `SYS_FALLOCATE`. `mode` is ignored -- always behaves like the default (no
/// `FALLOC_FL_KEEP_SIZE`/`FALLOC_FL_PUNCH_HOLE`/... flag support, a known simplification no
/// applet in this port's roster needs past). Zero-extends the file to `offset + len` if it's
/// currently shorter; otherwise a real no-op (real `fallocate()` never shrinks a file). Same real
/// `EINVAL`-if-not-open-for-writing check as `oxfs_ftruncate` (`ftruncate_blocked_readonly`), and
/// the same "this resize simply sticks" reasoning -- see that function's own doc comment.
extern "C" fn oxfs_fallocate(fd: u64, _mode: u64, offset: u64, len: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    if ftruncate_blocked_readonly(real_fd) {
        return -EINVAL;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd) else {
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
///
/// **Real permission checking**, previously entirely absent (any caller could unlink anything):
/// requires real `W_OK` on the *containing directory* (removing a name is a write to the
/// directory, not to the file itself -- standard Unix rule, matches `oxfs_mkdir`/`oxfs_symlink`'s
/// own `check_access(parent, ..., W_OK)` pattern). Additionally enforces the real **sticky-bit**
/// rule (`mode & 0o1000`, previously stored on `/tmp`/`/dev/shm`'s own inode -- see
/// `format_fresh_filesystem`'s own doc comment -- but never actually consulted anywhere): inside a
/// sticky directory, only root, the directory's own owner, or the *file's* own owner may remove an
/// entry, even though the directory itself is otherwise world-writable. Found live via
/// `shm_unlink/8-1.c`/`9-1.c` (Open POSIX Test Suite pilot): a non-root, non-owning caller must get
/// a real `EACCES` unlinking another uid's object out of the world-writable-but-sticky `/dev/shm`.
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
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    let parent_inode = read_inode(parent);
    if !check_access(&parent_inode, uid, gid, W_OK) {
        return -EACCES;
    }
    let Some(target) = dir_lookup(parent, leaf) else {
        // No directory entry exists yet -- real ENOENT, *unless* some still-open fd is mid-`open
        // (O_CREAT)` against this exact (parent, name) and hasn't committed (inserted its own
        // directory entry) yet. Real POSIX: `unlink()` racing ahead of a not-yet-`close()`d
        // `creat()` on the same path must still make the name unreachable the moment the create
        // eventually commits -- see `OpenFile::Write::unlinked`'s own doc comment (found live via
        // `mmap/12-1.c`).
        let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
        for slot in slots.iter_mut().flatten() {
            if let (_, OpenFile::Write {
                parent_inode,
                name,
                name_len,
                existing_inode: None,
                unlinked,
                ..
            }) = slot
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
    // Real sticky-bit protection (see this function's own doc comment) -- root and the directory's
    // own owner are always exempt; otherwise only the file's own owner may remove it.
    if parent_inode.mode & 0o1000 != 0
        && uid != 0
        && uid != parent_inode.uid as u64
        && uid != target_inode.uid as u64
    {
        return -EACCES;
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
    let Some(target) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    if read_inode(target).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    if dir_entry_count(target) > 2 {
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

/// Registered for `SYS_FCHDIR` at real Linux's own `__NR_fchdir = 81` -- same "still completely
/// unassigned in this ABI's own registry, no invented number or musl-side remap needed" story as
/// `SYS_FCHMOD` above (checked against every `SYS_*` constant in `src/`/`modules/` first). Found
/// live via `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own POSIX-vs-musl sweep -- `third_party/musl/src/
/// unistd/fchdir.c` calls this directly, though no BusyBox-roster applet was confirmed to call it
/// yet; cheap enough to close anyway.
///
/// Uses `resolve_write_fd_inode`, not the narrower `inode_of_open_file` -- same reasoning as
/// `oxfs_fstat`/`oxfs_fchmod` above. Rejects a non-directory target with `-ENOTDIR`, matching real
/// `fchdir(2)`; otherwise reuses `oxfs_chdir`'s own `set_current_cwd_real` tail directly (no `/proc`
/// case to consider here -- a `/proc` entry has no real inode for a fd to resolve to in the first
/// place, see `inode_of_open_file`'s own `ProcRead`/`ProcDir` doc comment above).
extern "C" fn oxfs_fchdir(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = resolve_write_fd_inode(real_fd as u64) else {
        return -EBADF;
    };
    if read_inode(inode_num).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    set_current_cwd_real(inode_num);
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
/// `{FileRead,DirListing,ProcRead,ProcDir}` variants have a real `position`/size to seek within,
/// plus now `Write` fds with real `readwrite` support (see that field's own doc comment) -- a
/// plain `O_WRONLY` `Write` fd (an in-progress accumulate-then-commit buffer, not a real
/// random-access file) and the synthetic `/dev/*` variants still report `ESPIPE`, the real POSIX
/// answer for "this fd has no seekable position", rather than silently accepting a seek that would
/// never actually change what a later `read`/`write` sees.
extern "C" fn oxfs_lseek(fd: u64, offset: u64, whence: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    // Real `O_RDWR` support: a separate, sequential lookup rather than a branch inside the match
    // below -- see `oxfs_read`'s own doc comment for why (`resolve_write_fd_inode` needs its own
    // fresh `find_open_file` call, which would alias the match's own `&mut OpenFile`). Forces an
    // early real commit so `size` reflects everything written so far, not just this fd's own
    // still-pending buffer.
    if matches!(find_open_file(real_fd), Some(OpenFile::Write { readwrite: true, .. })) {
        let Some(inode) = resolve_write_fd_inode(real_fd) else {
            return -EIO;
        };
        let size = read_inode(inode).size as i64;
        let Some(OpenFile::Write { position, .. }) = find_open_file(real_fd) else {
            return -EBADF;
        };
        let offset = offset as i64;
        let new_pos = match whence {
            0 => offset,
            1 => *position as i64 + offset,
            2 => size + offset,
            _ => return -EINVAL,
        };
        if new_pos < 0 {
            return -EINVAL;
        }
        *position = new_pos as usize;
        return new_pos;
    }
    let Some(open_file) = find_open_file(real_fd) else {
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
        OpenFile::Write { .. }
        | OpenFile::DevRandom
        | OpenFile::DevNull
        | OpenFile::DevZero
        | OpenFile::Framebuffer { .. } => {
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

/// Registered (via `oxidebsd_set_fd_pread_pwrite`) as every oxfs fd's `pread` callback -- real
/// `pread(2)`: like `oxfs_read`, but at an explicit `offset` that neither reads nor updates this
/// fd's own `position` (real POSIX: `pread`/`pwrite` are independent of `lseek`'s cursor). A plain
/// `FileRead` fd (`O_RDONLY`, or an existing path opened `O_RDWR` -- see `oxfs_open`'s own
/// existing-path branch) already has a real, committed inode to read directly; a `Write` fd needs
/// real `readwrite` (`O_RDWR`) support and the same forced-early-commit `oxfs_read`/`oxfs_lseek`
/// already use. Every other variant (directories, `/proc`, `/dev/*`, and a plain `O_WRONLY`
/// `Write` fd) has no real seekable position at all -- `ESPIPE`, matching `oxfs_lseek`'s own answer
/// for the same fd kinds.
extern "C" fn oxfs_pread(real_fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    let inode = match find_open_file(real_fd) {
        Some(OpenFile::FileRead { inode, .. }) => *inode,
        Some(OpenFile::Write { readwrite: true, .. }) => match resolve_write_fd_inode(real_fd) {
            Some(inode) => inode,
            None => return -EIO,
        },
        Some(_) => return -ESPIPE,
        None => return -EBADF,
    };
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    let n = read_inode_at(inode, offset as usize, out);
    if n > 0 {
        touch_atime(inode);
    }
    n as i64
}

/// Registered (via `oxidebsd_set_fd_pread_pwrite`) as every oxfs fd's `pwrite` callback -- real
/// `pwrite(2)`, writing directly into the fd's own real inode blocks via `write_inode_at` (bypassing
/// `OpenFile::Write`'s own pooled `WRITE_BUFFERS` slot and its `MAX_WRITE_BUFFER` flush-window
/// entirely -- found live via `lio_listio/1-1.c`, the Open POSIX Test Suite pilot, which needs a
/// real 1 MiB `pwrite()`). Unlike `oxfs_pread`, this works for **any** fd open for writing --
/// `O_WRONLY` included, not just `readwrite` (`O_RDWR`) -- matching real POSIX: `pwrite()` only
/// requires the fd be open for writing, never O_RDWR specifically. Forces the same real early
/// commit `resolve_write_fd_inode` already provides (a fd that's never had a plain `write()` yet
/// still needs a real inode to write into directly) -- no separate flag needed afterward: a later
/// `close()`/`fsync()` with no intervening plain `write()` finds nothing buffered (`len == 0`) and
/// flushes nothing, leaving this real, already-committed content alone (see
/// `commit_write_buffer`'s own doc comment).
extern "C" fn oxfs_pwrite(real_fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    match find_open_file(real_fd) {
        Some(OpenFile::Write { readonly: false, .. }) => {}
        Some(_) => return -EBADF,
        None => return -EBADF,
    }
    let Some(inode) = resolve_write_fd_inode(real_fd) else {
        return -EIO;
    };
    // SAFETY: same trust boundary as elsewhere -- caller-owned pointer/length.
    let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    if !write_inode_at(inode, offset as usize, data) {
        return -EIO;
    }
    len as i64
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
        self.push_decimal_u64(value as u64);
    }

    /// `push_decimal`'s 64-bit counterpart -- needed once `Inode::size` widened to `u64` (a real
    /// file can now legitimately report a size past `u32::MAX`), see this method's one real caller
    /// (`oxfs_getdents`'s human-readable directory listing).
    fn push_decimal_u64(&mut self, value: u64) {
        if value == 0 {
            self.push_bytes(b"0");
            return;
        }
        let mut digits = [0u8; 20];
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
    // `size` widened 4 -> 8 bytes (real `u64`, see `Inode::size`'s own doc comment) -- every offset
    // from here on shifts +4 relative to `SUPERBLOCK_VERSION`'s prior (version 1) on-disk shape.
    out[1..9].copy_from_slice(&inode.size.to_le_bytes());
    for (i, d) in inode.direct.iter().enumerate() {
        let off = 9 + i * 4;
        out[off..off + 4].copy_from_slice(&d.to_le_bytes());
    }
    let indirect_off = 9 + DIRECT_BLOCKS * 4;
    out[indirect_off..indirect_off + 4].copy_from_slice(&inode.indirect.to_le_bytes());
    // New field (see `Inode::double_indirect`'s own doc comment) -- inserted right after
    // `indirect`, shifting every following offset +4 again relative to version 1.
    let double_indirect_off = indirect_off + 4;
    out[double_indirect_off..double_indirect_off + 4]
        .copy_from_slice(&inode.double_indirect.to_le_bytes());
    let mode_off = double_indirect_off + 4;
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
    let mtime_off = device_char_off + 1;
    out[mtime_off..mtime_off + 8].copy_from_slice(&inode.mtime.to_le_bytes());
    let ctime_off = mtime_off + 8;
    out[ctime_off..ctime_off + 8].copy_from_slice(&inode.ctime.to_le_bytes());
    let atime_off = ctime_off + 8;
    out[atime_off..atime_off + 8].copy_from_slice(&inode.atime.to_le_bytes());
    for b in &mut out[atime_off + 8..] {
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
    let size = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let mut direct = [NO_BLOCK; DIRECT_BLOCKS];
    for (i, d) in direct.iter_mut().enumerate() {
        let off = 9 + i * 4;
        *d = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    }
    let indirect_off = 9 + DIRECT_BLOCKS * 4;
    let indirect = u32::from_le_bytes([
        data[indirect_off],
        data[indirect_off + 1],
        data[indirect_off + 2],
        data[indirect_off + 3],
    ]);
    let double_indirect_off = indirect_off + 4;
    let double_indirect = u32::from_le_bytes([
        data[double_indirect_off],
        data[double_indirect_off + 1],
        data[double_indirect_off + 2],
        data[double_indirect_off + 3],
    ]);
    let mode_off = double_indirect_off + 4;
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
    let mtime_off = device_char_off + 1;
    let mtime = i64::from_le_bytes(data[mtime_off..mtime_off + 8].try_into().unwrap());
    let ctime_off = mtime_off + 8;
    let ctime = i64::from_le_bytes(data[ctime_off..ctime_off + 8].try_into().unwrap());
    // A pre-existing on-disk inode written before this field existed decodes a zeroed tail here --
    // an honest `0` (Unix epoch), not an invalid value the way a decoded `nlink == 0` would be, so
    // no flooring is needed the way Inode::nlink's own doc comment describes for that field.
    let atime_off = ctime_off + 8;
    let atime = i64::from_le_bytes(data[atime_off..atime_off + 8].try_into().unwrap());
    Inode {
        kind,
        size,
        direct,
        indirect,
        double_indirect,
        mode,
        uid,
        gid,
        nlink,
        rdev,
        device_char,
        mtime,
        ctime,
        atime,
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

/// Write-through hook for `set_block_used` -- repacks and writes only the *one* physical bitmap
/// block covering `n`, from the in-memory `BLOCK_USED` array, same "memory is the complete source
/// of truth, no read-modify-write needed" reasoning as `persist_inode_block_if_ready`. **Used to
/// repack and write the *entire* multi-block bitmap on every single call** -- harmless at the old,
/// much smaller `NUM_BLOCKS`, but with the pool now spanning `BITMAP_BLOCKS` real physical blocks
/// (see that constant's own doc comment), rewriting every one of them on every single block
/// allocation would turn a real, big sequential file write into thousands of redundant PIO-under-
/// emulation sector transfers (see CLAUDE.md's own "Real disk persistence" gotcha on this exact
/// cost) for exactly one call site: the file's own already-correct data-block writes, which each
/// already write independently via `persist_data_block_if_ready`. Scoped to one block the same way
/// that function (and `persist_inode_block_if_ready`) already are.
fn persist_bitmap_if_ready(n: u32) {
    if n >= NUM_BLOCKS as u32 || !persistence_ready() || !block_device_present() {
        return;
    }
    let bits_per_block = (BLOCK_SIZE * 8) as u32;
    let bitmap_block_idx = n / bits_per_block;
    let base = bitmap_block_idx * bits_per_block;
    let end = (base + bits_per_block).min(NUM_BLOCKS as u32);
    let mut block = [0u8; BLOCK_SIZE];
    for i in base..end {
        if block_used(i) {
            let rel = (i - base) as usize;
            block[rel / 8] |= 1 << (rel % 8);
        }
    }
    unsafe {
        oxidebsd_block_write((BITMAP_START + bitmap_block_idx) as u64, block.as_ptr() as u64);
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
    // A pristine, all-free state means `alloc_block`'s own resume cursor (see `NEXT_FREE_BLOCK`'s
    // own doc comment) has nothing behind it to skip past either.
    unsafe { *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK) = 0 };
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
    // at every block-offset this build's own `INODE_TABLE_START`/`BITMAP_START`/
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

    // Real, multi-block bitmap read (`BITMAP_BLOCKS` physical blocks, not a hardcoded one -- see
    // that constant's own doc comment for the real bug this fixes). Each block covers its own real
    // `BLOCK_SIZE * 8`-bit range of the pool.
    let bits_per_block = BLOCK_SIZE * 8;
    for bitmap_block_idx in 0..BITMAP_BLOCKS as usize {
        let mut bitmap_block = [0u8; BLOCK_SIZE];
        let phys = BITMAP_START as u64 + bitmap_block_idx as u64;
        if unsafe { oxidebsd_block_read(phys, bitmap_block.as_mut_ptr() as u64) } != 0 {
            log("[oxfs] mount: failed to read block-used bitmap -- falling back to format\n");
            return false;
        }
        let base = bitmap_block_idx * bits_per_block;
        let end = (base + bits_per_block).min(NUM_BLOCKS);
        for i in base..end {
            let rel = i - base;
            let used = (bitmap_block[rel / 8] >> (rel % 8)) & 1 != 0;
            set_block_used(i as u32, used);
        }
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

    // Real, multi-block bitmap write -- see `mount_from_disk`'s own matching read loop and
    // `BITMAP_BLOCKS`'s own doc comment.
    let bits_per_block = BLOCK_SIZE * 8;
    for bitmap_block_idx in 0..BITMAP_BLOCKS as usize {
        let mut bitmap_block = [0u8; BLOCK_SIZE];
        let base = bitmap_block_idx * bits_per_block;
        let end = (base + bits_per_block).min(NUM_BLOCKS);
        for i in base..end {
            if block_used(i as u32) {
                let rel = i - base;
                bitmap_block[rel / 8] |= 1 << (rel % 8);
            }
        }
        let phys = BITMAP_START as u64 + bitmap_block_idx as u64;
        unsafe {
            oxidebsd_block_write(phys, bitmap_block.as_ptr() as u64);
        }
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

/// `POSIX_TEST_FILES` -- generated by build.rs's `write_posix_test_manifest`, same idiom as
/// `TCC_RUNTIME_FILES` above. Consumed by `format_fresh_filesystem`'s own `/posix-tests` seeding
/// below; see `posix_conformance.sh`'s own doc comment for what actually runs against this tree.
/// Also defines `POSIX_TEST_EXTRA_FILES` -- a second, separate array for pilot fixtures that need
/// seeding at a literal path *outside* `/posix-tests` entirely: `sigaltstack/9-1.c`'s own
/// `9-buildonly.test` `execl()` target, and `mlockall/3-7.c`'s own real source file (the one test
/// in the whole corpus that `open()`s itself by relative path) -- see each entry's own generation
/// comment in build.rs.
include!(env!("POSIX_TEST_MANIFEST_PATH"));

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

    // The real POSIX conformance pilot's own runner, meant to be run by hand at the hush prompt
    // (`sh /posix_conformance.sh`) -- see that file's own header comment. Runs each seeded, real
    // pre-built `/posix-tests/bin/**` ELF (cross-compiled host-side with musl-gcc -- see
    // `write_posix_test_manifest`'s own doc comment for why not on-target `tcc`) under `t0`'s real
    // timeout, and classifies the real POSIX result code -- same "hand-run broad coverage script"
    // tier as `test_busybox.sh` immediately above, not a `cargo test`.
    ok &= seed_file(
        root,
        b"posix_conformance.sh",
        include_bytes!("posix_conformance.sh"),
    );

    // All executables live under /bin, not root -- matches `src/process.rs`'s pid-1 `PATH=/bin`
    // envp, so a bare command name (`ls`, not `/ls`) resolves via musl's real `execvp` search.
    let bin = alloc_inode().expect("oxfs: failed to allocate /bin inode");
    write_inode(bin, Inode::new(InodeKind::Dir));
    dir_insert(bin, b".", bin).expect("oxfs: failed to seed /bin's . entry");
    dir_insert(bin, b"..", root).expect("oxfs: failed to seed /bin's .. entry");
    dir_insert(root, b"bin", bin).expect("oxfs: failed to insert /bin into root");

    ok &= seed_file(bin, b"smoke", include_bytes!(env!("OXFS_SMOKE_ELF_PATH")));
    ok &= seed_file(bin, b"musl", include_bytes!(env!("OXFS_MUSL_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"float-smoke",
        include_bytes!(env!("OXFS_FLOAT_SMOKE_ELF_PATH")),
    );
    // A real, playable port of Doom -- see build.rs's own build_doomgeneric doc comment.
    // doom1.wad seeded at root (not e.g. /usr/share/) since real, unmodified doomgeneric's own
    // d_iwad.c always searches "." first, and root's own $HOME (see /etc/passwd) is "/" -- the
    // ordinary hush prompt's default cwd -- so a bare `doom` invocation finds it with no `-iwad`
    // argument needed.
    ok &= seed_file(bin, b"doom", include_bytes!(env!("OXFS_DOOM_ELF_PATH")));
    ok &= seed_file(root, b"doom1.wad", include_bytes!(env!("OXFS_DOOM1_WAD_PATH")));
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
    // musl port (see build.rs's own BUSYBOX_APPLETS_PASS2 comment and OxideBSD-doc/BUSYBOX_APPLETS.md for
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

    // /tmp -- real POSIX conformance-suite tests (`mmap`'s own pilot subset) `open(O_CREAT|
    // O_EXCL)` a scratch file here as their first setup step; a missing directory ENOENTs before
    // the behavior actually under test ever runs, misclassifying every one of them UNRESOLVED
    // rather than a real PASS/FAIL. Mode 01777 matches real POSIX world-writable-plus-sticky `/tmp`
    // convention -- `oxfs_unlink` now real-enforces the sticky bit (see that function's own doc
    // comment, found live via `shm_unlink/8-1.c`/`9-1.c` against `/dev/shm` below), but every
    // caller in this pilot runs as root anyway, which bypasses permission bits entirely regardless.
    let tmp = ensure_dir(root, b"tmp");
    {
        let mut inode = read_inode(tmp);
        inode.mode = 0o1777;
        write_inode(tmp, inode);
    }

    // /dev/shm -- POSIX named shared memory/semaphores. musl's own `shm_open()`/`sem_open()`
    // (third_party/musl/src/mman/shm_open.c, src/thread/sem_open.c) aren't separate syscalls at
    // all -- both are pure userspace wrappers over a plain `open("/dev/shm/<name>", ...)` -- so
    // this is real infra, not a stub: no new syscall needed, just a real directory for that
    // `open()` to land in instead of the unconditional `/dev/` prefix interception's `ENOENT`
    // (see `oxfs_open`'s own updated doc comment above). Distinct from the four magic
    // `/dev/{random,urandom,null,zero}` paths, which stay intercepted before reaching here.
    let dev = ensure_dir(root, b"dev");
    let dev_shm = ensure_dir(dev, b"shm");
    {
        let mut inode = read_inode(dev_shm);
        inode.mode = 0o1777;
        write_inode(dev_shm, inode);
    }

    // /dev/fb0 -- a real character device node backing process::mm::do_mmap_fb (see
    // known_device's own (29, 0) arm and src/drivers/fbdev.rs's module doc comment, kernel tree).
    // Major:minor (29, 0) matches real Linux's own standard fbdev numbering (cosmetic here -- no
    // general device-driver framework backs the number choice, same precedent
    // /dev/{null,zero,random,urandom}'s own real-Linux-matching numbers already set). Mode 0o666:
    // any process may open/mmap the one real console framebuffer, matching this kernel's
    // single-session design (no "who owns the display" permission concept exists at all).
    {
        let fb0 = alloc_inode().expect("oxfs: failed to allocate /dev/fb0 inode");
        let mut inode = Inode::new(InodeKind::Device);
        inode.mode = 0o666;
        inode.rdev = (29u32 << 8) | 0;
        inode.device_char = true;
        write_inode(fb0, inode);
        dir_insert(dev, b"fb0", fb0).expect("oxfs: failed to insert /dev/fb0 into /dev");
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

    // A real POSIX conformance baseline (see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`'s own
    // "Verification" section): a curated pilot subset of `third_party/posixtestsuite`'s own
    // assertion files, each cross-compiled host-side with musl-gcc into a real ELF under
    // `/posix-tests/bin`, its real `t0` timeout-wrapper (also pre-built) at `/posix-tests/t0`, and
    // a plain-text `/posix-tests/manifest.txt` the runner script below iterates -- see
    // `write_posix_test_manifest`'s own doc comment in build.rs for how this set was chosen and why
    // it's cross-compiled ahead of time rather than seeded as source and compiled on-target by
    // `tcc` (a real `tcc` GOT/PLT linker bug, found live investigating this exact pilot's own
    // early crashes).
    let posix_tests = ensure_dir(root, b"posix-tests");
    ok &= seed_tree(posix_tests, POSIX_TEST_FILES);
    // `sigaltstack/9-1.c`'s own `execl()` target -- a literal path outside `/posix-tests` (see
    // `POSIX_TEST_EXTRA_FILES`'s own generation comment in build.rs), seeded straight off root.
    ok &= seed_tree(root, POSIX_TEST_EXTRA_FILES);

    // Real PT_INTERP / dynamic-linking milestone 1 -- see `build.rs`'s `build_musl_sysroot_shared`
    // for the separate, real `-fPIC`/`-shared` musl build this comes from (distinct from the
    // static `libc.a` seeded into `/usr/lib` above). musl has no separate `ld.so` binary -- real
    // upstream musl's own `make install` symlinks its interpreter path directly to `libc.so`
    // itself (confirmed empirically before writing this) -- so `libc.so`'s real bytes live once,
    // under `/usr/lib`, and `/lib/ld-musl-x86_64.so.1` is just a symlink to it. `/lib` is seeded as
    // a real directory containing only that one symlink (not a whole-directory `/lib -> /usr/lib`
    // alias) to match that same real upstream convention exactly, not invent a different one.
    ok &= seed_file(
        usr_lib,
        b"libc.so",
        include_bytes!(env!("OXFS_DYNLINK_LIBC_SO_PATH")),
    );
    let lib = ensure_dir(root, b"lib");
    ok &= seed_symlink(lib, b"ld-musl-x86_64.so.1", b"/usr/lib/libc.so");

    // A real, minimal, dynamically-linked fixture binary (one `write()` call) -- see
    // `userland/dynlink-smoke/main.c` -- for exercising a genuine `PT_INTERP` load end to end via
    // `tests/dynlink_syscall_smoke.rs`: real `fork`+`execve` of this path, through a real `SYSCALL`,
    // loading both this binary and the interpreter above into the same address space.
    ok &= seed_file(
        root,
        b"dynlink-smoke.elf",
        include_bytes!(env!("OXFS_DYNLINK_SMOKE_ELF_PATH")),
    );

    // "Real threading" phases 1-5's own finish line -- a genuine, unmodified musl
    // pthread_create()/pthread_join() round trip (`userland/pthread-smoke/main.c`'s own doc
    // comment has the full scenario), driven by `tests/pthread_syscall_smoke.rs` via a real
    // `fork`+`execve` of this path, exactly like `dynlink-smoke.elf` above.
    ok &= seed_file(
        root,
        b"pthread-smoke.elf",
        include_bytes!(env!("OXFS_PTHREAD_SMOKE_ELF_PATH")),
    );

    // Real cross-process named-semaphore coordination (`sem_open()`+`fork()`) via the real
    // `/dev/shm`-backed `MAP_SHARED` mmap two independent processes each map at their own,
    // generally *different*, virtual address -- see `userland/sem-open-smoke/main.c`'s own doc
    // comment for the scenario and `process::limits::futex_key`'s own doc comment for the real
    // physical-address-keyed `FUTEX_WAIT`/`FUTEX_WAKE` fix this proves. Driven by
    // `tests/sem_open_syscall_smoke.rs` via a real `fork`+`execve`, exactly like
    // `pthread-smoke.elf` above.
    ok &= seed_file(
        root,
        b"sem-open-smoke.elf",
        include_bytes!(env!("OXFS_SEM_OPEN_SMOKE_ELF_PATH")),
    );

    // Isolated repro of the real Open POSIX Test Suite `pthread_cancel/5-1.c` crash-then-wedge
    // investigation -- see `userland/pthread-cancel-crash/main.c`'s own doc comment for the exact
    // scenario (pthread_create/pthread_join/pthread_cancel-on-a-just-joined-thread, a real,
    // expected SIGSEGV via a write through memory `pthread_join`'s own real `munmap` already
    // freed). Driven by `tests/pthread_cancel_crash_smoke.rs`.
    ok &= seed_file(
        root,
        b"pthread-cancel-crash.elf",
        include_bytes!(env!("OXFS_PTHREAD_CANCEL_CRASH_ELF_PATH")),
    );

    // Isolated repro of the real Open POSIX Test Suite `pthread_cond_broadcast/1-2.c` real
    // cross-process stall -- see `userland/pshared-cond-crash/main.c`'s own doc comment for the
    // exact narrower scenario (one forked child using a real `PTHREAD_PROCESS_SHARED` mutex/cond
    // in a real file-backed `MAP_SHARED` region). Driven by `tests/pshared_cond_crash_smoke.rs`.
    ok &= seed_file(
        root,
        b"pshared-cond-crash.elf",
        include_bytes!(env!("OXFS_PSHARED_COND_CRASH_ELF_PATH")),
    );

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
        // O_WRONLY (0o1) is required now that a create-path fd's own requested access mode is
        // actually enforced (see `oxfs_open`'s `readonly` field) -- this used to be `O_CREAT`
        // alone, silently getting away with it back when every create-path fd was unconditionally
        // writable regardless of what flags asked for.
        let fd = oxfs_open(b"in.txt".as_ptr() as u64, 6, O_CREAT | 0o1, 0);
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

        // O_WRONLY required now that a create-path fd's own requested access mode is actually
        // enforced -- this used to be `O_CREAT` alone, which silently made the write below a
        // no-op (fixed here rather than left as a latent bug: harmless today only because the
        // later O_WRONLY reopen + real truncate never depended on this write having landed).
        let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, O_CREAT | O_WRONLY, 0);
        if fd < 0 {
            ok = false;
            log("[oxfs] self-check FAILED: create overwrite_test.txt failed\n");
        } else {
            let fd = fd as u64;
            if oxfs_write(fd, b"AAAAA".as_ptr() as u64, 5) != 5 {
                ok = false;
                log("[oxfs] self-check FAILED: write overwrite_test.txt (initial AAAAA) failed\n");
            }
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
        oxidebsd_register_syscall(SYS_FCHDIR, oxfs_fchdir);
        oxidebsd_register_syscall(SYS_UTIMENSAT, oxfs_utimensat);
        oxidebsd_register_syscall(SYS_MOUNT_BIND, oxfs_mount_bind);
        oxidebsd_register_syscall(SYS_MOUNT_TMPFS, oxfs_mount_tmpfs);
        oxidebsd_register_syscall(SYS_UMOUNT2, oxfs_umount2);
        oxidebsd_register_syscall(SYS_FSYNC, oxfs_fsync);
        oxidebsd_register_syscall(SYS_FDATASYNC, oxfs_fsync);
        oxidebsd_register_syscall(SYS_SYNC, oxfs_sync);
        oxidebsd_register_syscall(SYS_FTRUNCATE, oxfs_ftruncate);
        oxidebsd_register_syscall(SYS_FALLOCATE, oxfs_fallocate);
        oxidebsd_register_syscall(SYS_FLOCK, oxfs_flock);
        oxidebsd_register_syscall(SYS_STATFS, oxfs_statfs);
        oxidebsd_register_syscall(SYS_FSTATFS, oxfs_fstatfs);
        oxidebsd_register_content_accessors(
            oxfs_inode_content_read,
            oxfs_inode_content_write,
            oxfs_inode_content_size,
        );
    }

    if ok { 0 } else { -1 }
}
