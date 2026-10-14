//! `oxfs`: a small, real Unix-shaped filesystem (inodes with direct + single-indirect block
//! pointers, directories as ordinary inodes holding fixed-size records, real multi-component path
//! resolution, real per-process current-working-directory) -- replaced an earlier FAT32 module
//! (since removed) as the live filesystem BusyBox actually runs on. See `CLAUDE.md`'s oxfs section
//! for the full design rationale.
//!
//! There's no on-disk *format* to invent or generate at build time: `module_init` below populates
//! the inode table directly via ordinary function calls, using content `build.rs` hands this
//! crate's own `include_bytes!(env!(...))` calls (each already-built regress/BusyBox ELF gets its
//! own env var, the same `extra_env` mechanism `build_module_crate`'s own doc comment describes)
//! or, for the two small text files, a literal and the same `b'A' + i % 26` formula the old FAT32
//! module's own self-check used.
//!
//! **What this fixes relative to FAT32** (see CLAUDE.md's FAT32 section for the full list of
//! limitations this replaces): 8.3 short names -> real names up to `NAME_MAX` bytes; one path
//! component per syscall call -> real multi-component `a/b/c`/`../x`/`/a/b` resolution in one call
//! (`resolve_path`/`resolve_parent` below); a directory that can never grow past its first
//! cluster -> a directory's own inode grows additional blocks like any other file; a fixed
//! per-open-file read cap (`MAX_FILE_BUFFER`, raised three times) -> real files stream straight
//! from their own block chain on each `read()`, capped only by the block pool itself; one
//! kernel-wide current directory shared by every process -> real per-process cwd
//! (`Process::cwd` in `sys/process.rs`, via `oxidebsd_get_cwd`/`oxidebsd_set_cwd`); no
//! `unlink`/`rmdir`/`rename` at all -> all three now exist.
//!
//! **Storage**, all fixed-size `static mut` arrays (modules can't use `alloc`/`Vec`/`BTreeMap` --
//! see CLAUDE.md's module-loading section): a flat pool of `NUM_BLOCKS` `BLOCK_SIZE`-byte blocks
//! (`BLOCKS`/`BLOCK_USED`), and inodes packed into an inode file in that pool, which grows as
//! needed (`InodeTable`; the disk pool and the tmpfs pool each have one). An inode addresses
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

mod bcache;

// The on-disk format: layout constants, `Inode`, `pack_inode`/`unpack_inode`, directory records
// and the superblock (`lib/liboxfs`, shared with fsck_oxfs and the host tools).
use oxfs_format::*;

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
    ) -> i64;
    /// `0` if `n` more open files fit under `kern.maxfiles`, else `-ENFILE`.
    fn oxidebsd_fd_check_room(n: u64) -> i64;
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
    ) -> i64;
    /// See `crate::fs::fd::ContentRead`/`ContentWrite`/`ContentSize`'s own doc comment (kernel
    /// tree) for why real fd-backed `MAP_SHARED` mmap needs this instead of the plain per-fd
    /// read/write callbacks. Called once, from this module's own `module_init`.
    fn oxidebsd_register_content_accessors(
        read: extern "C" fn(u64, u64, u64, u64) -> i64,
        write: extern "C" fn(u64, u64, u64) -> i64,
        size: extern "C" fn(u64) -> i64,
        is_shm: extern "C" fn(u64) -> i64,
        setid: extern "C" fn(u64, *mut u32) -> i64,
    );
    fn oxidebsd_close_fd(fd: u64) -> i32;
    /// Sets (`on != 0`) or clears real `FD_CLOEXEC` on `fd`, in the *current* process's own table
    /// -- see `crate::fs::fd::oxidebsd_set_fd_cloexec`'s own doc comment (kernel tree). `oxfs_open`
    /// is the one caller here, right after a successful real `O_CLOEXEC` open.
    fn oxidebsd_set_fd_cloexec(fd: u64, on: u64) -> i64;
    /// Marks `fd` as having a file position, so `pread`/`pwrite` reach `oxfs_read`/`oxfs_write`
    /// with `FOF_OFFSET` (kernel tree: `crate::fs::fd::oxidebsd_set_fd_positioned`).
    /// `register_open_file` is the one caller here.
    fn oxidebsd_set_fd_positioned(fd: u64);
    /// Moves up to `len` bytes between this module's buffer `kbuf` and a read or write transfer
    /// (`uio`, opaque here; kernel tree: `crate::kern::subr_uio`, USERMEM.md §4.4). The count
    /// moved, or `-errno`.
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    /// Bytes a transfer still has to move.
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    /// A transfer's file offset, for `FOF_OFFSET`.
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    /// A transfer over this module's own buffer (`rw`: `0` read, `1` write), for I/O on its own
    /// descriptors; `0` on failure. Freed with `oxidebsd_uio_free`.
    fn oxidebsd_uio_kernel_new(buf: *mut u8, len: u64, rw: u64) -> u64;
    fn oxidebsd_uio_free(uio: u64);
    /// Copies `len` bytes from user memory at `src` into this module's buffer `dst` (kernel tree:
    /// `crate::memory::usercopy`). `0`, or a positive errno (`EFAULT`).
    fn oxidebsd_copyin(src: u64, dst: *mut u8, len: usize) -> u64;
    /// Copies `len` bytes of this module's buffer `src` to user memory at `dst`. `0`, or a
    /// positive errno.
    fn oxidebsd_copyout(src: *const u8, len: usize, dst: u64) -> u64;
    /// Overrides `fd`'s real `access_mode` callback -- see
    /// `crate::fs::fd::oxidebsd_set_fd_access_mode`/`FdAccessMode`'s own doc comment (kernel tree).
    /// `register_open_file` is the one caller here, right alongside `oxidebsd_set_fd_positioned`.
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
    /// Whether the kernel still refers to an inode (a working or root directory, a file mapping,
    /// a bound socket file): see `maybe_release`.
    fn oxidebsd_inode_in_use(inode: u64) -> u64;
    /// Drops the kernel's page cache entry for an inode whose contents change or which is freed
    /// (`PAGECACHE.md` §2.4): see `content_changed`.
    fn oxidebsd_content_changed(inode: u64);
    /// The kernel's device registry (`sys/fs/devfs.rs`, `DEVFS.md` §3).
    fn oxidebsd_make_dev(
        name_ptr: u64,
        name_len: u64,
        major: u64,
        minor: u64,
        owner: u64,
        mode: u64,
        open: extern "C" fn(u64, u64, u64) -> i64,
    ) -> i64;
    fn oxidebsd_dev_open(major: u64, minor: u64, flags: u64) -> i64;
    fn oxidebsd_dev_generation() -> u64;
    fn oxidebsd_dev_entry(index: u64, out: *mut RawDevEntry) -> i64;
    fn oxidebsd_set_cwd(inode: u64);
    fn oxidebsd_get_root() -> u64;
    fn oxidebsd_set_root(inode: u64);
    fn oxidebsd_real_fd_of(fd: u64) -> i64;
    /// Opens the FIFO whose inode is `key` with `open(2)`'s `flags`; returns the new fd or
    /// `-errno`. The kernel owns the pipe buffer and the reader/writer rendezvous (`fs::pipe`).
    fn oxidebsd_fifo_open(key: u64, flags: u64) -> i64;
    /// Hands the kernel's local sockets (UNIX.md §5.2) the two functions that create and look up
    /// socket files; see `oxfs_create_socket_node`. Called once, from `module_init`.
    /// Registers `oxfs_kern_open`, the open the kernel's `execve` uses for a path in kernel
    /// memory (kernel tree: `crate::process::lifecycle::oxidebsd_register_kernel_open`).
    fn oxidebsd_register_kernel_open(open: extern "C" fn(u64, u64, u64) -> i64);
    fn oxidebsd_register_socket_nodes(
        create: extern "C" fn(u64, u64) -> i64,
        lookup: extern "C" fn(u64, u64) -> i64,
    );
    /// What description `real_fd` is: an `FD_KIND_*` code, its argument stored through `arg`;
    /// `-1` if there's no such description.
    fn oxidebsd_real_fd_kind(real_fd: u64, arg: *mut u64) -> i64;
    /// Process `pid`'s `real_fd` for its descriptor `fd`, or `-1`.
    fn oxidebsd_real_fd_of_pid(pid: u64, fd: u64) -> i64;
    /// The pid `/proc/self` names: the caller's thread group's.
    fn oxidebsd_current_tgid() -> u64;
    fn oxidebsd_proc_exists(pid: u64) -> i32;
    fn oxidebsd_proc_pid_at(index: u64) -> i64;
    fn oxidebsd_proc_stat_line(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_cmdline(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_status(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_meminfo(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_initdeaths(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_uptime(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_stat_global(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_proc_modules(buf_ptr: *mut u8, buf_cap: u64) -> i64;
    fn oxidebsd_fd_at(pid: u64, index: u64) -> i64;
    fn oxidebsd_random_bytes(ptr: u64, len: u64) -> i64;
    /// Real framebuffer geometry -- see `sys/drivers/fbdev.rs`'s own doc comment (kernel tree).
    /// Writes a `RawFbGeometry` (this module's own local copy of that file's `FbGeometry` --
    /// modules can't depend on kernel-crate types directly, so this is duplicated, not shared;
    /// see this codebase's own "audit duplicated wire structs on kernel-side change" precedent)
    /// through `out`, returning `0` on success or `-1` if no usable (32bpp) framebuffer exists
    /// this boot. `known_device`'s `(29, 0)` arm is the one caller.
    fn oxidebsd_fb_geometry(out: u64) -> i32;
    fn oxidebsd_current_uid() -> u64;
    fn oxidebsd_current_gid() -> u64;
    /// The real IDs, for `access(2)`.
    fn oxidebsd_current_ruid() -> u64;
    fn oxidebsd_current_rgid() -> u64;
    /// `1` if `gid` is the caller's effective (`real == 0`) or real group, or a supplementary one.
    fn oxidebsd_current_in_group(gid: u64, real: u64) -> u64;
    fn oxidebsd_current_umask() -> u64;
    /// Real Unix epoch seconds, whole-second precision -- see `sys/cpu/rtc.rs`'s own doc comment
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
    /// Real, multi-block counterparts to `oxidebsd_block_read`/`_write` -- see their own doc
    /// comments (kernel tree, `sys/drivers/ata.rs`) for why `mount_from_disk`/`flush_all_to_disk`
    /// use these instead of the single-block versions for any *contiguous* run of blocks: one real
    /// ATA command (and, for writes, one `CACHE FLUSH`) per run instead of one per individual 4 KiB
    /// block, a real, measured difference at this pool's own scale (tens of thousands of blocks).
    /// `buf_ptr` must point to `count * BLOCK_SIZE` contiguous bytes.
    fn oxidebsd_block_read_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64;
    fn oxidebsd_block_write_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64;
    /// Real, kernel-allocated (not baked into this module's own object file) storage -- see
    /// `BLOCKS_PTR`'s own doc comment for why. Returns a zeroed, kernel-VA-mapped
    /// pointer to `size_bytes` of fresh memory, or `0` on failure (only ever called once each,
    /// from `module_init`, which reboots the whole system on any failure here the same as any
    /// other `module_init` failure -- see this module's own `fatal_on_panic = true` in
    /// `sys/kernel_main.rs`, kernel tree).
    fn oxidebsd_module_alloc_zeroed(size_bytes: u64) -> u64;
    /// Usable RAM in bytes, for sizing pools.
    fn oxidebsd_physmem_bytes() -> u64;
    /// The data disk's size in 4 KiB blocks.
    fn oxidebsd_block_device_blocks() -> u64;
    /// Makes every call into this module take the kernel's filesystem lock.
    fn oxidebsd_module_serialize();
    /// `1` when the root should be mounted read-only at boot (the real boot path).
    fn oxidebsd_root_readonly_at_boot() -> u64;
    /// Tells the kernel whether the root is mounted read-write (`1`) or read-only.
    fn oxidebsd_root_mounted_rw(rw: u64);
    /// `hook` runs before an orderly reboot, halt or power-off (`reboot(2)`).
    fn oxidebsd_register_shutdown_hook(hook: extern "C" fn());
}

/// Changes whenever a file this module embeds changes (`build.rs`'s `build_module_crate`); reading
/// it makes rustc rebuild the module then, which the embedded paths alone didn't reliably do.
const _EMBED_STAMP: &str = env!("OXIDEBSD_EMBED_STAMP");

const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
/// Real x86_64 Linux's own `__NR_lseek` value -- confirmed against
/// `external/mit/musl/arch/x86_64/bits/syscall.h.in` still at its inert value (no prior pass ever
/// needed it), and musl's own `lseek()` (`src/unistd/lseek.c`) already issues a plain
/// `syscall(SYS_lseek, fd, offset, whence)` with no `SYS__llseek` fallback on this arch -- no
/// musl-side patch needed at all, unlike almost every other syscall this ABI has added. Found live
/// via TinyCC (this project's first on-target C compiler, since removed once Clang/LLVM superseded
/// it): its own object-file loader needs a real file size upfront (`fseek(f, 0, SEEK_END)`/
/// `ftell`) to read `crt1.o`/`libc.a` whole into memory before parsing their real ELF/ar headers --
/// without this registered, that `fseek` silently failed (`[boot] unrecognized syscall number 8`),
/// and its own file-loading code didn't check the return value, so it went on to read a
/// garbage/zero-length buffer and reported `invalid object file` for every crt/lib file it opened,
/// not just "not found".
const SYS_LSEEK: u64 = 8;
/// Real x86_64 Linux's own `__NR_access` value -- like `SYS_LSEEK` above, still at its inert
/// value in `external/mit/musl/arch/x86_64/bits/syscall.h.in` (confirmed unclaimed by grepping
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
/// Next two syscall numbers after `SYS_READV=153` (`sys/syscall.rs`'s own highest at the time this
/// was added) -- real POSIX `readlink(2)`/`symlink(2)`, backing `sys/modules/oxfs`'s new general
/// `InodeKind::Symlink` support (see `resolve_path_impl`'s own doc comment).
const SYS_READLINK: u64 = 154;
const SYS_SYMLINK: u64 = 155;
/// Next two after `sys/modules/posix_compat`'s own `SYS_GETGROUPS = 164` (`sys/syscall.rs`'s highest
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
/// Real `umount2(2)`'s own wire format fits this ABI's 4 registers whole (just the length-prefixed
/// path convention added, same as every other path-taking syscall here) -- no shape change needed,
/// unlike `mount(2)`, whose five arguments don't fit (`SYS_NMOUNT` below). On Linux's
/// `delete_module` number (musl's `umount2` calls it by that name).
const SYS_UMOUNT2: u64 = 176;
/// `nmount(2)`: one call for every file-system type, by name/value options (FreeBSD's design;
/// OxideBSD's number). musl's `mount(3)` is built on it. (It replaced two syscalls, a bind mount
/// at 174 and a tmpfs mount at 175, which are gone.)
const SYS_NMOUNT: u64 = 584;

/// `SYS_FSYNC=471` through `SYS_FSTATFS=477` (continuing with `SYS_PRLIMIT64=478` through
/// `SYS_REBOOT=486` in `sys/modules/posix_compat`) are the NEEDS_SYSCALL gap-table pass's own
/// filesystem-owned half. All seven landed at 471-486, not a continuation of this ABI's existing
/// 105-178 invented sequence -- a first attempt at continuing that sequence collided with a
/// *second* set of real, still-inert Linux syscalls sharing those same low numbers further down
/// `external/mit/musl/arch/x86_64/bits/syscall.h.in` (e.g. real `__NR_gettid=186`, which has a live
/// caller inside musl itself, `src/thread/synccall.c`) -- see that file's own comment on
/// `__NR_flock` (right near `__NR_fsync`) for the full story on why 471-486 is provably
/// collision-free instead. `SYS_FSYNC`/`SYS_SYNC` put delayed writes on the disk (`sync_file`,
/// `bcache::flush_all`) -- one file's, or every one. `SYS_FTRUNCATE`/`SYS_FALLOCATE` resize a file's real content
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
/// numbers start at 100, and `external/mit/musl/src/unistd/fdatasync.c` issues this exact number
/// directly, no OxideBSD-side remap needed, matching `SYS_PREAD`/`SYS_PWRITE`'s own precedent).
/// Registered straight at `oxfs_fsync`: `fdatasync(2)` may skip metadata, and writing the inode
/// record too costs one block at most.
const SYS_FDATASYNC: u64 = 75;
const SYS_FTRUNCATE: u64 = 473;
const SYS_FALLOCATE: u64 = 474;
const SYS_FLOCK: u64 = 475;
const SYS_STATFS: u64 = 476;
const SYS_FSTATFS: u64 = 477;

/// Continues past `SYS_UMASK = 487` (the highest number assigned anywhere in this ABI before this
/// pass -- see `sys/modules/posix_compat`), not the `471`-`477` batch above -- confirmed via the same
/// "grep every still-inert real Linux `__NR_*` value in `bits/syscall.h.in`" audit those numbers
/// needed: none of real Linux's own `link`/`mknod`/`mknodat`/`chroot`/`getrusage` values (86/133/
/// 259/161/98) land anywhere near 488-491. `SYS_LINK`/`SYS_MKNOD` implement real hard links and
/// device-node creation (see `oxfs_link`/`oxfs_mknod`'s own doc comments -- neither existed before
/// this pass, since `Inode` had no link count and this filesystem had no device-node concept
/// distinct from `dev_open`'s own magic-path interception). `SYS_CHROOT` gives each process a real,
/// per-process root inode (`Process::root_inode` in `sys/process.rs`).
const SYS_LINK: u64 = 488;
const SYS_MKNOD: u64 = 489;
const SYS_CHROOT: u64 = 490;
/// The `*at()` family -- see the "`*at()` family" section below for the shared `RawAtPath` wire
/// format. Continues past `SYS_GETSOCKNAME=559`, the highest number assigned before these; `574`
/// (`SYS_EXECVEAT`) lives in `native_abi`, next to `execve`. musl remaps each real Linux name
/// (`openat`, `newfstatat`, ...) to these in `arch/x86_64/bits/syscall.h.in`. `SYS_UTIMENSAT_AT` is
/// a separate number (musl's `utimensat` name now maps to it) because the older path-only
/// `SYS_UTIMENSAT` (167) is still called directly by `lib/oxlibc`.
const SYS_OPENAT: u64 = 560;
const SYS_MKDIRAT: u64 = 561;
const SYS_MKNODAT: u64 = 562;
const SYS_FCHOWNAT: u64 = 563;
const SYS_NEWFSTATAT: u64 = 564;
const SYS_UNLINKAT: u64 = 565;
const SYS_RENAMEAT: u64 = 566;
const SYS_LINKAT: u64 = 567;
const SYS_SYMLINKAT: u64 = 568;
const SYS_READLINKAT: u64 = 569;
const SYS_FCHMODAT: u64 = 570;
const SYS_FACCESSAT: u64 = 571;
const SYS_UTIMENSAT_AT: u64 = 572;
const SYS_RENAMEAT2: u64 = 573;

/// Same real POSIX value FAT32's own `O_CREAT` already uses (`0o100`, not an arbitrary bit) --
/// see `modules/fat32`'s own doc comment for why matching the real bit matters (musl's real
/// `open()` passes real POSIX flag values).
const O_CREAT: u64 = 0o100;

/// Real generic (this target has no x86_64-specific override, see `external/mit/musl/arch/
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
/// (`sys/syscall/ffi.rs`'s `sys_fcntl` consults that one instead). Found live via `shm_open/
/// 11-1.c` (the Open POSIX Test Suite pilot): real `shm_open()` (`external/mit/musl/src/mman/
/// shm_open.c`) always passes this to `open()` directly, not through a separate `fcntl()` call --
/// `oxfs_open`'s own tail (see below) is what actually marks the returned fd.
const O_CLOEXEC: u64 = 0o2000000;
/// Real `O_DIRECTORY`/`O_NOFOLLOW` (x86_64/generic musl values). Honored by `oxfs_open` for an
/// existing path: `ENOTDIR` if the target isn't a directory, `ELOOP` if the final component is a
/// symlink. Found needed by libc++'s `std::filesystem::remove_all`, which `openat(O_DIRECTORY|
/// O_NOFOLLOW)`s every entry and relies on exactly those two errors to tell "recurse" from
/// "unlink" -- both used to be silently ignored.
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;

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
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
/// Real POSIX mask isolating the type bits above out of a raw `mode_t` -- used by `oxfs_mknod` to
/// read the caller's requested node type back out of its own `mode` argument.
const S_IFMT: u32 = 0o170000;

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
const DT_FIFO: u8 = 1;
const DT_SOCK: u8 = 12;

const EBADF: i64 = 9;
const ENOENT: i64 = 2;
const EBUSY: i64 = 16;
const EEXIST: i64 = 17;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const ENFILE: i64 = 23;
const EMFILE: i64 = 24;
const ENOSPC: i64 = 28;
const EIO: i64 = 5;
const EINVAL: i64 = 22;
const ERANGE: i64 = 34;
/// musl's real value -- `fchmodat(AT_SYMLINK_NOFOLLOW)` on a symlink (symlink permission bits
/// don't exist here, matching Linux), and unsupported `renameat2` flags.
const EOPNOTSUPP: i64 = 95;
/// musl's real compiled value (`external/mit/musl/arch/generic/bits/errno.h`, `29` -- same on
/// FreeBSD, no divergence to worry about here). Returned by `oxfs_lseek` for a fd this filesystem
/// has no real position to seek within (an in-progress `Write`, or a synthetic `/dev/*` node).
const ESPIPE: i64 = 29;
/// musl's value (`39`); used to be FreeBSD's `66`, which musl reads as `EREMOTE`.
const ENOTEMPTY: i64 = 39;
/// Real value (`3`, same on FreeBSD/Linux) -- returned when a `/proc/<pid>/...` path's `pid`
/// vanishes between `proc_open`'s own existence check and the kernel accessor call that follows it.
const ESRCH: i64 = 3;
/// musl's real *compiled* value (`external/mit/musl/arch/generic/bits/errno.h:40`) -- **not**
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
/// musl's `ENODEV`: an `nmount` file-system type that doesn't exist.
const ENODEV: i64 = 19;
const EACCES: i64 = 13;
const EADDRINUSE: i64 = 98;
const ENOTSOCK: i64 = 88;
/// musl's real *compiled* value (`external/mit/musl/arch/generic/bits/errno.h:11`) -- `EWOULDBLOCK`
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
/// musl's real *compiled* value (`external/mit/musl/arch/generic/bits/errno.h:19`). Returned by
/// `oxfs_link` when `existing` and the new parent directory fall in different inode pools (the
/// real, disk-persisted pool vs. a tmpfs mount's own in-memory-only pool) -- real POSIX "different
/// filesystem" behavior, and load-bearing here specifically to stop a tmpfs-pool inode from
/// gaining a real, disk-persisted name that points at content never actually written through (see
/// `alloc_inode_in`'s own doc comment for the same real/tmpfs-pool concern elsewhere).
const EXDEV: i64 = 18;
/// musl's real *compiled* value (`external/mit/musl/arch/generic/bits/errno.h:6`). Returned by
/// `oxfs_open` when a real `InodeKind::Device` entry's major:minor doesn't match one of the four
/// synthetic devices this kernel can actually service -- see `known_device`'s own doc comment for
/// the deliberately small, honestly documented scope boundary this represents.
const ENXIO: i64 = 6;

/// The disk filesystem's size in data blocks, from its superblock (or, at format, from the
/// device: `layout_for`). Block numbers `0..disk_blocks()` are the disk pool's; tmpfs's start at
/// `TMPFS_BLOCK_BASE`, far above any disk this can describe. (Until the 128 MB floor,
/// `OxideBSD-doc/RAM_FLOOR.md` §3.1.3, this was a compile-time 1 GiB `NUM_BLOCKS`, every block of
/// it held in RAM.)
static mut DISK_BLOCKS: u32 = 0;
/// Bitmap blocks: one bit per data block, `BITS_PER_BITMAP_BLOCK` to a block.
static mut BITMAP_BLOCKS: u32 = 0;
/// Device block holding data block `0`: right after the superblock and the bitmap.
static mut DATA_BLOCK_OFFSET: u32 = 0;

fn disk_blocks() -> u32 {
    // SAFETY: set once at mount or format, inside `module_init`.
    unsafe { *core::ptr::addr_of!(DISK_BLOCKS) }
}

fn bitmap_blocks() -> u32 {
    // SAFETY: as `disk_blocks`.
    unsafe { *core::ptr::addr_of!(BITMAP_BLOCKS) }
}

fn data_block_offset() -> u32 {
    // SAFETY: as `disk_blocks`.
    unsafe { *core::ptr::addr_of!(DATA_BLOCK_OFFSET) }
}


fn set_layout(data_blocks: u32, bitmap: u32) {
    // SAFETY: inside `module_init`, before any syscall.
    unsafe {
        *core::ptr::addr_of_mut!(DISK_BLOCKS) = data_blocks;
        *core::ptr::addr_of_mut!(BITMAP_BLOCKS) = bitmap;
        *core::ptr::addr_of_mut!(DATA_BLOCK_OFFSET) = BITMAP_START + bitmap;
    }
}
/// Inode numbers: the disk filesystem's are `0..TMPFS_INODE_BASE`, tmpfs mounts' are
/// `TMPFS_INODE_BASE..TMPFS_INODE_LIMIT`. Neither pool has a fixed inode count: each keeps its
/// inodes in an inode file (`InodeTable`) that grows a block at a time from its own block pool, so
/// the practical limit is free space (a 1 GiB pool holds at most ~8.4 million 128-byte inodes).
/// The disk pool gets nearly all of `u32`; tmpfs, scratch space, gets the top 2^24 numbers.
/// (Until `SUPERBLOCK_VERSION` 4 the disk pool was a fixed table of 8192 inodes, raised by hand
/// each time the seeded tree outgrew it.)
const TMPFS_INODE_BASE: u32 = MAX_DISK_INODES;
/// One past the last tmpfs inode number (`u32::MAX` itself is never handed out).
const TMPFS_INODE_LIMIT: u32 = u32::MAX;

/// A second, purely in-memory pool for tmpfs mounts and devfs, whose `/dev/shm` holds POSIX
/// shared memory; not persisted. Its size is fixed at boot from RAM (`tmpfs_pool_blocks`):
/// `RAM / 16`, at least `TMPFS_MIN_BLOCKS` (8 MiB: a 4 MiB `shm_open` object, `mmap/1-2.c`, must
/// fit) and at most `TMPFS_MAX_BLOCKS` (64 MiB). Block numbers from `TMPFS_BLOCK_BASE` and inode
/// numbers from `TMPFS_INODE_BASE` belong to it, far above anything the disk pool hands out, so
/// every accessor (`read_block`/`write_block`/`read_inode`/`dir_lookup`/...) works over one number
/// space and only the allocators (`inode_ensure_block_at`, `alloc_inode_in`), `block_ptr` and the
/// disk-persistence hooks need to know which pool a number is in.
const TMPFS_BLOCK_BASE: u32 = MAX_DISK_BLOCKS;
const TMPFS_MIN_BLOCKS: usize = 2048;
const TMPFS_MAX_BLOCKS: usize = 16384;


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


/// Synthetic `/proc/<pid>/{stat,cmdline,status}` content buffer -- comfortably covers any of the
/// three for this kernel's simple, single-threaded processes; longer content silently truncates
/// (accepted simplification for this tier, not indefinite-length-safe).
const PROC_BUFFER: usize = 1024;
/// How many `/proc` files can be open at once (`PROC_RENDERS`): 256 KiB in all.
const MAX_PROC_RENDERS: usize = 256;
/// Base for synthetic `d_ino` values `/proc`'s own `getdents` records report -- nothing
/// dereferences these as real inodes (there's no real inode backing any `/proc` entry), they only
/// need to be distinct and non-zero. Above every real inode number (those are `u32`).
const PROC_INODE_BASE: u64 = 1 << 32;

/// Sentinel tag marking `Process::cwd` (see `sys/process.rs`'s own doc comment -- a `u64`, fully
/// opaque to the kernel) as a synthetic `/proc` location rather than a real inode number. Real
/// inode numbers are `u32`, so the top bit of the `u64` is always free.
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
/// write buffer regardless of use (`OpenFile::Write` was the enum's dominant variant), so 256
/// was chosen as "enough headroom to stop the cascade, cheap enough to afford" -- not enough to
/// let `shm_open/23-1.c` itself actually pass (it needs up to 1000 real objects live at once, one
/// per `shm_open`'d name, held open until each holding process's own loop finishes).
///
/// **Bumped again to 2048 once the real fix landed**: `OpenFile::Write`'s buffer moved out of the
/// enum into a separate pool. Since the 128 MB floor (`OxideBSD-doc/RAM_FLOOR.md` §3.1.5-6) no
/// variant has a content buffer at all (writes go straight to the inode, directory fds have no
/// formatted listing, `/proc` renders live in `PROC_RENDERS`): the largest variants are the ones
/// carrying a name, a few hundred bytes.
const MAX_OPEN_FILES: usize = 2048;

const MAX_CWD_PATH: usize = 256;
const MAX_CWD_DEPTH: usize = 32;

/// Real POSIX `{PATH_MAX}` (musl's own compiled value, `external/mit/musl/include/limits.h`) --
/// the real whole-path-length limit, real `ENAMETOOLONG` when exceeded. Distinct from `NAME_MAX`'s
/// own per-*component* check in `resolve_parent` below (`InvalidPath`/`EINVAL`) -- this is real
/// POSIX text for the *whole* path, not any one component of it. Bigger than `MAX_CWD_PATH` (256,
/// a real but much smaller internal buffer for formatting *this filesystem's own* absolute cwd
/// string) -- the two serve unrelated purposes and were never meant to be the same number.
///
/// **Does not close `shm_open/39-2.c`/`shm_unlink/10-2.c`** (Open POSIX Test Suite pilot), the two
/// tests that originally flagged this gap -- investigated, not a kernel bug: both construct a name
/// with *embedded* `/` characters to build a genuinely `PATH_MAX`-length string, but real, upstream
/// musl's own `__shm_mapname()` (`external/mit/musl/src/mman/shm_open.c`) rejects any embedded `/`
/// as `EINVAL` *before* ever checking length -- real POSIX explicitly leaves embedded-slash
/// handling in a `shm_open()` name implementation-defined, so this is legitimate, spec-legal musl
/// behavior, not a bug to patch around. This check is still real and correct for what it actually
/// covers: an ordinary, non-shm path (a plain `open()`/`unlink()`/`mkdir()`/... on a genuinely
/// too-long path with no embedded weirdness) now gets the real `ENAMETOOLONG` POSIX requires,
/// where it previously fell through to whatever `resolve_parent`'s own component walk happened to
/// produce instead.
const OXFS_PATH_MAX: usize = 4096;

const BIG_FILE_LEN: usize = 5000;

/// One of the self-check's fixtures in `/usr/tests/oxfs` (seeded by `format_fresh_filesystem`).
fn self_check_fixture(name: &[u8]) -> Option<u32> {
    let usr = dir_lookup(ROOT_INODE, b"usr")?;
    dir_lookup(dir_lookup(dir_lookup(usr, b"tests")?, b"oxfs")?, name)
}


/// `static mut`, not `static` -- same requirement `modules/fat32`'s own `DISK`/`OPEN_FILES` have
/// (see that module's doc comment): every read happens from within this module's own exported,
/// syscall-reachable functions, whose results feed observably into `oxidebsd_log`/syscall return
/// values, so the optimizer can't treat any write as an unobservable dead store. All-zero initial
/// values place these in `.bss` (not baked into the merged object's own size).
/// Free blocks in each bitmap block (`BITS_PER_BITMAP_BLOCK` data blocks), resident so the
/// allocator and `statfs` never read a full bitmap block to learn it's full. Allocated in
/// `init_pools` for the largest filesystem the device can hold; counts are set at mount/format.
static mut FREE_COUNTS: *mut u32 = core::ptr::null_mut();
/// The tmpfs pool (`TMPFS_BLOCK_BASE`): `TMPFS_BLOCKS` blocks from `init_pools`.
static mut TMPFS_PTR: *mut [u8; BLOCK_SIZE] = core::ptr::null_mut();
static mut TMPFS_BLOCKS: u32 = 0;
static mut TMPFS_BLOCK_USED: [bool; TMPFS_MAX_BLOCKS] = [false; TMPFS_MAX_BLOCKS];

/// A fresh inode of `kind`, stamped with the current time.
fn fresh_inode(kind: InodeKind) -> Inode {
    Inode::new(kind, unsafe { oxidebsd_unix_time() })
}

fn is_tmpfs_block(n: u32) -> bool {
    n >= TMPFS_BLOCK_BASE
}

/// How many blocks the tmpfs pool gets on a machine with `ram` bytes.
fn tmpfs_pool_blocks(ram: u64) -> usize {
    (ram as usize / 16 / BLOCK_SIZE).clamp(TMPFS_MIN_BLOCKS, TMPFS_MAX_BLOCKS)
}

/// Tmpfs block `n`'s storage (`is_tmpfs_block(n)`). Disk blocks live in the cache (`bcache`).
fn tmpfs_ptr(n: u32) -> *mut [u8; BLOCK_SIZE] {
    // SAFETY: the pool is set once by `init_pools` before any syscall can reach here, and callers
    // only pass tmpfs block numbers this module handed out.
    unsafe { TMPFS_PTR.add((n - TMPFS_BLOCK_BASE) as usize) }
}

/// Bitmap block `index`'s free count.
fn free_count(index: u32) -> &'static mut u32 {
    // SAFETY: `index < bitmap_blocks()`, inside the `init_pools` allocation.
    unsafe { &mut *FREE_COUNTS.add(index as usize) }
}

/// One pool's inodes: an inode file whose data blocks, from that pool, hold packed inodes
/// (`INODES_PER_BLOCK` per block, inode number `base + slot` at byte `slot * INODE_STRIDE`). The
/// file's own inode record isn't numbered: the disk pool's is kept in the superblock, the tmpfs
/// pool's only here. The table grows a block (32 inodes) at a time when no slot is free; freshly
/// allocated blocks are zeroed, and a zeroed record decodes as `InodeKind::Free`.
#[derive(Clone, Copy)]
struct InodeTable {
    file: Inode,
    /// Slots in the file (`file.size / INODE_STRIDE`).
    count: u32,
    /// Slots holding `InodeKind::Free`, kept exact by `write_inode`.
    free: u32,
    /// Where `alloc_inode_from` starts looking.
    hint: u32,
}

impl InodeTable {
    const EMPTY: InodeTable = InodeTable { file: Inode::FREE, count: 0, free: 0, hint: 0 };
}

static mut DISK_INODES: InodeTable = InodeTable::EMPTY;
static mut TMPFS_INODES: InodeTable = InodeTable::EMPTY;

/// Whether `n` is a tmpfs mount's inode rather than the disk filesystem's.
fn is_tmpfs_inode(n: u32) -> bool {
    n >= TMPFS_INODE_BASE
}

fn inode_table(tmpfs: bool) -> &'static mut InodeTable {
    // SAFETY: single-core, syscall-serialized access (as every pool here); callers never hold the
    // reference across a call that takes it again.
    unsafe {
        if tmpfs {
            &mut *core::ptr::addr_of_mut!(TMPFS_INODES)
        } else {
            &mut *core::ptr::addr_of_mut!(DISK_INODES)
        }
    }
}

/// The table `n` belongs to, and its slot there.
fn table_slot(n: u32) -> (bool, u32) {
    if is_tmpfs_inode(n) { (true, n - TMPFS_INODE_BASE) } else { (false, n) }
}

/// Every inode number either table holds, free or not.
fn all_inode_numbers() -> impl Iterator<Item = u32> {
    let disk = inode_table(false).count;
    let tmpfs = inode_table(true).count;
    (0..disk).chain(TMPFS_INODE_BASE..TMPFS_INODE_BASE + tmpfs)
}
static mut OPEN_FILES: [Option<(u64, OpenFile)>; MAX_OPEN_FILES] = [None; MAX_OPEN_FILES];

/// Rendered `/proc` files (`OpenFile::ProcRead::render`), pooled so an `OPEN_FILES` slot doesn't
/// carry `PROC_BUFFER` bytes it rarely needs. A file is rendered once at `open`, so a reader sees
/// one consistent snapshot however it splits its reads.
static mut PROC_RENDERS: [[u8; PROC_BUFFER]; MAX_PROC_RENDERS] = [[0; PROC_BUFFER]; MAX_PROC_RENDERS];
static mut PROC_RENDER_USED: [bool; MAX_PROC_RENDERS] = [false; MAX_PROC_RENDERS];

/// Claims a `PROC_RENDERS` slot, `None` when every one is in use.
fn alloc_proc_render() -> Option<usize> {
    // SAFETY: single-core, syscall-serialized, as every pool here.
    let used = unsafe { &mut *core::ptr::addr_of_mut!(PROC_RENDER_USED) };
    let idx = used.iter().position(|&u| !u)?;
    used[idx] = true;
    Some(idx)
}

fn free_proc_render(idx: usize) {
    // SAFETY: as `alloc_proc_render`.
    unsafe { (*core::ptr::addr_of_mut!(PROC_RENDER_USED))[idx] = false };
}

fn proc_render(idx: usize) -> &'static mut [u8; PROC_BUFFER] {
    // SAFETY: as `alloc_proc_render`; callers never hold two borrows of one slot.
    unsafe { &mut (*core::ptr::addr_of_mut!(PROC_RENDERS))[idx] }
}

/// Registers a `ProcRead` for the `len` bytes rendered into slot `render`, releasing the slot if
/// no descriptor can be made.
fn register_proc_render(render: usize, len: usize) -> i64 {
    let fd = register_open_file(OpenFile::ProcRead { render: render as u16, len, position: 0 });
    if fd < 0 {
        free_proc_render(render);
    }
    fd
}

/// Claims real kernel-allocated storage for the cache, `FREE_COUNTS` and `TMPFS_PTR` -- must run
/// first, before
/// `module_init`'s mount-or-format decision (or anything else) ever calls `read_block`/
/// `write_block`. Returns `false` on failure (kernel out of memory), which
/// `module_init` treats as a fatal `module_init` failure like any other -- this module's own
/// `fatal_on_panic = true` (see `sys/kernel_main.rs`, kernel tree) reboots rather than resuming
/// with a filesystem that has nowhere to actually store a block.
fn init_pools() -> bool {
    // SAFETY: FFI calls to kernel-exported functions, matching their declared signatures.
    let ram = unsafe { oxidebsd_physmem_bytes() };
    let device_blocks = unsafe { oxidebsd_block_device_blocks() };
    if !bcache::init(ram) {
        return false;
    }
    let (_, most_bitmap_blocks) = layout_for(device_blocks);
    let counts = unsafe { oxidebsd_module_alloc_zeroed(most_bitmap_blocks.max(1) as u64 * 4) };
    if counts == 0 {
        return false;
    }
    // SAFETY: inside `module_init`, before any syscall.
    unsafe { FREE_COUNTS = counts as *mut u32 };
    let tmpfs_blocks = tmpfs_pool_blocks(ram);
    let tmpfs_addr = unsafe { oxidebsd_module_alloc_zeroed((tmpfs_blocks * BLOCK_SIZE) as u64) };
    if tmpfs_addr == 0 {
        return false;
    }
    // SAFETY: both addresses are freshly kernel-allocated, zeroed, and mapped read/write for
    // exactly the sizes requested above -- never written through any other pointer.
    unsafe {
        TMPFS_PTR = tmpfs_addr as *mut [u8; BLOCK_SIZE];
        TMPFS_BLOCKS = tmpfs_blocks as u32;
    }
    true
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

/// Runs `f` on block `n` in place, for reads that don't want `read_block`'s 4 KiB copy (index
/// blocks, inode records). `f` must not touch another block: a disk block is lent from the cache.
fn with_block<R>(n: u32, f: impl FnOnce(&[u8; BLOCK_SIZE]) -> R) -> R {
    if is_tmpfs_block(n) {
        // SAFETY: see `tmpfs_ptr`.
        f(unsafe { &*tmpfs_ptr(n) })
    } else {
        bcache::with(data_block_offset() + n, f)
    }
}

fn read_block(n: u32) -> [u8; BLOCK_SIZE] {
    with_block(n, |b| *b)
}

/// The regular file whose writes are being delayed (§3.3.2), `NO_OWNER` when none: set by
/// `delay_writes_of` for the length of a write, resize or atime update of that file.
static mut DELAY_OWNER: u32 = NO_OWNER;
const NO_OWNER: u32 = u32::MAX;

fn delay_owner() -> Option<u32> {
    // SAFETY: single-core, syscall-serialized.
    let owner = unsafe { *core::ptr::addr_of!(DELAY_OWNER) };
    (owner != NO_OWNER).then_some(owner)
}

/// Restores the previous delay context when dropped.
struct Delayed(u32);

impl Drop for Delayed {
    fn drop(&mut self) {
        // SAFETY: as `delay_owner`.
        unsafe { *core::ptr::addr_of_mut!(DELAY_OWNER) = self.0 };
    }
}

/// Until the returned guard drops, the data blocks, index blocks and inode record of `n` are
/// written back later instead of at once -- if `n` is a regular file on the disk. Everything
/// else (directories, symlinks, names, the bitmap) stays synchronous (§3.3.1).
fn delay_writes_of(n: u32) -> Delayed {
    // SAFETY: as `delay_owner`.
    let previous = unsafe { *core::ptr::addr_of!(DELAY_OWNER) };
    if !is_tmpfs_inode(n) && read_inode(n).kind == InodeKind::File {
        unsafe { *core::ptr::addr_of_mut!(DELAY_OWNER) = n };
    }
    Delayed(previous)
}

/// Stores block `n`. Inside `delay_writes_of`, it's that file's data: left dirty in the cache.
/// Otherwise it reaches the disk before the system call returns (or at `flush_all_to_disk`
/// while formatting).
fn write_block(n: u32, data: &[u8; BLOCK_SIZE]) {
    if is_tmpfs_block(n) {
        // SAFETY: see `tmpfs_ptr`.
        unsafe { *tmpfs_ptr(n) = *data };
    } else if let Some(owner) = delay_owner() {
        bcache::store(data_block_offset() + n, data, bcache::Kind::Data(owner));
    } else {
        bcache::write(data_block_offset() + n, data, bcache::Kind::Meta);
    }
}

/// `write_block` for an index (indirect) block: delayed as that file's index block, so it can't
/// reach the disk before the data blocks it points at.
fn write_index_block(n: u32, data: &[u8; BLOCK_SIZE]) {
    if is_tmpfs_block(n) {
        // SAFETY: see `tmpfs_ptr`.
        unsafe { *tmpfs_ptr(n) = *data };
    } else if let Some(owner) = delay_owner() {
        bcache::store(data_block_offset() + n, data, bcache::Kind::Index(owner));
    } else {
        bcache::write(data_block_offset() + n, data, bcache::Kind::Meta);
    }
}

/// Bitmap block and bit for disk block `n`.
fn bitmap_position(n: u32) -> (u32, usize) {
    (n / BITS_PER_BITMAP_BLOCK, (n % BITS_PER_BITMAP_BLOCK) as usize)
}

fn block_used(n: u32) -> bool {
    if is_tmpfs_block(n) {
        // SAFETY: single-core, syscall-serialized, as every pool here.
        return unsafe { (*core::ptr::addr_of!(TMPFS_BLOCK_USED))[(n - TMPFS_BLOCK_BASE) as usize] };
    }
    let (index, bit) = bitmap_position(n);
    bcache::with(BITMAP_START + index, |b| b[bit / 8] & (1 << (bit % 8)) != 0)
}

/// Marks block `n` used or free: a read-modify-write of its bitmap block through the cache, with
/// that block's free count kept in step.
fn set_block_used(n: u32, used: bool) {
    if is_tmpfs_block(n) {
        // SAFETY: as `block_used`.
        unsafe { (*core::ptr::addr_of_mut!(TMPFS_BLOCK_USED))[(n - TMPFS_BLOCK_BASE) as usize] = used };
        return;
    }
    let (index, bit) = bitmap_position(n);
    let mut block = bcache::read(BITMAP_START + index);
    let was = block[bit / 8] & (1 << (bit % 8)) != 0;
    if was == used {
        return;
    }
    block[bit / 8] ^= 1 << (bit % 8);
    bcache::write(BITMAP_START + index, &block, bcache::Kind::Meta);
    let count = free_count(index);
    if used { *count -= 1 } else { *count += 1 }
}

/// Where inode `n`'s record is: its inode-file block and byte offset. `None` past the table.
fn inode_location(n: u32) -> Option<(u32, usize)> {
    let (tmpfs, slot) = table_slot(n);
    let table = inode_table(tmpfs);
    if slot >= table.count {
        return None;
    }
    let block = inode_block_at(&table.file, slot as usize / INODES_PER_BLOCK)?;
    Some((block, slot as usize % INODES_PER_BLOCK * INODE_STRIDE))
}

/// Inode `n`, or a free one if `n` is past its table.
fn read_inode(n: u32) -> Inode {
    match inode_location(n) {
        Some((block, off)) => with_block(block, |b| unpack_inode(&b[off..off + INODE_STRIDE])),
        None => Inode::FREE,
    }
}

/// Stores inode `n` (persisted with its block, like any data), keeping the table's free count.
/// `n` must be in its table: numbers come from `alloc_inode_from`.
fn write_inode(n: u32, inode: Inode) {
    let Some((block, off)) = inode_location(n) else {
        return;
    };
    let was_free = with_block(block, |b| b[off] == 0);
    let mut data = read_block(block);
    pack_inode(&inode, &mut data[off..off + INODE_STRIDE]);
    if is_tmpfs_block(block) {
        write_block(block, &data);
    } else {
        // An inode-file block: written after the dirty data and index blocks of the inodes in it
        // (bcache's ordering); left dirty only for the file whose writes are being delayed.
        let kind = bcache::Kind::Inodes(n - n % INODES_PER_BLOCK as u32);
        let dev = data_block_offset() + block;
        if delay_owner() == Some(n) {
            bcache::store(dev, &data, kind);
        } else {
            bcache::write(dev, &data, kind);
        }
    }
    let is_free = inode.kind == InodeKind::Free;
    let table = inode_table(is_tmpfs_inode(n));
    match (was_free, is_free) {
        (true, false) => table.free -= 1,
        (false, true) => table.free += 1,
        _ => {}
    }
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
    let total = disk_blocks();
    let mut index = start / BITS_PER_BITMAP_BLOCK;
    while index < bitmap_blocks() {
        // A full bitmap block is skipped on its resident count, without reading it.
        if *free_count(index) > 0 {
            let base = index * BITS_PER_BITMAP_BLOCK;
            let from = start.max(base) - base;
            let end = (total - base).min(BITS_PER_BITMAP_BLOCK);
            let found = bcache::with(BITMAP_START + index, |b| {
                (from..end).find(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) == 0)
            });
            if let Some(bit) = found {
                let n = base + bit;
                set_block_used(n, true);
                write_block(n, &[0u8; BLOCK_SIZE]);
                unsafe { *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK) = n + 1 };
                return Some(n);
            }
        }
        index += 1;
    }
    None
}

/// Like `alloc_block`, but fills the fresh block with `0xFF` bytes, not zero -- required for an
/// indirect block specifically: each 4-byte slot is a block-number pointer, and a plain
/// zero-filled block would decode every slot as block `0` (a real, valid block), not `NO_BLOCK`
/// ("no pointer here yet").
fn alloc_indirect_block() -> Option<u32> {
    let n = alloc_block()?;
    write_index_block(n, &[0xFFu8; BLOCK_SIZE]);
    Some(n)
}

fn alloc_inode() -> Option<u32> {
    alloc_inode_from(false)
}

// --- Reclamation -----------------------------------------------------------------------------
//
// An inode is freed, with every block it addresses, once nothing refers to it: no name
// (`nlink == 0`), no oxfs descriptor, and nothing in the kernel (`oxidebsd_inode_in_use`: a working
// or root directory, a file mapping that writes back by inode number, a bound socket file). One
// the kernel still holds becomes an orphan, retried after later closes and unlinks; one left
// over at a reboot is freed by the sweep after mounting (`sweep_unnamed_inodes`). Until this
// existed, oxfs freed nothing: every temporary file ever made kept its inode and blocks.

/// Returns block `n` to its pool; the disk pool's allocation cursor steps back so it's reused.
fn free_block(n: u32) {
    if !is_tmpfs_block(n) {
        bcache::discard(data_block_offset() + n);
    }
    set_block_used(n, false);
    if !is_tmpfs_block(n) {
        // SAFETY: single-core, syscall-serialized, as `alloc_block`.
        unsafe {
            let cursor = &mut *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK);
            if n < *cursor {
                *cursor = n;
            }
        }
    }
}

/// Frees index block `ib` and the data blocks it points to.
fn free_index_block(ib: u32) {
    for slot in 0..PTRS_PER_INDIRECT {
        let b = read_index_ptr(ib, slot);
        if b != NO_BLOCK {
            free_block(b);
        }
    }
    free_block(ib);
}

/// Frees every block `inode` addresses, index blocks included.
fn free_inode_blocks(inode: &Inode) {
    for &b in &inode.direct {
        if b != NO_BLOCK {
            free_block(b);
        }
    }
    if inode.indirect != NO_BLOCK {
        free_index_block(inode.indirect);
    }
    if inode.double_indirect != NO_BLOCK {
        for slot in 0..PTRS_PER_INDIRECT {
            let inner = read_index_ptr(inode.double_indirect, slot);
            if inner != NO_BLOCK {
                free_index_block(inner);
            }
        }
        free_block(inode.double_indirect);
    }
}

/// Whether an oxfs descriptor has inode `n` open.
fn inode_is_open(n: u32) -> bool {
    let slots = unsafe { &*core::ptr::addr_of!(OPEN_FILES) };
    slots.iter().flatten().any(|(_, file)| match file {
        OpenFile::FileRead { inode, .. } | OpenFile::DirListing { inode, .. } => *inode == n,
        OpenFile::Write { inode, .. } => *inode == n,
        _ => false,
    })
}

/// Frees inode `n` if nothing refers to it any more (see the section comment); keeps it as an
/// orphan if only the kernel does.
fn maybe_release(n: u32) {
    let inode = read_inode(n);
    if n == ROOT_INODE || inode.kind == InodeKind::Free || inode.nlink > 0 || inode_is_open(n) {
        return;
    }
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    if unsafe { oxidebsd_inode_in_use(n as u64) } != 0 {
        add_orphan(n);
        return;
    }
    remove_orphan(n);
    release_inode(n, inode);
}

/// Every change to a file's contents (`write_inode_at`, `write_inode_data`, `resize_inode_data`)
/// and every freed inode (`release_inode`) goes through here first, so the kernel's page cache
/// never maps a file's old pages into a new exec or mapping, nor a freed inode's pages into the
/// file that reuses its number.
fn content_changed(inode_num: u32) {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_content_changed(inode_num as u64) };
}

/// Frees inode `n` (whose record is `inode`) and its blocks. The record goes first: interrupted
/// between the two, the disk leaks blocks rather than keeping an inode that points at blocks
/// someone else may be given.
fn release_inode(n: u32, inode: Inode) {
    content_changed(n);
    // Its unwritten data and index blocks are about to be freed: never write them.
    bcache::discard_owned(n);
    write_inode(n, Inode::FREE);
    free_inode_blocks(&inode);
    trim_inode_table(is_tmpfs_inode(n));
}

/// Unlinked inodes the kernel still referred to; `u32::MAX` is an empty slot. A full list only
/// delays freeing until the next boot's sweep.
const MAX_ORPHANS: usize = 256;
static mut ORPHANS: [u32; MAX_ORPHANS] = [u32::MAX; MAX_ORPHANS];

fn orphans() -> &'static mut [u32; MAX_ORPHANS] {
    // SAFETY: single-core, syscall-serialized, as every pool here.
    unsafe { &mut *core::ptr::addr_of_mut!(ORPHANS) }
}

fn add_orphan(n: u32) {
    let list = orphans();
    if list.contains(&n) {
        return;
    }
    if let Some(slot) = list.iter_mut().find(|s| **s == u32::MAX) {
        *slot = n;
    }
}

fn remove_orphan(n: u32) {
    for slot in orphans().iter_mut().filter(|s| **s == n) {
        *slot = u32::MAX;
    }
}

/// Tries each orphan again (after a close or unlink: a mapping or working directory may be gone).
fn retry_orphans() {
    for i in 0..MAX_ORPHANS {
        let n = orphans()[i];
        if n != u32::MAX {
            orphans()[i] = u32::MAX;
            maybe_release(n);
        }
    }
}

/// After mounting: frees every inode left without a name by the last boot (open, mapped or a
/// working directory when it went down). Nothing can refer to one yet. Runs once persistence is
/// on, so the frees and any trimming of the inode file reach the disk.
fn sweep_unnamed_inodes() {
    let count = inode_table(false).count;
    let mut freed: u32 = 0;
    for n in 1..count {
        let inode = read_inode(n);
        if inode.kind != InodeKind::Free && inode.nlink == 0 {
            release_inode(n, inode);
            freed += 1;
        }
    }
    if freed > 0 {
        let mut msg_buf = [0u8; 64];
        let mut msg = ByteBuf { buf: &mut msg_buf, len: 0 };
        msg.push_bytes(b"[oxfs] freed ");
        msg.push_decimal(freed);
        msg.push_bytes(if freed == 1 { b" unnamed inode" } else { b" unnamed inodes" });
        msg.push_bytes(b" left by the last boot\n");
        let len = msg.len;
        log_bytes(&msg_buf[..len]);
    }
}

/// Clears inode-file block `index`'s pointer in `file` and frees the block, along with any index
/// block that pointer was the first entry of. Only the table's last block is ever unmapped, so an
/// index block whose first entry goes has no others left.
fn unmap_last_block(file: &mut Inode, index: usize) {
    if index < DIRECT_BLOCKS {
        free_block(file.direct[index]);
        file.direct[index] = NO_BLOCK;
        return;
    }
    let clear = |ib: u32, slot: usize| {
        let mut data = read_block(ib);
        let b = u32::from_le_bytes(data[slot * 4..slot * 4 + 4].try_into().unwrap());
        data[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
        write_block(ib, &data);
        b
    };
    let i = index - DIRECT_BLOCKS;
    if i < PTRS_PER_INDIRECT {
        free_block(clear(file.indirect, i));
        if i == 0 {
            free_block(file.indirect);
            file.indirect = NO_BLOCK;
        }
        return;
    }
    let i = i - PTRS_PER_INDIRECT;
    let (outer, inner) = (i / PTRS_PER_INDIRECT, i % PTRS_PER_INDIRECT);
    let inner_block = read_index_ptr(file.double_indirect, outer);
    free_block(clear(inner_block, inner));
    if inner == 0 {
        clear(file.double_indirect, outer);
        free_block(inner_block);
        if outer == 0 {
            free_block(file.double_indirect);
            file.double_indirect = NO_BLOCK;
        }
    }
}

/// Gives the table's last blocks back to the pool while they hold only free inodes (the first
/// block, holding the root, always stays). The disk table's new shape goes to the superblock
/// before its blocks are freed, so an interruption can only leak them.
fn trim_inode_table(tmpfs: bool) {
    let base = if tmpfs { TMPFS_INODE_BASE } else { 0 };
    let per_block = INODES_PER_BLOCK as u32;
    loop {
        let table = *inode_table(tmpfs);
        if table.count <= per_block {
            return;
        }
        let first = table.count - per_block;
        if (first..table.count).any(|slot| read_inode(base + slot).kind != InodeKind::Free) {
            return;
        }
        let mut file = table.file;
        file.size = first as u64 * INODE_STRIDE as u64;
        {
            let t = inode_table(tmpfs);
            t.count = first;
            t.free -= per_block;
            t.hint = t.hint.min(first);
            t.file.size = file.size;
        }
        if !tmpfs && persistence_ready() && block_device_present() {
            write_superblock();
        }
        unmap_last_block(&mut file, first as usize / INODES_PER_BLOCK);
        inode_table(tmpfs).file = file;
        if !tmpfs && persistence_ready() && block_device_present() {
            write_superblock();
        }
    }
}

/// A free inode number from the disk (`tmpfs == false`) or tmpfs table, growing the table by a
/// block when none is free. The caller writes the new inode.
fn alloc_inode_from(tmpfs: bool) -> Option<u32> {
    if inode_table(tmpfs).free == 0 {
        grow_inode_table(tmpfs)?;
    }
    let base = if tmpfs { TMPFS_INODE_BASE } else { 0 };
    let table = *inode_table(tmpfs);
    let start = table.hint.min(table.count);
    let slot = (start..table.count)
        .chain(0..start)
        .find(|&slot| read_inode(base + slot).kind == InodeKind::Free)?;
    inode_table(tmpfs).hint = slot + 1;
    Some(base + slot)
}

/// Adds a block of free inodes to a table (`None` when its pool is out of blocks or its number
/// range is used up). The disk table's new shape goes to the superblock.
fn grow_inode_table(tmpfs: bool) -> Option<()> {
    let table = *inode_table(tmpfs);
    let limit = if tmpfs { TMPFS_INODE_LIMIT - TMPFS_INODE_BASE } else { TMPFS_INODE_BASE };
    if table.count as u64 + INODES_PER_BLOCK as u64 > limit as u64 {
        return None;
    }
    let mut file = table.file;
    // A fresh block from `alloc_block` is zeroed: `INODES_PER_BLOCK` free records.
    ensure_block(&mut file, table.count as usize / INODES_PER_BLOCK, tmpfs)?;
    let count = table.count + INODES_PER_BLOCK as u32;
    file.size = count as u64 * INODE_STRIDE as u64;
    let t = inode_table(tmpfs);
    t.file = file;
    t.count = count;
    t.free += INODES_PER_BLOCK as u32;
    if !tmpfs && persistence_ready() && block_device_present() {
        write_superblock();
    }
    Some(())
}

/// `alloc_block`'s tmpfs-pool counterpart -- same linear scan, over the tmpfs pool
/// (`TMPFS_BLOCK_BASE`) instead of `0..NUM_BLOCKS`. Only ever called from `inode_ensure_block_at`,
/// which picks this over `alloc_block` based on which pool `inode_num` falls in -- see that
/// function's own doc comment for why it's the sole call site that needs to know this pool exists.
fn alloc_tmpfs_block() -> Option<u32> {
    let end = TMPFS_BLOCK_BASE + unsafe { *core::ptr::addr_of!(TMPFS_BLOCKS) };
    for i in TMPFS_BLOCK_BASE..end {
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
/// directly by the tmpfs-mount-creation path (`mount_tmpfs`, which has no parent directory to
/// check -- it's creating the mount's own root) and by `alloc_inode_in` below for everything else.
fn alloc_tmpfs_inode() -> Option<u32> {
    alloc_inode_from(true)
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
    if is_tmpfs_inode(parent) {
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
    let off = slot * 4;
    with_block(ib_num, |ib| u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]]))
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
/// **The one place block allocation needs to know about the tmpfs pool** (see `TMPFS_BLOCK_BASE`'s
/// own doc comment): `dir_insert`'s directory-growth path and every real file write both funnel
/// through this single function (confirmed by grep -- `alloc_block`/`alloc_indirect_block` have no
/// other caller), so picking the allocator by whether `inode_num` falls in the tmpfs range here is
/// sufficient to make a tmpfs file/directory's own growth land in the tmpfs pool, with no other
/// call site needing to change.
fn inode_ensure_block_at(inode_num: u32, index: usize) -> Option<u32> {
    let mut inode = read_inode(inode_num);
    let result = ensure_block(&mut inode, index, is_tmpfs_inode(inode_num));
    write_inode(inode_num, inode);
    result
}

/// `inode_ensure_block_at` on an inode record held by the caller (the inode files' own records
/// aren't numbered), allocating from the tmpfs pool if `tmpfs`.
fn ensure_block(inode: &mut Inode, index: usize, tmpfs: bool) -> Option<u32> {
    if index < DIRECT_BLOCKS {
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
            write_index_block(inode.double_indirect, &outer);
        }
        ensure_index_slot(inner_block, inner_slot, tmpfs)
    }
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
    write_index_block(ib_num, &ib);
    Some(nb)
}

/// Reads up to `out.len()` bytes starting at `position` within `inode_num`'s data, honoring its
/// stored `size` (real files only -- directories never call this, they walk raw records instead).
/// Returns the number of bytes actually read (`0` at or past EOF).
fn read_inode_at(inode_num: u32, position: usize, out: &mut [u8]) -> usize {
    let mut written = 0;
    let _ = read_inode_with(inode_num, position, out.len(), |chunk| {
        out[written..written + chunk.len()].copy_from_slice(chunk);
        written += chunk.len();
        Ok(())
    });
    written
}

/// `read_inode_at` into a read transfer (`uio`): straight from the block pool, no buffer in
/// between. `Ok(count)` or `Err(-errno)`.
fn read_inode_uio(inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
    read_inode_with(inode_num, position, uio_resid(uio), |chunk| uio_out(uio, chunk).map(|_| ()))
}

/// The block walk `read_inode_at` and `read_inode_uio` share: hands `sink` up to `max` bytes of
/// `inode_num`'s content from `position`, one block's worth at a time. Stops at end of file, or at
/// a missing block. `Ok(count)`, or the first error `sink` returns.
fn read_inode_with(
    inode_num: u32,
    position: usize,
    max: usize,
    mut sink: impl FnMut(&[u8]) -> Result<(), i64>,
) -> Result<usize, i64> {
    let inode = read_inode(inode_num);
    let size = inode.size as usize;
    if position >= size {
        return Ok(0);
    }
    let n = max.min(size - position);
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
        sink(&block[in_block_off..in_block_off + chunk])?;
        written += chunk;
    }
    Ok(written)
}

/// `FOF_OFFSET` (kernel tree: `crate::kern::subr_uio`): `pread`/`pwrite`, at the transfer's
/// offset instead of the descriptor's position.
const FOF_OFFSET: u64 = 1;

/// Moves `data` out to a read transfer. `Ok(count)` or `Err(-errno)`.
fn uio_out(uio: u64, data: &[u8]) -> Result<usize, i64> {
    // SAFETY: FFI call to a kernel-exported function; a read transfer only reads `data`.
    let r = unsafe { oxidebsd_uiomove(data.as_ptr() as *mut u8, data.len() as u64, uio) };
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// Moves bytes in from a write transfer into `buf`. `Ok(count)` or `Err(-errno)`.
fn uio_in(uio: u64, buf: &mut [u8]) -> Result<usize, i64> {
    // SAFETY: FFI call to a kernel-exported function, with this module's own buffer.
    let r = unsafe { oxidebsd_uiomove(buf.as_mut_ptr(), buf.len() as u64, uio) };
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

fn uio_resid(uio: u64) -> usize {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_uio_resid(uio) as usize }
}

/// Fills a read transfer from `make`, a small buffer at a time (`/dev/zero`, `/dev/random`).
fn fill_uio(uio: u64, mut make: impl FnMut(&mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    let mut chunk = [0u8; 256];
    let mut total = 0;
    loop {
        let n = uio_resid(uio).min(chunk.len());
        if n == 0 {
            return Ok(total);
        }
        make(&mut chunk[..n])?;
        total += uio_out(uio, &chunk[..n])?;
    }
}

/// `Ok(count)` / `Err(-errno)` as an operation's return value.
fn uio_ret(r: Result<usize, i64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

// --- User memory (`OxideBSD-doc/USERMEM.md`) ----------------------------------------------------
//
// A system call's pointer arguments are user addresses: never dereferenced here, only copied in
// and out through the kernel's `oxidebsd_copyin`/`oxidebsd_copyout`, which fail with `EFAULT`
// instead of faulting.

/// Set while `module_init` formats a fresh filesystem: the format self-check calls this module's
/// system call handlers with its own stack buffers, so for that stretch their "user" pointers are
/// this module's memory and are copied plainly (USERMEM.md's kernel segment). No process runs then.
static mut KERNEL_SEGMENT: bool = false;

/// The start of the kernel half of the address space: the format self-check's buffers (on the
/// kernel stack) are all above it, every user address below.
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

fn kernel_segment() -> bool {
    // SAFETY: single-core, syscall-serialized, as every pool here.
    unsafe { *core::ptr::addr_of!(KERNEL_SEGMENT) }
}

/// Copies `dst.len()` bytes in from user memory at `src`. `Err(-EFAULT)` for a bad pointer.
fn copyin_bytes(src: u64, dst: &mut [u8]) -> Result<(), i64> {
    if dst.is_empty() {
        return Ok(());
    }
    // A user-range address goes through the kernel even in kernel-segment mode, so a flag left set
    // by mistake could never make a user pointer a raw access.
    if kernel_segment() && src >= KERNEL_HALF {
        // SAFETY: during the format self-check, `src` is this module's own buffer of that length.
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), dst.len()) };
        return Ok(());
    }
    // SAFETY: FFI call to a kernel-exported function, with this module's own buffer.
    match unsafe { oxidebsd_copyin(src, dst.as_mut_ptr(), dst.len()) } {
        0 => Ok(()),
        e => Err(-(e as i64)),
    }
}

/// Copies `src` out to user memory at `dst`. `Err(-EFAULT)` for a bad pointer.
fn copyout_bytes(src: &[u8], dst: u64) -> Result<(), i64> {
    if src.is_empty() {
        return Ok(());
    }
    if kernel_segment() && dst >= KERNEL_HALF {
        // SAFETY: as in `copyin_bytes`, the other way round.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len()) };
        return Ok(());
    }
    // SAFETY: FFI call to a kernel-exported function, with this module's own buffer.
    match unsafe { oxidebsd_copyout(src.as_ptr(), src.len(), dst) } {
        0 => Ok(()),
        e => Err(-(e as i64)),
    }
}

/// A wire struct that can be copied to and from user memory as raw bytes.
///
/// # Safety
/// The type must have no padding bytes (copying one out would leak kernel memory), and every bit
/// pattern must be a valid value of it (it's copied in from untrusted memory).
unsafe trait Pod: Copy {}

unsafe impl Pod for [i64; 4] {}

/// Copies one `T` in from user memory at `src`.
fn copyin_val<T: Pod>(src: u64) -> Result<T, i64> {
    let mut v = core::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: a zeroed `T`'s bytes, viewed as bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>())
    };
    copyin_bytes(src, bytes)?;
    // SAFETY: every byte is initialized, and any bit pattern is a valid `T` (`Pod`).
    Ok(unsafe { v.assume_init() })
}

/// Copies `v` out to user memory at `dst`.
fn copyout_val<T: Pod>(v: &T, dst: u64) -> Result<(), i64> {
    // SAFETY: `T` is `Pod`, so it has no padding: all its bytes are initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts((v as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    copyout_bytes(bytes, dst)
}

/// A path copied in from user memory, on the stack: this module can't allocate.
struct UserPath {
    buf: [u8; OXFS_PATH_MAX],
    len: usize,
}

impl UserPath {
    const fn empty() -> Self {
        UserPath { buf: [0; OXFS_PATH_MAX], len: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Copies the path at `ptr` (`len` bytes: this ABI's paths are length-prefixed) in.
/// `Err(-ENAMETOOLONG)` past `OXFS_PATH_MAX`, `Err(-EFAULT)` for a bad pointer.
fn copyin_path(ptr: u64, len: u64) -> Result<UserPath, i64> {
    if len > OXFS_PATH_MAX as u64 {
        return Err(-ENAMETOOLONG);
    }
    let mut path = UserPath::empty();
    path.len = len as usize;
    copyin_bytes(ptr, &mut path.buf[..len as usize])?;
    Ok(path)
}

/// Writes `content` as `inode_num`'s complete contents (replacing whatever was there before),
/// allocating whatever blocks are needed and setting `size`. `write(2)` writes positionally
/// (`write_inode_uio`); this whole-content-replace shape is right for its one real caller, `oxfs_inode_content_write` (real fd-backed `MAP_SHARED`
/// mmap writeback, which always supplies a mapping's complete current content).
fn write_inode_data(inode_num: u32, content: &[u8]) -> bool {
    content_changed(inode_num);
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
    if read_only_at(inode_num) {
        return;
    }
    let _delayed = delay_writes_of(inode_num);
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
    let _delayed = delay_writes_of(inode_num);
    content_changed(inode_num);
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
/// hold as one local buffer: there is no buffer-size ceiling short of the filesystem's own
/// addressing and free space (`lio_listio/1-1.c` needs a 1 MiB `pwrite()`).
fn write_inode_at(inode_num: u32, position: usize, data: &[u8]) -> bool {
    let mut taken = 0;
    write_inode_with(inode_num, position, data.len(), |dst| {
        dst.copy_from_slice(&data[taken..taken + dst.len()]);
        taken += dst.len();
        Ok(())
    }) == Ok(data.len())
}

/// `write_inode_at` from a write transfer (`uio`): straight into the block pool. The count
/// written, short when the filesystem fills or a fault stops it partway, as `write(2)` reports.
fn write_inode_uio(inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
    let n = uio_resid(uio);
    write_inode_with(inode_num, position, n, |dst| uio_in(uio, dst).map(|_| ()))
}

/// The block walk `write_inode_at` and `write_inode_uio` share: `fill` supplies each block's
/// share of the `len` bytes written at `position`. Returns how many bytes were written; an error
/// (`-ENOSPC` when a block can't be allocated, or the first error `fill` returns) only when that's
/// none. The size and times cover whatever was written.
fn write_inode_with(
    inode_num: u32,
    position: usize,
    len: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), i64>,
) -> Result<usize, i64> {
    let _delayed = delay_writes_of(inode_num);
    content_changed(inode_num);
    let old_size = read_inode(inode_num).size as usize;
    if position > old_size && !resize_inode_data(inode_num, position) {
        return Err(-ENOSPC);
    }
    let mut pos = position;
    let mut written = 0;
    let mut result = Ok(());
    while written < len {
        let block_index = pos / BLOCK_SIZE;
        let in_block_off = pos % BLOCK_SIZE;
        let Some(blk) = inode_ensure_block_at(inode_num, block_index) else {
            result = Err(-ENOSPC);
            break;
        };
        let mut block = read_block(blk);
        let chunk = (len - written).min(BLOCK_SIZE - in_block_off);
        // A failed fill may have half-written `block`: it isn't stored.
        if let Err(e) = fill(&mut block[in_block_off..in_block_off + chunk]) {
            result = Err(e);
            break;
        }
        // A regular file's data stays dirty in the cache (`delay_writes_of`) and goes to the
        // disk later, in long runs; anything else is written now.
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
    // Back-pressure (§3.2.5): a writer that has filled half the cache with unwritten blocks waits
    // for them, rather than leave eviction to write them a block at a time.
    if bcache::mostly_dirty() {
        bcache::flush_all();
    }
    match result {
        Err(e) if written == 0 => Err(e),
        _ => Ok(written),
    }
}

/// Byte-exact mirror of musl's `struct stat` for x86_64 (`arch/x86_64/bits/stat.h` in
/// `external/mit/musl`) -- `dev_t`/`ino_t`/`nlink_t`/`off_t`/`blksize_t`/`blkcnt_t` are all 64-bit
/// on this target, and `struct timespec`'s `{tv_sec, tv_nsec}` is bit-identical to two raw `i64`s
/// here, so this `repr(C)` struct's natural layout already matches the real one field-for-field --
/// no manual padding needed beyond `__pad0` (which upstream also has explicitly, between the
/// `u32` id fields and the next `u64`). `src/stat/{stat,fstat,lstat}.c` on the `oxidebsd` musl
/// branch write straight into this shape, bypassing musl's usual `fstatat`/`kstat` indirection
/// entirely (same "patch the entry point, not the generic multiplexer" pattern `open()`/`chdir()`/
/// `mkdir()` already established -- see `CLAUDE.md`'s musl section). Every field sits at its
/// natural alignment and the size is a multiple of 8, so there are no implicit padding bytes to
/// leak when it's copied out.
#[repr(C)]
#[derive(Clone, Copy)]
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

// SAFETY: integer fields only, no padding (see above).
unsafe impl Pod for MuslStat {}

/// Builds a `MuslStat` for `inode_num` and writes it into the caller's buffer at `buf_ptr` --
/// shared by `oxfs_stat`/`oxfs_lstat` (path-based) and `oxfs_fstat` (fd-based). `st_uid`/`st_gid`
/// and `st_mode`'s permission bits are now real, backed by the inode's own `uid`/`gid`/`mode`
/// fields (see `Inode`'s own doc comment) -- `st_atime`/`st_mtime`/`st_ctime` are real too (see
/// `Inode::atime`/`Inode::mtime`'s own doc comments), whole-second precision only (`*_nsec` fields
/// stay `0`). `st_dev` is `1` for the one real, persisted
/// filesystem and `2` for anything in the tmpfs pool (`is_tmpfs_inode`, see
/// `TMPFS_BLOCK_BASE`'s own doc comment) -- derivable from the inode number alone, and just enough
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
/// Copied out byte for byte, so a userland `struct stat*` needs no particular alignment.
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
        InodeKind::Fifo => (S_IFIFO, inode.nlink.max(1) as u64),
        InodeKind::Socket => (S_IFSOCK, inode.nlink.max(1) as u64),
        _ => (S_IFREG, inode.nlink.max(1) as u64),
    };
    let mode = type_bits | inode.mode as u32;
    let size = inode.size as i64;
    let dev = if is_tmpfs_inode(inode_num) { 2 } else { 1 };
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
    match copyout_val(&stat, buf_ptr) {
        Ok(()) => 0,
        Err(e) => e,
    }
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
/// far, see `Process::uid`'s own doc comment in `sys/process.rs`) means this always evaluates to
/// `true` today, but the logic is real, not a stub — it'll start mattering the moment `setuid`
/// actually gets used to drop privilege. Otherwise picks the owner/group/other rwx triplet by
/// comparing against the inode's own `uid`/`gid` (first match wins, real Unix semantics: being in
/// the owning group doesn't fall through to "other" just because the group bits happen to deny
/// it), then requires every bit in `want` (`R_OK`/`W_OK`/`X_OK`, singly or combined — real
/// `access(2)`'s own encoding, see the constants above) to be set. `oxfs_open`'s own existing
/// callers only ever pass a single bit (`R_OK` or `W_OK`); `oxfs_access` below is the one caller
/// that can pass a real combination.
/// The group a new file, directory, node or symlink in `parent` gets: `parent`'s, as on all
/// three BSDs (POSIX allows this or the creator's group). Its owner is always the creator.
fn new_entry_gid(parent: u32) -> u32 {
    read_inode(parent).gid
}

fn check_access(inode: &Inode, uid: u64, gid: u64, want: u8) -> bool {
    check_access_as(inode, uid, gid, false, want)
}

/// `check_access` with the group class decided by the effective group (or, for `access(2)`, the
/// real one: `real`) and the caller's supplementary groups.
fn check_access_as(inode: &Inode, uid: u64, gid: u64, real: bool, want: u8) -> bool {
    if uid == 0 {
        return true;
    }
    let mode = inode.mode;
    let in_group = gid == inode.gid as u64 || unsafe { oxidebsd_current_in_group(inode.gid as u64, real as u64) } != 0;
    let bits = if uid == inode.uid as u64 {
        (mode >> 6) & 0o7
    } else if in_group {
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
    match copyout_val(&stat, buf_ptr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Looks up the inode number backing an already-open real fd -- `oxfs_fstat`'s own lookup, since
/// `OPEN_FILES` is keyed by `real_fd` (see `oxidebsd_real_fd_of`'s own doc comment for why a
/// syscall-number-registered handler has to resolve that itself rather than getting it for free
/// the way `SYS_READ`/`SYS_WRITE` do). `None` for the synthetic variants, which have no inode.
fn inode_of_open_file(real_fd: u64) -> Option<u32> {
    match find_open_file(real_fd)? {
        OpenFile::FileRead { inode, .. } => Some(*inode),
        OpenFile::DirListing { inode, .. } => Some(*inode),
        OpenFile::Write { inode, .. } => Some(*inode),
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
const fn dirent_record_len(name_len: usize) -> usize {
    let unpadded = 8 + 8 + 2 + 1 + name_len + 1;
    (unpadded + 7) & !7
}

/// Writes one `SYS_GETDENTS` record into `out`, whose length must already be exactly
/// `dirent_record_len(name.len())` (`oxfs_getdents` slices its record buffer to that size before
/// calling this, then copies the record out). `off_cookie` becomes `d_off` -- real Linux uses this
/// as an opaque seek cookie for `telldir`/`seekdir`; nothing in this port's ported applets calls
/// either, so a monotonic counter (`oxfs_getdents`'s own `dirent_pos`, one-past the record just
/// written) is honest enough without pretending to support real seeking. Padding bytes past the
/// NUL terminator are zeroed, not left as whatever `out` already held (an earlier, longer record):
/// the whole record goes out to user memory.
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

/// Marks `dir_inode` changed after an entry was added or removed: POSIX has `creat`, `mkdir`,
/// `link`, `symlink`, `mknod`, `unlink`, `rmdir` and `rename` update the directory's `st_mtime`
/// and `st_ctime`, and programs rely on it to notice a directory's contents changed (cron(8)
/// rereads `/etc/cron.d` when its time moves). Like `touch_atime`, skips the write when the
/// stamp already holds this second, which keeps seeding thousands of files cheap.
fn touch_dir(dir_inode: u32) {
    let mut inode = read_inode(dir_inode);
    let now = unsafe { oxidebsd_unix_time() };
    if inode.mtime == now && inode.ctime == now {
        return;
    }
    inode.mtime = now;
    inode.ctime = now;
    write_inode(dir_inode, inode);
}

/// Inserts a new `(name, target_inode)` record into `dir_inode`, reusing the first free (cleared
/// by a previous `dir_remove`) or never-yet-used record slot -- growing `dir_inode` with a fresh
/// block via `inode_ensure_block_at` if every existing block is full. This is the "a directory can
/// grow past its first cluster" fix over `modules/fat32`'s own `DirectoryFull`/`ENOSPC` dead end.
fn dir_insert(dir_inode: u32, name: &[u8], target_inode: u32) -> Result<(), OxfsError> {
    // Real `ENAMETOOLONG`, not `EINVAL` -- see `NAME_MAX`'s own doc comment above for the real bug
    // this was: BusyBox tar's own extraction loop aborted the whole archive on the wrong errno for
    // a too-long name instead of skipping/reporting just that one file.
    if name.len() > NAME_MAX {
        return Err(OxfsError::NameTooLong);
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
                        touch_dir(dir_inode);
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
                touch_dir(dir_inode);
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
                dir_trim(dir_inode);
                touch_dir(dir_inode);
                return Ok(());
            }
        }
        i += 1;
    }
    Err(OxfsError::NotFound)
}

/// Gives back a directory's trailing blocks that no longer hold a record (never its first), as
/// FFS truncates a directory's empty end: a directory that once held many names doesn't keep
/// their blocks for good. Only trailing ones: a directory is read until its first missing block,
/// so a hole would hide what follows it. Each pointer is cleared on the disk before its block is
/// freed (`OxideBSD-doc/RAM_FLOOR.md` §3.3.1).
fn dir_trim(dir_inode: u32) {
    loop {
        let inode = read_inode(dir_inode);
        let mut count = 0;
        while inode_block_at(&inode, count).is_some() {
            count += 1;
        }
        if count <= 1 {
            return;
        }
        let last = count - 1;
        let Some(blk) = inode_block_at(&inode, last) else { return };
        if with_block(blk, |b| (0..RECORDS_PER_BLOCK).any(|r| dir_record_used(b, r))) {
            return;
        }
        if !clear_last_block_pointer(dir_inode, last) {
            return;
        }
        free_block(blk);
    }
}

/// Clears the pointer to block `index`, the last of inode `n`'s blocks, freeing the single-index
/// block too when that leaves it empty. `false` past the single-indirect range (not trimmed).
fn clear_last_block_pointer(n: u32, index: usize) -> bool {
    let mut inode = read_inode(n);
    if index < DIRECT_BLOCKS {
        inode.direct[index] = NO_BLOCK;
        write_inode(n, inode);
        return true;
    }
    let slot = index - DIRECT_BLOCKS;
    if slot >= PTRS_PER_INDIRECT || inode.indirect == NO_BLOCK {
        return false;
    }
    let mut ib = read_block(inode.indirect);
    ib[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
    write_index_block(inode.indirect, &ib);
    if slot == 0 {
        // Its last pointer gone: the index block goes too.
        let index_block = inode.indirect;
        inode.indirect = NO_BLOCK;
        write_inode(n, inode);
        free_block(index_block);
    }
    true
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
    /// devfs on `/dev` (`DEVFS.md` §4): a tmpfs-pool tree kept in step with the device registry.
    Devfs,
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
    /// `nosuid`: set-user-ID and set-group-ID bits of programs under this mount are ignored by
    /// `execve` (`exec_setid`).
    nosuid: bool,
    /// `wxallowed`: a program under this mount marked `wxneeded` (`PT_OXIDEBSD_WXNEEDED`) may map
    /// pages writable and executable at once (THREAT_MODEL.md §3.3, `exec_setid`).
    wxallowed: bool,
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
        nosuid: false,
        wxallowed: false,
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
    let mount = mounts().iter().rev().find(|m| m.used && m.mountpoint_inode == inode).copied();
    // Entering /dev: bring devfs up to date with the registry first (§4.3).
    if mount.is_some_and(|m| m.kind == MountKind::Devfs) {
        devfs_sync();
    }
    mount
}

/// `Process::root_inode` (`sys/process.rs`), decoded the same "opaque `u64`, oxfs-owned meaning"
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
    if leaf == b"." || leaf == b".." {
        return Err(OxfsError::InvalidPath);
    }
    // Real `ENAMETOOLONG`, not `EINVAL` -- same fix as `dir_insert`'s own identical check above,
    // split out from the `.`/`..` case (a genuinely different error: that's an invalid *use*, this
    // is a name that's simply too long).
    if leaf.len() > NAME_MAX {
        return Err(OxfsError::NameTooLong);
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

/// The `*at()` family's directory-fd base -- see `AtBaseGuard`. `Some` only for the duration of one
/// `*at()` handler, while it delegates to an ordinary path handler; encoded exactly like
/// `Process::cwd` (`decode_cwd`), so a `/proc` directory fd works as a base for free.
static mut AT_BASE_OVERRIDE: Option<u64> = None;

/// Swaps what `current_cwd()` reports for one `*at()` call, restoring it on drop. This is how every
/// existing path handler (`oxfs_open`/`oxfs_stat`/`oxfs_unlink`/...) becomes dirfd-relative
/// without threading a base inode through each of them: they all start resolution from
/// `current_cwd()`/`real_cwd_for_mutation()` already.
///
/// Sound only because a syscall here runs start to finish with interrupts masked (`SFMASK`) on a
/// single core -- no other syscall can observe the override mid-flight. Same assumption as the
/// stdin ring buffer's lock (see CLAUDE.md's "Interactive shell"); SMP breaks both.
struct AtBaseGuard;

impl AtBaseGuard {
    fn set(raw_cwd: u64) -> Self {
        unsafe { *core::ptr::addr_of_mut!(AT_BASE_OVERRIDE) = Some(raw_cwd) };
        AtBaseGuard
    }
}

impl Drop for AtBaseGuard {
    fn drop(&mut self) {
        unsafe { *core::ptr::addr_of_mut!(AT_BASE_OVERRIDE) = None };
    }
}

fn current_cwd() -> Cwd {
    if let Some(raw) = unsafe { *core::ptr::addr_of!(AT_BASE_OVERRIDE) } {
        return decode_cwd(raw);
    }
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
    let pid = parse_proc_pid(pid_str)?;
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
fn proc_relative_stat(kind: ProcDirKind, path: &[u8], buf_ptr: u64, follow: bool) -> i64 {
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
    proc_stat(&suffix[..len], buf_ptr, follow)
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
fn proc_relative_readlink(kind: ProcDirKind, path: &[u8], buf_ptr: u64, buf_cap: u64) -> i64 {
    if path.is_empty() || path == b"." || path == b".." {
        return -EINVAL;
    }
    let mut suffix = [0u8; MAX_CWD_PATH];
    let Some(len) = proc_join_suffix(kind, path, &mut suffix) else {
        return -ENOENT;
    };
    proc_readlink(&suffix[..len], buf_ptr, buf_cap)
}

/// `readlink(2)` of a `/proc` path (`suffix` follows `/proc`): the links' targets (`proc_link`);
/// anything else that exists isn't a link.
fn proc_readlink(suffix: &[u8], buf_ptr: u64, buf_cap: u64) -> i64 {
    let Some(link) = proc_link(suffix) else {
        return match proc_kind(suffix) {
            Some(_) => -EINVAL,
            None => -ENOENT,
        };
    };
    let mut target = [0u8; MAX_CWD_PATH];
    let len = match proc_link_target(link, &mut target) {
        Ok(len) => len.min(buf_cap as usize),
        Err(e) => return e,
    };
    match copyout_bytes(&target[..len], buf_ptr) {
        Ok(()) => len as i64,
        Err(e) => e,
    }
}

/// `stat(2)` (`follow`) or `lstat(2)` of a `/proc` path.
fn proc_stat(suffix: &[u8], buf_ptr: u64, follow: bool) -> i64 {
    match proc_link(suffix) {
        Some(ProcLink::Fd(real_fd)) if follow => return stat_real_fd(real_fd, buf_ptr),
        Some(_) if !follow => return write_synthetic_stat(S_IFLNK | 0o777, 0, PROC_INODE_BASE, buf_ptr),
        _ => {}
    }
    match proc_kind(suffix) {
        Some(is_dir) => write_proc_stat(is_dir, buf_ptr),
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

/// An open file's own state, keyed by fd in `OPEN_FILES`. Modules can't use `alloc`/`Box`, so
/// every slot is sized for the largest variant: no variant embeds a content buffer (the write
/// buffers and `/proc` renders are pooled and referenced by index), so a slot stays small (see
/// `MAX_OPEN_FILES`).
#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)]
enum OpenFile {
    /// A real file, opened for reading -- streams straight from `inode`'s own block chain on each
    /// `read()` call via `read_inode_at` rather than caching the whole file at `open` time (unlike
    /// `modules/fat32`'s own `OpenFile::Read`), so file size is bounded only by the block pool,
    /// not by a fixed per-fd buffer.
    FileRead {
        inode: u32,
        position: usize,
        /// The directory and name this was opened through, for `/proc/<pid>/fd/<n>`'s link
        /// (`open_file_path`).
        parent: u32,
        name: [u8; NAME_MAX],
        name_len: u8,
    },
    /// An open directory. `inode` is the directory's own inode number -- used by
    /// `inode_of_open_file` (`oxfs_fstat` on a directory fd) and by `oxfs_getdents`, which walks
    /// its live records. `dirent_pos` is `oxfs_getdents`'s resume cursor and the descriptor's
    /// offset (`oxfs_lseek`). `read` is `EISDIR`.
    DirListing {
        inode: u32,
        dirent_pos: usize,
    },
    /// A file opened for writing (or `O_RDONLY|O_CREAT`, see `readonly`). The inode exists, named,
    /// from `open` on: `write` stores straight into its blocks at `position`, so every other
    /// descriptor and every `stat` sees a completed write at once (POSIX), and `close` has nothing
    /// to commit. (Until the 128 MB floor, `OxideBSD-doc/RAM_FLOOR.md` §3.1.5, writes collected in
    /// a per-descriptor buffer and a new file got its inode only at its first commit.)
    Write {
        inode: u32,
        /// The directory and name this was opened through, for `/proc/<pid>/fd/<n>`'s link
        /// (`open_file_path`), kept current by `rename_open_files`.
        parent_inode: u32,
        name: [u8; NAME_MAX],
        name_len: u8,
        /// The requested access mode was `O_RDONLY`: only an `O_RDONLY|O_CREAT` open of a new file
        /// makes a `Write` with this set. `oxfs_write`/`oxfs_ftruncate`/`oxfs_fallocate` refuse
        /// (`EBADF`/`EINVAL`) -- `shm_open(O_RDONLY|O_CREAT, ...)` must not allow a later
        /// `ftruncate()` (`shm_open/13-1.c`).
        readonly: bool,
        /// `O_RDWR` rather than `O_WRONLY`: `read()`/`pread()` work on this descriptor too
        /// (`aio_read`/`aio_write`/`lio_listio` read back through the descriptor they wrote).
        readwrite: bool,
        /// The `read()`/`write()`/`lseek()` offset. Every `Write` descriptor seeks, `O_WRONLY`
        /// included: `ld.lld` backpatches an ELF header with `lseek(SEEK_SET)` + `write()`.
        position: usize,
        /// `O_APPEND`: every `write` first moves `position` to the end of the file. Also reported
        /// by `F_GETFL` (`oxfs_is_append`): musl's AIO serializes appending writes on it
        /// (`aio_write/2-1.c`).
        append: bool,
    },
    /// A synthetic `/proc` file's content, generated once at `open` time by calling into
    /// `sys/process.rs`'s kernel-exported accessors (see `open_proc_leaf`) into a `PROC_RENDERS`
    /// slot; no real inode backs this.
    ProcRead {
        render: u16,
        len: usize,
        position: usize,
    },
    /// A synthetic `/proc` directory -- see `ProcDirKind` for what each variant lists.
    /// `dirent_pos` has the same role as `DirListing::dirent_pos`.
    ProcDir {
        kind: ProcDirKind,
        dirent_pos: usize,
    },
    /// A synthetic `/dev/random` or `/dev/urandom` fd -- see `dev_open`'s own doc comment for why
    /// both device nodes share this one variant. Reads delegate to `oxidebsd_random_bytes`
    /// (`sys/random.rs` in the kernel tree); writes are accepted and discarded (matching real
    /// Linux's own behavior for these two nodes, though real entropy-pool mixing from a write
    /// isn't modeled here at all).
    DevRandom,
    /// A synthetic `/dev/null` fd -- every read is an immediate EOF, every write succeeds and
    /// discards its input.
    DevNull,
    /// A synthetic `/dev/zero` fd -- every read fills the caller's buffer with zero bytes (never
    /// EOF), every write succeeds and discards its input, same as `DevNull`.
    DevZero,
    /// A real `/dev/fb0` fd -- see `known_device`'s `(29, 0)` arm and `sys/drivers/fbdev.rs`'s own
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
    /// `/proc/<pid>/fd`: one symlink per fd this process has open (`oxidebsd_fd_at`), naming
    /// what it's open on (`proc_link_target`, TTY.md §6.3).
    FdList(u32),
}

fn register_open_file(open_file: OpenFile) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let room = unsafe { oxidebsd_fd_check_room(1) };
    if room < 0 {
        return room;
    }
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    let Some(slot) = slots.iter_mut().find(|s| s.is_none()) else {
        return -EMFILE;
    };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_alloc_fd() };
    *slot = Some((real_fd, open_file));
    // SAFETY: oxfs_read/oxfs_write/oxfs_close/oxfs_content_id are this module's own functions,
    // already relocated by the time module_init (which makes this function reachable) runs.
    // Always the `_with_content_id` variant, not just for `FileRead`/`Write` -- `oxfs_content_id`
    // itself already returns `-1` for every other variant, so there's no need to discriminate here.
    let fd = unsafe {
        let fd = oxidebsd_register_fd_ops_with_content_id(
            real_fd,
            oxfs_read,
            oxfs_write,
            oxfs_close,
            oxfs_content_id,
        );
        // Always registered, unconditionally -- same "the callback itself discriminates by
        // variant" reasoning `oxfs_content_id` above already established. See `oxfs_pread`/
        // `oxfs_pwrite`'s own doc comments for what each real variant actually supports.
        oxidebsd_set_fd_positioned(real_fd);
        oxidebsd_set_fd_access_mode(real_fd, oxfs_access_mode);
        oxidebsd_set_fd_append(real_fd, oxfs_is_append);
        oxidebsd_set_fd_fb_geometry(real_fd, oxfs_fb_geometry);
        fd
    };
    fd
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
/// doc comment: the inode behind `real_fd`, so `mmap` and the page cache can find its content.
/// `-1` for the synthetic variants (`DirListing` aside), which have none.
extern "C" fn oxfs_content_id(real_fd: u64) -> i64 {
    match inode_of_open_file(real_fd) {
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

/// `is_shm` accessor for `oxidebsd_register_content_accessors`: whether `inode` is a POSIX shared
/// memory object (`Inode::shm`).
extern "C" fn oxfs_inode_is_shm(inode: u64) -> i64 {
    read_inode(inode as u32).shm as i64
}

/// `setid` accessor for `oxidebsd_register_content_accessors`: for a file open for reading on
/// `real_fd` (the program `execve` is loading), its mode bits, owner and group, with `S_ISUID` and
/// `S_ISGID` cleared when it was opened from under a `nosuid` mount, and in `out[3]` whether it
/// was opened from under a `wxallowed` one.
extern "C" fn oxfs_exec_setid(real_fd: u64, out: *mut u32) -> i64 {
    let Some(&mut OpenFile::FileRead { inode, parent, .. }) = find_open_file(real_fd) else {
        return -1;
    };
    let node = read_inode(inode);
    let mut mode = node.mode;
    if on_mount_with(parent, |m| m.nosuid) {
        mode &= !SETID_BITS;
    }
    let wxallowed = on_mount_with(parent, |m| m.wxallowed);
    // SAFETY: the kernel passes a 4-element array of its own.
    unsafe {
        out.write(mode as u32);
        out.add(1).write(node.uid);
        out.add(2).write(node.gid);
        out.add(3).write(wxallowed as u32);
    }
    0
}

/// Whether directory `dir` is under a mount `option` holds for (`nosuid`, `wxallowed`): walks up
/// through `..` looking for one's root. A nullfs mount's root is its source directory, so a
/// `nosuid` nullfs mount makes its source tree `nosuid` too (stricter than FreeBSD, never looser),
/// and a `wxallowed` one makes it `wxallowed` (looser: only root mounts, and should mount a tree
/// only root can write).
fn on_mount_with(dir: u32, option: fn(&MountEntry) -> bool) -> bool {
    if !mounts().iter().any(|m| m.used && option(m)) {
        return false;
    }
    let mut d = dir;
    for _ in 0..256 {
        if mounts().iter().any(|m| m.used && option(m) && m.target_root_inode == d) {
            return true;
        }
        match dir_lookup(d, b"..") {
            Some(up) if up != d => d = up,
            _ => return false,
        }
    }
    false
}

/// Whether `dir` is devfs's `/dev/shm`, where musl's `shm_open` creates its objects.
fn is_shm_dir(dir: u32) -> bool {
    let root = devfs_root();
    root != u32::MAX && dir_lookup(root, b"shm") == Some(dir)
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

/// Registers a descriptor for directory `dir_inode`, read with `getdents`.
fn open_dir_listing(dir_inode: u32) -> i64 {
    register_open_file(OpenFile::DirListing { inode: dir_inode, dirent_pos: 0 })
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

/// `/proc` itself: the live pids (`oxidebsd_proc_pid_at`) and the system-wide files
/// (`proc_dir_nth_entry`).
fn open_proc_root_dir() -> i64 {
    register_open_file(OpenFile::ProcDir { kind: ProcDirKind::Root, dirent_pos: 0 })
}

/// `/proc/<pid>`: the fixed three leaf names.
fn open_proc_pid_dir(pid: u32) -> i64 {
    register_open_file(OpenFile::ProcDir { kind: ProcDirKind::PidFiles(pid), dirent_pos: 0 })
}

/// `/proc/<pid>/task`: exactly one entry, `pid`'s own decimal string -- see `ProcDirKind::TaskList`'s
/// own doc comment for why this exists at all.
fn open_task_dir(pid: u32) -> i64 {
    register_open_file(OpenFile::ProcDir { kind: ProcDirKind::TaskList(pid), dirent_pos: 0 })
}

/// `/proc/<pid>/fd`: one entry per real fd this process has open -- see `ProcDirKind::FdList`'s
/// own doc comment for why each entry is a plain placeholder rather than a real target-bearing
/// symlink.
fn open_fd_dir(pid: u32) -> i64 {
    register_open_file(OpenFile::ProcDir { kind: ProcDirKind::FdList(pid), dirent_pos: 0 })
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
    /// Why pid 1 died, each time the kernel restarted it (INIT.md §9).
    InitDeaths,
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
    push(if root_rdonly() { b"oxfs / oxfs ro 0 0\n" } else { b"oxfs / oxfs rw 0 0\n" });
    for m in mounts().iter().filter(|m| m.used) {
        push(&m.source[..m.source_len as usize]);
        push(b" ");
        push(&m.path[..m.path_len as usize]);
        push(match m.kind {
            MountKind::Bind => b" nullfs rw",
            MountKind::Tmpfs => b" tmpfs rw",
            MountKind::Devfs => b" devfs rw",
        });
        if m.nosuid {
            push(b",nosuid");
        }
        if m.wxallowed {
            push(b",wxallowed");
        }
        push(b" 0 0\n");
    }
    n
}

/// `/proc/{meminfo,uptime,stat,modules,mounts}`: same "format once at open time into a fixed
/// buffer" shape `open_proc_leaf` uses for the per-pid leaves, just backed by the system-wide
/// kernel accessors (or, for `Mounts`, this module's own state) instead of a per-pid one. Unlike
/// `open_proc_leaf`, there's no pid to vanish out from under this call -- none of these ever fail.
fn open_proc_sysfile(kind: ProcSysFile) -> i64 {
    let Some(render) = alloc_proc_render() else {
        return -ENFILE;
    };
    let content = proc_render(render);
    let n = match kind {
        ProcSysFile::Mounts => format_mounts(content) as i64,
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
                ProcSysFile::InitDeaths => {
                    oxidebsd_proc_initdeaths(content.as_mut_ptr(), PROC_BUFFER as u64)
                }
                ProcSysFile::Mounts => unreachable!(),
            }
        },
    };
    register_proc_render(render, n as usize)
}

/// `/proc/<pid>/{stat,cmdline,status}`: calls the matching kernel accessor once, at `open` time,
/// into a fresh fixed buffer -- same "format once, stream on read" shape `open_dir_listing` uses.
fn open_proc_leaf(pid: u32, leaf: ProcLeaf) -> i64 {
    let Some(render) = alloc_proc_render() else {
        return -ENFILE;
    };
    let content = proc_render(render);
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
        free_proc_render(render);
        return -ESRCH;
    }
    register_proc_render(render, n as usize)
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
        b"/initdeaths" => return open_proc_sysfile(ProcSysFile::InitDeaths),
        _ => {}
    }
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let Some(pid_str) = comps.next() else {
        return open_proc_root_dir();
    };
    let Some(pid) = parse_proc_pid(pid_str) else {
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
        b"/meminfo" | b"/uptime" | b"/stat" | b"/modules" | b"/mounts" | b"/initdeaths" => return Some(false),
        _ => {}
    }
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let Some(pid_str) = comps.next() else {
        return Some(true); // /proc itself
    };
    let pid = parse_proc_pid(pid_str)?;
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    if unsafe { oxidebsd_proc_exists(pid as u64) } == 0 {
        return None;
    }
    match comps.next() {
        None => Some(true), // /proc/<pid>
        Some(b"stat" | b"cmdline" | b"status") if comps.next().is_none() => Some(false),
        Some(b"fd") => match (comps.next(), comps.next()) {
            (None, _) => Some(true),
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            (Some(n), None) => (unsafe { oxidebsd_real_fd_of_pid(pid as u64, parse_pid(n)? as u64) } >= 0)
                .then_some(false),
            _ => None,
        },
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

// --- terminals and /proc symlinks (TTY.md §6) ------------------------------------------------

/// `oxidebsd_real_fd_kind`'s codes (`sys/fs/fd.rs`, kernel tree).
const FD_KIND_MODULE: i64 = 0;
const FD_KIND_TTY: i64 = 1;
const FD_KIND_PIPE: i64 = 2;
const FD_KIND_SOCKET: i64 = 3;
const FD_KIND_FIFO: i64 = 4;
const FD_KIND_MQUEUE: i64 = 5;
/// A device opened through devfs; the argument is its `st_rdev`.
const FD_KIND_DEVICE: i64 = 6;



/// A `/proc` path's first component: a pid, or `self`, the caller's own.
fn parse_proc_pid(bytes: &[u8]) -> Option<u32> {
    if bytes == b"self" {
        // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
        return Some(unsafe { oxidebsd_current_tgid() } as u32);
    }
    parse_pid(bytes)
}

/// `/dev`'s node for character device `rdev`: its inode and its name relative to `/dev`
/// (`ttyv0`, or `pts/0` one directory down). Searches devfs, whose root a bare `dir_lookup` of
/// `/dev` doesn't reach (it's a mount).
fn dev_node_for(rdev: u32) -> Option<(u32, [u8; NAME_MAX], u8)> {
    let dev = if devfs_root() != u32::MAX {
        devfs_sync();
        devfs_root()
    } else {
        dir_lookup(ROOT_INODE, b"dev")?
    };
    let mut found = None;
    let mut subdirs: [(u32, [u8; NAME_MAX], u8); 8] = [(0, [0; NAME_MAX], 0); 8];
    let mut nsub = 0;
    for_each_dir_record(dev, |name, child_num| {
        let child = read_inode(child_num);
        if child.kind == InodeKind::Device && child.device_char && child.rdev == rdev {
            let mut buf = [0u8; NAME_MAX];
            buf[..name.len()].copy_from_slice(name);
            found = Some((child_num, buf, name.len() as u8));
        } else if child.kind == InodeKind::Dir && name != b"." && name != b".." && nsub < subdirs.len() {
            subdirs[nsub].0 = child_num;
            subdirs[nsub].1[..name.len()].copy_from_slice(name);
            subdirs[nsub].2 = name.len() as u8;
            nsub += 1;
        }
        found.is_none()
    });
    if found.is_some() {
        return found;
    }
    for (dir, dname, dlen) in subdirs[..nsub].iter() {
        let prefix = &dname[..*dlen as usize];
        for_each_dir_record(*dir, |name, child_num| {
            let child = read_inode(child_num);
            if child.kind == InodeKind::Device && child.device_char && child.rdev == rdev {
                let len = prefix.len() + 1 + name.len();
                if len <= NAME_MAX {
                    let mut buf = [0u8; NAME_MAX];
                    buf[..prefix.len()].copy_from_slice(prefix);
                    buf[prefix.len()] = b'/';
                    buf[prefix.len() + 1..len].copy_from_slice(name);
                    found = Some((child_num, buf, len as u8));
                }
            }
            found.is_none()
        });
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Calls `f(name, inode)` for each record of directory `dir` while it returns true.
fn for_each_dir_record(dir: u32, mut f: impl FnMut(&[u8], u32) -> bool) {
    let inode = read_inode(dir);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if !dir_record_used(&block, r) {
                continue;
            }
            if !f(dir_record_name(&block, r), dir_record_inode(&block, r)) {
                return;
            }
        }
        i += 1;
    }
}

/// `stat` of a descriptor (`fstat`, and `stat` through a `/proc/<pid>/fd/<n>` link). A terminal
/// reports its device node (TTY.md §6.2), so that `ttyname(3)`'s comparison of the two matches;
/// pipes and sockets get the types they are.
fn stat_real_fd(real_fd: u64, buf_ptr: u64) -> i64 {
    let mut arg = 0u64;
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    match unsafe { oxidebsd_real_fd_kind(real_fd, &mut arg) } {
        FD_KIND_TTY => match dev_node_for(arg as u32) {
            Some((inode, _, _)) => write_stat(inode, buf_ptr),
            None => write_synthetic_stat(S_IFCHR | 0o600, arg, 0, buf_ptr),
        },
        FD_KIND_PIPE => write_synthetic_stat(S_IFIFO | 0o600, 0, arg, buf_ptr),
        FD_KIND_SOCKET => write_synthetic_stat(S_IFSOCK | 0o777, 0, arg, buf_ptr),
        FD_KIND_FIFO => write_stat(arg as u32, buf_ptr),
        FD_KIND_DEVICE => match dev_node_for(arg as u32) {
            Some((inode, _, _)) => write_stat(inode, buf_ptr),
            None => write_synthetic_stat(S_IFCHR | 0o600, arg, 0, buf_ptr),
        },
        _ => match inode_of_open_file(real_fd) {
            Some(inode_num) => write_stat(inode_num, buf_ptr),
            None => -EBADF,
        },
    }
}

/// A `struct stat` for something no oxfs inode backs (pipes, sockets, a terminal whose node was
/// removed).
fn write_synthetic_stat(mode: u32, rdev: u64, ino: u64, buf_ptr: u64) -> i64 {
    let stat = MuslStat {
        st_dev: 0,
        st_ino: ino,
        st_nlink: 1,
        st_mode: mode,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: rdev,
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
    match copyout_val(&stat, buf_ptr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// The `/proc` symlinks (TTY.md §6.3).
enum ProcLink {
    /// `/proc/self`, naming the caller's pid.
    SelfPid(u32),
    /// `/proc/<pid>/fd/<n>`, naming what the descriptor is open on.
    Fd(u64),
}

/// Whether `suffix` (a path after `/proc`) names a link itself, rather than going through one.
fn proc_link(suffix: &[u8]) -> Option<ProcLink> {
    let mut comps = suffix.split(|&b| b == b'/').filter(|c| !c.is_empty());
    let first = comps.next()?;
    let pid = parse_proc_pid(first)?;
    match (comps.next(), comps.next(), comps.next()) {
        // `/proc/self/` goes through the link, as any trailing slash does.
        (None, _, _) if first == b"self" && suffix.last() != Some(&b'/') => Some(ProcLink::SelfPid(pid)),
        (Some(b"fd"), Some(n), None) if suffix.last() != Some(&b'/') => {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let real_fd = unsafe { oxidebsd_real_fd_of_pid(pid as u64, parse_pid(n)? as u64) };
            (real_fd >= 0).then_some(ProcLink::Fd(real_fd as u64))
        }
        _ => None,
    }
}

/// A link's target into `out`: its length, or `-errno`.
fn proc_link_target(link: ProcLink, out: &mut [u8; MAX_CWD_PATH]) -> Result<usize, i64> {
    let real_fd = match link {
        ProcLink::SelfPid(pid) => return Ok(decimal_into(out, pid as u64)),
        ProcLink::Fd(real_fd) => real_fd,
    };
    let tagged = |out: &mut [u8; MAX_CWD_PATH], tag: &[u8], n: u64| {
        let mut b = ByteBuf { buf: &mut out[..], len: 0 };
        b.push_bytes(tag);
        b.push_bytes(b":[");
        b.push_decimal_u64(n);
        b.push_bytes(b"]");
        b.len
    };
    let mut arg = 0u64;
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
    match unsafe { oxidebsd_real_fd_kind(real_fd, &mut arg) } {
        FD_KIND_TTY | FD_KIND_DEVICE => {
            let (_, name, name_len) = dev_node_for(arg as u32).ok_or(-ENOENT)?;
            let mut b = ByteBuf { buf: &mut out[..], len: 0 };
            b.push_bytes(b"/dev/");
            b.push_bytes(&name[..name_len as usize]);
            Ok(b.len)
        }
        // Linux's names for descriptors without a path.
        FD_KIND_PIPE => Ok(tagged(out, b"pipe", arg)),
        FD_KIND_SOCKET => Ok(tagged(out, b"socket", arg)),
        FD_KIND_MQUEUE => {
            let mut b = ByteBuf { buf: &mut out[..], len: 0 };
            b.push_bytes(b"anon_inode:[mqueue]");
            Ok(b.len)
        }
        FD_KIND_FIFO => any_path_of(arg as u32, out).ok_or(-ENOENT),
        FD_KIND_MODULE => open_file_path(real_fd, out),
        _ => Err(-ENOENT),
    }
}

/// The path of one of this module's open files (`OPEN_FILES`, keyed by `real_fd`).
fn open_file_path(real_fd: u64, out: &mut [u8; MAX_CWD_PATH]) -> Result<usize, i64> {
    let fixed = |out: &mut [u8; MAX_CWD_PATH], path: &[u8]| {
        out[..path.len()].copy_from_slice(path);
        Ok(path.len())
    };
    match find_open_file(real_fd).ok_or(-ENOENT)? {
        &mut OpenFile::FileRead { inode, parent, name, name_len, .. } => {
            Ok(file_path(inode, parent, &name[..name_len as usize], out))
        }
        &mut OpenFile::Write { inode, parent_inode, name, name_len, .. } => {
            Ok(file_path(inode, parent_inode, &name[..name_len as usize], out))
        }
        &mut OpenFile::DirListing { inode, .. } => Ok(build_cwd_path(inode, out)),
        &mut OpenFile::ProcDir { kind, .. } => Ok(proc_dir_suffix(kind, out)),
        OpenFile::DevNull => fixed(out, b"/dev/null"),
        OpenFile::DevZero => fixed(out, b"/dev/zero"),
        OpenFile::DevRandom => fixed(out, b"/dev/urandom"),
        OpenFile::Framebuffer { .. } => fixed(out, b"/dev/fb0"),
        // Which /proc file it was isn't kept.
        OpenFile::ProcRead { .. } => Err(-ENOENT),
    }
}

/// The path of file `inode`, opened as `name` in `parent`: that name while it still names the
/// file, else another name the file has (renamed, or linked elsewhere), else the old one marked
/// ` (deleted)`, as Linux does.
fn file_path(inode: u32, parent: u32, name: &[u8], out: &mut [u8; MAX_CWD_PATH]) -> usize {
    if dir_lookup(parent, name) == Some(inode) {
        return join_path(parent, name, false, out);
    }
    if read_inode(inode).nlink > 0 {
        if let Some(len) = any_path_of(inode, out) {
            return len;
        }
    }
    join_path(parent, name, true, out)
}

/// `<dir's path>/<name>`, plus ` (deleted)`.
fn join_path(dir: u32, name: &[u8], deleted: bool, out: &mut [u8; MAX_CWD_PATH]) -> usize {
    let mut len = build_cwd_path(dir, out);
    if len == 1 {
        len = 0; // the root: no "//name"
    }
    let mut b = ByteBuf { buf: &mut out[..], len };
    b.push_bytes(b"/");
    b.push_bytes(name);
    if deleted {
        b.push_bytes(b" (deleted)");
    }
    b.len
}

/// Some path of `inode`, by searching every directory for an entry naming it. `None` if nothing
/// does (it was unlinked).
fn any_path_of(inode: u32, out: &mut [u8; MAX_CWD_PATH]) -> Option<usize> {
    all_inode_numbers()
        .filter(|&d| read_inode(d).kind == InodeKind::Dir)
        .find_map(|d| find_name_of_inode_in_dir(d, inode).map(|name| (d, name)))
        .map(|(dir, (name, name_len))| join_path(dir, &name[..name_len as usize], false, out))
}


/// Splits a raw `dev_t` register value into `(major, minor)` the same way musl's own
/// `major()`/`minor()` macros do (`external/mit/musl/include/sys/sysmacros.h`) for any major <
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

/// This module's own local copy of `sys/drivers/fbdev.rs`'s `FbGeometry` (kernel tree) -- modules
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

/// Registered for `SYS_OPEN`. `/proc/...` (absolute only -- a *relative* path reached while cwd is
/// already inside `/proc` is `proc_relative_open`'s job, below) is intercepted before any of the
/// real, cwd-relative special-casing below, since it isn't backed by a real inode at all -- see
/// `proc_open`. `/dev/...` gets the same treatment right after -- see `dev_open`.
///
/// `mode` (the 4th real syscall argument, `R10`) is `open(2)`'s own real creation-mode argument --
/// only meaningful (and only ever read) when `O_CREAT` actually creates a brand-new inode (the
/// `None if create` arm below); ignored for every other arm, the same way real `open(2)` ignores
/// it for an existing path. **Found live, a real bug, not a preemptive addition**: this ABI's own
/// `SYS_OPEN` used to carry no mode argument at all (`external/mit/musl/src/fcntl/open.c`'s own old
/// comment: "this filesystem doesn't model permissions" -- stale the moment the real per-inode
/// `mode`/`uid`/`gid` permission model landed, see CLAUDE.md's own "Permission model" section, but
/// never revisited), so every `open(O_CREAT, mode)` silently got `FIXED_PERM` (`0o755`) regardless
/// of what the caller actually asked for -- `sem_open/3-1.c` (Open POSIX Test Suite pilot) expects
/// a semaphore created `0444` to make a later write-access re-open genuinely `EACCES`, which can
/// only happen if the requested `0444` really lands on the inode. Fixed by extending `open(2)`'s
/// own wire format to a real 4-arg `(path_ptr, path_len, flags, mode)` -- `external/mit/musl/src/
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
    match copyin_path(path_ptr, path_len) {
        Ok(path) => open_path(path.as_bytes(), flags, mode),
        Err(e) => e,
    }
}

/// `open` for the kernel itself, with a path in kernel memory (exec's own copy of the program's
/// path, or its interpreter's): not a user pointer, so not `copyin_path`.
extern "C" fn oxfs_kern_open(path_ptr: u64, path_len: u64, flags: u64) -> i64 {
    if path_len as usize > OXFS_PATH_MAX {
        return -ENAMETOOLONG;
    }
    // SAFETY: the kernel passes its own buffer of `path_len` bytes.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    open_path(path, flags, 0)
}

/// `oxfs_open` on a path already copied in.
fn open_path(path: &[u8], flags: u64, mode: u64) -> i64 {
    let create = flags & O_CREAT != 0;

    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return proc_open(&path[5..]);
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
            // Real open() follows a final symlink component by default -- resolve_path already
            // knows how, so hand it the symlink's own stored target relative to its own parent
            // directory. A dangling target surfaces as the same -ENOENT any other failed
            // resolve_path call already returns. O_NOFOLLOW refuses instead (real ELOOP).
            if flags & O_NOFOLLOW != 0 && read_inode(inode_num).kind == InodeKind::Symlink {
                return -ELOOP;
            }
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
            // ELF-loading read (see sys/process.rs) always opens read-only, so its own approximate
            // execute-permission-via-read-bit check (a known, documented simplification, harmless
            // while every seeded file's default mode 0o755 sets both bits identically) is
            // unaffected by this.
            let inode = read_inode(resolved);
            if flags & O_DIRECTORY != 0 && inode.kind != InodeKind::Dir {
                return -ENOTDIR;
            }
            if inode.kind == InodeKind::Socket {
                return -EOPNOTSUPP; // UNIX.md §5.2, as in the BSDs
            }
            let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
            // Real O_RDONLY is 0 -- "anything but that" in the low two bits means O_WRONLY/O_RDWR.
            let want_write = flags & O_ACCMODE != 0;
            if !check_access(&inode, uid, gid, if want_write { W_OK } else { R_OK }) {
                return -EACCES;
            }
            match inode.kind {
                InodeKind::Dir if want_write => -EISDIR,
                InodeKind::Dir => open_dir_listing(resolved),
                // Every device, in devfs or made by mknod elsewhere, opens through the kernel's
                // registry by number (`DEVFS.md` §3.4).
                InodeKind::Device if inode.device_char => {
                    let (major, minor) = dev_major_minor(inode.rdev);
                    // SAFETY: FFI call to a kernel-exported function, matching its declared
                    // signature.
                    unsafe { oxidebsd_dev_open(major as u64, minor as u64, flags) }
                }
                InodeKind::Device => -ENXIO,
                InodeKind::Fifo => {
                    // The open can block until the other end shows up, and other processes'
                    // syscalls run meanwhile -- they must not see an `*at()` base override.
                    let saved =
                        unsafe { core::ptr::replace(core::ptr::addr_of_mut!(AT_BASE_OVERRIDE), None) };
                    let fd = unsafe { oxidebsd_fifo_open(resolved as u64, flags) };
                    unsafe { *core::ptr::addr_of_mut!(AT_BASE_OVERRIDE) = saved };
                    fd
                }
                _ if want_write && read_only_at(resolved) => -EROFS,
                _ if want_write => {
                    let mut name = [0u8; NAME_MAX];
                    name[..leaf.len()].copy_from_slice(leaf);
                    // Only O_TRUNC truncates. Otherwise, O_WRONLY or O_RDWR alike, the content
                    // stays and writes land at the descriptor's offset, so bytes never written keep
                    // their old content. (A plain O_WRONLY open used to truncate as well, on the
                    // theory that a write-only fd can't see the tail; every other reader of the
                    // file can, and exec of a program patched in place ran zeros.) O_APPEND moves
                    // the offset to the end before every write (`oxfs_write`).
                    if flags & O_TRUNC != 0 {
                        resize_inode_data(resolved, 0);
                    }
                    register_open_file(OpenFile::Write {
                        inode: resolved,
                        parent_inode: parent,
                        name,
                        name_len: leaf.len() as u8,
                        readonly: false, // this whole arm only runs when want_write is true
                        readwrite: flags & O_ACCMODE == O_RDWR,
                        position: 0,
                        append: flags & O_APPEND != 0,
                    })
                }
                _ => {
                    let mut name = [0u8; NAME_MAX];
                    name[..leaf.len()].copy_from_slice(leaf);
                    register_open_file(OpenFile::FileRead {
                        inode: resolved,
                        position: 0,
                        parent,
                        name,
                        name_len: leaf.len() as u8,
                    })
                }
            }
        }
        None if create && read_only_at(parent) => -EROFS,
        None if create => {
            let parent_inode = read_inode(parent);
            let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
            if !check_access(&parent_inode, uid, gid, W_OK) {
                return -EACCES;
            }
            // The file exists, named, the moment open(2) returns: another open, a stat or an
            // unlink of the path sees it at once.
            let Some(new_inode) = alloc_inode_in(parent) else {
                return -ENOSPC;
            };
            let mut inode = fresh_inode(InodeKind::File);
            inode.uid = uid as u32;
            inode.gid = new_entry_gid(parent);
            // `mode & ~umask` (`shm_open/18-1.c` sets a umask and checks for it).
            inode.mode = (mode as u16 & !(unsafe { oxidebsd_current_umask() } as u16)) & 0o777;
            inode.shm = is_shm_dir(parent);
            write_inode(new_inode, inode);
            if let Err(e) = dir_insert(parent, leaf, new_inode) {
                return errno_for(e);
            }
            let mut name = [0u8; NAME_MAX];
            name[..leaf.len()].copy_from_slice(leaf);
            register_open_file(OpenFile::Write {
                inode: new_inode,
                parent_inode: parent,
                name,
                name_len: leaf.len() as u8,
                // Real O_RDONLY is 0: an `O_RDONLY|O_CREAT` descriptor still makes the file but
                // can't write it (`readonly`'s own doc comment).
                readonly: flags & O_ACCMODE == 0,
                readwrite: flags & O_ACCMODE == O_RDWR,
                position: 0,
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

extern "C" fn oxfs_read(fd: u64, uio: u64, flags: u64) -> i64 {
    if flags & FOF_OFFSET != 0 {
        return oxfs_pread(fd, uio);
    }
    let Some(file) = find_open_file(fd) else {
        return -EBADF;
    };
    match file {
        OpenFile::FileRead { inode, position, .. } => {
            let n = match read_inode_uio(*inode, *position, uio) {
                Ok(n) => n,
                Err(e) => return e,
            };
            *position += n;
            // Real POSIX read(): a real data access, marked for st_atime update -- skipped for a
            // zero-byte read (at or past EOF), matching real Unix's own "no state change" behavior
            // for that case.
            if n > 0 {
                touch_atime(*inode);
            }
            n as i64
        }
        // read(2) on a directory is EISDIR, as on OpenBSD and FreeBSD 13+: getdents reads it.
        OpenFile::DirListing { .. } | OpenFile::ProcDir { .. } => -EISDIR,
        OpenFile::Write { inode, position, readwrite: true, .. } => {
            let n = match read_inode_uio(*inode, *position, uio) {
                Ok(n) => n,
                Err(e) => return e,
            };
            *position += n;
            if n > 0 {
                touch_atime(*inode);
            }
            n as i64
        }
        OpenFile::Write { .. } => -EBADF,
        OpenFile::ProcRead {
            render,
            len: total,
            position,
        } => {
            let remaining = *total - *position;
            let n = remaining.min(uio_resid(uio));
            let content = proc_render(*render as usize);
            match uio_out(uio, &content[*position..*position + n]) {
                Ok(m) => {
                    *position += m;
                    m as i64
                }
                Err(e) => e,
            }
        }
        OpenFile::DevRandom => uio_ret(fill_uio(uio, |chunk| {
            // SAFETY: FFI call to a kernel-exported function, with this module's own buffer.
            let r = unsafe { oxidebsd_random_bytes(chunk.as_mut_ptr() as u64, chunk.len() as u64) };
            if r < 0 { Err(r) } else { Ok(()) }
        })),
        OpenFile::DevNull => 0, // immediate EOF, matching real /dev/null's own read behavior
        OpenFile::DevZero => uio_ret(fill_uio(uio, |chunk| {
            chunk.fill(0);
            Ok(())
        })),
        // Real pixel I/O only ever happens through mmap() (process::mm::do_mmap_fb, kernel
        // tree) -- see OpenFile::Framebuffer's own doc comment.
        OpenFile::Framebuffer { .. } => -EBADF,
    }
}

/// `write(2)`: stores straight into the inode's blocks at the descriptor's offset (the end of the
/// file first, for `O_APPEND`), so the data is visible to every reader when this returns. A short
/// count when the filesystem fills partway; `ENOSPC` when nothing fit.
extern "C" fn oxfs_write(fd: u64, uio: u64, flags: u64) -> i64 {
    if flags & FOF_OFFSET != 0 {
        return oxfs_pwrite(fd, uio);
    }
    let len = uio_resid(uio);
    let (inode, offset) = match find_open_file(fd) {
        Some(OpenFile::Write { readonly: true, .. }) => return -EBADF,
        Some(OpenFile::Write { inode, position, append, .. }) => {
            if *append {
                *position = read_inode(*inode).size as usize;
            }
            (*inode, *position)
        }
        Some(OpenFile::DevRandom | OpenFile::DevNull | OpenFile::DevZero) => {
            // Matches real /dev/null's and /dev/zero's own write behavior (accept and discard);
            // real /dev/urandom also accepts writes (mixing them into the entropy pool) -- this
            // kernel has no such pool to mix into, so accept-and-discard is the honest
            // simplification here too.
            return len as i64;
        }
        _ => return -EBADF,
    };
    if len == 0 {
        return 0;
    }
    clear_setid_on_write(fd);
    let n = match write_inode_uio(inode, offset, uio) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Some(OpenFile::Write { position, .. }) = find_open_file(fd) {
        *position = offset + n;
    }
    n as i64
}

/// Registered as `fd`'s close callback via `oxidebsd_register_fd_ops`. Releases any `flock()`
/// locks `fd` still holds (closing the locked fd releases its locks), and frees the file if this
/// was the last thing keeping an unlinked file alive (`maybe_release`).
extern "C" fn oxfs_close(fd: u64) -> i64 {
    release_flocks_for(fd);
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    let Some(slot) = slots
        .iter_mut()
        .find(|s| matches!(s, Some((slot_fd, _)) if *slot_fd == fd))
    else {
        return -EBADF;
    };
    let (_, file) = slot.take().expect("just matched Some above");
    if let OpenFile::ProcRead { render, .. } = file {
        free_proc_render(render as usize);
    }
    let closed = match file {
        OpenFile::FileRead { inode, .. }
        | OpenFile::DirListing { inode, .. }
        | OpenFile::Write { inode, .. } => Some(inode),
        _ => None,
    };
    if let Some(inode) = closed {
        maybe_release(inode);
    }
    retry_orphans();
    0
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

/// Registered for `SYS_FSYNC`: the file's delayed writes go to the disk (`sync_file`) before this
/// returns.
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
    if find_open_file(real_fd as u64).is_none() {
        // A disk device (a raw partition `newfs_oxfs` or `fsck_oxfs` wrote) has nothing left to
        // put on the disk: its writes are durable when they return (`drivers::disk`). Anything
        // else that isn't an oxfs file can't be synchronized (POSIX `EINVAL`).
        let mut arg = 0u64;
        // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
        return match unsafe { oxidebsd_real_fd_kind(real_fd as u64, &mut arg) } {
            FD_KIND_DEVICE => 0,
            _ => -EINVAL,
        };
    }
    if let Some(inode) = inode_of_open_file(real_fd as u64) {
        sync_file(inode);
    }
    0
}

/// Puts regular file `n`'s delayed writes on the disk: its data, its index blocks, then its inode
/// record (§3.3.5). Nothing to do for anything else, which is never delayed.
fn sync_file(n: u32) {
    if is_tmpfs_inode(n) {
        return;
    }
    let inode_block = inode_location(n).map(|(block, _)| data_block_offset() + block);
    bcache::flush_file(n, inode_block);
}

/// Registered for `SYS_SYNC`: every delayed write goes to the disk before this returns (POSIX lets
/// `sync(2)` return early; OxideBSD doesn't, since `update(8)` and shutdown rely on it). No
/// failure return.
extern "C" fn oxfs_sync(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    bcache::flush_all();
    0
}

/// Registered with the kernel as the shutdown hook (`oxidebsd_register_shutdown_hook`): an
/// orderly reboot, halt or power-off writes everything delayed, then marks the filesystem clean
/// (§3.4.1). Not called on a panic or a fault.
extern "C" fn oxfs_shutdown() {
    if root_rdonly() {
        return; // nothing delayed, and the disk can't be written
    }
    bcache::flush_all();
    set_clean(true);
    write_superblock();
    log("[oxfs] filesystem synced and marked clean\n");
}

/// Real POSIX `ftruncate(2)`/`fallocate(2)`: `EINVAL` when `fd` isn't open for writing -- shared by
/// both callers below. Peeks the registered `OpenFile::Write` state directly (`inode_of_open_file`
/// returns only the inode, with no access mode) -- see `OpenFile::Write::readonly`'s own doc
/// comment.
fn ftruncate_blocked_readonly(real_fd: u64) -> bool {
    matches!(
        find_open_file(real_fd),
        Some(OpenFile::Write {
            readonly: true,
            ..
        })
    )
}

/// Registered for `SYS_FTRUNCATE`. Resizes the fd's inode directly (`resize_inode_data`); writes
/// are never held back, so whichever of `ftruncate()` and `write()` happens last wins, as on any
/// Unix.
extern "C" fn oxfs_ftruncate(fd: u64, len: u64, _a2: u64, _a3: u64) -> i64 {
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    if ftruncate_blocked_readonly(real_fd) {
        return -EINVAL;
    }
    let Some(inode_num) = inode_of_open_file(real_fd) else {
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
    let Some(inode_num) = inode_of_open_file(real_fd) else {
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
    // A descriptor open for writing has an inode only once something is committed; lock files
    // (pid files) are usually opened O_RDWR|O_CREAT and locked before anything is written.
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

/// musl's real generic `struct statfs` (`arch/generic/bits/statfs.h` in `external/mit/musl` -- this
/// target has no x86_64-specific override, and no separate `statfs64` syscall exists on a 64-bit
/// arch, so this is the one and only shape `src/stat/statvfs.c`'s `__statfs`/`__fstatfs` ever
/// build). All eight `unsigned long`/`fsblkcnt_t`/`fsfilcnt_t` fields are 8 bytes wide on this
/// target, `fsid_t` is a 2-element `int` array -- `f_spare` pads the real kernel-reserved tail.
/// `f_fsid` fills exactly the 8 bytes before `f_namelen`, so there's no implicit padding.
#[repr(C)]
#[derive(Clone, Copy)]
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

// SAFETY: integer fields only, no padding (see above).
unsafe impl Pod for MuslStatfs {}

/// An arbitrary but recognizable magic (`"OXFS"` as big-endian ASCII bytes) -- no applet in this
/// port's roster branches on `f_type`'s specific value, so any fixed constant would do.
const OXFS_STATFS_MAGIC: u64 = 0x4f584653;

/// Builds a real `struct statfs` from this filesystem's own live usage counts and writes it into
/// the caller's buffer -- shared by `oxfs_statfs` (path-based) and `oxfs_fstatfs` (fd-based).
/// `is_tmpfs` picks which of the two block/inode pools to report on (see `TMPFS_BLOCK_BASE`'s own
/// doc comment) -- free counts are computed by scanning that pool's `block_used` bits fresh on
/// every call (no cached running total exists to go stale). `f_bavail` is set
/// equal to `f_bfree` -- this filesystem has no reserved-for-root-only block reservation to make
/// the two diverge, unlike a real ext-family filesystem's own `statfs()`.
fn write_statfs(is_tmpfs: bool, buf_ptr: u64) -> i64 {
    let (blocks_lo, blocks_hi) = if is_tmpfs {
        (TMPFS_BLOCK_BASE, TMPFS_BLOCK_BASE + unsafe { *core::ptr::addr_of!(TMPFS_BLOCKS) })
    } else {
        (0, disk_blocks())
    };
    let free_blocks = if is_tmpfs {
        (blocks_lo..blocks_hi).filter(|&i| !block_used(i)).count() as u64
    } else {
        (0..bitmap_blocks()).map(|i| *free_count(i) as u64).sum()
    };
    // The table grows into free blocks, so each free block is `INODES_PER_BLOCK` inodes to come
    // (as ZFS reports it): the count is an estimate that shrinks as data fills the pool.
    let table = inode_table(is_tmpfs);
    let free_inodes = table.free as u64 + free_blocks * INODES_PER_BLOCK as u64;
    let used_inodes = (table.count - table.free) as u64;
    let statfs = MuslStatfs {
        f_type: OXFS_STATFS_MAGIC,
        f_bsize: BLOCK_SIZE as u64,
        f_blocks: (blocks_hi - blocks_lo) as u64,
        f_bfree: free_blocks,
        f_bavail: free_blocks,
        f_files: used_inodes + free_inodes,
        f_ffree: free_inodes,
        f_fsid: [0, 0],
        f_namelen: NAME_MAX as u64,
        f_frsize: BLOCK_SIZE as u64,
        f_flags: 0,
        f_spare: [0; 4],
    };
    match copyout_val(&statfs, buf_ptr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Registered for `SYS_STATFS`. No `/proc` interception (unlike `oxfs_stat`) -- `/proc` isn't a
/// real, statfs-able mount in this design, and no target applet's own `df`/`statvfs()` call ever
/// targets it. A synthetic-`/proc` cwd falls back to resolving from the real root for an absolute
/// path, same as `oxfs_stat`'s own handling of that case.
extern "C" fn oxfs_statfs(path_ptr: u64, path_len: u64, buf_ptr: u64, _r10: u64) -> i64 {
    let path_buf = match copyin_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let path = path_buf.as_bytes();
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
        Ok(inode_num) => write_statfs(is_tmpfs_inode(inode_num), buf_ptr),
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
        Some(inode_num) => write_statfs(is_tmpfs_inode(inode_num), buf_ptr),
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
    let path_buf = match copyin_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let path = path_buf.as_bytes();

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
    let path_buf = match copyin_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let path = path_buf.as_bytes();
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

    if let Err(e) = copyout_bytes(&path[..len], buf_ptr) {
        return e;
    }
    match copyout_bytes(&[0], buf_ptr.wrapping_add(len as u64)) {
        Ok(()) => (len + 1) as i64,
        Err(e) => e,
    }
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
///
/// `mode` is real now: `(mode & 0o1777) & !umask`, owned by the caller, and creating needs `W_OK`
/// on the parent -- all three used to be skipped (every directory was `0o755`, root-owned, and
/// anyone could create one anywhere).
extern "C" fn oxfs_mkdir(path_ptr: u64, path_len: u64, mode: u64, _a3: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => mkdir_path(path.as_bytes(), mode),
        Err(e) => e,
    }
}

/// `oxfs_mkdir` on a path already copied in.
fn mkdir_path(path: &[u8], mode: u64) -> i64 {
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(OxfsError::InvalidPath) if resolve_path(cwd, path).is_ok() => return -EEXIST,
        Err(e) => return errno_for(e),
    };
    if read_only_at(parent) {
        return -EROFS;
    }
    if dir_lookup(parent, leaf).is_some() {
        return -EEXIST;
    }
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if !check_access(&read_inode(parent), uid, gid, W_OK) {
        return -EACCES;
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return -ENOSPC;
    };
    let mut inode = fresh_inode(InodeKind::Dir);
    inode.mode = ((mode as u16) & 0o1777) & !(unsafe { oxidebsd_current_umask() } as u16);
    inode.uid = uid as u32;
    inode.gid = new_entry_gid(parent);
    write_inode(new_inode, inode);
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
    match copyin_path(path_ptr, path_len) {
        Ok(path) => unlink_path(path.as_bytes()),
        Err(e) => e,
    }
}

/// `oxfs_unlink` on a path already copied in.
fn unlink_path(path: &[u8]) -> i64 {
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if !check_access(&read_inode(parent), uid, gid, W_OK) {
        return -EACCES;
    }
    if read_only_at(parent) {
        return -EROFS;
    }
    let Some(target) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    let mut target_inode = read_inode(target);
    if target_inode.kind == InodeKind::Dir {
        return -EISDIR;
    }
    // Real sticky-bit protection (see this function's own doc comment).
    if let Err(e) = may_delete(parent, target, uid, gid) {
        return e;
    }
    if let Err(e) = dir_remove(parent, leaf) {
        return errno_for(e);
    }
    // A device node removed from devfs stays gone until reboot (`DEVFS.md` §4.4.1).
    if target_inode.kind == InodeKind::Device && in_devfs(parent) {
        devfs_hide(target_inode.rdev);
    }
    target_inode.nlink = target_inode.nlink.saturating_sub(1);
    write_inode(target, target_inode);
    maybe_release(target);
    retry_orphans();
    0
}

/// Registered for `SYS_LINK`. `(existing_ptr, existing_len, new_ptr, new_len)` -- same 4-register
/// two-path shape `SYS_RENAME`/`SYS_SYMLINK` already use (see
/// `external/mit/musl/src/unistd/link.c`'s own patch for why `existing`/`new` need explicit lengths
/// where real `link(2)` doesn't). `existing` is resolved via the normal, symlink-following
/// `resolve_path` -- same as `stat`/`open` already do -- so linking a symlink *path* links its
/// real target, not the symlink entry itself (this filesystem doesn't support hard-linking a
/// symlink directly, a documented simplification; POSIX itself leaves this implementation-defined).
/// Only `File`/`Device` inodes can be linked (`EPERM` for a directory, real Unix's own
/// hard-link-to-a-directory prohibition). Rejects linking across the real/tmpfs inode-pool
/// boundary with `EXDEV` -- see that constant's own doc comment for why (a tmpfs-pool inode must
/// never gain a real, disk-persisted name).
extern "C" fn oxfs_link(existing_ptr: u64, existing_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    let existing_buf = match copyin_path(existing_ptr, existing_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_buf = match copyin_path(new_ptr, new_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let (existing_path, new_path) = (existing_buf.as_bytes(), new_buf.as_bytes());
    let existing_cwd = match real_cwd_for_mutation(existing_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_cwd = match real_cwd_for_mutation(new_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Plain link(2) keeps its existing follow-the-symlink behavior (POSIX leaves it
    // implementation-defined); `linkat(2)` defaults to not following, see `oxfs_linkat`.
    link_impl(existing_cwd, existing_path, new_cwd, new_path, true)
}

/// Shared body of `link(2)`/`linkat(2)`, with each side's base directory already resolved (the two
/// can differ for `linkat`). `follow` is whether a symlink `existing_path` is followed to its
/// target; when it isn't, the symlink itself gains the new name (real Linux behavior).
fn link_impl(
    existing_cwd: u32,
    existing_path: &[u8],
    new_cwd: u32,
    new_path: &[u8],
    follow: bool,
) -> i64 {
    let resolved = if follow {
        resolve_path(existing_cwd, existing_path)
    } else {
        resolve_path_nofollow_last(existing_cwd, existing_path)
    };
    let existing_inode = match resolved {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let mut inode = read_inode(existing_inode);
    let linkable = match inode.kind {
        InodeKind::File | InodeKind::Device | InodeKind::Fifo | InodeKind::Socket => true,
        InodeKind::Symlink => !follow,
        _ => false,
    };
    if !linkable {
        return -EPERM;
    }

    let (new_parent, new_leaf) = match resolve_parent(new_cwd, new_path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if read_only_at(new_parent) {
        return -EROFS;
    }
    if dir_lookup(new_parent, new_leaf).is_some() {
        return -EEXIST;
    }
    let existing_pool_tmpfs = is_tmpfs_inode(existing_inode);
    let new_pool_tmpfs = is_tmpfs_inode(new_parent);
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
/// syscall here uses (see `external/mit/musl/src/stat/mknod.c`'s own patch). Creates a real,
/// listable inode reporting `S_IFCHR`/`S_IFBLK` and a real `st_rdev` via `stat`/`getdents` --
/// unlike `/dev/{random,urandom,null,zero}`'s existing magic-path interception in `dev_open` (not
/// backed by any inode at all). See `known_device`'s own doc comment for the deliberately small
/// set of major:minor pairs `open()` actually services. Also supports `S_IFREG` (an immediately
/// committed empty regular file, unlike `O_CREAT`'s deferred-to-`close()` commit -- matches
/// `oxfs_symlink`'s eager-allocate shape instead) and `S_IFIFO` (a named pipe, `mkfifo(3)`).
/// `S_IFSOCK`/anything else in `mode`'s type bits is `-EINVAL`. Creating a device node is root-only
/// (`-EPERM` otherwise, real `mknod(2)`'s own `CAP_MKNOD` requirement, same genuine-root-only tier
/// as `oxfs_chown`); `S_IFREG`/`S_IFIFO` only need ordinary write permission on the parent, same as
/// any other create.
extern "C" fn oxfs_mknod(path_ptr: u64, path_len: u64, mode: u64, dev: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => mknod_path(path.as_bytes(), mode, dev),
        Err(e) => e,
    }
}

/// `oxfs_mknod` on a path already copied in.
fn mknod_path(path: &[u8], mode: u64, dev: u64) -> i64 {
    let (kind, device_char) = match (mode as u32) & S_IFMT {
        S_IFREG => (InodeKind::File, false),
        S_IFCHR => (InodeKind::Device, true),
        S_IFBLK => (InodeKind::Device, false),
        S_IFIFO => (InodeKind::Fifo, false),
        _ => return -EINVAL,
    };
    match make_node(path, kind, mode as u16 & 0o777, dev as u32, device_char) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// Creates a new, empty inode of `kind` at `path` with permissions `perm & ~umask`, owned by the
/// caller: `mknod(2)`'s body, shared with local-socket names (`oxfs_create_socket_node`).
/// `-EEXIST` if the name exists. Returns the new inode's number.
fn make_node(path: &[u8], kind: InodeKind, perm: u16, dev: u32, device_char: bool) -> Result<u32, i64> {
    let cwd = real_cwd_for_mutation(path)?;
    let (parent, leaf) = resolve_parent(cwd, path).map_err(errno_for)?;
    if read_only_at(parent) {
        return Err(-EROFS);
    }
    if dir_lookup(parent, leaf).is_some() {
        return Err(-EEXIST);
    }
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    // Devices come from drivers in devfs (`DEVFS.md` §4.4.3), and only root makes them elsewhere.
    if kind == InodeKind::Device && (uid != 0 || in_devfs(parent)) {
        return Err(-EPERM);
    }
    if !check_access(&read_inode(parent), uid, gid, W_OK) {
        return Err(-EACCES);
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return Err(-ENOSPC);
    };
    let mut inode = fresh_inode(kind);
    inode.mode = perm & !(unsafe { oxidebsd_current_umask() } as u16);
    inode.uid = uid as u32;
    inode.gid = new_entry_gid(parent);
    if kind == InodeKind::Device {
        inode.rdev = dev;
        inode.device_char = device_char;
    }
    write_inode(new_inode, inode);
    dir_insert(parent, leaf, new_inode).map_err(errno_for)?;
    Ok(new_inode)
}

/// For the kernel's local sockets (UNIX.md §5.2): `bind(2)` to a path creates a socket file there,
/// mode `0777 & ~umask`. `-EADDRINUSE` if anything already exists at `path`, dangling symlinks
/// included. Returns the inode number, which the kernel maps to the bound socket.
extern "C" fn oxfs_create_socket_node(path_ptr: u64, path_len: u64) -> i64 {
    // SAFETY: a kernel buffer holding the caller's path.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    match make_node(path, InodeKind::Socket, 0o777, 0, false) {
        Ok(inode) => inode as i64,
        Err(e) if e == -EEXIST => -EADDRINUSE,
        Err(e) => e,
    }
}

/// For the kernel's local sockets: `connect(2)` and sends to a path. Follows symlinks; needs write
/// permission on the socket file (`-EACCES`); `-ENOTSOCK` for another file type. Returns the inode
/// number.
extern "C" fn oxfs_lookup_socket_node(path_ptr: u64, path_len: u64) -> i64 {
    // SAFETY: as `oxfs_create_socket_node`.
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(_) if path.first() == Some(&b'/') => ROOT_INODE,
        Cwd::Proc(_) => return -ENOENT,
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    let inode = read_inode(inode_num);
    if inode.kind != InodeKind::Socket {
        return -ENOTSOCK;
    }
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if !check_access(&inode, uid, gid, W_OK) {
        return -EACCES;
    }
    inode_num as i64
}

/// May the caller remove (or rename away) entry `target` from directory `parent`? Needs `W_OK` on
/// `parent`, and inside a sticky directory (`/tmp`) the caller must also be root, the directory's
/// owner, or `target`'s owner. Shared by unlink, rmdir and rename.
fn may_delete(parent: u32, target: u32, uid: u64, gid: u64) -> Result<(), i64> {
    let parent_inode = read_inode(parent);
    if !check_access(&parent_inode, uid, gid, W_OK) {
        return Err(-EACCES);
    }
    if parent_inode.mode & 0o1000 != 0
        && uid != 0
        && uid != parent_inode.uid as u64
        && uid != read_inode(target).uid as u64
    {
        return Err(-EACCES);
    }
    Ok(())
}

/// Registered for `SYS_RMDIR`. Only succeeds on an empty directory (`.`/`..` excepted, via
/// `dir_entry_count`).
extern "C" fn oxfs_rmdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => rmdir_path(path.as_bytes()),
        Err(e) => e,
    }
}

/// `oxfs_rmdir` on a path already copied in.
fn rmdir_path(path: &[u8]) -> i64 {
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if read_only_at(parent) {
        return -EROFS;
    }
    let Some(raw_target) = dir_lookup(parent, leaf) else {
        return -ENOENT;
    };
    if read_inode(raw_target).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if let Err(e) = may_delete(parent, raw_target, uid, gid) {
        return e;
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
    if let Err(e) = dir_remove(parent, leaf) {
        return errno_for(e);
    }
    // A directory's link count isn't kept (`write_stat` reports its own); 0 marks it unnamed.
    let mut dir = read_inode(raw_target);
    dir.nlink = 0;
    write_inode(raw_target, dir);
    maybe_release(raw_target);
    retry_orphans();
    0
}

/// Registered for `SYS_RENAME`. `(old_ptr, old_len, new_ptr, new_len)` -- uses all four of this
/// ABI's argument registers (see the module doc comment). Overwriting an existing plain file at
/// `new` is allowed (its old record is cleared first, its inode leaked like every other removal
/// here); overwriting an existing directory is refused (`EISDIR`, kept simple rather than
/// implementing real directory-replace semantics).
extern "C" fn oxfs_rename(old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    let old_buf = match copyin_path(old_ptr, old_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_buf = match copyin_path(new_ptr, new_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let (old_path, new_path) = (old_buf.as_bytes(), new_buf.as_bytes());
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
    rename_impl(old_cwd, old_path, new_cwd, new_path, false)
}

/// Shared body of `rename(2)`/`renameat(2)`/`renameat2(2)`, with each side's base directory already
/// resolved. `noreplace` is `renameat2`'s `RENAME_NOREPLACE`: fail `EEXIST` instead of replacing.
///
/// Follows POSIX: needs delete permission on the old entry and `W_OK` on the new parent; a
/// directory may replace only an empty directory, and never move into its own subtree
/// (`EINVAL`); a directory moved to a new parent gets its `..` rewritten (which, like Linux,
/// needs `W_OK` on the directory itself).
fn rename_impl(old_cwd: u32, old_path: &[u8], new_cwd: u32, new_path: &[u8], noreplace: bool) -> i64 {
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
    let target_inode = read_inode(target);
    let is_dir = target_inode.kind == InodeKind::Dir;
    if read_only_at(old_parent) || read_only_at(new_parent) {
        return -EROFS;
    }
    let existing = dir_lookup(new_parent, new_leaf);
    // Real POSIX: old and new naming the same file is a successful no-op. This used to remove
    // the "destination" (i.e. the source itself) and then fail the source's own removal with
    // EIO, losing the entry.
    if existing == Some(target) {
        return if noreplace { -EEXIST } else { 0 };
    }
    if is_dir && is_same_or_descendant(new_parent, target) {
        return -EINVAL;
    }

    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if let Err(e) = may_delete(old_parent, target, uid, gid) {
        return e;
    }
    if !check_access(&read_inode(new_parent), uid, gid, W_OK) {
        return -EACCES;
    }
    let reparent = is_dir && new_parent != old_parent;
    if reparent && !check_access(&target_inode, uid, gid, W_OK) {
        return -EACCES;
    }

    if let Some(existing) = existing {
        if noreplace {
            return -EEXIST;
        }
        if let Err(e) = may_delete(new_parent, existing, uid, gid) {
            return e;
        }
        let existing_is_dir = read_inode(existing).kind == InodeKind::Dir;
        match (is_dir, existing_is_dir) {
            (false, true) => return -EISDIR,
            (true, false) => return -ENOTDIR,
            (true, true) if dir_entry_count(existing) > 2 => return -ENOTEMPTY,
            _ => {}
        }
        let _ = dir_remove(new_parent, new_leaf);
        let mut replaced = read_inode(existing);
        replaced.nlink = if existing_is_dir { 0 } else { replaced.nlink.saturating_sub(1) };
        write_inode(existing, replaced);
    }
    if dir_remove(old_parent, old_leaf).is_err() {
        return -EIO;
    }
    if let Err(e) = dir_insert(new_parent, new_leaf, target) {
        // Best-effort rollback so a failed rename doesn't just lose the entry outright.
        let _ = dir_insert(old_parent, old_leaf, target);
        return errno_for(e);
    }
    rename_open_files(old_parent, old_leaf, new_parent, new_leaf);
    if reparent {
        // Removing then re-adding `..` reuses the slot just freed, so this can't run out of space.
        let _ = dir_remove(target, b"..");
        if let Err(e) = dir_insert(target, b"..", new_parent) {
            return errno_for(e);
        }
    }
    if let Some(existing) = existing {
        maybe_release(existing);
    }
    0
}

/// Files open through `old_parent`/`old_leaf` now go by the new name, for their
/// `/proc/<pid>/fd` links (`open_file_path`).
fn rename_open_files(old_parent: u32, old_leaf: &[u8], new_parent: u32, new_leaf: &[u8]) {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_FILES) };
    for (_, file) in slots.iter_mut().flatten() {
        let (parent, name, name_len) = match file {
            OpenFile::FileRead { parent, name, name_len, .. } => (parent, name, name_len),
            OpenFile::Write { parent_inode, name, name_len, .. } => (parent_inode, name, name_len),
            _ => continue,
        };
        if *parent == old_parent && &name[..*name_len as usize] == old_leaf {
            *parent = new_parent;
            name[..new_leaf.len()].copy_from_slice(new_leaf);
            *name_len = new_leaf.len() as u8;
        }
    }
}

/// Is `dir` the directory `ancestor` itself, or somewhere beneath it? Walks `..` up to the root.
fn is_same_or_descendant(mut dir: u32, ancestor: u32) -> bool {
    // Bounded: a corrupted `..` chain must not hang a syscall.
    for _ in 0..(1u32 << 16) {
        if dir == ancestor {
            return true;
        }
        match dir_lookup(dir, b"..") {
            Some(parent) if parent != dir => dir = parent,
            _ => return false,
        }
    }
    false
}

/// Registered for `SYS_ACCESS`, kept at real Linux's own inert value (`21`) rather than one of
/// this ABI's own invented numbers -- `external/mit/musl/arch/x86_64/bits/syscall.h.in` never
/// remapped `__NR_access`, and nothing else in this ABI claims `21` (confirmed by grep across
/// every registered syscall number here), the same "leave it where musl already emits it" call
/// already made for `SYS_WRITEV`/`SYS_PIPE` in that same header. `(path_ptr, path_len, amode)` --
/// real `access(2)`'s own `(path, amode)` shape plus the length-prefixed path convention every
/// other path-taking syscall here uses (see `external/mit/musl/src/unistd/access.c`'s own patch).
/// `amode == F_OK` (`0`) is existence-only; otherwise every requested `R_OK`/`W_OK`/`X_OK` bit
/// (singly or combined) must be granted, checked against the caller's real uid/gid via
/// `check_access` (this kernel has no separate effective uid to diverge from -- see `Process::
/// uid`'s own doc comment in `sys/process.rs`). `/proc` entries have no real permission bits (see
/// `write_proc_stat`'s own fixed-placeholder stance) -- existence alone is treated as access,
/// matching this codebase's "don't pretend to model what isn't there" approach elsewhere.
/// Registered for `SYS_ACCESS`: checked with the real user and group IDs (POSIX).
extern "C" fn oxfs_access(path_ptr: u64, path_len: u64, amode: u64, _r10: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => access_path(path.as_bytes(), amode, false),
        Err(e) => e,
    }
}

/// `access(2)`'s check, with the effective IDs instead for `faccessat(AT_EACCESS)`.
fn access_path(path: &[u8], amode: u64, effective: bool) -> i64 {
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
    if access_ok(&inode, amode, effective) {
        0
    } else {
        -EACCES
    }
}

fn access_ok(inode: &Inode, amode: u8, effective: bool) -> bool {
    // SAFETY: plain kernel queries.
    let (uid, gid) = unsafe {
        if effective {
            (oxidebsd_current_uid(), oxidebsd_current_gid())
        } else {
            (oxidebsd_current_ruid(), oxidebsd_current_rgid())
        }
    };
    check_access_as(inode, uid, gid, !effective, amode)
}

/// Registered for `SYS_STAT`. Follows a final symlink component (`resolve_path`'s own default) --
/// `oxfs_lstat` below no longer just aliases this, now that real symlinks exist (see
/// `resolve_path_impl`'s own doc comment for the two functions' actual difference). `/proc/...` is
/// intercepted the same way `oxfs_open` does (see `proc_kind`) -- needed for `ls`/`pstree`, both of
/// which `stat()` a path before deciding whether to list it. A relative path while cwd is inside
/// `/proc` delegates to `proc_relative_stat`.
extern "C" fn oxfs_stat(path_ptr: u64, path_len: u64, buf_ptr: u64, _r10: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => stat_path(path.as_bytes(), buf_ptr),
        Err(e) => e,
    }
}

/// `oxfs_stat` on a path already copied in.
fn stat_path(path: &[u8], buf_ptr: u64) -> i64 {
    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return proc_stat(&path[5..], buf_ptr, true);
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_stat(kind, path, buf_ptr, true);
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
    match copyin_path(path_ptr, path_len) {
        Ok(path) => lstat_path(path.as_bytes(), buf_ptr),
        Err(e) => e,
    }
}

/// `oxfs_lstat` on a path already copied in.
fn lstat_path(path: &[u8], buf_ptr: u64) -> i64 {
    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return proc_stat(&path[5..], buf_ptr, false);
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_stat(kind, path, buf_ptr, false);
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
/// here uses (see `external/mit/musl/src/unistd/readlink.c`'s own patch). Never NUL-terminates the
/// output (real `readlink(2)` semantics) -- returns the byte count actually copied.
extern "C" fn oxfs_readlink(path_ptr: u64, path_len: u64, buf_ptr: u64, buf_cap: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => readlink_path(path.as_bytes(), buf_ptr, buf_cap),
        Err(e) => e,
    }
}

/// `oxfs_readlink` on a path already copied in.
fn readlink_path(path: &[u8], buf_ptr: u64, buf_cap: u64) -> i64 {
    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        return proc_readlink(&path[5..], buf_ptr, buf_cap);
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        Cwd::Proc(kind) => {
            if path.first() == Some(&b'/') {
                ROOT_INODE
            } else {
                return proc_relative_readlink(kind, path, buf_ptr, buf_cap);
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
    // A symlink's target is at most `OXFS_PATH_MAX` bytes (`oxfs_symlink` copies it in).
    let mut target = [0u8; OXFS_PATH_MAX];
    let cap = (buf_cap as usize).min(target.len());
    let n = read_inode_at(inode_num, 0, &mut target[..cap]);
    match copyout_bytes(&target[..n], buf_ptr) {
        Ok(()) => n as i64,
        Err(e) => e,
    }
}

/// Registered for `SYS_SYMLINK`. `(target_ptr, target_len, linkpath_ptr, linkpath_len)` -- mirrors
/// `oxfs_rename`'s own 4-register shape exactly (two path strings, no other args); see
/// `external/mit/musl/src/unistd/symlink.c`'s own patch for why `target`/`linkpath` need explicit
/// lengths where real `symlink(2)` doesn't. `target` is stored verbatim, unvalidated and
/// unresolved (matching real `symlink(2)`: a dangling or even syntactically-nonsensical target is
/// perfectly legal to create, only resolving it later can fail).
extern "C" fn oxfs_symlink(
    target_ptr: u64,
    target_len: u64,
    linkpath_ptr: u64,
    linkpath_len: u64,
) -> i64 {
    let target = match copyin_path(target_ptr, target_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match copyin_path(linkpath_ptr, linkpath_len) {
        Ok(linkpath) => symlink_path(target.as_bytes(), linkpath.as_bytes()),
        Err(e) => e,
    }
}

/// `oxfs_symlink` on paths already copied in.
fn symlink_path(target: &[u8], linkpath: &[u8]) -> i64 {
    let cwd = match real_cwd_for_mutation(linkpath) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (parent, leaf) = match resolve_parent(cwd, linkpath) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if read_only_at(parent) {
        return -EROFS;
    }
    if dir_lookup(parent, leaf).is_some() {
        return -EEXIST;
    }
    let Some(new_inode) = alloc_inode_in(parent) else {
        return -ENOSPC;
    };
    let mut inode = fresh_inode(InodeKind::Symlink);
    inode.uid = unsafe { oxidebsd_current_uid() } as u32;
    inode.gid = new_entry_gid(parent);
    write_inode(new_inode, inode);
    if !write_inode_data(new_inode, target) {
        return -EIO;
    }
    match dir_insert(parent, leaf, new_inode) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}

/// `chmod(2)` of inode `inode_num`, for `oxfs_chmod` and `oxfs_fchmod`: only its owner or root may,
/// `EPERM` otherwise. All twelve permission bits are kept, setuid, setgid and sticky included
/// (`/tmp` and `/dev/shm` are sticky); as POSIX requires, setgid is cleared when the caller isn't
/// root and isn't in the file's group. (This masked to `0o777` until 2026-09-30, so a `chmod 1777
/// /tmp` silently took `/tmp`'s sticky bit away.)
fn set_mode(inode_num: u32, mode: u64) -> i64 {
    if read_only_at(inode_num) {
        return -EROFS;
    }
    let mut inode = read_inode(inode_num);
    let (caller_uid, caller_gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if caller_uid != 0 && caller_uid != inode.uid as u64 {
        return -EPERM;
    }
    let mut mode = (mode & 0o7777) as u16;
    if caller_uid != 0 && caller_gid != inode.gid as u64 {
        mode &= !0o2000;
    }
    inode.mode = mode;
    write_inode(inode_num, inode);
    0
}

/// Registered for `SYS_CHMOD`. `(path_ptr, path_len, mode)` -- real `chmod(2)`'s own `(path, mode)`
/// shape plus the length-prefixed path convention every other path-taking syscall here uses (see
/// `external/mit/musl/src/stat/chmod.c`'s own patch). Follows a final symlink component (real
/// `chmod(2)` semantics -- there's no `lchmod` in POSIX at all, unlike `chown`/`lchown` below).
/// Only the inode's own owner or root may change its permission bits (`EPERM` otherwise, matching
/// real Unix; see `set_mode`).
extern "C" fn oxfs_chmod(path_ptr: u64, path_len: u64, mode: u64, _r10: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => chmod_path(path.as_bytes(), mode),
        Err(e) => e,
    }
}

/// `oxfs_chmod` on a path already copied in.
fn chmod_path(path: &[u8], mode: u64) -> i64 {
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    set_mode(inode_num, mode)
}

/// Registered for `SYS_CHOWN`. `(path_ptr, path_len, uid, gid)` -- real `chown(2)`'s own
/// `(path, uid, gid)` shape, using all four of this ABI's argument registers the same way
/// `SYS_RENAME`/`SYS_SYMLINK` already do (see `external/mit/musl/src/unistd/chown.c`'s own patch).
/// Follows a final symlink component, matching real `chown(2)` (unlike `lchown(2)`, not
/// implemented this pass -- no target applet in the current roster calls it). Real POSIX
/// `(uid_t)-1`/`(gid_t)-1` "leave this field unchanged" convention (`u32::MAX` once truncated
/// through this ABI's `u64` register), so a caller can change just one of the two. Permission:
/// `chown_inode`.
extern "C" fn oxfs_chown(path_ptr: u64, path_len: u64, uid: u64, gid: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => chown_path(path.as_bytes(), uid, gid),
        Err(e) => e,
    }
}

/// `oxfs_chown` on a path already copied in.
fn chown_path(path: &[u8], uid: u64, gid: u64) -> i64 {
    let cwd = match real_cwd_for_mutation(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode_num = match resolve_path(cwd, path) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    chown_inode(inode_num, uid, gid)
}

/// Registered for `SYS_FCHMOD` at real Linux's own `__NR_fchmod = 91` -- unlike every other
/// syscall in this module, this one needed no invented number and no musl-side remap at all:
/// `external/mit/musl/arch/x86_64/bits/syscall.h.in` never touches `__NR_fchmod`, so musl's
/// `fchmod(2)` wrapper already calls `syscall(91, fd, mode)` directly, and `91` was still
/// completely unassigned in this ABI's own registry (checked against every `SYS_*` constant in
/// `src/`/`modules/` before landing here -- same collision-avoidance discipline as inventing a new
/// number, just confirming the reverse: that using the real value directly doesn't collide with an
/// already-invented one). Found live: BusyBox's `uudecode` restores the encoded file's mode via
/// `fchmod(fd, mode)` on its still-open output fd, not a path-based `chmod()` -- previously a
/// silent `ENOSYS` (uudecode ignores the return value, so the roundtrip test still passed on
/// content alone; the restored mode was just silently wrong).
///
/// The change itself is `set_mode`'s.
extern "C" fn oxfs_fchmod(fd: u64, mode: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = inode_of_open_file(real_fd as u64) else {
        return -EBADF;
    };
    set_mode(inode_num, mode)
}

/// Registered for `SYS_FCHDIR` at real Linux's own `__NR_fchdir = 81` -- same "still completely
/// unassigned in this ABI's own registry, no invented number or musl-side remap needed" story as
/// `SYS_FCHMOD` above (checked against every `SYS_*` constant in `src/`/`modules/` first). Found
/// live via `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own POSIX-vs-musl sweep -- `external/mit/musl/src/
/// unistd/fchdir.c` calls this directly, though no BusyBox-roster applet was confirmed to call it
/// yet; cheap enough to close anyway.
///
/// Rejects a non-directory target with `-ENOTDIR`, matching real
/// `fchdir(2)`; otherwise reuses `oxfs_chdir`'s own `set_current_cwd_real` tail directly (no `/proc`
/// case to consider here -- a `/proc` entry has no real inode for a fd to resolve to in the first
/// place, see `inode_of_open_file`'s own `ProcRead`/`ProcDir` doc comment above).
extern "C" fn oxfs_fchdir(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let Some(inode_num) = inode_of_open_file(real_fd as u64) else {
        return -EBADF;
    };
    if read_inode(inode_num).kind != InodeKind::Dir {
        return -ENOTDIR;
    }
    set_current_cwd_real(inode_num);
    0
}

/// Registered for `SYS_UTIMENSAT`. `(path_ptr, path_len, times_ptr, flags)` -- see
/// `external/mit/musl/src/stat/utimensat.c`'s own patch comment for the wire-format story (dropped
/// the always-`AT_FDCWD` `fd` argument, computed `path_len` explicitly). Real, not a stub: sets
/// `Inode::atime`/`mtime` (and `ctime`, which real POSIX also bumps on any timestamp change) and
/// persists them via `write_inode`.
///
/// `times_ptr == 0` means "both now"; otherwise it points at two `struct timespec`s
/// (`{tv_sec: i64, tv_nsec: i64}`, atime then mtime), each of which may instead carry the real
/// `UTIME_NOW`/`UTIME_OMIT` sentinel in `tv_nsec` (`(1<<30)-1`/`(1<<30)-2`). Timestamps here are
/// whole-second (see `Inode::atime`/`mtime`), so a real `tv_nsec` is validated but not stored.
/// `AT_SYMLINK_NOFOLLOW` (`0x100`) stamps a final symlink itself instead of its target.
///
/// Real POSIX permission rules: explicit times (anything other than "now"/omit) need the caller to
/// own the file or be root (`EPERM`); "now" alone also allows anyone with write access
/// (`EACCES` otherwise). A missing path is `ENOENT` -- the distinction BusyBox's and this
/// project's own native `touch` use to decide whether to create the file with `open(O_CREAT)`.
extern "C" fn oxfs_utimensat(path_ptr: u64, path_len: u64, times_ptr: u64, flags: u64) -> i64 {
    match copyin_path(path_ptr, path_len) {
        Ok(path) => utimensat_path(path.as_bytes(), times_ptr, flags),
        Err(e) => e,
    }
}

/// `oxfs_utimensat` on a path already copied in.
fn utimensat_path(path: &[u8], times_ptr: u64, flags: u64) -> i64 {
    if path.starts_with(b"/proc") && (path.len() == 5 || path[5] == b'/') {
        // Synthetic /proc entries have no real inode to stamp -- existence check only.
        return match proc_kind(&path[5..]) {
            Some(_) => 0,
            None => -ENOENT,
        };
    }

    let cwd = match current_cwd() {
        Cwd::Real(inode) => inode,
        // cwd inside /proc and a *relative* (non-`/`-leading) target: nothing real to resolve
        // against, and no caller here does this -- ENOENT is the honest POSIX answer.
        Cwd::Proc(_) if path.first() != Some(&b'/') => return -ENOENT,
        Cwd::Proc(_) => ROOT_INODE,
    };
    let resolved = if flags & AT_SYMLINK_NOFOLLOW != 0 {
        resolve_path_nofollow_last(cwd, path)
    } else {
        resolve_path(cwd, path)
    };
    let inode_num = match resolved {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    utimens_inode(inode_num, times_ptr)
}

/// The timestamp-setting half of `oxfs_utimensat`, split out so `oxfs_utimensat_at` can also apply
/// it straight to a dirfd's own inode -- real `utimensat(fd, NULL, ...)`, which is how musl
/// implements `futimens(fd)` (that used to be a flat `ENOSYS` here).
fn utimens_inode(inode_num: u32, times_ptr: u64) -> i64 {
    if read_only_at(inode_num) {
        return -EROFS;
    }
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;

    let now = unsafe { oxidebsd_unix_time() };
    let (mut new_atime, mut new_mtime) = (Some(now), Some(now));
    let mut explicit = false;
    if times_ptr != 0 {
        let t: [i64; 4] = match copyin_val(times_ptr) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let mut resolve = |sec: i64, nsec: i64| -> Result<Option<i64>, i64> {
            if nsec == UTIME_NOW {
                Ok(Some(now))
            } else if nsec == UTIME_OMIT {
                Ok(None)
            } else if !(0..1_000_000_000).contains(&nsec) {
                Err(-EINVAL)
            } else {
                explicit = true;
                Ok(Some(sec))
            }
        };
        new_atime = match resolve(t[0], t[1]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        new_mtime = match resolve(t[2], t[3]) {
            Ok(v) => v,
            Err(e) => return e,
        };
    }
    if new_atime.is_none() && new_mtime.is_none() {
        return 0;
    }

    let mut inode = read_inode(inode_num);
    let (uid, gid) = unsafe { (oxidebsd_current_uid(), oxidebsd_current_gid()) };
    if uid != 0 && uid != inode.uid as u64 {
        if explicit {
            return -EPERM;
        }
        if !check_access(&inode, uid, gid, W_OK) {
            return -EACCES;
        }
    }
    if let Some(a) = new_atime {
        inode.atime = a;
    }
    if let Some(m) = new_mtime {
        inode.mtime = m;
    }
    inode.ctime = now;
    write_inode(inode_num, inode);
    0
}

/// Copies `src` into a fixed `[u8; MAX_MOUNT_PATH]` for `MountEntry`'s own display-only `path`/
/// `source` fields, truncating if `src` is longer -- these are never compared against (matching by
/// inode, see `oxfs_umount2`), only ever formatted back out for `/proc/mounts`, so silent
/// truncation of a pathologically long path is a cosmetic degradation, not a correctness bug.
// --- The `*at()` family ----------------------------------------------------------------------
//
// Every `*at()` call resolves a path relative to a directory fd (`dirfd`) instead of the cwd;
// `AT_FDCWD` or an absolute path makes it identical to the plain call. This ABI carries at most 4
// register arguments and passes paths length-prefixed, so a `(dirfd, path)` pair can't ride in
// registers for the two-path calls (`linkat`/`renameat2` need 2 dirfds + 2 paths + flags). Instead
// each pair is one `RawAtPath` in the caller's memory -- the same "small struct in user memory"
// convention `RawArgvEntry` already uses for `execve`'s argv. musl builds it
// (`src/internal/oxidebsd_at.h` on the `oxidebsd` branch).
//
// Single-base calls delegate to the ordinary path handler under an `AtBaseGuard` (see its doc
// comment), so `/proc`, mounts, chroot containment and every errno path behave exactly like the
// plain call. `link`/`rename` take each side's base explicitly (`link_impl`/`rename_impl`).

/// musl's `AT_*` values (`include/fcntl.h`). `AT_REMOVEDIR` and `AT_EACCESS` share `0x200` -- each
/// is only meaningful to its own call (`unlinkat`/`faccessat`).
const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EACCESS: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
/// `renameat2` flags (`include/stdio.h`).
const RENAME_NOREPLACE: u64 = 1;
const RENAME_EXCHANGE: u64 = 2;
const RENAME_WHITEOUT: u64 = 4;

/// One `(dirfd, path)` pair -- see this section's header. `ptr == 0` is a real NULL path (only
/// `utimensat` accepts one: it means "the fd itself", which is how musl's `futimens` works).
/// Must match `struct __oxidebsd_at` in musl's `src/internal/oxidebsd_at.h` byte for byte.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawAtPath {
    dirfd: i64,
    ptr: u64,
    len: u64,
}

// SAFETY: three 8-byte integers, no padding.
unsafe impl Pod for RawAtPath {}

/// A `RawAtPath` with its path copied in.
struct AtPath {
    dirfd: i64,
    /// A NULL path (`RawAtPath::ptr == 0`).
    null: bool,
    path: UserPath,
}

impl AtPath {
    fn path(&self) -> &[u8] {
        self.path.as_bytes()
    }

    /// Relative to `dirfd` for real, i.e. neither absolute nor `AT_FDCWD`.
    fn uses_dirfd(&self) -> bool {
        self.dirfd != AT_FDCWD && self.path().first() != Some(&b'/')
    }
}

/// Copies the `RawAtPath` at `at_ptr`, then its path, in.
fn read_at(at_ptr: u64) -> Result<AtPath, i64> {
    let raw: RawAtPath = copyin_val(at_ptr)?;
    let path = if raw.ptr == 0 { UserPath::empty() } else { copyin_path(raw.ptr, raw.len)? };
    Ok(AtPath { dirfd: raw.dirfd, null: raw.ptr == 0, path })
}

/// `dirfd` as a cwd-encoded base (see `decode_cwd`): a real directory fd, or a `/proc` directory
/// fd. `EBADF` for a closed fd, `ENOTDIR` for any open fd that isn't a directory (including a
/// pipe/socket owned by another module -- `real_fd`s come from one global counter, so it simply
/// isn't in this module's table).
fn dirfd_base(dirfd: i64) -> Result<u64, i64> {
    if dirfd < 0 {
        return Err(-EBADF);
    }
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(dirfd as u64) };
    if real_fd < 0 {
        return Err(-EBADF);
    }
    match find_open_file(real_fd as u64) {
        Some(OpenFile::DirListing { inode, .. }) => Ok(*inode as u64),
        Some(OpenFile::ProcDir { kind, .. }) => Ok(encode_proc_cwd(*kind)),
        _ => Err(-ENOTDIR),
    }
}

/// Runs `f` (an ordinary path handler call on `at`'s own path) with `at.dirfd` as its base.
/// An empty path is `ENOENT`, matching real Linux (every caller that accepts `AT_EMPTY_PATH`
/// checks for it before getting here).
fn with_at(at: &AtPath, f: impl FnOnce() -> i64) -> i64 {
    if at.path().is_empty() {
        return -ENOENT;
    }
    if !at.uses_dirfd() {
        return f();
    }
    match dirfd_base(at.dirfd) {
        Ok(base) => {
            let _guard = AtBaseGuard::set(base);
            f()
        }
        Err(e) => e,
    }
}

/// `real_cwd_for_mutation`, relative to `at.dirfd` -- one side of `linkat`/`renameat2`.
fn at_cwd_for_mutation(at: &AtPath) -> Result<u32, i64> {
    let path = at.path();
    if path.is_empty() {
        return Err(-ENOENT);
    }
    if !at.uses_dirfd() {
        return real_cwd_for_mutation(path);
    }
    let base = dirfd_base(at.dirfd)?;
    let _guard = AtBaseGuard::set(base);
    real_cwd_for_mutation(path)
}

/// Resolves `at`'s path without following a final symlink, relative to `at.dirfd` -- for the
/// `AT_SYMLINK_NOFOLLOW` variants whose plain handler always follows (`fchownat`/`fchmodat`/
/// `faccessat`).
fn at_resolve_nofollow(at: &AtPath) -> Result<u32, i64> {
    let cwd = at_cwd_for_mutation(at)?;
    resolve_path_nofollow_last(cwd, at.path()).map_err(errno_for)
}

/// The inode behind an `AT_EMPTY_PATH` fd (or the cwd, for `AT_FDCWD`). `EPERM` when the fd is
/// real but has no oxfs inode behind it (the console, `/proc`, `/dev/*`) -- nothing to change.
fn at_empty_path_inode(dirfd: i64) -> Result<u32, i64> {
    if dirfd == AT_FDCWD {
        return match current_cwd() {
            Cwd::Real(inode) => Ok(inode),
            Cwd::Proc(_) => Err(-EPERM),
        };
    }
    if dirfd < 0 {
        return Err(-EBADF);
    }
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(dirfd as u64) };
    if real_fd < 0 {
        return Err(-EBADF);
    }
    inode_of_open_file(real_fd as u64).ok_or(-EPERM)
}

/// `oxfs_chown`'s own rules (root-only; `-1` leaves a field unchanged), applied to an already-
/// resolved inode -- for `lchown`/`fchown` (`fchownat` with `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH`),
/// both of which were flat `ENOSYS` before this.
/// `chown(2)` on an inode, with `_POSIX_CHOWN_RESTRICTED` as on the BSDs: the superuser may change
/// either ID; the owner may only change the group, to one it belongs to. A change by anyone but
/// the superuser clears the set-user-ID and set-group-ID bits (`OxideBSD-doc/SUDO.md` §5.1.5).
fn chown_inode(inode_num: u32, uid: u64, gid: u64) -> i64 {
    if read_only_at(inode_num) {
        return -EROFS;
    }
    let caller = unsafe { oxidebsd_current_uid() };
    let mut inode = read_inode(inode_num);
    let new_uid = if uid == u32::MAX as u64 { inode.uid } else { uid as u32 };
    let new_gid = if gid == u32::MAX as u64 { inode.gid } else { gid as u32 };
    if caller != 0 {
        let owner = caller == inode.uid as u64 && new_uid == inode.uid;
        let group_ok = new_gid == inode.gid || unsafe { oxidebsd_current_in_group(new_gid as u64, 0) } != 0;
        if !owner || !group_ok {
            return -EPERM;
        }
        inode.mode &= !SETID_BITS;
    }
    inode.uid = new_uid;
    inode.gid = new_gid;
    write_inode(inode_num, inode);
    0
}

/// `S_ISUID | S_ISGID`.
const SETID_BITS: u16 = 0o6000;

/// A write by anyone but the superuser clears the set-user-ID and set-group-ID bits of the file
/// written (`OxideBSD-doc/SUDO.md` §5.1.5), so a modified program can't keep running as its owner.
fn clear_setid_on_write(fd: u64) {
    if unsafe { oxidebsd_current_uid() } == 0 {
        return;
    }
    if let Some(inode_num) = inode_of_open_file(fd) {
        let mut inode = read_inode(inode_num);
        if inode.mode & SETID_BITS != 0 {
            inode.mode &= !SETID_BITS;
            write_inode(inode_num, inode);
        }
    }
}

/// Registered for `SYS_OPENAT`. `(at, flags, mode)`.
extern "C" fn oxfs_openat(at_ptr: u64, flags: u64, mode: u64, _a3: u64) -> i64 {
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    with_at(&at, || open_path(at.path(), flags, mode))
}

/// Registered for `SYS_MKDIRAT`. `(at, mode)`.
extern "C" fn oxfs_mkdirat(at_ptr: u64, mode: u64, _a2: u64, _a3: u64) -> i64 {
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    with_at(&at, || mkdir_path(at.path(), mode))
}

/// Registered for `SYS_MKNODAT`. `(at, mode, dev)`.
extern "C" fn oxfs_mknodat(at_ptr: u64, mode: u64, dev: u64, _a3: u64) -> i64 {
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    with_at(&at, || mknod_path(at.path(), mode, dev))
}

/// Registered for `SYS_FCHOWNAT`. `(at, uid, gid, flags)`. musl's `lchown` and `fchown` route
/// here too (`AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH`).
extern "C" fn oxfs_fchownat(at_ptr: u64, uid: u64, gid: u64, flags: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if at.path().is_empty() && flags & AT_EMPTY_PATH != 0 {
        return match at_empty_path_inode(at.dirfd) {
            Ok(inode) => chown_inode(inode, uid, gid),
            Err(e) => e,
        };
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        return match at_resolve_nofollow(&at) {
            Ok(inode) => chown_inode(inode, uid, gid),
            Err(e) => e,
        };
    }
    with_at(&at, || chown_path(at.path(), uid, gid))
}

/// Registered for `SYS_NEWFSTATAT` (musl's `SYS_fstatat`). `(at, statbuf, flags)`.
extern "C" fn oxfs_fstatat(at_ptr: u64, buf_ptr: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if at.path().is_empty() && flags & AT_EMPTY_PATH != 0 {
        if at.dirfd == AT_FDCWD {
            return stat_path(b".", buf_ptr);
        }
        if at.dirfd < 0 {
            return -EBADF;
        }
        return oxfs_fstat(at.dirfd as u64, buf_ptr, 0, 0);
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        with_at(&at, || lstat_path(at.path(), buf_ptr))
    } else {
        with_at(&at, || stat_path(at.path(), buf_ptr))
    }
}

/// Registered for `SYS_UNLINKAT`. `(at, flags)` -- `AT_REMOVEDIR` makes it `rmdir`.
extern "C" fn oxfs_unlinkat(at_ptr: u64, flags: u64, _a2: u64, _a3: u64) -> i64 {
    if flags & !AT_REMOVEDIR != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if flags & AT_REMOVEDIR != 0 {
        with_at(&at, || rmdir_path(at.path()))
    } else {
        with_at(&at, || unlink_path(at.path()))
    }
}

/// Registered for `SYS_RENAMEAT2`. `(old_at, new_at, flags)`. `RENAME_NOREPLACE` is real;
/// `RENAME_EXCHANGE`/`RENAME_WHITEOUT` are `EINVAL`, which is what real Linux returns for a flag
/// the filesystem doesn't support.
extern "C" fn oxfs_renameat2(old_at_ptr: u64, new_at_ptr: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
    {
        return -EINVAL;
    }
    let old_at = match read_at(old_at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let new_at = match read_at(new_at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let old_cwd = match at_cwd_for_mutation(&old_at) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_cwd = match at_cwd_for_mutation(&new_at) {
        Ok(v) => v,
        Err(e) => return e,
    };
    rename_impl(
        old_cwd,
        old_at.path(),
        new_cwd,
        new_at.path(),
        flags & RENAME_NOREPLACE != 0,
    )
}

/// Registered for `SYS_RENAMEAT`. `(old_at, new_at)` -- `renameat2` with no flags.
extern "C" fn oxfs_renameat(old_at_ptr: u64, new_at_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    oxfs_renameat2(old_at_ptr, new_at_ptr, 0, 0)
}

/// Registered for `SYS_LINKAT`. `(old_at, new_at, flags)`. Unlike plain `link`, doesn't follow a
/// symlink `old` unless `AT_SYMLINK_FOLLOW`. `AT_EMPTY_PATH` (link the fd's own inode) needs
/// `CAP_DAC_READ_SEARCH` on Linux; with no capability model here it's the unprivileged `ENOENT`.
extern "C" fn oxfs_linkat(old_at_ptr: u64, new_at_ptr: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let old_at = match read_at(old_at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let new_at = match read_at(new_at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let old_cwd = match at_cwd_for_mutation(&old_at) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_cwd = match at_cwd_for_mutation(&new_at) {
        Ok(v) => v,
        Err(e) => return e,
    };
    link_impl(
        old_cwd,
        old_at.path(),
        new_cwd,
        new_at.path(),
        flags & AT_SYMLINK_FOLLOW != 0,
    )
}

/// Registered for `SYS_SYMLINKAT`. `(target_ptr, target_len, linkpath_at)` -- the target is the
/// link's stored content, never resolved here, so only the new link's own path is dirfd-relative.
extern "C" fn oxfs_symlinkat(target_ptr: u64, target_len: u64, at_ptr: u64, _a3: u64) -> i64 {
    let target = match copyin_path(target_ptr, target_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    with_at(&at, || symlink_path(target.as_bytes(), at.path()))
}

/// Registered for `SYS_READLINKAT`. `(at, buf, bufsize)`.
extern "C" fn oxfs_readlinkat(at_ptr: u64, buf_ptr: u64, buf_cap: u64, _a3: u64) -> i64 {
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    with_at(&at, || readlink_path(at.path(), buf_ptr, buf_cap))
}

/// Registered for `SYS_FCHMODAT`. `(at, mode, flags)` -- real `fchmodat2` semantics: a symlink
/// with `AT_SYMLINK_NOFOLLOW` is `EOPNOTSUPP` (no symlink permission bits, same as Linux).
extern "C" fn oxfs_fchmodat(at_ptr: u64, mode: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if at.path().is_empty() && flags & AT_EMPTY_PATH != 0 {
        if at.dirfd == AT_FDCWD {
            return chmod_path(b".", mode);
        }
        if at.dirfd < 0 {
            return -EBADF;
        }
        return oxfs_fchmod(at.dirfd as u64, mode, 0, 0);
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        match at_resolve_nofollow(&at) {
            Ok(inode) if read_inode(inode).kind == InodeKind::Symlink => return -EOPNOTSUPP,
            Ok(_) => {}
            Err(e) => return e,
        }
    }
    with_at(&at, || chmod_path(at.path(), mode))
}

/// Registered for `SYS_FACCESSAT`. `(at, amode, flags)`. Checked with the real IDs, or the
/// effective ones with `AT_EACCESS`. With
/// `AT_SYMLINK_NOFOLLOW`, a symlink itself always passes (its own permissions are `0777`).
extern "C" fn oxfs_faccessat(at_ptr: u64, amode: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if at.path().is_empty() && flags & AT_EMPTY_PATH != 0 {
        let inode_num = match at_empty_path_inode(at.dirfd) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if amode == 0 {
            return 0;
        }
        return if access_ok(&read_inode(inode_num), amode as u8, flags & AT_EACCESS != 0) {
            0
        } else {
            -EACCES
        };
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0
        && let Ok(inode) = at_resolve_nofollow(&at)
        && read_inode(inode).kind == InodeKind::Symlink
    {
        return 0;
    }
    with_at(&at, || access_path(at.path(), amode, flags & AT_EACCESS != 0))
}

/// Registered for `SYS_UTIMENSAT_AT` -- real, dirfd-aware `utimensat(2)`: `(at, times, flags)`.
/// A NULL path (`at.ptr == 0`, or empty with `AT_EMPTY_PATH`) stamps `dirfd`'s own inode -- musl's
/// `futimens(fd)`. The older path-only `SYS_UTIMENSAT` (167) stays registered as-is: `lib/oxlibc`'s
/// native `touch` calls it directly.
extern "C" fn oxfs_utimensat_at(at_ptr: u64, times_ptr: u64, flags: u64, _a3: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let at = match read_at(at_ptr) {
        Ok(at) => at,
        Err(e) => return e,
    };
    if at.null || (at.path().is_empty() && flags & AT_EMPTY_PATH != 0) {
        return match at_empty_path_inode(at.dirfd) {
            Ok(inode) => utimens_inode(inode, times_ptr),
            Err(e) => e,
        };
    }
    with_at(&at, || utimensat_path(at.path(), times_ptr, flags))
}

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

/// A nullfs (bind) mount of directory `source` on directory `target`: `oxfs_nmount` with
/// `fstype=nullfs`. Both must be directories; `source` is resolved through any mount already on
/// it (binding from inside another mount binds the effective view, not the raw inode).
fn mount_nullfs(source: &[u8], target: &[u8], nosuid: bool, wxallowed: bool) -> i64 {
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
        nosuid,
        wxallowed,
    };
    0
}

/// A new, empty tmpfs on directory `target`: `oxfs_nmount` with `fstype=tmpfs`. Its root comes
/// from the tmpfs pool (`alloc_tmpfs_inode`) with real `.`/`..` records, `..` the mountpoint's own
/// parent, so `cd ..` from inside it escapes back to the real tree with no special-casing.
fn mount_tmpfs(target: &[u8], nosuid: bool, wxallowed: bool) -> i64 {
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
    write_inode(new_root, fresh_inode(InodeKind::Dir));
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
        nosuid,
        wxallowed,
    };
    0
}

/// One `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: u64,
    len: u64,
}

// SAFETY: two 8-byte integers, no padding.
unsafe impl Pod for IoVec {}

/// The most `struct iovec`s `nmount` takes (32 name/value pairs).
const NMOUNT_MAX_IOV: usize = 64;

/// Copies an `nmount` option in, without the terminating NUL the caller may include in its
/// length. `Err(-ENAMETOOLONG)` past `OXFS_PATH_MAX`, `Err(-EFAULT)` for a bad pointer.
fn iov_str(v: IoVec) -> Result<UserPath, i64> {
    if v.base == 0 {
        return Ok(UserPath::empty());
    }
    let mut s = copyin_path(v.base, v.len)?;
    if let Some(n) = s.as_bytes().iter().position(|&b| b == 0) {
        s.len = n;
    }
    Ok(s)
}

/// Registered for `SYS_NMOUNT`: `nmount(iov, niov, flags)`, after FreeBSD's. `iov` holds
/// `niov / 2` name/value pairs, each a `struct iovec` (a value may be empty): `fstype` (`tmpfs` or
/// `nullfs`), `fspath` (the directory to mount on), and for nullfs `from` or `target` (the
/// directory to mount), `nosuid` (no value; or `MNT_NOSUID` in `flags`) and `wxallowed` (no
/// value). `errmsg`, if given,
/// is a buffer the kernel fills with a sentence saying why the call failed. Any other option or
/// flag is refused with `EOPNOTSUPP`. Only root may mount.
extern "C" fn oxfs_nmount(iov_ptr: u64, niov: u64, flags: u64, _a3: u64) -> i64 {
    if niov % 2 != 0 || niov > NMOUNT_MAX_IOV as u64 {
        return -EINVAL;
    }
    let mut iov_buf = [IoVec { base: 0, len: 0 }; NMOUNT_MAX_IOV];
    let iov = &mut iov_buf[..niov as usize];
    for (i, v) in iov.iter_mut().enumerate() {
        *v = match copyin_val(iov_ptr.wrapping_add((i * core::mem::size_of::<IoVec>()) as u64)) {
            Ok(v) => v,
            Err(e) => return e,
        };
    }
    let mut errmsg: Option<IoVec> = None;
    let mut fstype = UserPath::empty();
    let mut fspath = UserPath::empty();
    let mut from = UserPath::empty();
    let mut unknown = false;
    // The first option that couldn't be copied in, reported once `errmsg` is known.
    let mut bad_option: Option<i64> = None;
    // FreeBSD's MNT_NOSUID, as a flag or as the `nosuid` option.
    const MNT_NOSUID: u64 = 0x8;
    let mut nosuid = flags & MNT_NOSUID != 0;
    // OpenBSD's option, as an option only: its MNT_WXALLOWED bit is an export flag on FreeBSD.
    let mut wxallowed = false;
    // FreeBSD's MNT_RDONLY and MNT_UPDATE (`mount -u`), as flags or as the `ro`/`rw` options.
    const MNT_RDONLY: u64 = 0x1;
    const MNT_UPDATE: u64 = 0x0001_0000;
    let mut rdonly = flags & MNT_RDONLY != 0;
    for pair in iov.chunks_exact(2) {
        let name = match iov_str(pair[0]) {
            Ok(name) => name,
            Err(e) => {
                bad_option.get_or_insert(e);
                continue;
            }
        };
        let value = pair[1];
        let slot = match name.as_bytes() {
            b"nosuid" => {
                nosuid = true;
                continue;
            }
            b"wxallowed" => {
                wxallowed = true;
                continue;
            }
            b"ro" => {
                rdonly = true;
                continue;
            }
            b"rw" => {
                rdonly = false;
                continue;
            }
            b"errmsg" => {
                errmsg = Some(value);
                continue;
            }
            b"fstype" => &mut fstype,
            b"fspath" => &mut fspath,
            b"from" | b"target" => &mut from,
            _ => {
                unknown = true;
                continue;
            }
        };
        match iov_str(value) {
            Ok(v) => *slot = v,
            Err(e) => {
                bad_option.get_or_insert(e);
            }
        }
    }
    let (fstype, fspath, from) = (fstype.as_bytes(), fspath.as_bytes(), from.as_bytes());
    let fail = |errno: i64, msg: &[u8]| -> i64 {
        if let Some(buf) = errmsg
            && buf.base != 0
            && buf.len > 0
        {
            // Best effort: the call fails with `errno` whether or not the message gets out.
            let n = msg.len().min(buf.len as usize - 1);
            let _ = copyout_bytes(&msg[..n], buf.base);
            let _ = copyout_bytes(&[0], buf.base.wrapping_add(n as u64));
        }
        errno
    };
    if unsafe { oxidebsd_current_uid() } != 0 {
        return fail(-EPERM, b"only root may mount file systems");
    }
    if let Some(e) = bad_option {
        return fail(e, b"an option's name or value can't be read, or is too long");
    }
    if unknown || flags & !(MNT_NOSUID | MNT_RDONLY | MNT_UPDATE) != 0 {
        return fail(-EOPNOTSUPP, b"the only mount options are nosuid, wxallowed, ro and rw");
    }
    if fspath.is_empty() {
        return fail(-EINVAL, b"no fspath: the directory to mount on");
    }
    if flags & MNT_UPDATE != 0 {
        if fspath != b"/" {
            return fail(-EOPNOTSUPP, b"only / can be updated (mount -u) for now");
        }
        return match remount_root(rdonly) {
            0 => 0,
            e if e == -EBUSY => fail(e, b"files are open for writing on /"),
            e => fail(e, b"can't reread the root file system's superblock"),
        };
    }
    if rdonly {
        return fail(-EOPNOTSUPP, b"read-only mounts are for / only, with mount -u, for now");
    }
    match fstype {
        b"tmpfs" => mount_tmpfs(fspath, nosuid, wxallowed),
        b"nullfs" if from.is_empty() => fail(-EINVAL, b"nullfs needs a target: the directory to mount"),
        b"nullfs" => mount_nullfs(from, fspath, nosuid, wxallowed),
        b"" => fail(-EINVAL, b"no fstype"),
        _ => fail(-ENODEV, b"unknown file system type"),
    }
}

/// `mount -u` of `/` (RAM_FLOOR.md §3.4.3), to read-only or read-write.
///
/// To read-write: the cache is dropped whole (`fsck_oxfs` may have changed the disk underneath
/// it, through the raw device) and the layout, free counts and inode table reread, as at mount;
/// then the clean flag is cleared on the disk and the orphans a read-only boot left are swept.
/// To read-only: refused (`EBUSY`) while a file on it is open for writing; otherwise every
/// delayed write goes out and the file system is marked clean.
fn remount_root(rdonly: bool) -> i64 {
    if rdonly == root_rdonly() {
        return 0;
    }
    if rdonly {
        let slots = unsafe { &*core::ptr::addr_of!(OPEN_FILES) };
        let writing = slots
            .iter()
            .flatten()
            .any(|(_, f)| matches!(f, OpenFile::Write { inode, .. } if !is_tmpfs_inode(*inode)));
        if writing {
            return -EBUSY;
        }
        bcache::flush_all();
        set_clean(true);
        write_superblock();
        set_root_rdonly(true);
        log("[oxfs] root remounted read-only\n");
        return 0;
    }
    bcache::invalidate_all();
    if !mount_from_disk() {
        return -EIO;
    }
    set_root_rdonly(false);
    set_clean(false);
    write_superblock();
    sweep_unnamed_inodes();
    log("[oxfs] root remounted read-write\n");
    0
}

// --- devfs (`DEVFS.md` §4) ---------------------------------------------------------------------
//
// `/dev` is a tree in the tmpfs pool, mounted at boot and rebuilt every boot: a node for every
// device in the kernel's registry (kept current by `devfs_sync`, run whenever a lookup enters
// `/dev` and the registry has changed), and `/dev/shm`. Nodes removed with `rm` stay hidden until
// reboot; `mknod` of a device is refused there; other files can be made and last until reboot.

/// One registry entry, as `oxidebsd_dev_entry` writes it. Duplicated from `sys/fs/devfs.rs`.
#[repr(C)]
struct RawDevEntry {
    name: [u8; 64],
    name_len: u32,
    major: u32,
    minor: u32,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// devfs's root, `u32::MAX` until it's mounted.
static mut DEVFS_ROOT: u32 = u32::MAX;
/// The registry generation `/dev` was last brought up to.
static mut DEVFS_GENERATION: u64 = 0;
/// Device numbers whose nodes were removed (§4.4.1); `(u32::MAX, u32::MAX)` is an empty slot.
const MAX_DEVFS_HIDDEN: usize = 64;
static mut DEVFS_HIDDEN: [(u32, u32); MAX_DEVFS_HIDDEN] = [(u32::MAX, u32::MAX); MAX_DEVFS_HIDDEN];

fn devfs_root() -> u32 {
    // SAFETY: single-core, syscall-serialized, as every pool here.
    unsafe { *core::ptr::addr_of!(DEVFS_ROOT) }
}

fn devfs_hidden() -> &'static mut [(u32, u32); MAX_DEVFS_HIDDEN] {
    // SAFETY: as `devfs_root`.
    unsafe { &mut *core::ptr::addr_of_mut!(DEVFS_HIDDEN) }
}

/// Whether directory `dir` is devfs's root or inside it.
fn in_devfs(dir: u32) -> bool {
    let root = devfs_root();
    root != u32::MAX && is_same_or_descendant(dir, root)
}

/// Remembers that device `rdev`'s node was removed, so `devfs_sync` doesn't bring it back.
fn devfs_hide(rdev: u32) {
    let dev = dev_major_minor(rdev);
    let hidden = devfs_hidden();
    if !hidden.contains(&dev) {
        if let Some(slot) = hidden.iter_mut().find(|s| **s == (u32::MAX, u32::MAX)) {
            *slot = dev;
        }
    }
}

/// A directory named `name` in devfs directory `parent`, made if missing (from the tmpfs pool).
fn devfs_dir(parent: u32, name: &[u8], mode: u16) -> Option<u32> {
    if let Some(existing) = dir_lookup(parent, name) {
        return Some(existing);
    }
    let dir = alloc_tmpfs_inode()?;
    let mut inode = fresh_inode(InodeKind::Dir);
    inode.mode = mode;
    write_inode(dir, inode);
    dir_insert(dir, b".", dir).ok()?;
    dir_insert(dir, b"..", parent).ok()?;
    dir_insert(parent, name, dir).ok()?;
    Some(dir)
}

/// Makes `/dev` match the registry (§4.3): a node for each registered device that isn't there
/// (unless hidden), and none for devices no longer registered.
fn devfs_sync() {
    let root = devfs_root();
    if root == u32::MAX {
        return;
    }
    // SAFETY: FFI call to a kernel-exported function.
    let generation = unsafe { oxidebsd_dev_generation() };
    // SAFETY: as `devfs_root`.
    if unsafe { *core::ptr::addr_of!(DEVFS_GENERATION) } == generation {
        return;
    }
    unsafe { *core::ptr::addr_of_mut!(DEVFS_GENERATION) = generation };

    let mut index = 0;
    loop {
        let mut e = RawDevEntry { name: [0; 64], name_len: 0, major: 0, minor: 0, uid: 0, gid: 0, mode: 0 };
        // SAFETY: a buffer for one entry.
        if unsafe { oxidebsd_dev_entry(index, &mut e) } != 0 {
            break;
        }
        index += 1;
        if devfs_hidden().contains(&(e.major, e.minor)) {
            continue;
        }
        let name = &e.name[..e.name_len as usize];
        let (dir_path, leaf) = match name.iter().rposition(|&b| b == b'/') {
            Some(i) => (&name[..i], &name[i + 1..]),
            None => (&name[..0], name),
        };
        let mut dir = root;
        for component in dir_path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            match devfs_dir(dir, component, 0o755) {
                Some(d) => dir = d,
                None => break,
            }
        }
        if dir_lookup(dir, leaf).is_some() {
            continue;
        }
        let Some(node) = alloc_tmpfs_inode() else { break };
        let mut inode = fresh_inode(InodeKind::Device);
        inode.mode = e.mode as u16;
        inode.uid = e.uid;
        inode.gid = e.gid;
        inode.rdev = (e.major << 8) | e.minor;
        inode.device_char = true;
        write_inode(node, inode);
        if dir_insert(dir, leaf, node).is_err() {
            write_inode(node, Inode::FREE);
        }
    }
    devfs_prune(root, 0);
}

/// Removes device nodes under `dir` whose device is no longer registered.
fn devfs_prune(dir: u32, depth: u32) {
    if depth > 8 {
        return;
    }
    let mut n = 0;
    while let Some((inode_num, name, name_len)) = dir_nth_used_record(dir, n) {
        n += 1;
        let name = &name[..name_len as usize];
        if name == b"." || name == b".." {
            continue;
        }
        let inode = read_inode(inode_num);
        match inode.kind {
            InodeKind::Dir => devfs_prune(inode_num, depth + 1),
            InodeKind::Device => {
                let (major, minor) = dev_major_minor(inode.rdev);
                if !device_registered(major, minor) && dir_remove(dir, name).is_ok() {
                    let mut gone = inode;
                    gone.nlink = 0;
                    write_inode(inode_num, gone);
                    maybe_release(inode_num);
                    n -= 1;
                }
            }
            _ => {}
        }
    }
}

fn device_registered(major: u32, minor: u32) -> bool {
    let mut index = 0;
    loop {
        let mut e = RawDevEntry { name: [0; 64], name_len: 0, major: 0, minor: 0, uid: 0, gid: 0, mode: 0 };
        // SAFETY: a buffer for one entry.
        if unsafe { oxidebsd_dev_entry(index, &mut e) } != 0 {
            return false;
        }
        if (e.major, e.minor) == (major, minor) {
            return true;
        }
        index += 1;
    }
}

/// Mounts devfs on `/dev` (§4.1), making `/dev` on the disk first if it's missing.
fn mount_devfs() -> bool {
    let mountpoint = ensure_dir(ROOT_INODE, b"dev");
    let Some(slot) = free_mount_slot() else { return false };
    let Some(root) = alloc_tmpfs_inode() else { return false };
    write_inode(root, fresh_inode(InodeKind::Dir));
    if dir_insert(root, b".", root).is_err() || dir_insert(root, b"..", ROOT_INODE).is_err() {
        return false;
    }
    // POSIX shared memory and semaphores (musl's shm_open/sem_open), world-writable and sticky.
    if devfs_dir(root, b"shm", 0o1777).is_none() {
        return false;
    }
    let (path, path_len) = copy_mount_path(b"/dev");
    let (source, source_len) = copy_mount_path(b"devfs");
    mounts()[slot] = MountEntry {
        used: true,
        mountpoint_inode: mountpoint,
        target_root_inode: root,
        kind: MountKind::Devfs,
        path,
        path_len,
        source,
        source_len,
        nosuid: false,
        wxallowed: false,
    };
    // SAFETY: as `devfs_root`.
    unsafe { *core::ptr::addr_of_mut!(DEVFS_ROOT) = root };
    devfs_sync();
    true
}

/// The registry's open function for the devices oxfs implements itself.
extern "C" fn oxfs_dev_open(major: u64, minor: u64, _flags: u64) -> i64 {
    match known_device(((major as u32) << 8) | minor as u32, true) {
        Some(open_file) => register_open_file(open_file),
        None => -ENXIO,
    }
}

/// Registers the devices oxfs implements (`DEVFS.md` §3.4-3.5): `null`, `zero`, `random`,
/// `urandom`, and `fb0` when there is a framebuffer. Open to all, as on the BSDs.
fn register_oxfs_devices() {
    let fb = framebuffer_open_file().is_some();
    let devices: [(&[u8], u64, u64, bool); 5] = [
        (b"null", 1, 3, true),
        (b"zero", 1, 5, true),
        (b"random", 1, 8, true),
        (b"urandom", 1, 9, true),
        (b"fb0", 29, 0, fb),
    ];
    for (name, major, minor, present) in devices {
        if present {
            // SAFETY: FFI call to a kernel-exported function, with a live name buffer.
            unsafe { oxidebsd_make_dev(name.as_ptr() as u64, name.len() as u64, major, minor, 0, 0o666, oxfs_dev_open) };
        }
    }
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
    let target_buf = match copyin_path(target_ptr, target_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let target = target_buf.as_bytes();

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
extern "C" fn oxfs_fstat(fd: u64, buf_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    // A terminal reports its device node, a pipe or socket its type (`stat_real_fd`). Found
    // live via the Clang/LLVM port that this matters for the console: `llvm::sys::Process::
    // FixupStandardFileDescriptors()` `fstat()`s fd 0/1/2 at startup, and an `EBADF` made it
    // `dup2` all three onto `/dev/null`, silently discarding every diagnostic.
    stat_real_fd(real_fd as u64, buf_ptr)
}

/// Registered for `SYS_LSEEK` -- see that constant's own doc comment for why this exists at all
/// (found live via TinyCC needing a real file size upfront to load `crt1.o`/`libc.a` whole).
/// `offset`/`whence` arrive as real `u64` register values -- `offset` is reinterpreted as `i64`
/// (real `lseek(2)`'s own signed-offset convention; musl's `off_t` is 64-bit on this arch, so no
/// truncation). Real `SEEK_SET=0`/`SEEK_CUR=1`/`SEEK_END=2` -- no divergence to remap. The
/// `{FileRead,DirListing,ProcRead,ProcDir}` variants have a real `position`/size to seek within,
/// and so does every `Write` fd now, `O_WRONLY` included, not just `O_RDWR` ones -- only the
/// synthetic `/dev/*` variants still report `ESPIPE`, the real POSIX answer for "this fd has no
/// seekable position". **Real, previously-missing plain-`O_WRONLY` seek support**, found live via
/// a real on-target Clang/LLVM `ld.lld` link: `llvm::raw_fd_ostream` backpatches a freshly
/// written ELF object's header fields (`e_shoff`/`e_shnum`) via `lseek(SEEK_SET)` + `write()` +
/// `lseek(SEEK_SET)` on its own `O_WRONLY` output fd -- with this reporting `ESPIPE` (silently
/// ignored by LLVM's own error-handling, no crash), `oxfs_write`'s own append-only fast path
/// never noticed the corresponding `write()`s were meant to overwrite the header in place, so
/// they landed at the file's real tail instead (see `oxfs_write`'s own doc comment for the full
/// story and the exact `ld.lld` error this produced).
extern "C" fn oxfs_lseek(fd: u64, offset: u64, whence: u64, _a3: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let real_fd = unsafe { oxidebsd_real_fd_of(fd) };
    if real_fd < 0 {
        return -EBADF;
    }
    let real_fd = real_fd as u64;
    let Some(open_file) = find_open_file(real_fd) else {
        return -EBADF;
    };
    let offset = offset as i64;
    let (position, size): (&mut usize, i64) = match open_file {
        OpenFile::FileRead { inode, position, .. } | OpenFile::Write { inode, position, .. } => {
            (position, read_inode(*inode).size as i64)
        }
        // A directory's offset is `getdents`' record cursor (`d_off` is the next record's index),
        // so `rewinddir`'s `lseek(fd, 0, SEEK_SET)` and `seekdir` land where they should.
        OpenFile::DirListing { dirent_pos, .. } | OpenFile::ProcDir { dirent_pos, .. } => {
            let new_pos = match whence {
                0 => offset,
                1 => *dirent_pos as i64 + offset,
                _ => return -EINVAL,
            };
            if new_pos < 0 {
                return -EINVAL;
            }
            *dirent_pos = new_pos as usize;
            return new_pos;
        }
        OpenFile::ProcRead { len, position, .. } => (position, *len as i64),
        OpenFile::DevRandom
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

/// `oxfs_read` with `FOF_OFFSET` -- real `pread(2)`: like `oxfs_read`, but at an explicit `offset` that neither reads nor updates this
/// fd's own `position` (real POSIX: `pread`/`pwrite` are independent of `lseek`'s cursor). A plain
/// `FileRead` fd (`O_RDONLY`, or an existing path opened `O_RDWR` -- see `oxfs_open`'s own
/// existing-path branch) already has a real, committed inode to read directly; a `Write` fd needs
/// real `readwrite` (`O_RDWR`) support and the same forced-early-commit `oxfs_read`/`oxfs_lseek`
/// already use. Every other variant (directories, `/proc`, `/dev/*`, and a plain `O_WRONLY`
/// `Write` fd) has no real seekable position at all -- `ESPIPE`, matching `oxfs_lseek`'s own answer
/// for the same fd kinds.
fn oxfs_pread(real_fd: u64, uio: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function.
    let offset = unsafe { oxidebsd_uio_offset(uio) };
    let inode = match find_open_file(real_fd) {
        Some(OpenFile::FileRead { inode, .. }) => *inode,
        Some(OpenFile::Write { inode, readwrite: true, .. }) => *inode,
        Some(_) => return -ESPIPE,
        None => return -EBADF,
    };
    let n = match read_inode_uio(inode, offset as usize, uio) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if n > 0 {
        touch_atime(inode);
    }
    n as i64
}

/// `oxfs_write` with `FOF_OFFSET` -- real `pwrite(2)`, writing directly into the fd's inode blocks
/// at `offset` without moving the descriptor's offset. Unlike `oxfs_pread`, this works for **any**
/// fd open for writing -- `O_WRONLY` included, not just `readwrite` (`O_RDWR`) -- matching real
/// POSIX: `pwrite()` only requires the fd be open for writing.
fn oxfs_pwrite(real_fd: u64, uio: u64) -> i64 {
    // SAFETY: FFI call to a kernel-exported function.
    let offset = unsafe { oxidebsd_uio_offset(uio) };
    match find_open_file(real_fd) {
        Some(OpenFile::Write { readonly: false, .. }) => {}
        Some(_) => return -EBADF,
        None => return -EBADF,
    }
    let Some(inode) = inode_of_open_file(real_fd) else {
        return -EIO;
    };
    uio_ret(write_inode_uio(inode, offset as usize, uio))
}

/// Writes `value`'s decimal digits (no leading zeros; `0` prints as `"0"`) into `buf`, returning
/// the byte count -- module-side equivalent of `sys/process.rs`'s own `push_decimal`, duplicated
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
            const SYS_NAMES: [&[u8]; 6] = [b"meminfo", b"uptime", b"stat", b"modules", b"mounts", b"initdeaths"];
            if let Some(name_bytes) = SYS_NAMES.get(n) {
                let mut name = [0u8; NAME_MAX];
                name[..name_bytes.len()].copy_from_slice(name_bytes);
                // Distinct, cosmetic-only d_ino (see PROC_INODE_BASE's own doc comment) -- clear
                // of every real inode number and every pid-derived d_ino.
                return Some((
                    PROC_INODE_BASE - 1 - n as u64,
                    name,
                    name_bytes.len() as u8,
                    DT_REG,
                ));
            }
            // Then the `self` link, then the pids.
            if n == SYS_NAMES.len() {
                let mut name = [0u8; NAME_MAX];
                name[..4].copy_from_slice(b"self");
                return Some((PROC_INODE_BASE - 1 - n as u64, name, 4, DT_LNK));
            }
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            let pid = unsafe { oxidebsd_proc_pid_at((n - SYS_NAMES.len() - 1) as u64) };
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
                DT_LNK,
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
    // Each record is built here, then copied out. A record that can't be copied out ends the
    // call: `-EFAULT` if it was the first, else the count already copied (as Linux does), with the
    // cursor left on that record.
    let mut record = [0u8; dirent_record_len(NAME_MAX)];
    let out_len = buf_len as usize;
    let mut fault = 0i64;
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
                if written + reclen > out_len {
                    break;
                }
                let child = read_inode(child_inode);
                let dtype = match child.kind {
                    InodeKind::Dir => DT_DIR,
                    InodeKind::Symlink => DT_LNK,
                    InodeKind::Device if child.device_char => DT_CHR,
                    InodeKind::Device => DT_BLK,
                    InodeKind::Fifo => DT_FIFO,
                    InodeKind::Socket => DT_SOCK,
                    _ => DT_REG,
                };
                write_dirent_record(
                    &mut record[..reclen],
                    child_inode as u64,
                    (*dirent_pos + 1) as i64,
                    dtype,
                    name,
                );
                let dst = buf_ptr.wrapping_add(written as u64);
                if let Err(e) = copyout_bytes(&record[..reclen], dst) {
                    fault = e;
                    break;
                }
                written += reclen;
                *dirent_pos += 1;
            }
            if written == 0 && fault != 0 { fault } else { written as i64 }
        }
        OpenFile::ProcDir {
            kind, dirent_pos, ..
        } => {
            let kind = *kind;
            let mut written = 0usize;
            while let Some((ino, name, name_len, dtype)) = proc_dir_nth_entry(kind, *dirent_pos) {
                let name = &name[..name_len as usize];
                let reclen = dirent_record_len(name.len());
                if written + reclen > out_len {
                    break;
                }
                let off = (*dirent_pos + 1) as i64;
                write_dirent_record(&mut record[..reclen], ino, off, dtype, name);
                let dst = buf_ptr.wrapping_add(written as u64);
                if let Err(e) = copyout_bytes(&record[..reclen], dst) {
                    fault = e;
                    break;
                }
                written += reclen;
                *dirent_pos += 1;
            }
            if written == 0 && fault != 0 { fault } else { written as i64 }
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



/// Whether the root file system is mounted read-only (`OxideBSD-doc/RAM_FLOOR.md` §3.4.3): from
/// boot on the real boot path until `/etc/rc` remounts it read-write (`mount -u`), or after a
/// remount read-only. Every change to it is refused with `EROFS`; tmpfs and devfs stay writable.
static mut ROOT_RDONLY: bool = false;

fn root_rdonly() -> bool {
    // SAFETY: single-core, under the filesystem lock.
    unsafe { *core::ptr::addr_of!(ROOT_RDONLY) }
}

/// Whether a change at inode `n` (the file, or the directory a name goes in) is refused: it's on
/// the root file system, mounted read-only.
fn read_only_at(n: u32) -> bool {
    root_rdonly() && !is_tmpfs_inode(n)
}

/// Records the root's mode, and tells the kernel (raw writes to the partition are refused while
/// it's read-write).
fn set_root_rdonly(rdonly: bool) {
    // SAFETY: as `root_rdonly`.
    unsafe { *core::ptr::addr_of_mut!(ROOT_RDONLY) = rdonly };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_root_mounted_rw(!rdonly as u64) };
}

/// Whether the filesystem is clean on the disk (§3.4.1): cleared by mount, before anything else is
/// written, and set by an orderly shutdown (`oxfs_shutdown`) once every delayed write is out.
static mut CLEAN: bool = false;

fn set_clean(clean: bool) {
    // SAFETY: single-core, syscall-serialized.
    unsafe { *core::ptr::addr_of_mut!(CLEAN) = clean };
}

/// The volume label read at mount (`newfs_oxfs -L`), written back with every superblock; none
/// for a filesystem the kernel formatted.
static mut LABEL: [u8; SB_LABEL_LEN] = [0; SB_LABEL_LEN];

fn write_superblock() {
    let table = inode_table(false);
    let sb = Superblock {
        data_blocks: disk_blocks(),
        inode_count: table.count,
        root_inode: ROOT_INODE,
        // SAFETY: as `set_clean`.
        clean: unsafe { *core::ptr::addr_of!(CLEAN) },
        // SAFETY: as `set_clean`.
        label: unsafe { *core::ptr::addr_of!(LABEL) },
        inode_file: table.file,
    };
    let mut block = [0u8; BLOCK_SIZE];
    sb.encode(&mut block);
    // Written straight to the disk, never through the cache: it's the commit record of a format
    // (`flush_all_to_disk`), and nothing reads it after mount.
    unsafe {
        oxidebsd_block_write(0, block.as_ptr() as u64);
    }
}

/// Starts a format: invalidates the superblock on the disk (the commit record, written last by
/// `flush_all_to_disk`), lays the filesystem out over the whole device, and resets the bitmap
/// (every block free), the free counts, the disk inode table and the allocation cursor. The new
/// bitmap stays in the cache, dirty, until `flush_all_to_disk`.
fn reset_real_pool_for_fresh_format() {
    let blank = [0u8; BLOCK_SIZE];
    // SAFETY: as `set_clean`.
    unsafe { *core::ptr::addr_of_mut!(LABEL) = [0; SB_LABEL_LEN] };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_block_write(0, blank.as_ptr() as u64) };
    bcache::invalidate_all();
    let (data_blocks, bitmap) = layout_for(unsafe { oxidebsd_block_device_blocks() });
    set_layout(data_blocks, bitmap);
    for index in 0..bitmap {
        bcache::store(BITMAP_START + index, &blank, bcache::Kind::Meta);
        let base = index * BITS_PER_BITMAP_BLOCK;
        *free_count(index) = (data_blocks - base).min(BITS_PER_BITMAP_BLOCK);
    }
    *inode_table(false) = InodeTable::EMPTY;
    unsafe { *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK) = 0 };
}

/// Mounts a formatted disk: checks the superblock, takes the layout from it, and counts each
/// bitmap block's free blocks. Nothing else is read: every other block comes from the disk on
/// first use, through the cache. `false` for a missing or mismatched superblock (an unformatted
/// disk, another filesystem, or a layout from another `SUPERBLOCK_VERSION`), and the caller
/// formats instead.
fn mount_from_disk() -> bool {
    let mut sb = [0u8; BLOCK_SIZE];
    if unsafe { oxidebsd_block_read(0, sb.as_mut_ptr() as u64) } != 0 {
        return false;
    }
    let sb = match Superblock::decode(&sb) {
        Ok(sb) => sb,
        Err(SuperblockError::NotOxfs) => return false,
        Err(SuperblockError::Version(_)) => {
            log("[oxfs] mount: on-disk layout doesn't match this build or disk -- falling back to format\n");
            return false;
        }
    };
    let data_blocks = sb.data_blocks;
    let (_, bitmap_most) = layout_for(unsafe { oxidebsd_block_device_blocks() });
    let bitmap = sb.bitmap_blocks();
    if bitmap > bitmap_most {
        log("[oxfs] mount: on-disk layout doesn't match this build or disk -- falling back to format\n");
        return false;
    }
    set_layout(data_blocks, bitmap);
    // SAFETY: inside `module_init` or a remount, before anything writes a superblock.
    unsafe { *core::ptr::addr_of_mut!(LABEL) = sb.label };
    if !sb.clean {
        log("[oxfs] mount: filesystem was not cleanly unmounted\n");
    }
    let mut used = 0u32;
    for index in 0..bitmap {
        let base = index * BITS_PER_BITMAP_BLOCK;
        let bits = (data_blocks - base).min(BITS_PER_BITMAP_BLOCK);
        let set = bcache::with(BITMAP_START + index, |b| {
            (0..bits).filter(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) != 0).count() as u32
        });
        *free_count(index) = bits - set;
        used += set;
    }

    let count = sb.inode_count;
    *inode_table(false) = InodeTable { file: sb.inode_file, count, free: 0, hint: 0 };
    let free = (0..count).filter(|&n| read_inode(n).kind == InodeKind::Free).count() as u32;
    inode_table(false).free = free;

    let mut msg_buf = [0u8; 192];
    let mut msg = ByteBuf {
        buf: &mut msg_buf,
        len: 0,
    };
    msg.push_bytes(b"[oxfs] mounted existing filesystem from disk (");
    msg.push_decimal(used);
    msg.push_bytes(b" of ");
    msg.push_decimal(data_blocks);
    msg.push_bytes(b" blocks used, ");
    msg.push_decimal(count - free);
    msg.push_bytes(b" inodes in use)\n");
    let len = msg.len;
    log_bytes(&msg_buf[..len]);
    true
}

/// Finishes a format: writes every block the format left dirty in the cache (the bitmap, the
/// inode file, every seeded file), then the superblock.
///
/// **The superblock is the commit record: cleared first (`reset_real_pool_for_fresh_format`),
/// written last.** It used to be written first, so a format interrupted partway (QEMU closed
/// during the old 17-minute PIO format) left a valid superblock over mostly-unwritten data, which
/// every later boot mounted as a gutted filesystem -- found live: a disk with 1,719 of ~66,470
/// blocks, `/bin/ls` and most of `/etc` missing, and doom faulting on its unwritten WAD. Now an
/// interrupted format leaves no valid superblock, and the next boot formats again.
fn flush_all_to_disk() {
    let flushed = bcache::flush_all();
    write_superblock();

    let mut msg_buf = [0u8; 192];
    let mut msg = ByteBuf {
        buf: &mut msg_buf,
        len: 0,
    };
    msg.push_bytes(b"[oxfs] formatted fresh filesystem and flushed to disk (");
    msg.push_decimal(flushed);
    msg.push_bytes(b" blocks, ");
    let table = inode_table(false);
    msg.push_decimal(table.count - table.free);
    msg.push_bytes(b" inodes, ");
    msg.push_decimal(disk_blocks());
    msg.push_bytes(b"-block filesystem, ");
    msg.push_decimal(bcache::buffers());
    msg.push_bytes(b" cache buffers)\n");
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
    let mut node = fresh_inode(InodeKind::File);
    node.mode = seed_mode(content);
    write_inode(inode, node);
    write_inode_data(inode, content) && dir_insert(parent, name, inode).is_ok()
}

/// The permission bits a seeded file starts with: `0o755` if this kernel could actually execute it
/// -- a `#!` script, or an ELF that's `ET_EXEC` (static) or `ET_DYN` (a PIE, or `libc.so`) -- and
/// `0o644` for everything else (data, headers, `.a` archives, and relocatable `.o` files, which are
/// ELF but not loadable). Every seeded file used to get `FIXED_PERM` (`0o755`) regardless, so
/// `/etc/passwd`, headers and the WAD all looked executable (and `ls --color` painted them green).
fn seed_mode(content: &[u8]) -> u16 {
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    if content.starts_with(b"#!") {
        return 0o755;
    }
    if content.len() >= 18 && content.starts_with(b"\x7fELF") {
        let e_type = u16::from_le_bytes([content[16], content[17]]);
        if e_type == ET_EXEC || e_type == ET_DYN {
            return 0o755;
        }
    }
    0o644
}

/// `seed_file`'s symlink counterpart -- allocates a fresh `InodeKind::Symlink` inode under
/// `parent` named `name`, pointing at `target` (stored verbatim, exactly like `oxfs_symlink`
/// itself stores a real caller's target -- see that function's own doc comment). Used to seed
/// `/bin/lsmod` as an alias of `/bin/lsoxmod` without needing two copies of the same binary.
fn seed_symlink(parent: u32, name: &[u8], target: &[u8]) -> bool {
    let Some(inode) = alloc_inode() else {
        return false;
    };
    write_inode(inode, fresh_inode(InodeKind::Symlink));
    write_inode_data(inode, target) && dir_insert(parent, name, inode).is_ok()
}

/// A second name for the already-seeded `existing` in the same directory -- a real hard link,
/// for programs that pick their behavior from `argv[0]` (`/sbin/reboot`, `halt`, `poweroff`).
fn seed_hardlink(parent: u32, name: &[u8], existing: &[u8]) -> bool {
    let Some(inode) = dir_lookup(parent, existing) else {
        return false;
    };
    let mut node = read_inode(inode);
    node.nlink += 1;
    write_inode(inode, node);
    dir_insert(parent, name, inode).is_ok()
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
    write_inode(inode, fresh_inode(InodeKind::Dir));
    dir_insert(inode, b".", inode).expect("oxfs: failed to seed a directory's . entry");
    dir_insert(inode, b"..", parent).expect("oxfs: failed to seed a directory's .. entry");
    dir_insert(parent, name, inode)
        .expect("oxfs: failed to insert a new directory into its parent");
    inode
}

/// Seeds a whole manifest of `(relative_path, content)` pairs (each `relative_path` real,
/// `/`-separated, e.g. `"bits/alltypes.h"`) under `root`, creating any missing intermediate
/// directories via `ensure_dir` along the way. Used for the on-target musl runtime tree
/// (`/usr/include`, `/usr/lib` -- see `format_fresh_filesystem`'s own call sites) -- the first
/// content this filesystem seeds shaped like a real nested directory tree (musl's own
/// `include/bits`, `include/sys`, ...) rather than a small fixed set of top-level files.
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

/// Symbolic links under `root`: `(link, target)`, `link` a `/`-separated path relative to `root`
/// (its directories created as needed), `target` stored as given (`libcrypto.so` ->
/// `libcrypto.so.3`).
fn seed_tree_symlinks(root: u32, links: &[(&str, &str)]) -> bool {
    let mut ok = true;
    for (link, target) in links {
        let (dir_path, name) = link.rsplit_once('/').unwrap_or(("", link));
        let mut dir = root;
        for component in dir_path.split('/').filter(|c| !c.is_empty()) {
            dir = ensure_dir(dir, component.as_bytes());
        }
        ok &= seed_symlink(dir, name.as_bytes(), target.as_bytes());
    }
    ok
}

/// Second names under `root` for files `seed_tree` already put there: `(link, existing)`, both
/// `/`-separated paths relative to `root`, in any directories (the time zone aliases:
/// `US/Eastern` for `America/New_York`).
fn seed_tree_links(root: u32, links: &[(&str, &str)]) -> bool {
    let mut ok = true;
    for (link, existing) in links {
        let mut inode = Some(root);
        for component in existing.split('/') {
            inode = inode.and_then(|dir| dir_lookup(dir, component.as_bytes()));
        }
        let Some(inode) = inode else {
            ok = false;
            continue;
        };
        let (dir_path, name) = link.rsplit_once('/').unwrap_or(("", link));
        let mut dir = root;
        for component in dir_path.split('/').filter(|c| !c.is_empty()) {
            dir = ensure_dir(dir, component.as_bytes());
        }
        let mut node = read_inode(inode);
        node.nlink += 1;
        write_inode(inode, node);
        ok &= dir_insert(dir, name.as_bytes(), inode).is_ok();
    }
    ok
}

/// `TZ_ZONEINFO_FILES`/`TZ_ZONEINFO_LINKS` -- the compiled time zone database, generated by
/// build.rs's `build_tz`; seeded as `/usr/share/zoneinfo`.
include!(env!("TZ_ZONEINFO_MANIFEST_PATH"));

/// `OPENSSL_FILES`/`OPENSSL_SYMLINKS` -- OpenSSL's install (libraries, headers, the legacy provider
/// module, `/usr/bin/openssl`, `/etc/ssl`), generated by build.rs's `build_openssl`; seeded from `/`.
include!(env!("OPENSSL_MANIFEST_PATH"));

/// `CERTS_FILES`/`CERTS_SYMLINKS`/`CERTS_DIRS` -- the trust store (`/usr/share/certs`,
/// `/etc/ssl/certs`, `/etc/ssl/untrusted`, `/etc/ssl/cert.pem`), generated by build.rs's
/// `build_trust_store`; seeded from `/`.
include!(env!("CERTS_MANIFEST_PATH"));

/// `MUSL_INCLUDE_FILES`/`MUSL_LIB_FILES` -- generated by build.rs's
/// `write_musl_runtime_manifest` (see its own doc comment for why this is a generated `include!`
/// rather than the `env!()`-per-file pattern every other embedded ELF in this file uses). Declared
/// at module scope since it defines real top-level `pub static` items, consumed by
/// `format_fresh_filesystem`'s own `/usr` seeding below.
include!(env!("MUSL_RUNTIME_MANIFEST_PATH"));

/// `CLANG_RESOURCE_FILES` -- generated by build.rs's `write_clang_runtime_manifest`, same idiom as
/// `MUSL_INCLUDE_FILES` above. Consumed by `format_fresh_filesystem`'s own `/lib/clang/23` seeding
/// below -- see CLAUDE.md's Clang/LLVM port section.
include!(env!("CLANG_RUNTIME_MANIFEST_PATH"));

/// `LIBCXX_INCLUDE_FILES`/`LIBCXX_TARGET_INCLUDE_FILES`/`LIBCXX_LIB_FILES` -- generated by
/// build.rs's `write_libcxx_runtime_manifest`. Seeded under `/usr` below.
include!(env!("LIBCXX_RUNTIME_MANIFEST_PATH"));

/// `NINJA_SRC_FILES` -- generated by build.rs's `write_ninja_src_manifest`: ninja's own source,
/// seeded at `/usr/src/ninja` for the on-target self-hosted build.
include!(env!("NINJA_SRC_MANIFEST_PATH"));

/// `BMAKE_MK_FILES` -- generated by build.rs's `write_bmake_mk_manifest`, same idiom as
/// `CLANG_RESOURCE_FILES` above. Seeded at `/usr/share/mk` (bmake's compiled-in default sys path).
include!(env!("BMAKE_MK_MANIFEST_PATH"));

/// `NCURSES_INCLUDE_FILES`/`NCURSES_LIB_FILES` -- generated by build.rs's
/// `write_ncurses_runtime_manifest`, same idiom as `MUSL_INCLUDE_FILES` above. Seeded on top of
/// the same `/usr/include`/`/usr/lib` inodes musl's own runtime tree already populates -- see
/// CLAUDE.md's ncurses/nano/nvi section.
include!(env!("NCURSES_RUNTIME_MANIFEST_PATH"));

/// `NCURSES_TERMINFO_FILES` -- generated by build.rs's `write_ncurses_terminfo_manifest`, a
/// deliberately minimal (`linux`/`vt100`/`vt100-am`/`dumb`) compiled terminfo database. Seeded at
/// `/usr/share/terminfo` below.
include!(env!("NCURSES_TERMINFO_MANIFEST_PATH"));

/// `POSIX_TEST_FILES` -- generated by build.rs's `write_posix_test_manifest`, same idiom as
/// `MUSL_INCLUDE_FILES` above. Consumed by `format_fresh_filesystem`'s own `/usr/tests/posix`
/// seeding below; see `posix_conformance.sh`'s own doc comment for what actually runs against this
/// tree. Also defines `POSIX_TEST_EXTRA_FILES` -- a second, separate array for pilot fixtures that
/// need seeding at a cwd-relative path outside `bin/`: `sigaltstack/9-1.c`'s own
/// `9-buildonly.test` `execl()` target, and `mlockall/3-7.c`'s own real source file (the one test
/// in the whole corpus that `open()`s itself by relative path) -- see each entry's own generation
/// comment in build.rs.
include!(env!("POSIX_TEST_MANIFEST_PATH"));

/// For `format_fresh_filesystem`'s self-check: `oxfs_open` returns a process fd, but `oxfs_read`/
/// `oxfs_write` are per-open-file callbacks keyed by `real_fd`, and closing has to go through the
/// kernel so the fd table entry goes too.
fn sc_read(fd: u64, ptr: u64, len: u64) -> i64 {
    sc_io(fd, ptr, len, 0)
}

fn sc_write(fd: u64, ptr: u64, len: u64) -> i64 {
    sc_io(fd, ptr, len, 1)
}

/// `oxfs_read`/`oxfs_write` over this module's own buffer at `ptr`, through a kernel-segment
/// transfer: the operations take a transfer, not a pointer (USERMEM.md §4.4).
fn sc_io(fd: u64, ptr: u64, len: u64, rw: u64) -> i64 {
    // SAFETY: FFI calls to kernel-exported functions; `ptr` is this module's own buffer.
    unsafe {
        let uio = oxidebsd_uio_kernel_new(ptr as *mut u8, len, rw);
        if uio == 0 {
            return -EINVAL;
        }
        let real_fd = oxidebsd_real_fd_of(fd) as u64;
        let r = if rw == 0 { oxfs_read(real_fd, uio, 0) } else { oxfs_write(real_fd, uio, 0) };
        oxidebsd_uio_free(uio);
        r
    }
}

fn sc_close(fd: u64) {
    sys_close(fd, 0, 0, 0);
}

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
    write_inode(root, fresh_inode(InodeKind::Dir));
    dir_insert(root, b".", root).expect("oxfs: failed to seed root's . entry");
    dir_insert(root, b"..", root).expect("oxfs: failed to seed root's .. entry");

    let mut ok = true;

    // All executables live under /bin, not root -- matches `sys/process.rs`'s pid-1 `PATH=/bin`
    // envp, so a bare command name (`ls`, not `/ls`) resolves via musl's real `execvp` search.
    let bin = alloc_inode().expect("oxfs: failed to allocate /bin inode");
    write_inode(bin, fresh_inode(InodeKind::Dir));
    dir_insert(bin, b".", bin).expect("oxfs: failed to seed /bin's . entry");
    dir_insert(bin, b"..", root).expect("oxfs: failed to seed /bin's .. entry");
    dir_insert(root, b"bin", bin).expect("oxfs: failed to insert /bin into root");

    // The rest of the program hierarchy (hier(7), share/man/man7/hier.7): /bin and /sbin are what
    // single-user repair needs, /usr/bin and /usr/sbin everything else.
    let sbin = ensure_dir(root, b"sbin");
    // Where fsck_oxfs(8) reconnects files that lost their names (newfs(8) makes it too). Root's
    // only: what lands there was someone's, and nobody else may read it.
    let lost_found = ensure_dir(root, b"lost+found");
    let mut node = read_inode(lost_found);
    node.mode = 0o700;
    write_inode(lost_found, node);
    let usr = ensure_dir(root, b"usr");
    let usr_bin = ensure_dir(usr, b"bin");
    let usr_sbin = ensure_dir(usr, b"sbin");
    let usr_libexec = ensure_dir(usr, b"libexec");
    let usr_games = ensure_dir(usr, b"games");
    let usr_tests = ensure_dir(usr, b"tests");
    // The self-check's own fixtures (read back at the end of this function, and by the access,
    // proc and native-bin smokes): one small file, and one spanning several blocks whose bytes are
    // formula-derived so the check can recompute them.
    let usr_tests_oxfs = ensure_dir(usr_tests, b"oxfs");
    ok &= seed_file(usr_tests_oxfs, b"hello.txt", b"Hello from OxideBSD's own filesystem!\n");
    let mut big = [0u8; BIG_FILE_LEN];
    for (i, b) in big.iter_mut().enumerate() {
        *b = b'A' + (i % 26) as u8;
    }
    ok &= seed_file(usr_tests_oxfs, b"big.txt", &big);

    ok &= seed_file(usr_tests, b"smoke", include_bytes!(env!("OXFS_SMOKE_ELF_PATH")));
    let usr_tests_rc = ensure_dir(usr_tests, b"rc");
    ok &= seed_file(usr_tests_rc, b"run.sh", include_bytes!("../../../../regress/rc-syscall-smoke/run.sh"));
    let usr_tests_devfs = ensure_dir(usr_tests, b"devfs");
    ok &= seed_file(usr_tests_devfs, b"run.sh", include_bytes!("../../../../regress/devfs-syscall-smoke/run.sh"));
    let usr_tests_cred = ensure_dir(usr_tests, b"cred");
    ok &= seed_file(usr_tests_cred, b"cred-smoke", include_bytes!(env!("OXFS_CRED_SMOKE_ELF_PATH")));
    let usr_tests_init = ensure_dir(usr_tests, b"init");
    ok &= seed_file(usr_tests_init, b"init-smoke", include_bytes!(env!("OXFS_INIT_SMOKE_ELF_PATH")));
    let usr_tests_tz = ensure_dir(usr_tests, b"tz");
    ok &= seed_file(usr_tests_tz, b"run.sh", include_bytes!("../../../../regress/tz-syscall-smoke/run.sh"));
    ok &= seed_file(usr_tests_tz, b"tz-smoke", include_bytes!(env!("OXFS_TZ_SMOKE_ELF_PATH")));
    let usr_tests_openssl = ensure_dir(usr_tests, b"openssl");
    ok &= seed_file(usr_tests_openssl, b"run.sh", include_bytes!("../../../../regress/openssl-syscall-smoke/run.sh"));
    ok &= seed_file(usr_tests_openssl, b"openssl-smoke", include_bytes!(env!("OXFS_OPENSSL_SMOKE_ELF_PATH")));
    ok &= seed_file(usr_tests_openssl, b"openssl-rs-smoke", include_bytes!(env!("OXFS_OPENSSL_RS_SMOKE_ELF_PATH")));
    let usr_tests_net = ensure_dir(usr_tests, b"net");
    ok &= seed_file(usr_tests_net, b"run.sh", include_bytes!("../../../../regress/loopback-syscall-smoke/run.sh"));
    ok &= seed_file(usr_tests_net, b"loopback-smoke", include_bytes!(env!("OXFS_LOOPBACK_SMOKE_ELF_PATH")));
    let usr_tests_syslog = ensure_dir(usr_tests, b"syslog");
    ok &= seed_file(usr_tests_syslog, b"run.sh", include_bytes!("../../../../regress/syslog-syscall-smoke/run.sh"));
    let usr_tests_bin = ensure_dir(usr_tests, b"bin");
    ok &= seed_file(usr_tests_bin, b"run.sh", include_bytes!("../../../../regress/bin-syscall-smoke/run.sh"));
    let usr_tests_cron = ensure_dir(usr_tests, b"cron");
    ok &= seed_file(usr_tests_cron, b"run.sh", include_bytes!("../../../../regress/cron-syscall-smoke/run.sh"));
    ok &= seed_file(usr_tests, b"musl", include_bytes!(env!("OXFS_MUSL_ELF_PATH")));
    ok &= seed_file(
        usr_tests,
        b"std-hello-oxidebsd",
        include_bytes!(env!("OXFS_STD_HELLO_OXIDEBSD_ELF_PATH")),
    );
    ok &= seed_file(
        usr_tests,
        b"std-process-fs-oxidebsd",
        include_bytes!(env!("OXFS_STD_PROCESS_FS_OXIDEBSD_ELF_PATH")),
    );
    ok &= seed_file(
        usr_tests,
        b"std-thread-net-signal-oxidebsd",
        include_bytes!(env!("OXFS_STD_THREAD_NET_SIGNAL_OXIDEBSD_ELF_PATH")),
    );
    ok &= seed_file(
        usr_tests,
        b"float-smoke",
        include_bytes!(env!("OXFS_FLOAT_SMOKE_ELF_PATH")),
    );
    // A real, playable port of Doom -- see build.rs's own build_doomgeneric doc comment. The
    // shareware IWAD lives where Unix ports keep IWADs, /usr/share/games/doom, which is our
    // doomgeneric fork's FILES_DIR: found from any directory, not only from `/`.
    ok &= seed_file(usr_games, b"doom", include_bytes!(env!("OXFS_DOOM_ELF_PATH")));
    let doom_wads = ensure_dir(ensure_dir(ensure_dir(usr, b"share"), b"games"), b"doom");
    ok &= seed_file(doom_wads, b"doom1.wad", include_bytes!(env!("OXFS_DOOM1_WAD_PATH")));
    // lsoxmod: a real standalone Rust userland ELF (sbin/lsoxmod/, same "freestanding,
    // raw-SYSCALL, no musl/BusyBox involved" category as regress/musl-smoke above), not a BusyBox applet
    // -- lists OxideBSD's own dynamically loaded kernel modules by reading the real /proc/modules
    // this pass added, the same "port real format, read real data" approach the rest of this
    // filesystem's /proc support already uses. `lsmod` is seeded as a real symlink to it rather
    // than a second copy of the same bytes -- real BusyBox has its own `lsmod` (see CLAUDE.md's
    // BusyBox gap analysis), but that one reads Linux's own `/proc/modules` format expecting real
    // Linux kernel modules, not this kernel's own module system, so the name is intentionally
    // pointed at the OxideBSD-native tool instead of BusyBox's applet of the same name.
    ok &= seed_file(
        sbin,
        b"lsoxmod",
        include_bytes!(env!("OXFS_LSOXMOD_ELF_PATH")),
    );
    ok &= seed_symlink(sbin, b"lsmod", b"lsoxmod");
    // clang/ld.lld: OxideBSD's real on-target C/C++ compiler (see CLAUDE.md's Clang/LLVM port
    // section -- TinyCC, this project's earlier, simpler on-target compiler, served as an early
    // proof that a real on-target compile+link was even possible, and was removed once Clang/LLVM
    // superseded it) -- a real, statically-linked, self-hosted Clang+LLD, cross-compiled by itself
    // (build.rs's `build_llvm_target_toolchain`) rather than upstream-vendored binaries. Seeded as
    // `ld.lld` (not `lld`): lld's own single binary dispatches ELF/COFF/MachO/wasm flavor off
    // `argv[0]`, and `ld.lld` is exactly what `OxideBSD::getDefaultLinker()` (the Clang driver)
    // looks for by that literal name. `/lib/clang/23`'s own resource-dir tree (intrinsic headers +
    // compiler-rt builtins) is seeded separately, near `/lib/ld-musl-x86_64.so.1` below.
    ok &= seed_file(usr_bin, b"clang", include_bytes!(env!("OXFS_CLANG_ELF_PATH")));
    // The driver picks C++ mode (libc++ headers, `-lc++` link line) off argv[0]'s basename.
    ok &= seed_symlink(usr_bin, b"clang++", b"clang");
    ok &= seed_file(usr_bin, b"ld.lld", include_bytes!(env!("OXFS_LLD_ELF_PATH")));
    // bmake (`usr.bin/make`, build.rs's `build_bmake`) -- `/usr/share/mk` is seeded below, next to
    // the rest of `/usr`.
    ok &= seed_file(usr_bin, b"bmake", include_bytes!(env!("OXFS_BMAKE_ELF_PATH")));
    ok &= seed_symlink(usr_bin, b"make", b"/usr/bin/bmake");
    ok &= seed_file(bin, b"true", include_bytes!(env!("OXFS_TRUE_ELF_PATH")));
    ok &= seed_file(bin, b"echo", include_bytes!(env!("OXFS_ECHO_ELF_PATH")));
    ok &= seed_file(bin, b"cat", include_bytes!(env!("OXFS_CAT_ELF_PATH")));
    // /bin/sh is OxideBSD's own shell (lib/libsh); BusyBox's ash stays as /bin/ash, which runs
    // autoconf configure scripts until /bin/sh can.
    ok &= seed_file(bin, b"sh", include_bytes!(env!("OXFS_SH_ELF_PATH")));
    ok &= seed_file(bin, b"false", include_bytes!(env!("OXFS_FALSE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"yes", include_bytes!(env!("OXFS_YES_ELF_PATH")));
    ok &= seed_file(usr_bin, b"more", include_bytes!(env!("OXFS_MORE_ELF_PATH")));
    ok &= seed_file(bin, b"mkdir", include_bytes!(env!("OXFS_MKDIR_ELF_PATH")));
    ok &= seed_file(bin, b"rmdir", include_bytes!(env!("OXFS_RMDIR_ELF_PATH")));
    ok &= seed_file(bin, b"rm", include_bytes!(env!("OXFS_RM_ELF_PATH")));
    ok &= seed_file(bin, b"mv", include_bytes!(env!("OXFS_MV_ELF_PATH")));
    ok &= seed_file(bin, b"cp", include_bytes!(env!("OXFS_CP_ELF_PATH")));
    ok &= seed_file(bin, b"touch", include_bytes!(env!("OXFS_TOUCH_ELF_PATH")));
    // OpenVi -- real BSD's own editor, `/bin` (not `/usr/bin`) since it's the essential,
    // single-user-mode-capable editor -- see CLAUDE.md's ncurses/nano/nvi section.
    ok &= seed_file(bin, b"vi", include_bytes!(env!("OXFS_VI_ELF_PATH")));
    ok &= seed_file(usr_bin, b"head", include_bytes!(env!("OXFS_HEAD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"tail", include_bytes!(env!("OXFS_TAIL_ELF_PATH")));
    ok &= seed_file(usr_bin, b"wc", include_bytes!(env!("OXFS_WC_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"basename",
        include_bytes!(env!("OXFS_BASENAME_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"dirname",
        include_bytes!(env!("OXFS_DIRNAME_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"printf", include_bytes!(env!("OXFS_PRINTF_ELF_PATH")));
    ok &= seed_file(usr_bin, b"seq", include_bytes!(env!("OXFS_SEQ_ELF_PATH")));
    ok &= seed_file(usr_bin, b"cut", include_bytes!(env!("OXFS_CUT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"sort", include_bytes!(env!("OXFS_SORT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"uniq", include_bytes!(env!("OXFS_UNIQ_ELF_PATH")));
    ok &= seed_file(bin, b"kill", include_bytes!(env!("OXFS_KILL_ELF_PATH")));

    // Second pass: every applet build.rs's own second-pass probe found buildable against this
    // musl port (see build.rs's own BUSYBOX_APPLETS_PASS2 comment and OxideBSD-doc/BUSYBOX_APPLETS.md for
    // what each one actually needs at runtime -- most need something OxideBSD doesn't implement
    // yet; "builds" was the bar this pass used, not "works"). One-liner form (not the multi-line
    // seed_file(...) call the first 24 applets above use) purely because there are ~300 of these --
    // no behavioral difference.
    ok &= seed_file(usr_bin, b"ar", include_bytes!(env!("OXFS_AR_ELF_PATH")));
    ok &= seed_file(bin, b"ash", include_bytes!(env!("OXFS_ASH_ELF_PATH")));
    ok &= seed_file(usr_bin, b"awk", include_bytes!(env!("OXFS_AWK_ELF_PATH")));
    ok &= seed_file(usr_bin, b"base32", include_bytes!(env!("OXFS_BASE32_ELF_PATH")));
    ok &= seed_file(usr_bin, b"base64", include_bytes!(env!("OXFS_BASE64_ELF_PATH")));
    ok &= seed_file(usr_bin, b"arch", include_bytes!(env!("OXFS_ARCH_ELF_PATH")));
    // OxideBSD's own sysctl(8) and dmesg(8) (sbin/), not BusyBox's, which read Linux's /proc.
    ok &= seed_file(sbin, b"sysctl", include_bytes!(env!("OXFS_SBIN_SYSCTL_ELF_PATH")));
    ok &= seed_file(usr_bin, b"bc", include_bytes!(env!("OXFS_BC_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"bunzip2",
        include_bytes!(env!("OXFS_BUNZIP2_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"bzcat", include_bytes!(env!("OXFS_BZCAT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"bzip2", include_bytes!(env!("OXFS_BZIP2_ELF_PATH")));
    ok &= seed_file(usr_bin, b"cal", include_bytes!(env!("OXFS_CAL_ELF_PATH")));
    ok &= seed_file(usr_bin, b"chat", include_bytes!(env!("OXFS_CHAT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"chgrp", include_bytes!(env!("OXFS_CHGRP_ELF_PATH")));
    ok &= seed_file(bin, b"chmod", include_bytes!(env!("OXFS_CHMOD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"chown", include_bytes!(env!("OXFS_CHOWN_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"chroot", include_bytes!(env!("OXFS_CHROOT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"cksum", include_bytes!(env!("OXFS_CKSUM_ELF_PATH")));
    ok &= seed_file(usr_bin, b"clear", include_bytes!(env!("OXFS_CLEAR_ELF_PATH")));
    ok &= seed_file(usr_bin, b"cmp", include_bytes!(env!("OXFS_CMP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"comm", include_bytes!(env!("OXFS_COMM_ELF_PATH")));
    ok &= seed_file(usr_bin, b"cpio", include_bytes!(env!("OXFS_CPIO_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"crontab",
        include_bytes!(env!("OXFS_CRONTAB_ELF_PATH")),
    );
    ok &= seed_file(bin, b"date", include_bytes!(env!("OXFS_DATE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"dc", include_bytes!(env!("OXFS_DC_ELF_PATH")));
    ok &= seed_file(bin, b"dd", include_bytes!(env!("OXFS_DD_ELF_PATH")));
    ok &= seed_file(bin, b"df", include_bytes!(env!("OXFS_DF_ELF_PATH")));
    ok &= seed_file(usr_bin, b"diff", include_bytes!(env!("OXFS_DIFF_ELF_PATH")));
    ok &= seed_file(sbin, b"dmesg", include_bytes!(env!("OXFS_SBIN_DMESG_ELF_PATH")));
    ok &= seed_file(sbin, b"update", include_bytes!(env!("OXFS_UPDATE_ELF_PATH")));
    ok &= seed_file(sbin, b"fsck", include_bytes!(env!("OXFS_FSCK_ELF_PATH")));
    ok &= seed_file(sbin, b"fsck_oxfs", include_bytes!(env!("OXFS_FSCK_OXFS_ELF_PATH")));
    ok &= seed_file(sbin, b"newfs_oxfs", include_bytes!(env!("OXFS_NEWFS_OXFS_ELF_PATH")));
    ok &= seed_file(usr_bin, b"du", include_bytes!(env!("OXFS_DU_ELF_PATH")));
    ok &= seed_file(bin, b"ed", include_bytes!(env!("OXFS_ED_ELF_PATH")));
    ok &= seed_file(bin, b"egrep", include_bytes!(env!("OXFS_EGREP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"env", include_bytes!(env!("OXFS_ENV_ELF_PATH")));
    ok &= seed_file(usr_bin, b"expand", include_bytes!(env!("OXFS_EXPAND_ELF_PATH")));
    ok &= seed_file(bin, b"expr", include_bytes!(env!("OXFS_EXPR_ELF_PATH")));
    ok &= seed_file(usr_bin, b"factor", include_bytes!(env!("OXFS_FACTOR_ELF_PATH")));
    ok &= seed_file(bin, b"fgrep", include_bytes!(env!("OXFS_FGREP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"find", include_bytes!(env!("OXFS_FIND_ELF_PATH")));
    ok &= seed_file(usr_bin, b"flock", include_bytes!(env!("OXFS_FLOCK_ELF_PATH")));
    ok &= seed_file(usr_bin, b"fold", include_bytes!(env!("OXFS_FOLD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"fsync", include_bytes!(env!("OXFS_FSYNC_ELF_PATH")));
    ok &= seed_file(usr_bin, b"ftpget", include_bytes!(env!("OXFS_FTPGET_ELF_PATH")));
    ok &= seed_file(usr_bin, b"ftpput", include_bytes!(env!("OXFS_FTPPUT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"fuser", include_bytes!(env!("OXFS_FUSER_ELF_PATH")));
    ok &= seed_file(usr_bin, b"getopt", include_bytes!(env!("OXFS_GETOPT_ELF_PATH")));
    // getty, login, passwd and pwd_mkdb are OxideBSD's own (LOGIN.md), not BusyBox's; getty,
    // login and passwd keep the env var names the BusyBox applets had.
    ok &= seed_file(usr_libexec, b"getty", include_bytes!(env!("OXFS_GETTY_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"pwd_mkdb", include_bytes!(env!("OXFS_PWD_MKDB_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"fsconf_mkdb", include_bytes!(env!("OXFS_FSCONF_MKDB_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"makefs", include_bytes!(env!("OXFS_MAKEFS_ELF_PATH")));
    ok &= seed_file(usr_bin, b"mkimg", include_bytes!(env!("OXFS_MKIMG_ELF_PATH")));
    ok &= seed_file(bin, b"grep", include_bytes!(env!("OXFS_GREP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"groups", include_bytes!(env!("OXFS_GROUPS_ELF_PATH")));
    ok &= seed_file(bin, b"gunzip", include_bytes!(env!("OXFS_GUNZIP_ELF_PATH")));
    ok &= seed_file(bin, b"gzip", include_bytes!(env!("OXFS_GZIP_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"hexdump",
        include_bytes!(env!("OXFS_HEXDUMP_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"hostid", include_bytes!(env!("OXFS_HOSTID_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"install",
        include_bytes!(env!("OXFS_INSTALL_ELF_PATH")),
    );
    ok &= seed_file(bin, b"link", include_bytes!(env!("OXFS_LINK_ELF_PATH")));
    ok &= seed_file(bin, b"ln", include_bytes!(env!("OXFS_LN_ELF_PATH")));
    ok &= seed_file(usr_bin, b"logger", include_bytes!(env!("OXFS_LOGGER_ELF_PATH")));
    ok &= seed_file(usr_bin, b"login", include_bytes!(env!("OXFS_LOGIN_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"logname",
        include_bytes!(env!("OXFS_LOGNAME_ELF_PATH")),
    );
    ok &= seed_file(bin, b"ls", include_bytes!(env!("OXFS_LS_ELF_PATH")));
    // man(1), oxdoc(1) and more(1) are OxideBSD's own (MAN.md), not BusyBox's; less(1) is more.
    ok &= seed_file(usr_bin, b"man", include_bytes!(env!("OXFS_MAN_ELF_PATH")));
    ok &= seed_file(usr_bin, b"oxdoc", include_bytes!(env!("OXFS_OXDOC_ELF_PATH")));
    ok &= seed_file(usr_bin, b"apropos", include_bytes!(env!("OXFS_APROPOS_ELF_PATH")));
    ok &= seed_symlink(usr_bin, b"whatis", b"apropos");
    ok &= seed_file(usr_sbin, b"makewhatis", include_bytes!(env!("OXFS_MAKEWHATIS_ELF_PATH")));
    ok &= seed_symlink(usr_bin, b"less", b"more");
    ok &= seed_file(usr_bin, b"md5sum", include_bytes!(env!("OXFS_MD5SUM_ELF_PATH")));
    ok &= seed_file(usr_bin, b"minips", include_bytes!(env!("OXFS_MINIPS_ELF_PATH")));
    ok &= seed_file(sbin, b"mknod", include_bytes!(env!("OXFS_MKNOD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"mktemp", include_bytes!(env!("OXFS_MKTEMP_ELF_PATH")));
    ok &= seed_file(sbin, b"mount", include_bytes!(env!("OXFS_MOUNT_ELF_PATH")));
    ok &= seed_hardlink(sbin, b"mount_nullfs", b"mount");
    ok &= seed_file(usr_bin, b"nc", include_bytes!(env!("OXFS_NC_ELF_PATH")));
    ok &= seed_file(usr_bin, b"netcat", include_bytes!(env!("OXFS_NETCAT_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"netstat",
        include_bytes!(env!("OXFS_NETSTAT_ELF_PATH")),
    );
    ok &= seed_file(usr_sbin, b"newsyslog", include_bytes!(env!("OXFS_NEWSYSLOG_ELF_PATH")));
    ok &= seed_file(usr_bin, b"nice", include_bytes!(env!("OXFS_NICE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"nl", include_bytes!(env!("OXFS_NL_ELF_PATH")));
    ok &= seed_file(usr_bin, b"nohup", include_bytes!(env!("OXFS_NOHUP_ELF_PATH")));
    ok &= seed_file(bin, b"nproc", include_bytes!(env!("OXFS_NPROC_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"nslookup",
        include_bytes!(env!("OXFS_NSLOOKUP_ELF_PATH")),
    );
    ok &= seed_file(usr_sbin, b"ntpd", include_bytes!(env!("OXFS_NTPD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"od", include_bytes!(env!("OXFS_OD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"passwd", include_bytes!(env!("OXFS_PASSWD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"paste", include_bytes!(env!("OXFS_PASTE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"patch", include_bytes!(env!("OXFS_PATCH_ELF_PATH")));
    ok &= seed_file(bin, b"pgrep", include_bytes!(env!("OXFS_PGREP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"pidof", include_bytes!(env!("OXFS_PIDOF_ELF_PATH")));
    ok &= seed_file(sbin, b"ping", include_bytes!(env!("OXFS_PING_ELF_PATH")));
    ok &= seed_file(bin, b"pkill", include_bytes!(env!("OXFS_PKILL_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"printenv",
        include_bytes!(env!("OXFS_PRINTENV_ELF_PATH")),
    );
    ok &= seed_file(bin, b"pwd", include_bytes!(env!("OXFS_PWD_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"readlink",
        include_bytes!(env!("OXFS_READLINK_ELF_PATH")),
    );
    ok &= seed_file(
        bin,
        b"realpath",
        include_bytes!(env!("OXFS_REALPATH_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"renice", include_bytes!(env!("OXFS_RENICE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"reset", include_bytes!(env!("OXFS_RESET_ELF_PATH")));
    ok &= seed_file(usr_bin, b"resize", include_bytes!(env!("OXFS_RESIZE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"rev", include_bytes!(env!("OXFS_REV_ELF_PATH")));
    ok &= seed_file(bin, b"sed", include_bytes!(env!("OXFS_SED_ELF_PATH")));
    ok &= seed_file(usr_bin, b"setsid", include_bytes!(env!("OXFS_SETSID_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"sha1sum",
        include_bytes!(env!("OXFS_SHA1SUM_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"sha256sum",
        include_bytes!(env!("OXFS_SHA256SUM_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"sha3sum",
        include_bytes!(env!("OXFS_SHA3SUM_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"sha512sum",
        include_bytes!(env!("OXFS_SHA512SUM_ELF_PATH")),
    );
    ok &= seed_file(bin, b"sleep", include_bytes!(env!("OXFS_SLEEP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"split", include_bytes!(env!("OXFS_SPLIT_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"ssl_client",
        include_bytes!(env!("OXFS_SSL_CLIENT_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"stat", include_bytes!(env!("OXFS_STAT_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"strings",
        include_bytes!(env!("OXFS_STRINGS_ELF_PATH")),
    );
    ok &= seed_file(bin, b"stty", include_bytes!(env!("OXFS_STTY_ELF_PATH")));
    // sudo-rs (OxideBSD-doc SUDO.md §3): sudo and su set-user-ID root, visudo, sudoedit. Its su
    // replaces BusyBox's, which is still built but no longer installed.
    ok &= seed_file(usr_bin, b"sudo", include_bytes!(env!("OXFS_SUDO_ELF_PATH")));
    ok &= seed_file(usr_bin, b"su", include_bytes!(env!("OXFS_SUDO_RS_SU_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"visudo", include_bytes!(env!("OXFS_VISUDO_ELF_PATH")));
    ok &= seed_symlink(usr_bin, b"sudoedit", b"sudo");
    for name in [b"sudo".as_slice(), b"su"] {
        if let Some(n) = dir_lookup(usr_bin, name) {
            let mut inode = read_inode(n);
            inode.uid = 0;
            inode.gid = 0;
            inode.mode = 0o4755;
            write_inode(n, inode);
        }
    }
    ok &= seed_file(usr_bin, b"sum", include_bytes!(env!("OXFS_SUM_ELF_PATH")));
    ok &= seed_file(bin, b"sync", include_bytes!(env!("OXFS_SYNC_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"syslogd", include_bytes!(env!("OXFS_SYSLOGD_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"cron", include_bytes!(env!("OXFS_CRON_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"periodic", include_bytes!("../../../../usr.sbin/periodic/periodic.sh"));
    ok &= seed_file(usr_sbin, b"tzsetup", include_bytes!(env!("OXFS_TZSETUP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"zdump", include_bytes!(env!("OXFS_ZDUMP_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"zic", include_bytes!(env!("OXFS_ZIC_ELF_PATH")));
    ok &= seed_file(usr_sbin, b"certctl", include_bytes!(env!("OXFS_CERTCTL_ELF_PATH")));
    ok &= seed_file(usr_bin, b"tac", include_bytes!(env!("OXFS_TAC_ELF_PATH")));
    ok &= seed_file(bin, b"tar", include_bytes!(env!("OXFS_TAR_ELF_PATH")));
    ok &= seed_file(usr_bin, b"tee", include_bytes!(env!("OXFS_TEE_ELF_PATH")));
    ok &= seed_file(usr_bin, b"telnet", include_bytes!(env!("OXFS_TELNET_ELF_PATH")));
    ok &= seed_file(bin, b"test", include_bytes!(env!("OXFS_TEST_ELF_PATH")));
    ok &= seed_hardlink(bin, b"[", b"test");
    ok &= seed_file(usr_bin, b"time", include_bytes!(env!("OXFS_TIME_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"timeout",
        include_bytes!(env!("OXFS_TIMEOUT_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"top", include_bytes!(env!("OXFS_TOP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"tr", include_bytes!(env!("OXFS_TR_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"traceroute",
        include_bytes!(env!("OXFS_TRACEROUTE_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"truncate",
        include_bytes!(env!("OXFS_TRUNCATE_ELF_PATH")),
    );
    ok &= seed_file(usr_bin, b"tsort", include_bytes!(env!("OXFS_TSORT_ELF_PATH")));
    ok &= seed_file(usr_bin, b"tty", include_bytes!(env!("OXFS_TTY_ELF_PATH")));
    ok &= seed_file(sbin, b"umount", include_bytes!(env!("OXFS_UMOUNT_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"uncompress",
        include_bytes!(env!("OXFS_UNCOMPRESS_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"unexpand",
        include_bytes!(env!("OXFS_UNEXPAND_ELF_PATH")),
    );
    ok &= seed_file(bin, b"unlink", include_bytes!(env!("OXFS_UNLINK_ELF_PATH")));
    ok &= seed_file(usr_bin, b"unxz", include_bytes!(env!("OXFS_UNXZ_ELF_PATH")));
    ok &= seed_file(usr_bin, b"unzip", include_bytes!(env!("OXFS_UNZIP_ELF_PATH")));
    ok &= seed_file(usr_bin, b"uptime", include_bytes!(env!("OXFS_UPTIME_ELF_PATH")));
    ok &= seed_file(
        usr_bin,
        b"uudecode",
        include_bytes!(env!("OXFS_UUDECODE_ELF_PATH")),
    );
    ok &= seed_file(
        usr_bin,
        b"uuencode",
        include_bytes!(env!("OXFS_UUENCODE_ELF_PATH")),
    );
    // Real `vi` (OpenVi, not BusyBox's own applet) is seeded above, near the other native/real
    // `/bin` replacements -- see `REPLACED_BUSYBOX_APPLETS`'s own doc comment in build.rs.
    ok &= seed_file(usr_bin, b"wget", include_bytes!(env!("OXFS_WGET_ELF_PATH")));
    ok &= seed_file(usr_bin, b"which", include_bytes!(env!("OXFS_WHICH_ELF_PATH")));
    ok &= seed_file(usr_bin, b"whoami", include_bytes!(env!("OXFS_WHOAMI_ELF_PATH")));
    ok &= seed_file(usr_bin, b"whois", include_bytes!(env!("OXFS_WHOIS_ELF_PATH")));
    ok &= seed_file(usr_bin, b"xargs", include_bytes!(env!("OXFS_XARGS_ELF_PATH")));
    ok &= seed_file(usr_bin, b"xxd", include_bytes!(env!("OXFS_XXD_ELF_PATH")));
    ok &= seed_file(usr_bin, b"xzcat", include_bytes!(env!("OXFS_XZCAT_ELF_PATH")));
    ok &= seed_file(bin, b"zcat", include_bytes!(env!("OXFS_ZCAT_ELF_PATH")));
    // Appended out of alphabetical order, added after SYS_UNAME existed -- see build.rs's own
    // BUSYBOX_APPLETS_PASS2 comment.
    ok &= seed_file(usr_bin, b"uname", include_bytes!(env!("OXFS_UNAME_ELF_PATH")));
    ok &= seed_file(
        bin,
        b"hostname",
        include_bytes!(env!("OXFS_HOSTNAME_ELF_PATH")),
    );

    // /etc/resolv.conf, for musl's own real DNS stub resolver (external/mit/musl/src/network/) --
    // no DNS logic lives in this kernel; musl's resolver is a real UDP client already built on
    // socket/sendto/recvfrom/poll (see sys/net/mod.rs's oxidebsd_sys_poll doc comment), it just
    // needs a nameserver address to send queries to. 10.0.2.3 is QEMU SLIRP's own built-in DNS
    // relay (must stay in sync with sys/netinet/ipv4.rs's own DNS_SERVER_IP -- this crate can't import
    // that constant directly, it's a separate no_std module build, see CLAUDE.md's module-loading
    // section).
    let etc = alloc_inode().expect("oxfs: failed to allocate /etc inode");
    write_inode(etc, fresh_inode(InodeKind::Dir));
    dir_insert(etc, b".", etc).expect("oxfs: failed to seed /etc's . entry");
    dir_insert(etc, b"..", root).expect("oxfs: failed to seed /etc's .. entry");
    dir_insert(root, b"etc", etc).expect("oxfs: failed to insert /etc into root");
    ok &= seed_file(etc, b"resolv.conf", b"nameserver 10.0.2.3\n");
    ok &= seed_file(etc, b"hosts", include_bytes!("../../../../etc/hosts"));
    // rc(8): the boot and shutdown scripts and the rc.d services, from the source tree's etc/
    // (INIT.md in OxideBSD-doc).
    ok &= seed_file(etc, b"rc", include_bytes!("../../../../etc/rc"));
    ok &= seed_file(etc, b"rc.shutdown", include_bytes!("../../../../etc/rc.shutdown"));
    ok &= seed_file(etc, b"rc.subr", include_bytes!("../../../../etc/rc.subr"));
    ok &= seed_file(etc, b"rc.conf", include_bytes!("../../../../etc/rc.conf"));
    ok &= seed_file(etc, b"ttys", include_bytes!("../../../../etc/ttys"));
    let etc_defaults = ensure_dir(etc, b"defaults");
    ok &= seed_file(etc_defaults, b"rc.conf", include_bytes!("../../../../etc/defaults/rc.conf"));
    let rc_d = ensure_dir(etc, b"rc.d");
    ok &= seed_file(rc_d, b"FILESYSTEMS", include_bytes!("../../../../etc/rc.d/FILESYSTEMS"));
    ok &= seed_file(rc_d, b"root", include_bytes!("../../../../etc/rc.d/root"));
    ok &= seed_file(rc_d, b"fsck", include_bytes!("../../../../etc/rc.d/fsck"));
    ok &= seed_file(rc_d, b"NETWORKING", include_bytes!("../../../../etc/rc.d/NETWORKING"));
    ok &= seed_file(rc_d, b"SERVERS", include_bytes!("../../../../etc/rc.d/SERVERS"));
    ok &= seed_file(rc_d, b"DAEMON", include_bytes!("../../../../etc/rc.d/DAEMON"));
    ok &= seed_file(rc_d, b"LOGIN", include_bytes!("../../../../etc/rc.d/LOGIN"));
    ok &= seed_file(rc_d, b"cleanvar", include_bytes!("../../../../etc/rc.d/cleanvar"));
    ok &= seed_file(rc_d, b"hostname", include_bytes!("../../../../etc/rc.d/hostname"));
    ok &= seed_file(rc_d, b"tmp", include_bytes!("../../../../etc/rc.d/tmp"));
    ok &= seed_file(rc_d, b"sysctl", include_bytes!("../../../../etc/rc.d/sysctl"));
    ok &= seed_file(rc_d, b"devfs", include_bytes!("../../../../etc/rc.d/devfs"));
    ok &= seed_file(rc_d, b"newsyslog", include_bytes!("../../../../etc/rc.d/newsyslog"));
    ok &= seed_file(rc_d, b"syslogd", include_bytes!("../../../../etc/rc.d/syslogd"));
    ok &= seed_file(rc_d, b"cron", include_bytes!("../../../../etc/rc.d/cron"));
    ok &= seed_file(rc_d, b"update", include_bytes!("../../../../etc/rc.d/update"));
    ok &= seed_file(rc_d, b"mountcritlocal", include_bytes!("../../../../etc/rc.d/mountcritlocal"));
    ok &= seed_file(etc, b"sysctl.conf", include_bytes!("../../../../etc/sysctl.conf"));
    // System logging (SYSLOG.md): routing, rotation, and their drop-in directories.
    ok &= seed_file(etc, b"devfs.conf", include_bytes!("../../../../etc/devfs.conf"));
    ok &= seed_file(etc, b"syslog.conf", include_bytes!("../../../../etc/syslog.conf"));
    ensure_dir(etc, b"syslog.d");
    ok &= seed_file(etc, b"newsyslog.conf", include_bytes!("../../../../etc/newsyslog.conf"));
    ensure_dir(etc, b"newsyslog.conf.d");
    // /etc/passwd + /etc/group -- musl's own getpwnam/getpwuid/getgrnam/getgrgid
    // (external/mit/musl/src/passwd/*.c) parse these directly via plain fopen/fgets, no syscall of
    // their own beyond the open/read/readv this filesystem already supports -- same "port libc's
    // real code, don't reimplement its logic kernel-side" philosophy CLAUDE.md's musl-port section
    // already documents for DNS resolution. Two real accounts now, not just root -- a second,
    // non-root `user` (uid/gid 1000) exists specifically so `su`/`login` have something real to
    // exercise: root calling either always skips the password check entirely (see busybox's own
    // su.c), so a root-only passwd file could never demonstrate real authentication at all.
    ok &= seed_file(etc, b"passwd", include_bytes!("../../../../etc/passwd"));
    ok &= seed_file(etc, b"group", include_bytes!("../../../../etc/group"));

    // /etc/master.passwd: the BSD account file (LOGIN.md §7.4) -- real crypt(3) SHA-512 (`$6$`)
    // hashes, which pam_unix and musl's getspnam (patched to read this file; there is no
    // /etc/shadow) check. Both passwords equal the account's own username (`root`/`user`) -- fine
    // for a kernel with no external network exposure. `/etc/passwd` above is what pwd_mkdb(8)
    // generates from it. Mode 0600, as on the BSDs: only root may read the hashes.
    ok &= seed_file(etc, b"master.passwd", include_bytes!("../../../../etc/master.passwd"));
    if let Some(master) = dir_lookup(etc, b"master.passwd") {
        let mut inode = read_inode(master);
        inode.mode = 0o600;
        write_inode(master, inode);
    } else {
        ok = false;
    }

    // getty(8), login(1) and PAM (LOGIN.md): terminal descriptions, login classes, the message of
    // the day and the PAM policies.
    ok &= seed_file(etc, b"gettytab", include_bytes!("../../../../etc/gettytab"));
    ok &= seed_file(etc, b"login.conf", include_bytes!("../../../../etc/login.conf"));
    ok &= seed_file(etc, b"motd", include_bytes!("../../../../etc/motd"));
    // Read by every login shell (sh(1)); the prompt the console shell had before login sessions.
    ok &= seed_file(etc, b"profile", include_bytes!("../../../../etc/profile"));
    ok &= seed_file(etc, b"man.conf", include_bytes!("../../../../etc/man.conf"));
    let pam_d = ensure_dir(etc, b"pam.d");
    ok &= seed_file(pam_d, b"login", include_bytes!("../../../../etc/pam.d/login"));
    ok &= seed_file(pam_d, b"other", include_bytes!("../../../../etc/pam.d/other"));
    ok &= seed_file(pam_d, b"passwd", include_bytes!("../../../../etc/pam.d/passwd"));
    ok &= seed_file(pam_d, b"system", include_bytes!("../../../../etc/pam.d/system"));
    ok &= seed_file(pam_d, b"cron", include_bytes!("../../../../etc/pam.d/cron"));
    ok &= seed_file(pam_d, b"sudo", include_bytes!("../../../../etc/pam.d/sudo"));
    ok &= seed_file(pam_d, b"su", include_bytes!("../../../../etc/pam.d/su"));
    ok &= seed_file(etc, b"sudoers", include_bytes!("../../../../etc/sudoers"));
    if let Some(n) = dir_lookup(etc, b"sudoers") {
        let mut inode = read_inode(n);
        inode.mode = 0o440;
        write_inode(n, inode);
    }

    // /home/user -- real, owned by uid/gid 1000 -- so `su -`/`login`'s own real chdir-to-home
    // lands somewhere that's actually theirs (permission-checked, not just root's own `/`).
    let home = alloc_inode().expect("oxfs: failed to allocate /home inode");
    write_inode(home, fresh_inode(InodeKind::Dir));
    dir_insert(home, b".", home).expect("oxfs: failed to seed /home's . entry");
    dir_insert(home, b"..", root).expect("oxfs: failed to seed /home's .. entry");
    dir_insert(root, b"home", home).expect("oxfs: failed to insert /home into root");

    let user_home = alloc_inode().expect("oxfs: failed to allocate /home/user inode");
    write_inode(user_home, fresh_inode(InodeKind::Dir));
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
    // /var: /var/run for pid files and shutdown(8)'s nologin (emptied at boot by rc.d/cleanvar),
    // /var/log for logs.
    let var = ensure_dir(root, b"var");
    ensure_dir(var, b"run");
    ensure_dir(var, b"log");
    // Mailboxes, $MAIL for every login (login.conf's setenv).
    ensure_dir(var, b"mail");
    // cron (CRON.md §2): the system table, a directory for more, and the users' tables, which
    // only root may list (crontab(1) writes them).
    ok &= seed_file(etc, b"crontab", include_bytes!("../../../../etc/crontab"));
    // fstab(5): the file systems rc.d/mountcritlocal mounts.
    ok &= seed_file(etc, b"fstab", include_bytes!("../../../../etc/fstab"));
    ensure_dir(etc, b"cron.d");
    // periodic(8) (CRON.md §7): its settings, and the daily, weekly and monthly scripts.
    ok &= seed_file(etc_defaults, b"periodic.conf", include_bytes!("../../../../etc/defaults/periodic.conf"));
    let periodic = ensure_dir(etc, b"periodic");
    let periodic_daily = ensure_dir(periodic, b"daily");
    ok &= seed_file(periodic_daily, b"110.clean-tmps", include_bytes!("../../../../etc/periodic/daily/110.clean-tmps"));
    ok &= seed_file(periodic_daily, b"200.backup-passwd", include_bytes!("../../../../etc/periodic/daily/200.backup-passwd"));
    ok &= seed_file(periodic_daily, b"400.status-disks", include_bytes!("../../../../etc/periodic/daily/400.status-disks"));
    ok &= seed_file(periodic_daily, b"430.status-uptime", include_bytes!("../../../../etc/periodic/daily/430.status-uptime"));
    ok &= seed_file(periodic_daily, b"999.local", include_bytes!("../../../../etc/periodic/daily/999.local"));
    let periodic_weekly = ensure_dir(periodic, b"weekly");
    ok &= seed_file(periodic_weekly, b"999.local", include_bytes!("../../../../etc/periodic/weekly/999.local"));
    let periodic_monthly = ensure_dir(periodic, b"monthly");
    ok &= seed_file(periodic_monthly, b"999.local", include_bytes!("../../../../etc/periodic/monthly/999.local"));
    ensure_dir(var, b"backups");
    let var_cron = ensure_dir(var, b"cron");
    let var_cron_tabs = ensure_dir(var_cron, b"tabs");
    {
        let mut inode = read_inode(var_cron_tabs);
        inode.mode = 0o700;
        write_inode(var_cron_tabs, inode);
    }

    let tmp = ensure_dir(root, b"tmp");
    {
        let mut inode = read_inode(tmp);
        inode.mode = 0o1777;
        write_inode(tmp, inode);
    }

    // /dev: only the mountpoint. Its contents are devfs's, made at every boot (`DEVFS.md` §4).
    ensure_dir(root, b"dev");

    // The real, on-target musl runtime tree -- `/usr/include`/`/usr/lib` -- what Clang/LLVM's own
    // on-target `clang`/`ld.lld` links a user's C file against (`-DDEFAULT_SYSROOT=/usr`,
    // see `build_llvm_target_toolchain`'s own doc comment in build.rs), so no extra `--sysroot`
    // flag is needed to invoke `clang` on target. Originally built for TinyCC (this project's
    // first on-target C compiler, since removed once Clang/LLVM superseded it).
    // /sbin: system programs. init is pid 1 (the kernel runs its own copy); init_sh (lib/libsh
    // with the init dialect) runs /etc/rc and rc.d.
    let sbin = ensure_dir(root, b"sbin");
    ok &= seed_file(sbin, b"init", include_bytes!(env!("OXFS_INIT_ELF_PATH")));
    ok &= seed_file(sbin, b"init_sh", include_bytes!(env!("OXFS_INIT_SH_ELF_PATH")));
    ok &= seed_file(sbin, b"rcorder", include_bytes!(env!("OXFS_RCORDER_ELF_PATH")));
    ok &= seed_file(sbin, b"reboot", include_bytes!(env!("OXFS_REBOOT_ELF_PATH")));
    // BusyBox's halt/poweroff aren't installed: they signal init with BusyBox init's meanings
    // (SIGTERM = reboot), not INIT.md §6's.
    ok &= seed_hardlink(sbin, b"halt", b"reboot");
    ok &= seed_hardlink(sbin, b"poweroff", b"reboot");
    ok &= seed_file(sbin, b"shutdown", include_bytes!(env!("OXFS_SHUTDOWN_ELF_PATH")));
    ok &= seed_file(sbin, b"emergency", include_bytes!(env!("OXFS_EMERGENCY_ELF_PATH")));
    ok &= seed_file(sbin, b"nologin", include_bytes!(env!("OXFS_NOLOGIN_ELF_PATH")));

    let usr = ensure_dir(root, b"usr");
    let usr_include = ensure_dir(usr, b"include");
    ok &= seed_tree(usr_include, MUSL_INCLUDE_FILES);
    let usr_lib = ensure_dir(usr, b"lib");
    ok &= seed_tree(usr_lib, MUSL_LIB_FILES);
    let usr_share = ensure_dir(usr, b"share");
    // mdoc(7) manual pages, from the source tree's share/man.
    let usr_share_man = ensure_dir(usr_share, b"man");
    let man_man1 = ensure_dir(usr_share_man, b"man1");
    // Their index, built with the image (makewhatis(8)).
    ok &= seed_file(usr_share_man, b"oxdoc.db", include_bytes!(env!("OXFS_MAN_DB_PATH")));
    ok &= seed_file(man_man1, b"apropos.1", include_bytes!("../../../../share/man/man1/apropos.1"));
    ok &= seed_hardlink(man_man1, b"whatis.1", b"apropos.1");
    ok &= seed_file(man_man1, b"login.1", include_bytes!("../../../../share/man/man1/login.1"));
    ok &= seed_file(man_man1, b"less.1", include_bytes!("../../../../share/man/man1/more.1"));
    ok &= seed_file(man_man1, b"logger.1", include_bytes!("../../../../share/man/man1/logger.1"));
    ok &= seed_file(man_man1, b"crontab.1", include_bytes!("../../../../share/man/man1/crontab.1"));
    ok &= seed_file(man_man1, b"chmod.1", include_bytes!("../../../../share/man/man1/chmod.1"));
    ok &= seed_file(man_man1, b"kill.1", include_bytes!("../../../../share/man/man1/kill.1"));
    ok &= seed_file(man_man1, b"link.1", include_bytes!("../../../../share/man/man1/link.1"));
    ok &= seed_file(man_man1, b"nproc.1", include_bytes!("../../../../share/man/man1/nproc.1"));
    ok &= seed_file(man_man1, b"rmdir.1", include_bytes!("../../../../share/man/man1/rmdir.1"));
    ok &= seed_file(man_man1, b"sleep.1", include_bytes!("../../../../share/man/man1/sleep.1"));
    ok &= seed_file(man_man1, b"test.1", include_bytes!("../../../../share/man/man1/test.1"));
    ok &= seed_file(man_man1, b"unlink.1", include_bytes!("../../../../share/man/man1/unlink.1"));
    ok &= seed_file(man_man1, b"man.1", include_bytes!("../../../../share/man/man1/man.1"));
    ok &= seed_hardlink(man_man1, b"more.1", b"less.1");
    ok &= seed_file(man_man1, b"oxdoc.1", include_bytes!("../../../../share/man/man1/oxdoc.1"));
    ok &= seed_file(man_man1, b"passwd.1", include_bytes!("../../../../share/man/man1/passwd.1"));
    let man_man2 = ensure_dir(usr_share_man, b"man2");
    ok &= seed_file(man_man2, b"accept.2", include_bytes!("../../../../share/man/man2/accept.2"));
    ok &= seed_file(man_man2, b"nmount.2", include_bytes!("../../../../share/man/man2/nmount.2"));
    ok &= seed_hardlink(man_man2, b"accept4.2", b"accept.2");
    ok &= seed_file(man_man2, b"bind.2", include_bytes!("../../../../share/man/man2/bind.2"));
    ok &= seed_file(man_man2, b"connect.2", include_bytes!("../../../../share/man/man2/connect.2"));
    ok &= seed_file(man_man2, b"getsockname.2", include_bytes!("../../../../share/man/man2/getsockname.2"));
    ok &= seed_hardlink(man_man2, b"getpeername.2", b"getsockname.2");
    ok &= seed_file(man_man2, b"getsockopt.2", include_bytes!("../../../../share/man/man2/getsockopt.2"));
    ok &= seed_hardlink(man_man2, b"setsockopt.2", b"getsockopt.2");
    ok &= seed_file(man_man2, b"listen.2", include_bytes!("../../../../share/man/man2/listen.2"));
    ok &= seed_file(man_man2, b"recvmsg.2", include_bytes!("../../../../share/man/man2/recvmsg.2"));
    ok &= seed_hardlink(man_man2, b"recv.2", b"recvmsg.2");
    ok &= seed_hardlink(man_man2, b"recvfrom.2", b"recvmsg.2");
    ok &= seed_file(man_man2, b"sendmsg.2", include_bytes!("../../../../share/man/man2/sendmsg.2"));
    ok &= seed_hardlink(man_man2, b"send.2", b"sendmsg.2");
    ok &= seed_hardlink(man_man2, b"sendto.2", b"sendmsg.2");
    ok &= seed_file(man_man2, b"shutdown.2", include_bytes!("../../../../share/man/man2/shutdown.2"));
    ok &= seed_file(man_man2, b"socket.2", include_bytes!("../../../../share/man/man2/socket.2"));
    ok &= seed_file(man_man2, b"socketpair.2", include_bytes!("../../../../share/man/man2/socketpair.2"));
    let man_man3 = ensure_dir(usr_share_man, b"man3");
    ok &= seed_file(man_man3, b"getpeereid.3", include_bytes!("../../../../share/man/man3/getpeereid.3"));
    ok &= seed_file(man_man3, b"sysctl.3", include_bytes!("../../../../share/man/man3/sysctl.3"));
    ok &= seed_hardlink(man_man3, b"sysctlbyname.3", b"sysctl.3");
    ok &= seed_hardlink(man_man3, b"sysctlnametomib.3", b"sysctl.3");
    let man_man4 = ensure_dir(usr_share_man, b"man4");
    ok &= seed_file(man_man4, b"devfs.4", include_bytes!("../../../../share/man/man4/devfs.4"));
    ok &= seed_file(man_man4, b"klog.4", include_bytes!("../../../../share/man/man4/klog.4"));
    ok &= seed_file(man_man4, b"pts.4", include_bytes!("../../../../share/man/man4/pts.4"));
    ok &= seed_file(man_man4, b"unix.4", include_bytes!("../../../../share/man/man4/unix.4"));
    let man_man5 = ensure_dir(usr_share_man, b"man5");
    ok &= seed_file(man_man5, b"devfs.conf.5", include_bytes!("../../../../share/man/man5/devfs.conf.5"));
    ok &= seed_file(man_man5, b"fsconf.5", include_bytes!("../../../../share/man/man5/fsconf.5"));
    ok &= seed_file(man_man5, b"gettytab.5", include_bytes!("../../../../share/man/man5/gettytab.5"));
    ok &= seed_file(man_man5, b"login.conf.5", include_bytes!("../../../../share/man/man5/login.conf.5"));
    ok &= seed_file(man_man5, b"man.conf.5", include_bytes!("../../../../share/man/man5/man.conf.5"));
    ok &= seed_file(man_man5, b"newsyslog.conf.5", include_bytes!("../../../../share/man/man5/newsyslog.conf.5"));
    ok &= seed_file(man_man5, b"passwd.5", include_bytes!("../../../../share/man/man5/passwd.5"));
    ok &= seed_hardlink(man_man5, b"master.passwd.5", b"passwd.5");
    ok &= seed_file(man_man5, b"rc.conf.5", include_bytes!("../../../../share/man/man5/rc.conf.5"));
    ok &= seed_file(man_man5, b"sysctl.conf.5", include_bytes!("../../../../share/man/man5/sysctl.conf.5"));
    ok &= seed_file(man_man5, b"syslog.conf.5", include_bytes!("../../../../share/man/man5/syslog.conf.5"));
    ok &= seed_file(man_man5, b"crontab.5", include_bytes!("../../../../share/man/man5/crontab.5"));
    ok &= seed_file(man_man5, b"fstab.5", include_bytes!("../../../../share/man/man5/fstab.5"));
    ok &= seed_file(man_man5, b"periodic.conf.5", include_bytes!("../../../../share/man/man5/periodic.conf.5"));
    // tzcode's own pages, as IANA ships them.
    ok &= seed_file(man_man5, b"tzfile.5", include_bytes!("../../../../external/public-domain/tz/tzfile.5"));
    ok &= seed_file(man_man5, b"ttys.5", include_bytes!("../../../../share/man/man5/ttys.5"));
    let man_man7 = ensure_dir(usr_share_man, b"man7");
    ok &= seed_file(man_man7, b"eqn.7", include_bytes!("../../../../share/man/man7/eqn.7"));
    ok &= seed_file(man_man7, b"hier.7", include_bytes!("../../../../share/man/man7/hier.7"));
    ok &= seed_file(man_man7, b"man.7", include_bytes!("../../../../share/man/man7/man.7"));
    ok &= seed_file(man_man7, b"mdoc.7", include_bytes!("../../../../share/man/man7/mdoc.7"));
    ok &= seed_file(man_man7, b"roff.7", include_bytes!("../../../../share/man/man7/roff.7"));
    ok &= seed_file(man_man7, b"tbl.7", include_bytes!("../../../../share/man/man7/tbl.7"));
    let man_man8 = ensure_dir(usr_share_man, b"man8");
    ok &= seed_file(man_man8, b"emergency.8", include_bytes!("../../../../share/man/man8/emergency.8"));
    ok &= seed_file(man_man8, b"dmesg.8", include_bytes!("../../../../share/man/man8/dmesg.8"));
    ok &= seed_file(man_man8, b"update.8", include_bytes!("../../../../share/man/man8/update.8"));
    ok &= seed_file(man_man8, b"fsck.8", include_bytes!("../../../../share/man/man8/fsck.8"));
    ok &= seed_file(man_man8, b"fsck_oxfs.8", include_bytes!("../../../../share/man/man8/fsck_oxfs.8"));
    ok &= seed_file(man_man8, b"newfs_oxfs.8", include_bytes!("../../../../share/man/man8/newfs_oxfs.8"));
    ok &= seed_file(man_man8, b"getty.8", include_bytes!("../../../../share/man/man8/getty.8"));
    ok &= seed_file(man_man8, b"init.8", include_bytes!("../../../../share/man/man8/init.8"));
    ok &= seed_file(man_man8, b"makewhatis.8", include_bytes!("../../../../share/man/man8/makewhatis.8"));
    ok &= seed_file(man_man8, b"newsyslog.8", include_bytes!("../../../../share/man/man8/newsyslog.8"));
    ok &= seed_file(man_man8, b"pwd_mkdb.8", include_bytes!("../../../../share/man/man8/pwd_mkdb.8"));
    ok &= seed_file(man_man8, b"fsconf_mkdb.8", include_bytes!("../../../../share/man/man8/fsconf_mkdb.8"));
    ok &= seed_file(man_man8, b"makefs.8", include_bytes!("../../../../share/man/man8/makefs.8"));
    ok &= seed_file(man_man1, b"mkimg.1", include_bytes!("../../../../share/man/man1/mkimg.1"));
    ok &= seed_file(man_man5, b"mtree.5", include_bytes!("../../../../share/man/man5/mtree.5"));
    ok &= seed_file(man_man8, b"rc.8", include_bytes!("../../../../share/man/man8/rc.8"));
    ok &= seed_file(man_man8, b"rc.subr.8", include_bytes!("../../../../share/man/man8/rc.subr.8"));
    ok &= seed_file(man_man8, b"rcorder.8", include_bytes!("../../../../share/man/man8/rcorder.8"));
    ok &= seed_file(man_man8, b"reboot.8", include_bytes!("../../../../share/man/man8/reboot.8"));
    ok &= seed_file(man_man8, b"sysctl.8", include_bytes!("../../../../share/man/man8/sysctl.8"));
    ok &= seed_file(man_man8, b"syslogd.8", include_bytes!("../../../../share/man/man8/syslogd.8"));
    ok &= seed_file(man_man8, b"cron.8", include_bytes!("../../../../share/man/man8/cron.8"));
    ok &= seed_file(man_man8, b"mount.8", include_bytes!("../../../../share/man/man8/mount.8"));
    ok &= seed_hardlink(man_man8, b"mount_nullfs.8", b"mount.8");
    ok &= seed_file(man_man8, b"umount.8", include_bytes!("../../../../share/man/man8/umount.8"));
    ok &= seed_file(man_man8, b"sync.8", include_bytes!("../../../../share/man/man8/sync.8"));
    ok &= seed_file(man_man8, b"periodic.8", include_bytes!("../../../../share/man/man8/periodic.8"));
    ok &= seed_file(man_man8, b"tzsetup.8", include_bytes!("../../../../share/man/man8/tzsetup.8"));
    ok &= seed_file(man_man8, b"zdump.8", include_bytes!("../../../../external/public-domain/tz/zdump.8"));
    ok &= seed_file(man_man8, b"zic.8", include_bytes!("../../../../external/public-domain/tz/zic.8"));
    ok &= seed_hardlink(man_man8, b"halt.8", b"reboot.8");
    ok &= seed_hardlink(man_man8, b"poweroff.8", b"reboot.8");
    ok &= seed_file(man_man8, b"shutdown.8", include_bytes!("../../../../share/man/man8/shutdown.8"));
    ok &= seed_file(man_man8, b"nologin.8", include_bytes!("../../../../share/man/man8/nologin.8"));
    let usr_share_mk = ensure_dir(usr_share, b"mk");
    ok &= seed_tree(usr_share_mk, BMAKE_MK_FILES);

    // Real ncurses (see CLAUDE.md's ncurses/nano/nvi section) -- headers/archives layered onto the
    // same `/usr/include`/`/usr/lib` inodes musl's own runtime tree already populates, plus a
    // deliberately minimal compiled terminfo database at `/usr/share/terminfo` (ncurses' own
    // compiled-in default lookup path, matched by `--with-default-terminfo-dir=` in
    // `build_ncurses`). `seed_tree` creates the `l/`, `v/`, `d/` hash-bucket subdirectories on its
    // own from each entry's own relative path (e.g. `"l/linux"`), same as any other nested tree.
    ok &= seed_tree(usr_include, NCURSES_INCLUDE_FILES);
    ok &= seed_tree(usr_lib, NCURSES_LIB_FILES);

    // libc++/libc++abi/libunwind (build.rs's `write_libcxx_runtime_manifest`), FreeBSD's layout:
    // `/usr/include/c++/v1`, the per-triple `__config_site` under `/usr/include/<triple>/c++/v1`
    // (found by the LLVM fork's `OxideBSD::addLibCxxIncludePaths`), archives in `/usr/lib`.
    let usr_include_cxx = ensure_dir(usr_include, b"c++");
    let usr_include_cxx_v1 = ensure_dir(usr_include_cxx, b"v1");
    ok &= seed_tree(usr_include_cxx_v1, LIBCXX_INCLUDE_FILES);
    let usr_include_triple = ensure_dir(usr_include, b"x86_64-unknown-oxidebsd-musl");
    let usr_include_triple_cxx = ensure_dir(usr_include_triple, b"c++");
    let usr_include_triple_cxx_v1 = ensure_dir(usr_include_triple_cxx, b"v1");
    ok &= seed_tree(usr_include_triple_cxx_v1, LIBCXX_TARGET_INCLUDE_FILES);
    ok &= seed_tree(usr_lib, LIBCXX_LIB_FILES);
    let usr_share_terminfo = ensure_dir(usr_share, b"terminfo");
    ok &= seed_tree(usr_share_terminfo, NCURSES_TERMINFO_FILES);
    let usr_share_zoneinfo = ensure_dir(usr_share, b"zoneinfo");
    ok &= seed_tree(usr_share_zoneinfo, TZ_ZONEINFO_FILES);
    ok &= seed_tree_links(usr_share_zoneinfo, TZ_ZONEINFO_LINKS);
    ok &= seed_tree(root, OPENSSL_FILES);
    ok &= seed_tree_symlinks(root, OPENSSL_SYMLINKS);
    ok &= seed_tree(root, CERTS_FILES);
    ok &= seed_tree_symlinks(root, CERTS_SYMLINKS);
    for dir in CERTS_DIRS {
        let mut d = root;
        for component in dir.split('/') {
            d = ensure_dir(d, component.as_bytes());
        }
    }

    // GNU nano -- `/usr/bin`, not `/bin`, since it's real BSD-convention "everything else" rather
    // than an essential single-user-mode-capable tool (OpenVi fills that role at `/bin/vi` above)
    // -- see CLAUDE.md's ncurses/nano/nvi section.
    let usr_bin = ensure_dir(usr, b"bin");
    ok &= seed_file(usr_bin, b"nano", include_bytes!(env!("OXFS_NANO_ELF_PATH")));
    // ninja (build.rs's `build_ninja`) and its own source at `/usr/src/ninja`, which on-target
    // bmake + clang++ can rebuild it from (`bmake -f Makefile.oxidebsd`).
    ok &= seed_file(usr_bin, b"ninja", include_bytes!(env!("OXFS_NINJA_ELF_PATH")));
    let usr_src = ensure_dir(usr, b"src");
    let usr_src_ninja = ensure_dir(usr_src, b"ninja");
    ok &= seed_tree(usr_src_ninja, NINJA_SRC_FILES);

    // The POSIX conformance pilot (`OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`): a curated
    // subset of `external/gpl2/posixtestsuite`'s assertion files, cross-compiled on the host with
    // musl-gcc (build.rs's `write_posix_test_manifest`), under `/usr/tests/posix/bin`, with the
    // suite's `t0` timeout wrapper, `manifest.txt`, and `run.sh`, which runs every test in the
    // manifest (`sh /usr/tests/posix/run.sh`). `run.sh` runs from that directory, where
    // `sigaltstack/9-1.c`'s cwd-relative `execl()` target (`POSIX_TEST_EXTRA_FILES`) also lives.
    let usr_tests_posix = ensure_dir(ensure_dir(usr, b"tests"), b"posix");
    ok &= seed_tree(usr_tests_posix, POSIX_TEST_FILES);
    ok &= seed_tree(usr_tests_posix, POSIX_TEST_EXTRA_FILES);
    ok &= seed_file(usr_tests_posix, b"run.sh", include_bytes!("posix_conformance.sh"));

    // Shared libraries the programs in /bin and /sbin need live in /lib, as on the BSDs: musl's
    // libc.so, which is also its dynamic linker (musl's `make install` makes the interpreter path
    // a symlink to it), and libgcc_s.so.1, the unwinder (LLVM libunwind, build.rs's
    // build_libgcc_s). /usr/lib has symlinks to them under the names a link looks for.
    let lib = ensure_dir(root, b"lib");
    ok &= seed_file(lib, b"libc.so", include_bytes!(env!("OXFS_LIBC_SO_PATH")));
    ok &= seed_symlink(lib, b"ld-musl-x86_64.so.1", b"libc.so");
    ok &= seed_file(lib, b"libgcc_s.so.1", include_bytes!(env!("OXFS_LIBGCC_S_PATH")));
    ok &= seed_symlink(usr_lib, b"libc.so", b"/lib/libc.so");
    ok &= seed_symlink(usr_lib, b"libgcc_s.so", b"/lib/libgcc_s.so.1");

    // Clang's own resource-dir tree (intrinsic headers, compiler-rt's builtins archive) -- see
    // CLAUDE.md's Clang/LLVM port section. `/usr/lib/clang/23` is clang's own binary-relative
    // default (`<bindir>/../lib/clang/<ver>`, `/usr/bin/clang` -> `/usr/lib/clang/23`), distinct
    // from `/usr/include` + `/usr/lib` (`--sysroot`/`DEFAULT_SYSROOT`, baked in at build time so
    // no on-target `--sysroot` flag is needed).
    let lib_clang = ensure_dir(usr_lib, b"clang");
    let lib_clang_23 = ensure_dir(lib_clang, b"23");
    ok &= seed_tree(lib_clang_23, CLANG_RESOURCE_FILES);

    // Programs the syscall smokes `fork`+`execve` (`tests/<area>_syscall_smoke.rs`, each driven
    // by `regress/<area>-syscall-smoke`); the sources are `regress/<name>/main.c`.
    let usr_tests = ensure_dir(usr, b"tests");
    let fixture = |area: &[u8], name: &[u8], elf: &[u8]| seed_file(ensure_dir(usr_tests, area), name, elf);
    // PT_INTERP dynamic linking, fixed-address and PIE.
    ok &= fixture(b"dynlink", b"dynlink-smoke", include_bytes!(env!("OXFS_DYNLINK_SMOKE_ELF_PATH")));
    ok &= fixture(b"dynlink", b"dynlink-pie-smoke", include_bytes!(env!("OXFS_DYNLINK_PIE_SMOKE_ELF_PATH")));
    // A PIE without PT_INTERP, for `process::aslr::pick_bias` (`regress/pie-aslr-driver/`). Its
    // build.rs has no linker script on purpose.
    ok &= fixture(b"aslr", b"pie-aslr-probe", include_bytes!(env!("OXFS_PIE_ASLR_PROBE_ELF_PATH")));
    // pthread_create/pthread_join, and two isolated Open POSIX Test Suite repros:
    // `pthread_cancel/5-1.c` (an expected SIGSEGV through memory pthread_join unmapped) and
    // `pthread_cond_broadcast/1-2.c` (a PTHREAD_PROCESS_SHARED cond in a file MAP_SHARED region).
    ok &= fixture(b"pthread", b"pthread-smoke", include_bytes!(env!("OXFS_PTHREAD_SMOKE_ELF_PATH")));
    ok &= fixture(b"pthread", b"pthread-cancel-crash", include_bytes!(env!("OXFS_PTHREAD_CANCEL_CRASH_ELF_PATH")));
    ok &= fixture(b"pthread", b"pshared-cond-crash", include_bytes!(env!("OXFS_PSHARED_COND_CRASH_ELF_PATH")));
    ok &= fixture(b"at", b"at-smoke", include_bytes!(env!("OXFS_AT_SMOKE_ELF_PATH")));
    ok &= fixture(b"net", b"socket-smoke", include_bytes!(env!("OXFS_SOCKET_SMOKE_ELF_PATH")));
    ok &= fixture(b"sysctl", b"sysctl-smoke", include_bytes!(env!("OXFS_SYSCTL_SMOKE_ELF_PATH")));
    ok &= fixture(b"pagecache", b"pagecache-smoke", include_bytes!(env!("OXFS_PAGECACHE_SMOKE_ELF_PATH")));
    // W^X's escape hatch: the same program marked wxneeded (PT_OXIDEBSD_WXNEEDED) and not.
    ok &= fixture(b"wx", b"wx-needed", include_bytes!(env!("OXFS_WX_NEEDED_ELF_PATH")));
    ok &= fixture(b"wx", b"wx-plain", include_bytes!(env!("OXFS_WX_PLAIN_ELF_PATH")));
    ok &= fixture(b"poll", b"ppoll-smoke", include_bytes!(env!("OXFS_PPOLL_SMOKE_ELF_PATH")));
    ok &= fixture(b"fd", b"fd-smoke", include_bytes!(env!("OXFS_FD_SMOKE_ELF_PATH")));
    ok &= fixture(b"tty", b"tty-smoke", include_bytes!(env!("OXFS_TTY_SMOKE_ELF_PATH")));
    // sem_open across fork: a /dev/shm MAP_SHARED region at a different address in each process,
    // so the futex must key on the physical address (`process::limits::futex_key`).
    ok &= fixture(b"ipc", b"sem-open-smoke", include_bytes!(env!("OXFS_SEM_OPEN_SMOKE_ELF_PATH")));

    // Sample programs (hier(7): /usr/share/examples), which the clang, clang++ and ninja smokes
    // also build. hello.c prints rather than just returning, so it goes through musl's stdio.
    let examples = ensure_dir(ensure_dir(usr, b"share"), b"examples");
    let examples_clang = ensure_dir(examples, b"clang");
    ok &= seed_file(
        examples_clang,
        b"hello.c",
        b"#include <stdio.h>\nint main(void) {\n    printf(\"hello, OxideBSD\\n\");\n    return 0;\n}\n",
    );
    // The C++ counterpart: STL, exceptions/RTTI, std::thread, std::filesystem.
    ok &= seed_file(examples_clang, b"hello.cpp", include_bytes!("hello.cpp"));
    // A tiny ninja project: two `clang -c` jobs and a link.
    let examples_ninja = ensure_dir(examples, b"ninja");
    ok &= seed_file(examples_ninja, b"build.ninja", include_bytes!("ninja-demo/build.ninja"));
    ok &= seed_file(examples_ninja, b"main.c", include_bytes!("ninja-demo/main.c"));
    ok &= seed_file(examples_ninja, b"greet.c", include_bytes!("ninja-demo/greet.c"));
    // lib/libsh's differential corpus plus dash's output for each, for tests/sh_syscall_smoke.rs
    // (`run.sh <shell>` runs every script under that shell and compares).
    let sh_smoke = ensure_dir(usr_tests, b"sh");
    ok &= seed_file(sh_smoke, b"run.sh", include_bytes!("../../../../lib/libsh/tests/run-on-target.sh"));
    ok &= seed_file(sh_smoke, b"builtins.sh", include_bytes!("../../../../lib/libsh/tests/diff/builtins.sh"));
    ok &= seed_file(sh_smoke, b"builtins.expected", include_bytes!("../../../../lib/libsh/tests/diff/builtins.expected"));
    ok &= seed_file(sh_smoke, b"control.sh", include_bytes!("../../../../lib/libsh/tests/diff/control.sh"));
    ok &= seed_file(sh_smoke, b"control.expected", include_bytes!("../../../../lib/libsh/tests/diff/control.expected"));
    ok &= seed_file(sh_smoke, b"dot.sh", include_bytes!("../../../../lib/libsh/tests/diff/dot.sh"));
    ok &= seed_file(sh_smoke, b"dot.expected", include_bytes!("../../../../lib/libsh/tests/diff/dot.expected"));
    ok &= seed_file(sh_smoke, b"errexit.sh", include_bytes!("../../../../lib/libsh/tests/diff/errexit.sh"));
    ok &= seed_file(sh_smoke, b"errexit.expected", include_bytes!("../../../../lib/libsh/tests/diff/errexit.expected"));
    ok &= seed_file(sh_smoke, b"expand.sh", include_bytes!("../../../../lib/libsh/tests/diff/expand.sh"));
    ok &= seed_file(sh_smoke, b"expand.expected", include_bytes!("../../../../lib/libsh/tests/diff/expand.expected"));
    ok &= seed_file(sh_smoke, b"glob.sh", include_bytes!("../../../../lib/libsh/tests/diff/glob.sh"));
    ok &= seed_file(sh_smoke, b"glob.expected", include_bytes!("../../../../lib/libsh/tests/diff/glob.expected"));
    ok &= seed_file(sh_smoke, b"redirect.sh", include_bytes!("../../../../lib/libsh/tests/diff/redirect.sh"));
    ok &= seed_file(sh_smoke, b"redirect.expected", include_bytes!("../../../../lib/libsh/tests/diff/redirect.expected"));
    ok &= seed_file(sh_smoke, b"traps.sh", include_bytes!("../../../../lib/libsh/tests/diff/traps.sh"));
    ok &= seed_file(sh_smoke, b"traps.expected", include_bytes!("../../../../lib/libsh/tests/diff/traps.expected"));

    if !ok {
        log("[oxfs] self-check FAILED: seeding embedded files failed\n");
    }

    // --- Round-trip check: hello.txt/big.txt read back correctly. ---
    if let Some(hello) = self_check_fixture(b"hello.txt") {
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
    if let Some(big_inode) = self_check_fixture(b"big.txt") {
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
    if let Some(hello) = self_check_fixture(b"hello.txt") {
        let expected_size = read_inode(hello).size as i64;
        let path = b"/usr/tests/oxfs/hello.txt";
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
            sc_close(fd as u64);
        }
    } else {
        ok = false;
        log("[oxfs] self-check FAILED: hello.txt not found for stat check\n");
    }

    // --- getdents round trip, through the real registered handler. ---
    let gdtest = b"/gdtest";
    if oxfs_mkdir(gdtest.as_ptr() as u64, gdtest.len() as u64, 0o755, 0) != 0 {
        ok = false;
        log("[oxfs] self-check FAILED: mkdir /gdtest failed\n");
    } else {
        let mut seeded = true;
        for name in [&b"/gdtest/a"[..], &b"/gdtest/b"[..]] {
            let fd = oxfs_open(name.as_ptr() as u64, name.len() as u64, O_CREAT, 0);
            if fd < 0 {
                seeded = false;
            } else {
                sc_close(fd as u64);
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
            sc_close(dfd);
        }
    }

    // --- mkdir/chdir/open(O_CREAT)/write/close/read, through the real registered handlers. ---
    if oxfs_mkdir(b"sub".as_ptr() as u64, 3, 0o755, 0) != 0 {
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
            if sc_write(fd, content.as_ptr() as u64, content.len() as u64) != content.len() as i64
            {
                ok = false;
                log("[oxfs] self-check FAILED: write sub/in.txt failed\n");
            }
            sc_close(fd);

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
                let n = sc_read(fd, buf.as_mut_ptr() as u64, buf.len() as u64);
                sc_close(fd);
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
                    sc_close(fd as u64);
                }
            }

            // unlink /sub/renamed.txt, mkdir /sub/nested (multi-component mkdir), rmdir checks.
            if oxfs_unlink(new.as_ptr() as u64, new.len() as u64, 0, 0) != 0 {
                ok = false;
                log("[oxfs] self-check FAILED: unlink /sub/renamed.txt failed\n");
            }
            let nested = b"/sub/nested";
            if oxfs_mkdir(nested.as_ptr() as u64, nested.len() as u64, 0o755, 0) != 0 {
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
            if sc_write(fd, b"AAAAA".as_ptr() as u64, 5) != 5 {
                ok = false;
                log("[oxfs] self-check FAILED: write overwrite_test.txt (initial AAAAA) failed\n");
            }
            sc_close(fd);

            // Plain O_WRONLY on an existing path overwrites only what it writes; O_TRUNC
            // first empties the file.
            for (flags, want, what) in [
                (O_WRONLY, &b"BBAAA"[..], "[oxfs] self-check FAILED: O_WRONLY overwrite lost the file's tail\n"),
                (O_WRONLY | O_TRUNC, &b"BB"[..], "[oxfs] self-check FAILED: O_TRUNC overwrite did not truncate\n"),
            ] {
                let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, flags, 0);
                if fd < 0 {
                    ok = false;
                    log("[oxfs] self-check FAILED: O_WRONLY reopen of an existing file failed\n");
                    continue;
                }
                sc_write(fd as u64, b"BB".as_ptr() as u64, 2);
                sc_close(fd as u64);

                let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
                let mut buf = [0u8; 16];
                let n = sc_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                sc_close(fd as u64);
                if fd < 0 || n != want.len() as i64 || &buf[..want.len()] != want {
                    ok = false;
                    log(what);
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
                sc_write(fd, b"CC".as_ptr() as u64, 2);
                sc_close(fd);

                let fd = oxfs_open(path.as_ptr() as u64, path.len() as u64, 0, 0);
                let mut buf = [0u8; 16];
                let n = sc_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                sc_close(fd as u64);
                if fd < 0 || n != 4 || &buf[..4] != b"BBCC" {
                    ok = false;
                    log("[oxfs] self-check FAILED: O_APPEND did not preserve existing content\n");
                }
            }

            oxfs_unlink(path.as_ptr() as u64, path.len() as u64, 0, 0);
        }

        // Opening a real directory (not the "/" special case) for writing is a real EISDIR now.
        let dir_path = b"/writetest_dir";
        if oxfs_mkdir(dir_path.as_ptr() as u64, dir_path.len() as u64, 0o755, 0) != 0 {
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
        let n = sc_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
        sc_close(fd as u64);
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
            // Relative "" opens cwd, /proc itself: a directory, so read() is EISDIR.
            let empty = b"";
            let dfd = oxfs_open(empty.as_ptr() as u64, 0, 0, 0);
            if dfd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: relative open(\"\") inside /proc failed\n");
            } else {
                let mut buf = [0u8; 16];
                let n = sc_read(dfd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                sc_close(dfd as u64);
                if n != -EISDIR {
                    ok = false;
                    log("[oxfs] self-check FAILED: read() of the /proc directory isn't EISDIR\n");
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
                let rn = sc_read(rfd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64);
                let an = sc_read(afd as u64, abuf.as_mut_ptr() as u64, abuf.len() as u64);
                if rn != an || rbuf != abuf {
                    ok = false;
                    log("[oxfs] self-check FAILED: relative /proc/meminfo content mismatch\n");
                }
            }
            if rfd >= 0 {
                sc_close(rfd as u64);
            }
            if afd >= 0 {
                sc_close(afd as u64);
            }

            // EROFS guard: nothing can be created while cwd is inside /proc.
            let x = b"x";
            if oxfs_mkdir(x.as_ptr() as u64, x.len() as u64, 0o755, 0) != -EROFS {
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
            let real_path = b"usr/tests/oxfs/hello.txt";
            let real_fd = oxfs_open(real_path.as_ptr() as u64, real_path.len() as u64, 0, 0);
            if real_fd < 0 {
                ok = false;
                log("[oxfs] self-check FAILED: real open after leaving /proc failed\n");
            } else {
                sc_close(real_fd as u64);
            }
        }
    }

    // --- Real symlinks, through the real registered handlers (Part D). ---
    if let Some(hello) = self_check_fixture(b"hello.txt") {
        let target = b"/usr/tests/oxfs/hello.txt";
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
                let n = sc_read(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64);
                sc_close(fd as u64);
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
            if self_check_fixture(b"hello.txt").is_none() {
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
    if let Some(hello) = self_check_fixture(b"hello.txt") {
        let hello_size = read_inode(hello).size;
        let hello_name = b"/usr/tests/oxfs/hello.txt";
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
            if self_check_fixture(b"hello.txt").is_none() {
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
                let wrote = sc_write(fd as u64, payload.as_ptr() as u64, 1);
                let mut rbuf = [1u8; 8];
                let read = sc_read(fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64);
                sc_close(fd as u64);
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
        if oxfs_mkdir(dir_name.as_ptr() as u64, dir_name.len() as u64, 0o755, 0) != 0 {
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
    if let Some(hello) = self_check_fixture(b"hello.txt") {
        let path = b"/usr/tests/oxfs/hello.txt";
        let seeded_mode = read_inode(hello).mode;
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
        inode.mode = seeded_mode;
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
/// step and called by `sys/module.rs::load`). Decides between mounting an already-formatted disk
/// and formatting a fresh one (or running purely in-memory, if no data disk is attached at all --
/// see `src/ata.rs`), then performs the state every path needs regardless: resetting the boot-time
/// cwd and registering every syscall this module owns. Must never early-return before that tail --
/// skipping syscall registration on any path would silently ship a filesystem no process could
/// actually use.
#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // One system call at a time inside oxfs, even once a call sleeps for the disk: every call into
    // this module takes the kernel's filesystem lock (`OxideBSD-doc/RAM_FLOOR.md` §3.5.2).
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_module_serialize() };
    if !init_pools() {
        return -1;
    }
    // oxfs's own devices join the registry first: the format's self-check opens one.
    register_oxfs_devices();

    let has_disk = block_device_present();

    let mounted = has_disk && mount_from_disk();
    let ok = if mounted {
        true
    } else {
        // Lays the filesystem out over the whole disk (the memory disk, `md`, when there's no
        // real one) and forgets anything a failed mount left in the cache.
        reset_real_pool_for_fresh_format();
        // SAFETY: single-core, before any process exists (see `KERNEL_SEGMENT`).
        unsafe { *core::ptr::addr_of_mut!(KERNEL_SEGMENT) = true };
        let ok = format_fresh_filesystem();
        unsafe { *core::ptr::addr_of_mut!(KERNEL_SEGMENT) = false };
        if has_disk {
            // Freshly made, nothing half-written: clean, until a read-write mount says otherwise.
            set_clean(true);
            flush_all_to_disk();
        }
        ok
    };

    // Both the mount and the format-then-flush path above leave PERSISTENCE_READY false
    // throughout their own bulk work (see that flag's own doc comment) -- flipped here, once,
    // right before real syscalls become reachable, so every write a running process makes from
    // this point on is persisted immediately.
    set_persistence_ready(true);
    bcache::set_write_through(true);
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    let rdonly = unsafe { oxidebsd_root_readonly_at_boot() } != 0;
    set_root_rdonly(rdonly);
    if rdonly {
        log("[oxfs] root mounted read-only\n");
    } else {
        // Mounted: not clean on the disk until an orderly shutdown says so (§3.4.1).
        set_clean(false);
        write_superblock();
    }
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_register_shutdown_hook(oxfs_shutdown) };
    if mounted && !rdonly {
        sweep_unnamed_inodes();
    }
    // /dev (`DEVFS.md` §4.1): devfs over the disk's /dev, before any process runs.
    if !mount_devfs() {
        log("[oxfs] failed to mount devfs on /dev\n");
    }

    // Back to root, matching the state a booting kernel with no real process yet should leave
    // BOOT_CWD in (a real process's own cwd starts at Process::cwd's default, 0/root, regardless
    // of whatever format_fresh_filesystem's self-check did to BOOT_CWD -- see sys/process.rs's own
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
        oxidebsd_register_syscall(SYS_OPENAT, oxfs_openat);
        oxidebsd_register_syscall(SYS_MKDIRAT, oxfs_mkdirat);
        oxidebsd_register_syscall(SYS_MKNODAT, oxfs_mknodat);
        oxidebsd_register_syscall(SYS_FCHOWNAT, oxfs_fchownat);
        oxidebsd_register_syscall(SYS_NEWFSTATAT, oxfs_fstatat);
        oxidebsd_register_syscall(SYS_UNLINKAT, oxfs_unlinkat);
        oxidebsd_register_syscall(SYS_RENAMEAT, oxfs_renameat);
        oxidebsd_register_syscall(SYS_LINKAT, oxfs_linkat);
        oxidebsd_register_syscall(SYS_SYMLINKAT, oxfs_symlinkat);
        oxidebsd_register_syscall(SYS_READLINKAT, oxfs_readlinkat);
        oxidebsd_register_syscall(SYS_FCHMODAT, oxfs_fchmodat);
        oxidebsd_register_syscall(SYS_FACCESSAT, oxfs_faccessat);
        oxidebsd_register_syscall(SYS_UTIMENSAT_AT, oxfs_utimensat_at);
        oxidebsd_register_syscall(SYS_RENAMEAT2, oxfs_renameat2);
        oxidebsd_register_syscall(SYS_UMOUNT2, oxfs_umount2);
        oxidebsd_register_syscall(SYS_NMOUNT, oxfs_nmount);
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
            oxfs_inode_is_shm,
            oxfs_exec_setid,
        );
        oxidebsd_register_socket_nodes(oxfs_create_socket_node, oxfs_lookup_socket_node);
        oxidebsd_register_kernel_open(oxfs_kern_open);
    }

    if ok { 0 } else { -1 }
}
