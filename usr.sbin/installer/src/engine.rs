//! The install itself (OxideBSD-doc `INSTALLER.md` §9.2-9.4), from a [`Config`]: what the
//! screens ask for and `installer -f` reads from a file.
//!
//! In order: the install medium is found and mounted on `/dist`, the chosen sets checked against
//! its `MANIFEST`; the disk gets its new table, or OxideBSD's partitions in the largest free space
//! of the one it has (§9.5), and Limine's BIOS boot code (§8.4); each new partition gets its file
//! system; they're mounted under `/mnt`, the sets extracted onto them, and the new system's
//! `fstab`, `rc.conf`, `wsconsctl.conf` and root's password written; the EFI system partition (a
//! new one, or the one the disk has) gets Limine and the kernel in `\EFI\OxideBSD`, a menu entry
//! in `/boot/limine/limine.conf` beside one for each other system found (`loaders`), and on UEFI
//! the firmware a boot entry (`efibootmgr`, §9.6); the answer file's script runs in the new
//! system; everything is unmounted.
//!
//! The new system names its partitions by GPT GUID (`/dev/gptid/<guid>`), which no other disk
//! shares: two systems both labelled `rootfs` would leave `/dev/gpt/rootfs` the first's.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use part::{Kind, Scheme, Table};
use sha2::{Digest, Sha256};

use crate::config::{Config, Guided, Layout, PartSpec, guided_parts};
use crate::loaders;

const DIOCGSECTORSIZE: u64 = 0x8004_6480;
const DIOCGMEDIASIZE: u64 = 0x8008_6481;
const DIOCRESCAN: u64 = 0x6482;

/// Where the install medium is mounted, and where the new system is.
const DIST: &str = "/dist";
const TARGET: &str = "/mnt";
/// The install medium's ISO 9660 volume label (`scripts/mkinstalliso.sh`).
const MEDIUM_LABEL: &str = "OXIDEBSD_INSTALL";

/// The smallest `/` the guided layout makes beside other systems: the base set takes about a
/// third of it.
const MIN_ROOT_BYTES: u64 = 1 << 30;

/// Runs `cmd` with `args`; its error output becomes the error.
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr);
    Err(format!("{cmd} {}: {}", args.join(" "), msg.trim()))
}

/// A `sysctl -n` value.
fn sysctl(name: &str) -> Option<String> {
    let out = Command::new("/sbin/sysctl").args(["-n", name]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The registered disks (`kern.disks`, INSTALLER.md §5.5) with their kinds: `disk` or `cd`.
pub fn disks() -> Vec<(String, String)> {
    let names = sysctl("kern.disks").unwrap_or_default();
    names
        .split_whitespace()
        .map(|d| (d.to_string(), sysctl(&format!("kern.disk.{d}.kind")).unwrap_or_default()))
        .collect()
}

/// A disk, open for reading (and writing) its table.
pub(crate) struct Disk {
    name: String,
    file: File,
    sector_size: u32,
    sectors: u64,
}

impl part::Disk for Disk {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.file.read_exact_at(buf, lba * self.sector_size as u64).is_ok()
    }
}

impl Disk {
    fn open(name: &str) -> Result<Disk, String> {
        Disk::open_with(name, true)
    }

    pub(crate) fn open_read(name: &str) -> Result<Disk, String> {
        Disk::open_with(name, false)
    }

    fn open_with(name: &str, write: bool) -> Result<Disk, String> {
        let path = format!("/dev/{name}");
        let file = OpenOptions::new().read(true).write(write).open(&path).map_err(|e| format!("{path}: {e}"))?;
        let mut ss: u32 = 0;
        let mut bytes: i64 = 0;
        // SAFETY: each request writes one value of the type passed.
        let ok = unsafe {
            libc::ioctl(file.as_raw_fd(), DIOCGSECTORSIZE as _, &mut ss) == 0
                && libc::ioctl(file.as_raw_fd(), DIOCGMEDIASIZE as _, &mut bytes) == 0
        };
        if !ok || !ss.is_power_of_two() || ss < 512 {
            return Err(format!("{path}: not a disk"));
        }
        Ok(Disk { name: name.to_string(), file, sector_size: ss, sectors: bytes as u64 / ss as u64 })
    }

    /// Writes `sectors` (`Table::write`'s), then has the kernel read the table again.
    fn write(&mut self, sectors: &[(u64, Vec<u8>)]) -> Result<(), String> {
        let io = |e: std::io::Error| format!("{}: {e}", self.name);
        for (lba, bytes) in sectors {
            self.file.write_all_at(bytes, lba * self.sector_size as u64).map_err(io)?;
        }
        self.file.sync_all().map_err(io)?;
        // SAFETY: a request with no argument.
        if unsafe { libc::ioctl(self.file.as_raw_fd(), DIOCRESCAN as _, 0) } < 0 {
            return Err(format!("{}: rereading its table: {}", self.name, std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

/// Sixteen random bytes, for a GUID.
fn random_guid() -> [u8; 16] {
    let mut g = [0u8; 16];
    if File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut g)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        g = part::guid_from(&t.as_nanos().to_le_bytes());
    }
    // RFC 4122 version 4, variant 1.
    g[7] = (g[7] & 0x0f) | 0x40;
    g[8] = (g[8] & 0x3f) | 0x80;
    g
}

/// A partition as made, or found and kept (an EFI system partition other systems use too).
struct Made {
    spec: PartSpec,
    dev: String,
    /// Its GPT name (`rootfs`), or empty.
    label: String,
    index: u32,
    /// Its GPT unique GUID; zero on MBR.
    guid: [u8; 16],
    /// Its size in bytes.
    bytes: u64,
    /// Already there: it keeps its file system.
    kept: bool,
}

/// A partition's GPT label: `rootfs` for `/`, the mount point's path (`usr`, `var-log`) for any
/// other, `efi`, `swap<N>`; the BIOS boot partition has none.
fn label_for(spec: &PartSpec, nth_swap: usize) -> String {
    match (spec.kind, spec.mount.as_deref()) {
        (Kind::Oxfs, Some("/")) => "rootfs".into(),
        (Kind::Oxfs, Some(m)) => m.trim_matches('/').replace('/', "-"),
        (Kind::Efi, _) => "efi".into(),
        (Kind::Swap, _) => format!("swap{nth_swap}"),
        _ => String::new(),
    }
}

/// The node the new system names partition `index` of `disk` by: its GUID's on GPT.
fn dev_for(disk: &str, scheme: Scheme, index: u32, guid: &[u8; 16]) -> String {
    match scheme {
        Scheme::Gpt => format!("/dev/gptid/{}", part::guid_string(guid).to_ascii_lowercase()),
        Scheme::Mbr => format!("/dev/{disk}s{index}"),
    }
}

/// What goes on the disk.
enum Plan {
    /// A new table of this scheme, with these partitions, over whatever the disk held.
    New(Scheme, Vec<PartSpec>),
    /// The guided layout in the largest free space of the disk's table, all of it kept.
    Beside,
}

/// The guided layout beside the systems in `t`: OxideBSD's own BIOS boot partition (on GPT; on
/// MBR the boot code goes into the gap before the first partition), an EFI system partition only
/// if the disk has none, and `/` over the rest.
fn beside_parts(t: &Table) -> Vec<PartSpec> {
    let mut parts = guided_parts();
    if t.entries.iter().any(|e| e.kind() == Kind::Efi) {
        parts.retain(|p| p.kind != Kind::Efi);
    }
    parts
}

/// Adds `parts` to `t` one after another in its free space `(start, sectors)`, each on a 1 MiB
/// boundary, of whole 4 KiB blocks; `auto` takes what the ones after it leave.
fn lay_out(t: &mut Table, disk: &str, parts: &[PartSpec], (start, len): (u64, u64)) -> Result<Vec<Made>, String> {
    let scheme = t.scheme;
    let ss = t.sector_size as u64;
    let block = part::BLOCK_BYTES / ss;
    let align = part::ALIGN_BYTES / ss;
    let up = |n: u64| n.div_ceil(align) * align;
    let sectors_of = |bytes: u64| bytes.div_ceil(part::BLOCK_BYTES) * block;
    // MBR's boot code goes into the gap before the first partition instead.
    let parts: Vec<&PartSpec> = parts.iter().filter(|p| !(scheme == Scheme::Mbr && p.kind == Kind::BiosBoot)).collect();
    let end = start + len;
    let mut at = start;
    let mut made = Vec::new();
    let mut swaps = 0;
    for (i, p) in parts.iter().enumerate() {
        let first = up(at);
        let sectors = match p.size {
            Some(b) => sectors_of(b),
            None => {
                let later: u64 = parts[i + 1..].iter().filter_map(|q| q.size).map(|b| up(sectors_of(b))).sum();
                let room = end.saturating_sub(first + later);
                // Ending on a boundary for the later ones, or on a block.
                if i + 1 < parts.len() { room / align * align } else { room / block * block }
            }
        };
        if sectors == 0 || first + sectors > end {
            return Err(format!("{disk}: too small for the partitions"));
        }
        let label = if scheme == Scheme::Gpt { label_for(p, swaps) } else { String::new() };
        if p.kind == Kind::Swap {
            swaps += 1;
        }
        let code = p.kind.code(scheme).ok_or(format!("{}: not a type {} holds", p.kind.name(), scheme.name()))?;
        let guid = if scheme == Scheme::Gpt { random_guid() } else { [0; 16] };
        let index = t.add(code, &label, Some(first), Some(sectors), guid).map_err(|e| format!("{disk}: {e}"))?;
        let dev = dev_for(disk, scheme, index, &guid);
        made.push(Made { spec: (*p).clone(), dev, label, index, guid, bytes: sectors * ss, kept: false });
        at = first + sectors;
    }
    Ok(made)
}

/// Lays the disk out as `plan` says, with Limine's BIOS boot code from `bootcode`, and writes it:
/// the partitions OxideBSD uses, the EFI system partition among them.
fn partition(disk: &str, plan: Plan, bootcode: &[u8]) -> Result<Vec<Made>, String> {
    let mut d = Disk::open(disk)?;
    let beside = matches!(plan, Plan::Beside);
    let (mut t, parts, mut made) = match plan {
        Plan::New(scheme, parts) => {
            let t = Table::new(scheme, d.sector_size, d.sectors, random_guid()).map_err(|e| format!("{disk}: {e}"))?;
            (t, parts, Vec::new())
        }
        Plan::Beside => {
            let t = part::read(&mut d)
                .map_err(|_| format!("{disk}: its partition table can't be read"))?
                .ok_or(format!("{disk}: no partition table to install beside"))?;
            let parts = beside_parts(&t);
            let esp = t.entries.iter().find(|e| e.kind() == Kind::Efi).map(|e| Made {
                spec: PartSpec { size: None, kind: Kind::Efi, mount: None },
                dev: dev_for(disk, t.scheme, e.index, &e.guid),
                label: e.label.clone(),
                index: e.index,
                guid: e.guid,
                bytes: e.sectors * t.sector_size as u64,
                kept: true,
            });
            (t, parts, esp.into_iter().collect())
        }
    };
    let free = t.free().into_iter().max_by_key(|&(_, n)| n).ok_or(format!("{disk}: no free space"))?;
    let new = lay_out(&mut t, disk, &parts, free)?;
    if let Some(root) = new.iter().find(|m| m.spec.mount.as_deref() == Some("/")).filter(|_| beside) {
        if root.bytes < MIN_ROOT_BYTES {
            return Err(format!(
                "{disk}: {} MiB free beside the other systems; OxideBSD needs {} MiB",
                free.1 * t.sector_size as u64 >> 20,
                MIN_ROOT_BYTES >> 20
            ));
        }
    }
    let bios = new.iter().find(|m| m.spec.kind == Kind::BiosBoot).map(|m| m.index);
    made.extend(new);
    let stage2 = t.set_bios_bootcode_in(bootcode, bios).map_err(|e| format!("{disk}: {e}"))?;
    let mut sectors = t.write();
    sectors.push(stage2);
    d.write(&sectors)?;
    drop(d);
    for m in &made {
        if m.spec.kind != Kind::BiosBoot && !Path::new(&m.dev).exists() {
            return Err(format!("{}: the kernel didn't make it", m.dev));
        }
    }
    Ok(made)
}

/// The ISO 9660 volume label of `dev`, from its primary volume descriptor (sector 16).
fn volume_label(dev: &str) -> Option<String> {
    let f = File::open(dev).ok()?;
    let mut pvd = [0u8; 2048];
    f.read_exact_at(&mut pvd, 16 * 2048).ok()?;
    (pvd[0] == 1 && &pvd[1..6] == b"CD001").then(|| String::from_utf8_lossy(&pvd[40..72]).trim_end().to_string())
}

/// Finds the install medium among the optical drives by its label and mounts it on `/dist`, read
/// only; the directory holding its sets.
fn mount_medium() -> Result<PathBuf, String> {
    let top = Path::new(DIST).join("OxideBSD");
    if !top.exists() {
        let cd = disks()
            .into_iter()
            .filter(|(_, kind)| kind == "cd")
            .find(|(d, _)| volume_label(&format!("/dev/{d}")).as_deref() == Some(MEDIUM_LABEL))
            .ok_or(format!("no install medium: no CD labelled {MEDIUM_LABEL}"))?;
        std::fs::create_dir_all(DIST).map_err(|e| format!("{DIST}: {e}"))?;
        run("/sbin/mount", &["-r", "-t", "cd9660", &format!("/dev/{}", cd.0), DIST])?;
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&top)
        .map_err(|e| format!("{}: {e}", top.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("MANIFEST").is_file())
        .collect();
    dirs.sort();
    dirs.pop().ok_or(format!("{}: no sets", top.display()))
}

/// The SHA-256 of file `path`, in hex.
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Checks each of `sets` against the medium's `MANIFEST` (FreeBSD's: name, SHA-256, files,
/// distribution, description, default, tab-separated).
fn check_sets(dir: &Path, sets: &[String], say: &mut dyn FnMut(&str)) -> Result<(), String> {
    let manifest = std::fs::read_to_string(dir.join("MANIFEST")).map_err(|e| format!("MANIFEST: {e}"))?;
    for set in sets {
        let want = manifest
            .lines()
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .find(|f| f.first() == Some(&set.as_str()))
            .and_then(|f| f.get(1).map(|s| s.to_string()))
            .ok_or(format!("{set}: not on the install medium"))?;
        say(&format!("Checking {set}"));
        if sha256_file(&dir.join(set))? != want {
            return Err(format!("{set}: damaged (its SHA-256 isn't MANIFEST's)"));
        }
    }
    Ok(())
}

/// The new system's `/etc/fstab`: its partitions' lines in place of the base set's `/` line,
/// whose comments and other lines are kept.
fn fstab(base: &str, made: &[Made]) -> String {
    let mut ours = String::new();
    let mut by_depth: Vec<&Made> = made.iter().filter(|m| m.spec.mount.is_some()).collect();
    by_depth.sort_by_key(|m| m.spec.mount.as_deref().map_or(0, |p| p.matches('/').count() + (p != "/") as usize));
    for m in by_depth {
        let mount = m.spec.mount.as_deref().unwrap_or("/");
        let pass = if mount == "/" { 1 } else { 2 };
        ours.push_str(&format!("{}\t{mount}\t\toxfs\trw\t\t1\t{pass}\n", m.dev));
    }
    for m in made.iter().filter(|m| m.spec.kind == Kind::Efi) {
        ours.push_str(&format!("{}\t/boot/efi\tmsdosfs\trw\t\t2\t2\n", m.dev));
    }
    for m in made.iter().filter(|m| m.spec.kind == Kind::Swap) {
        ours.push_str(&format!("{}\tnone\t\tswap\tsw\t\t0\t0\n", m.dev));
    }
    let mut out = String::new();
    let mut placed = false;
    for line in base.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let entry = !line.trim_start().starts_with('#') && fields.len() >= 2;
        if entry && !placed {
            out.push_str(&ours);
            placed = true;
        }
        if entry && fields[1] == "/" {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !placed {
        out.push_str(&ours);
    }
    out
}

/// `rc.conf` with `hostname` set.
fn set_hostname(rc_conf: &str, name: &str) -> String {
    let line = format!("hostname=\"{name}\"");
    let mut found = false;
    let mut out: Vec<String> = rc_conf
        .lines()
        .map(|l| {
            if l.starts_with("hostname=") {
                found = true;
                line.clone()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        out.push(line);
    }
    out.join("\n") + "\n"
}

/// Where on the EFI system partition this install's kernel and `fsconf` go: a directory of its own
/// under `\EFI\OxideBSD`, named by its root's GUID, so another OxideBSD can share the partition.
fn system_dir(root: &Made) -> String {
    let id = if root.guid == [0; 16] { random_guid() } else { root.guid };
    format!("EFI/OxideBSD/{}", &part::guid_string(&id).to_ascii_lowercase()[..8])
}

/// The menu entry for this system, `title`, its files in `dir` of the EFI system partition.
fn limine_entry(title: &str, dir: &str) -> String {
    format!("/{title}\n    protocol: limine\n    kernel_path: boot():/{dir}/kernel\n    module_path: boot():/{dir}/fsconf\n")
}

/// `/boot/limine/limine.conf`, which every Limine on the partition reads (`\EFI\OxideBSD`'s, the
/// removable fallback's, BIOS's): `old`, if there is one, with this system's entry and each of
/// `others` it hasn't got added at its end (none removed), else a new one, this system first.
fn limine_conf(old: Option<&str>, name: &str, dir: &str, others: &[loaders::Loader]) -> String {
    let mut conf = match old {
        Some(o) => {
            let mut c = o.to_string();
            if !c.ends_with('\n') {
                c.push('\n');
            }
            c + "\n" + &limine_entry(&format!("OxideBSD ({name})"), dir)
        }
        None => format!("timeout: 3\nserial: yes\n\n{}", limine_entry("OxideBSD", dir)),
    };
    for l in others {
        if !l.listed_in(&conf) {
            conf += "\n";
            conf += &l.conf();
        }
    }
    conf
}

/// A command run inside the new system (`chroot` to `/mnt`).
fn in_target(cmd: &str) -> Command {
    let mut c = Command::new(cmd);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        c.pre_exec(|| {
            let root = b"/mnt\0";
            if libc::chroot(root.as_ptr().cast()) != 0 || libc::chdir(b"/\0".as_ptr().cast()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

fn status_ok(cmd: &str, r: std::io::Result<std::process::ExitStatus>) -> Result<(), String> {
    match r {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("{cmd}: {s}")),
        Err(e) => Err(format!("{cmd}: {e}")),
    }
}

/// The disk the guided layout uses: `disk`, or the first one that isn't an optical drive.
fn guided_disk(disk: Option<&str>) -> Result<String, String> {
    if let Some(d) = disk {
        return Ok(d.to_string());
    }
    disks().into_iter().find(|(_, k)| k == "disk").map(|(d, _)| d).ok_or("no disk to install on".into())
}

/// What is mounted, to unmount in reverse at the end or on a failure.
struct Mounts(Vec<String>);

impl Mounts {
    fn mount(&mut self, args: &[&str], on: &str) -> Result<(), String> {
        std::fs::create_dir_all(on).map_err(|e| format!("{on}: {e}"))?;
        let mut all = args.to_vec();
        all.push(on);
        run("/sbin/mount", &all)?;
        self.0.push(on.to_string());
        Ok(())
    }

    fn unmount_all(&mut self) -> Result<(), String> {
        let mut first = Ok(());
        while let Some(on) = self.0.pop() {
            if let Err(e) = run("/sbin/umount", &[&on]) {
                first = first.and(Err(e));
            }
        }
        first
    }
}

impl Drop for Mounts {
    fn drop(&mut self) {
        let _ = self.unmount_all();
    }
}

/// Installs the system as `cfg` says; `say` hears each step.
pub fn install(cfg: &Config, say: &mut dyn FnMut(&str)) -> Result<(), String> {
    say("Looking for the install medium");
    let sets_dir = mount_medium()?;
    check_sets(&sets_dir, &cfg.sets, say)?;
    let boot = Path::new(DIST).join("boot");
    let bootcode = std::fs::read(boot.join("limine/limine-bios-hdd.bin")).map_err(|e| format!("limine-bios-hdd.bin: {e}"))?;

    let (disk, plan) = match &cfg.layout {
        Layout::Explicit { disk, scheme, parts } => (disk.clone(), Plan::New(*scheme, parts.clone())),
        Layout::Guided { disk, how } => {
            let disk = guided_disk(disk.as_deref())?;
            let beside = match how {
                Guided::Whole => false,
                Guided::Beside => true,
                // A table that can't be read is not a blank disk.
                Guided::Auto => part::read(&mut Disk::open_read(&disk)?)
                    .map_err(|_| format!("{disk}: its partition table can't be read"))?
                    .is_some(),
            };
            (disk, if beside { Plan::Beside } else { Plan::New(Scheme::Gpt, guided_parts()) })
        }
    };
    say(&format!("Partitioning {disk}"));
    let made = partition(&disk, plan, &bootcode)?;

    for m in made.iter().filter(|m| !m.kept) {
        match m.spec.kind {
            Kind::Oxfs => {
                let label = if m.label.is_empty() { "rootfs" } else { &m.label };
                say(&format!("Making an oxfs file system on {}", m.dev));
                run("/sbin/newfs_oxfs", &["-L", label, &m.dev])?;
            }
            Kind::Efi => {
                say(&format!("Making the EFI system partition's FAT32 on {}", m.dev));
                run("/sbin/newfs_msdos", &["-F", "32", "-L", "EFISYS", &m.dev])?;
            }
            _ => {}
        }
    }

    let mut mounts = Mounts(Vec::new());
    let mut oxfs: Vec<&Made> = made.iter().filter(|m| m.spec.mount.is_some()).collect();
    oxfs.sort_by_key(|m| m.spec.mount.clone());
    for m in &oxfs {
        let on = format!("{TARGET}{}", m.spec.mount.as_deref().unwrap_or("/"));
        mounts.mount(&["-t", "oxfs", &m.dev], on.trim_end_matches('/'))?;
    }
    for set in &cfg.sets {
        say(&format!("Extracting {set}"));
        run("/bin/tar", &["-xpf", &sets_dir.join(set).to_string_lossy(), "-C", TARGET])?;
    }
    let esp = made.iter().find(|m| m.spec.kind == Kind::Efi);
    if let Some(e) = esp {
        // A kept partition must be FAT already: msdosfs refuses anything else.
        mounts.mount(&["-t", "msdosfs", &e.dev], &format!("{TARGET}/boot/efi"))?;
    }

    say("Writing the new system's settings");
    let etc = Path::new(TARGET).join("etc");
    let rd = |f: &str| std::fs::read_to_string(etc.join(f)).map_err(|e| format!("/etc/{f}: {e}"));
    let wr = |f: &str, s: &str| std::fs::write(etc.join(f), s).map_err(|e| format!("/etc/{f}: {e}"));
    wr("fstab", &fstab(&rd("fstab")?, &made))?;
    if let Some(h) = &cfg.hostname {
        wr("rc.conf", &set_hostname(&rd("rc.conf")?, h))?;
    }
    if let Some(k) = &cfg.keymap {
        wr("wsconsctl.conf", &format!("{}keyboard.encoding={k}\n", rd("wsconsctl.conf")?))?;
    }
    if let Some(p) = &cfg.rootpass {
        let mut c = in_target("/usr/sbin/pw");
        c.args(["usermod", "root", "-h", "0"]).stdin(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("pw: {e}"))?;
        if let Some(mut i) = child.stdin.take() {
            let _ = writeln!(i, "{p}");
        }
        status_ok("pw usermod root", child.wait())?;
    }

    if let Some(esp) = esp {
        say("Installing the boot loader");
        let efi = PathBuf::from(format!("{TARGET}/boot/efi"));
        let copy = |from: PathBuf, to: PathBuf| -> Result<(), String> {
            if let Some(dir) = to.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::copy(&from, &to).map(|_| ()).map_err(|e| format!("{}: {e}", from.display()))
        };
        let medium = Path::new(DIST);
        let root = made.iter().find(|m| m.spec.mount.as_deref() == Some("/")).ok_or("no / partition")?;
        let dir = system_dir(root);
        copy(medium.join("EFI/BOOT/BOOTX64.EFI"), efi.join("EFI/OxideBSD/BOOTX64.EFI"))?;
        // The removable fallback, which firmware with no boot entries runs, only if no system has
        // taken it.
        if !efi.join("EFI/BOOT/BOOTX64.EFI").exists() {
            for f in ["BOOTX64.EFI", "BOOTIA32.EFI"] {
                copy(medium.join("EFI/BOOT").join(f), efi.join("EFI/BOOT").join(f))?;
            }
        }
        // BIOS: the boot code written above is this Limine's, so its stage 3 is too.
        copy(boot.join("limine/limine-bios.sys"), efi.join("boot/limine/limine-bios.sys"))?;
        copy(boot.join("kernel"), efi.join(&dir).join("kernel"))?;
        let r = in_target("/usr/sbin/fsconf_mkdb").args(["-f", "/etc/fstab", "-o", &format!("/boot/efi/{dir}/fsconf")]).status();
        status_ok("fsconf_mkdb", r)?;

        say("Looking for other systems");
        let others = loaders::scan(Some((&esp.guid, &efi)));
        let conf_path = efi.join("boot/limine/limine.conf");
        let old = std::fs::read_to_string(&conf_path).ok();
        let name = cfg.hostname.clone().unwrap_or_else(|| dir.rsplit('/').next().unwrap_or("").to_string());
        let conf = limine_conf(old.as_deref(), &name, &dir, &others);
        std::fs::write(&conf_path, conf).map_err(|e| format!("limine.conf: {e}"))?;
        for l in &others {
            say(&format!("Boot menu: {}", l.title));
        }

        // UEFI: the firmware's own entry, first in its order (EFIRT.md).
        if Path::new("/dev/efi").exists() {
            say("Adding the firmware's boot entry");
            let loader = efi.join("EFI/OxideBSD/BOOTX64.EFI");
            run("/usr/sbin/efibootmgr", &["-c", "-a", "-l", &loader.to_string_lossy(), "-L", "OxideBSD"])?;
        }
    }

    if let Some(script) = &cfg.script {
        say("Running the answer file's script in the new system");
        let path = Path::new(TARGET).join("tmp/installerconfig.script");
        std::fs::write(&path, script).map_err(|e| format!("{}: {e}", path.display()))?;
        let r = in_target("/bin/sh").arg("/tmp/installerconfig.script").status();
        let _ = std::fs::remove_file(&path);
        status_ok("the answer file's script", r)?;
    }

    say("Unmounting");
    mounts.unmount_all()?;
    let _ = run("/bin/sync", &[]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn made(kind: Kind, mount: Option<&str>, dev: &str) -> Made {
        let spec = PartSpec { size: None, kind, mount: mount.map(str::to_string) };
        Made { spec, dev: dev.into(), label: String::new(), index: 1, guid: [0; 16], bytes: 0, kept: false }
    }

    #[test]
    fn fstab_replaces_the_root_line() {
        let base = "# header\n#\n/dev/gpt/rootfs\t/\toxfs\trw\t1\t1\ntmpfs\t/dev/shm\ttmpfs\trw\t0\t0\n# tail\n";
        let m = [
            made(Kind::Oxfs, Some("/usr"), "/dev/gpt/usr"),
            made(Kind::Oxfs, Some("/"), "/dev/gpt/rootfs"),
            made(Kind::Efi, None, "/dev/gpt/efi"),
            made(Kind::Swap, None, "/dev/gpt/swap0"),
        ];
        let f = fstab(base, &m);
        let lines: Vec<&str> = f.lines().collect();
        assert_eq!(lines[0], "# header");
        assert!(lines[2].starts_with("/dev/gpt/rootfs\t/\t"));
        assert!(lines[3].starts_with("/dev/gpt/usr\t/usr\t"));
        assert!(lines[4].starts_with("/dev/gpt/efi\t/boot/efi\tmsdosfs"));
        assert!(lines[5].starts_with("/dev/gpt/swap0\tnone\t\tswap"));
        assert!(lines[6].starts_with("tmpfs"));
        assert_eq!(f.matches("\t/\t").count(), 1);
    }

    #[test]
    fn layouts() {
        let gib = (1u64 << 30) / 512;
        // A blank 4 GiB disk: bios, efi, / over the rest, on 1 MiB boundaries.
        let mut t = Table::new(Scheme::Gpt, 512, 4 * gib, [1; 16]).unwrap();
        let free = t.free()[0];
        let m = lay_out(&mut t, "d", &guided_parts(), free).unwrap();
        let firsts: Vec<u64> = t.entries.iter().map(|e| e.first).collect();
        assert_eq!(firsts, [2048, 4096, 4096 + (260 << 11)]);
        assert_eq!(m.iter().map(|m| m.spec.kind).collect::<Vec<_>>(), [Kind::BiosBoot, Kind::Efi, Kind::Oxfs]);
        assert!(m[2].dev.starts_with("/dev/gptid/") && m[2].label == "rootfs");
        assert_eq!(t.entries[2].end(), (t.last_usable + 1) / 8 * 8);

        // Beside: an ESP and another system's partition kept; the new ones in the larger gap.
        let mut t = Table::new(Scheme::Gpt, 512, 8 * gib, [1; 16]).unwrap();
        let esp = t.add(Kind::Efi.code(Scheme::Gpt).unwrap(), "EFI system partition", None, Some(100 << 11), [2; 16]).unwrap();
        t.add(Kind::MsBasicData.code(Scheme::Gpt).unwrap(), "C", Some(2 * gib), Some(gib), [3; 16]).unwrap();
        let before = t.entries.clone();
        let parts = beside_parts(&t);
        assert_eq!(parts.iter().map(|p| p.kind).collect::<Vec<_>>(), [Kind::BiosBoot, Kind::Oxfs]);
        let free = t.free().into_iter().max_by_key(|&(_, n)| n).unwrap();
        assert_eq!(free.0, 3 * gib);
        let m = lay_out(&mut t, "d", &parts, free).unwrap();
        assert_eq!(&t.entries[..2], &before[..]);
        assert!(m.iter().all(|m| t.entry(m.index).unwrap().first >= 3 * gib));
        assert!(m.iter().all(|m| m.index != esp));
    }

    #[test]
    fn limine_confs() {
        let win = loaders::Loader { title: "Windows Boot Manager".into(), lines: vec!["protocol: efi".into(), "path: guid(x):/EFI/Microsoft/Boot/bootmgfw.efi".into()] };
        let new = limine_conf(None, "oxide", "EFI/OxideBSD/0123abcd", std::slice::from_ref(&win));
        assert!(new.starts_with("timeout: 3\nserial: yes\n\n/OxideBSD\n    protocol: limine\n    kernel_path: boot():/EFI/OxideBSD/0123abcd/kernel\n"));
        assert!(new.ends_with("\n/Windows Boot Manager\n    protocol: efi\n    path: guid(x):/EFI/Microsoft/Boot/bootmgfw.efi\n"));
        // Another system's conf: kept whole, this system added, Windows not twice.
        let again = limine_conf(Some(&new), "second", "EFI/OxideBSD/89abcdef", &[win]);
        assert!(again.starts_with(&new));
        assert_eq!(again.matches("bootmgfw").count(), 1);
        assert!(again.contains("/OxideBSD (second)\n    protocol: limine\n    kernel_path: boot():/EFI/OxideBSD/89abcdef/kernel"));
    }

    #[test]
    fn hostname_and_labels() {
        assert_eq!(set_hostname("a=1\nhostname=\"x\"\n", "oxide"), "a=1\nhostname=\"oxide\"\n");
        assert_eq!(set_hostname("a=1\n", "oxide"), "a=1\nhostname=\"oxide\"\n");
        let p = |kind, mount: Option<&str>| PartSpec { size: None, kind, mount: mount.map(str::to_string) };
        assert_eq!(label_for(&p(Kind::Oxfs, Some("/")), 0), "rootfs");
        assert_eq!(label_for(&p(Kind::Oxfs, Some("/var/log")), 0), "var-log");
        assert_eq!(label_for(&p(Kind::Swap, None), 1), "swap1");
        assert_eq!(label_for(&p(Kind::BiosBoot, None), 0), "");
    }
}
