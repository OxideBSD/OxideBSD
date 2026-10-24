//! The install itself (OxideBSD-doc `INSTALLER.md` §9.2-9.4), from a [`Config`]: what the
//! screens ask for and `installer -f` reads from a file.
//!
//! In order: the install medium is found and mounted on `/dist`, the chosen sets checked against
//! its `MANIFEST`; the disk gets its new table (and Limine's BIOS boot code, §8.4), each partition
//! its file system; they're mounted under `/mnt`, the sets extracted onto them, and the new
//! system's `fstab`, `rc.conf`, `wsconsctl.conf` and root's password written; the EFI system
//! partition gets Limine, the kernel, `limine.conf` and `fsconf`; the answer file's script runs in
//! the new system; everything is unmounted.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use part::{Kind, Scheme, Table};
use sha2::{Digest, Sha256};

use crate::config::{Config, Layout, PartSpec, guided_parts};

const DIOCGSECTORSIZE: u64 = 0x8004_6480;
const DIOCGMEDIASIZE: u64 = 0x8008_6481;
const DIOCRESCAN: u64 = 0x6482;

/// Where the install medium is mounted, and where the new system is.
const DIST: &str = "/dist";
const TARGET: &str = "/mnt";
/// The install medium's ISO 9660 volume label (`scripts/mkinstalliso.sh`).
const MEDIUM_LABEL: &str = "OXIDEBSD_INSTALL";

/// Runs `cmd` with `args`; its error output becomes the error.
fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
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

/// A disk, open for reading and writing its table.
struct Disk {
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
        let path = format!("/dev/{name}");
        let file = OpenOptions::new().read(true).write(true).open(&path).map_err(|e| format!("{path}: {e}"))?;
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

/// A partition as made: what it is, and its device node.
struct Made {
    spec: PartSpec,
    dev: String,
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

/// Lays `parts` out in a new table of `scheme` on `disk`, with Limine's BIOS boot code from
/// `bootcode`, and writes it.
fn partition(disk: &str, scheme: Scheme, parts: &[PartSpec], bootcode: &[u8]) -> Result<Vec<Made>, String> {
    let mut d = Disk::open(disk)?;
    let ss = d.sector_size as u64;
    let mut t = Table::new(scheme, d.sector_size, d.sectors, random_guid()).map_err(|e| format!("{disk}: {e}"))?;
    // Whole 4 KiB blocks, in the disk's sectors.
    let sectors_of = |bytes: u64| bytes.div_ceil(part::BLOCK_BYTES) * part::BLOCK_BYTES / ss;
    let align = part::ALIGN_BYTES / ss;
    let mut made = Vec::new();
    let mut swaps = 0;
    for (i, p) in parts.iter().enumerate() {
        if scheme == Scheme::Mbr && p.kind == Kind::BiosBoot {
            // MBR's boot code goes into the gap before the first partition instead.
            continue;
        }
        let sectors = match p.size {
            Some(b) => Some(sectors_of(b)),
            // `auto` before other partitions: what's left once they have theirs.
            None if i + 1 < parts.len() => {
                let free = t.free().into_iter().map(|(_, n)| n).max().unwrap_or(0);
                let later: u64 = parts[i + 1..].iter().filter_map(|q| q.size).map(|b| sectors_of(b).div_ceil(align) * align).sum();
                Some(free.checked_sub(later + align).filter(|&n| n > 0).ok_or(format!("{disk}: too small for the partitions"))? / (part::BLOCK_BYTES / ss) * (part::BLOCK_BYTES / ss))
            }
            None => None,
        };
        let label = if scheme == Scheme::Gpt { label_for(p, swaps) } else { String::new() };
        if p.kind == Kind::Swap {
            swaps += 1;
        }
        let code = p.kind.code(scheme).ok_or(format!("{}: not a type {} holds", p.kind.name(), scheme.name()))?;
        let guid = if scheme == Scheme::Gpt { random_guid() } else { [0; 16] };
        let index = t.add(code, &label, None, sectors, guid).map_err(|e| format!("{disk}: {e}"))?;
        let dev = match scheme {
            Scheme::Gpt if !label.is_empty() => format!("/dev/gpt/{label}"),
            Scheme::Gpt => format!("/dev/{disk}p{index}"),
            Scheme::Mbr => format!("/dev/{disk}s{index}"),
        };
        made.push(Made { spec: p.clone(), dev });
    }
    let stage2 = t.set_bios_bootcode(bootcode).map_err(|e| format!("{disk}: {e}"))?;
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

/// Limine's configuration on the EFI system partition: the kernel, with `fsconf` naming the root.
fn limine_conf() -> String {
    "timeout: 3\nserial: yes\n\n/OxideBSD\n    protocol: limine\n    kernel_path: boot():/boot/kernel\n    module_path: boot():/boot/fsconf\n".into()
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

    let (disk, scheme, parts) = match &cfg.layout {
        Layout::Explicit { disk, scheme, parts } => (disk.clone(), *scheme, parts.clone()),
        Layout::Guided(d) => (guided_disk(d.as_deref())?, Scheme::Gpt, guided_parts()),
    };
    say(&format!("Partitioning {disk}"));
    let made = partition(&disk, scheme, &parts, &bootcode)?;

    for m in &made {
        match m.spec.kind {
            Kind::Oxfs => {
                let label = m.dev.rsplit('/').next().unwrap_or("rootfs");
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

    if esp.is_some() {
        say("Installing the boot loader");
        let efi = PathBuf::from(format!("{TARGET}/boot/efi"));
        let copy = |from: PathBuf, to: PathBuf| -> Result<(), String> {
            if let Some(dir) = to.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::copy(&from, &to).map(|_| ()).map_err(|e| format!("{}: {e}", from.display()))
        };
        let medium = Path::new(DIST);
        for f in ["BOOTX64.EFI", "BOOTIA32.EFI"] {
            copy(medium.join("EFI/BOOT").join(f), efi.join("EFI/BOOT").join(f))?;
        }
        copy(boot.join("limine/limine-bios.sys"), efi.join("boot/limine/limine-bios.sys"))?;
        copy(boot.join("kernel"), efi.join("boot/kernel"))?;
        std::fs::write(efi.join("boot/limine/limine.conf"), limine_conf()).map_err(|e| format!("limine.conf: {e}"))?;
        let r = in_target("/usr/sbin/fsconf_mkdb").args(["-f", "/etc/fstab", "-o", "/boot/efi/boot/fsconf"]).status();
        status_ok("fsconf_mkdb", r)?;
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
        Made { spec: PartSpec { size: None, kind, mount: mount.map(str::to_string) }, dev: dev.into() }
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
