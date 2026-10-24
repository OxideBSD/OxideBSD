//! The other systems' boot loaders (OxideBSD-doc `INSTALLER.md` §9.6), found for Limine's menu to
//! chainload. On UEFI: every EFI system partition of every disk is looked through, each
//! `\EFI\<dir>` but the removable fallback `\EFI\BOOT` (a copy of some other loader) and, on the
//! partition OxideBSD is installed on, OxideBSD's own giving at most one entry -- Windows'
//! `bootmgfw.efi`, shim before GRUB, systemd-boot, another Limine (a loader that reads a
//! `limine.conf`), else the directory's first `.efi`. On BIOS: each MBR disk's active partitions,
//! and each GPT disk's FreeBSD boot partitions (Limine stands in for FreeBSD's `pmbr`).
//!
//! An entry names its partition by GPT GUID (`guid(...)`, MBR disks by their signature), never by
//! drive number: the firmware's order isn't this system's.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use part::{Kind, Scheme, TypeCode};

use crate::engine::{Disk, disks, run};

/// FreeBSD's `freebsd-boot` partition type, `gptboot`'s home.
const FREEBSD_BOOT_GUID: &str = "83BD6B9D-7F41-11DC-BE0B-001560B84F0F";

/// One menu entry: its title and its lines after the title's.
#[derive(Clone, Debug, PartialEq)]
pub struct Loader {
    pub title: String,
    pub lines: Vec<String>,
}

impl Loader {
    /// The entry as `limine.conf` holds it.
    pub fn conf(&self) -> String {
        let mut s = format!("/{}\n", self.title);
        for l in &self.lines {
            s += &format!("    {l}\n");
        }
        s
    }

    /// Whether `conf` (an existing `limine.conf`) has this loader already: its path, or its
    /// partition.
    pub fn listed_in(&self, conf: &str) -> bool {
        let conf = conf.to_ascii_lowercase();
        let key: Vec<String> = self.lines.iter().filter(|l| !l.starts_with("protocol:")).map(|l| l.to_ascii_lowercase()).collect();
        let lines: Vec<String> = conf.lines().map(|l| l.trim().to_string()).collect();
        key.iter().all(|k| lines.contains(k))
    }
}

/// `Loader`'s guess for directory `dir` (its stored name) of an EFI system partition, holding
/// `files` (their stored names); `limine` says whether a file is a Limine.
fn efi_loader(dir: &str, files: &[String], limine: &dyn Fn(&str) -> bool) -> Option<(String, String)> {
    let has = |name: &str| files.iter().find(|f| f.eq_ignore_ascii_case(name)).cloned();
    if dir.eq_ignore_ascii_case("Microsoft") {
        return files
            .iter()
            .find(|f| f.eq_ignore_ascii_case("Boot"))
            .map(|b| ("Windows Boot Manager".to_string(), format!("{b}/bootmgfw.efi")));
    }
    if let Some(f) = has("systemd-bootx64.efi") {
        return Some(("systemd-boot".into(), f));
    }
    if let Some(f) = has("shimx64.efi").or_else(|| has("grubx64.efi")) {
        return Some((format!("{dir} (GRUB)"), f));
    }
    let mut efis: Vec<&String> = files.iter().filter(|f| f.to_ascii_lowercase().ends_with(".efi")).collect();
    efis.sort_by_key(|f| (!f.to_ascii_lowercase().contains("x64"), f.to_ascii_lowercase()));
    if let Some(f) = efis.iter().find(|f| limine(f)) {
        return Some((format!("Limine ({dir})"), f.to_string()));
    }
    efis.first().map(|f| (dir.to_string(), f.to_string()))
}

/// The names in directory `dir`, as stored.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|r| r.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// Whether file `path` is a Limine: its text names the configuration it reads.
fn is_limine(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|b| b.windows(11).any(|w| w == b"limine.conf"))
}

/// The loaders on the EFI system partition mounted on `top`, GPT partition GUID `guid`; `skip`
/// names a directory to leave out (OxideBSD's own).
fn scan_esp(top: &Path, guid: &[u8; 16], skip: Option<&str>) -> Vec<Loader> {
    let Some(efi) = names(top).into_iter().find(|n| n.eq_ignore_ascii_case("EFI")) else { return Vec::new() };
    let efi = top.join(efi);
    let id = part::guid_string(guid).to_ascii_lowercase();
    let mut out = Vec::new();
    for dir in names(&efi) {
        if dir.eq_ignore_ascii_case("BOOT") || skip.is_some_and(|s| dir.eq_ignore_ascii_case(s)) || !efi.join(&dir).is_dir() {
            continue;
        }
        let files = names(&efi.join(&dir));
        let here = efi.join(&dir);
        let Some((title, file)) = efi_loader(&dir, &files, &|f| is_limine(&here.join(f))) else { continue };
        if !efi.join(&dir).join(&file).is_file() {
            continue;
        }
        let path = format!("guid({id}):/{}/{dir}/{file}", efi.file_name().unwrap_or_default().to_string_lossy());
        out.push(Loader { title, lines: vec!["protocol: efi".into(), format!("path: {path}")] });
    }
    out
}

/// A disk's table, read through its raw node.
fn table(name: &str) -> Option<part::Table> {
    let mut d = Disk::open_read(name).ok()?;
    part::read(&mut d).ok().flatten()
}

/// Every loader on this machine's disks but OxideBSD's own: `target_esp` is the EFI system
/// partition the new system boots from (its GUID, and where it's mounted), whose `\EFI\OxideBSD`
/// is left out.
pub fn scan(target_esp: Option<(&[u8; 16], &Path)>) -> Vec<Loader> {
    let mut out = Vec::new();
    let mut n = 0;
    for (name, kind) in disks() {
        if kind != "disk" {
            continue;
        }
        let Some(t) = table(&name) else { continue };
        for e in &t.entries {
            match (t.scheme, e.kind()) {
                (Scheme::Gpt, Kind::Efi) => {
                    if let Some((guid, on)) = target_esp.filter(|(g, _)| **g == e.guid) {
                        out.extend(scan_esp(on, guid, Some("OxideBSD")));
                        continue;
                    }
                    let on = format!("/tmp/esp{n}");
                    n += 1;
                    let _ = std::fs::create_dir_all(&on);
                    if run("/sbin/mount", &["-r", "-t", "msdosfs", &format!("/dev/{name}p{}", e.index), &on]).is_ok() {
                        out.extend(scan_esp(Path::new(&on), &e.guid, None));
                        let _ = run("/sbin/umount", &[&on]);
                    }
                    let _ = std::fs::remove_dir(&on);
                }
                (Scheme::Gpt, Kind::Other(TypeCode::Gpt(g))) if part::guid_string(&g) == FREEBSD_BOOT_GUID => {
                    out.push(Loader {
                        title: format!("FreeBSD ({name})"),
                        lines: vec![
                            "protocol: bios".into(),
                            format!("gpt_uuid: {}", part::guid_string(&t.disk_guid).to_ascii_lowercase()),
                            format!("partition: {}", e.index),
                        ],
                    });
                }
                (Scheme::Mbr, kind) if e.active && kind != Kind::Oxfs => {
                    let sig = mbr_signature(&name).unwrap_or(0);
                    out.push(Loader {
                        title: format!("{} on {name}s{}", kind.name(), e.index),
                        lines: vec!["protocol: bios".into(), format!("mbr_id: 0x{sig:08x}"), format!("partition: {}", e.index)],
                    });
                }
                _ => {}
            }
        }
    }
    out
}

/// An MBR disk's 32-bit signature (sector 0, byte 440), which Limine finds the disk by.
fn mbr_signature(disk: &str) -> Option<u32> {
    let f = File::open(format!("/dev/{disk}")).ok()?;
    let mut b = [0u8; 4];
    f.read_exact_at(&mut b, 440).ok()?;
    Some(u32::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn guesses() {
        let no = |_: &str| false;
        assert_eq!(efi_loader("Microsoft", &s(&["Boot", "Recovery"]), &no), Some(("Windows Boot Manager".into(), "Boot/bootmgfw.efi".into())));
        assert_eq!(efi_loader("ubuntu", &s(&["grubx64.efi", "mmx64.efi", "shimx64.efi"]), &no), Some(("ubuntu (GRUB)".into(), "shimx64.efi".into())));
        assert_eq!(efi_loader("fedora", &s(&["grubx64.efi"]), &no), Some(("fedora (GRUB)".into(), "grubx64.efi".into())));
        assert_eq!(efi_loader("systemd", &s(&["systemd-bootx64.efi"]), &no), Some(("systemd-boot".into(), "systemd-bootx64.efi".into())));
        let limine = |f: &str| f == "BOOTX64.EFI";
        assert_eq!(efi_loader("Other", &s(&["BOOTIA32.EFI", "BOOTX64.EFI"]), &limine), Some(("Limine (Other)".into(), "BOOTX64.EFI".into())));
        assert_eq!(efi_loader("FreeBSD", &s(&["loader.efi", "notes.txt"]), &no), Some(("FreeBSD".into(), "loader.efi".into())));
        assert_eq!(efi_loader("refind", &s(&["refind_ia32.efi", "refind_x64.efi"]), &no), Some(("refind".into(), "refind_x64.efi".into())));
        assert_eq!(efi_loader("Dell", &s(&["logs"]), &no), None);
    }

    #[test]
    fn listed() {
        let l = Loader { title: "Windows Boot Manager".into(), lines: s(&["protocol: efi", "path: guid(ab):/EFI/Microsoft/Boot/bootmgfw.efi"]) };
        assert!(l.listed_in("/Windows\n    protocol: efi\n    path: guid(AB):/EFI/Microsoft/Boot/bootmgfw.efi\n"));
        assert!(!l.listed_in("/OxideBSD\n    protocol: limine\n"));
        assert_eq!(l.conf(), "/Windows Boot Manager\n    protocol: efi\n    path: guid(ab):/EFI/Microsoft/Boot/bootmgfw.efi\n");
    }
}
