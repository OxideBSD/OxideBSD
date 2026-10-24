//! The partition editor (OxideBSD-doc `INSTALLER.md` §8.2, step 9b2): every disk of the machine,
//! its partitions and free space, laid out by hand. Nothing is written here: the editor works on
//! a copy of each disk's table, and the install writes it after the last screen (§9.3), which
//! lists every change.
//!
//! A partition made here can be resized and retyped freely. One already on a disk is never
//! resized but for an oxfs grown into the free space after it (`growfs`); an oxfs is `/`
//! (formatted) or another mount point (formatted, or kept), an EFI system partition kept or
//! formatted, a swap partition swap; any other system's is kept, or deleted. One install may
//! span disks: `/` on one, `/home` on another; the disk with the EFI system partition is the one
//! the machine boots from.

use part::{Kind, Scheme, Table};

use crate::config::{DiskUse, Layout, PartSpec, Use, parse_size};
use crate::engine;
use crate::screens::human;
use crate::ui::{Dialog, Field, Ui};

const HELP: &str = "Choose a disk, a partition or free space, then a button. Create makes a \
    partition in free space (on a blank disk, first a partition table: GPT, or MBR for old \
    machines). Delete removes a partition, and what it holds. Modify says what a partition is \
    for: an oxfs one / or another mount point, an EFI system partition the boot loader's place, a \
    swap one swap; an existing oxfs can grow into free space after it. Revert puts a disk back as \
    it was. Finish goes on: one partition must be /, one the EFI system partition (shared with \
    other systems if the disk has one). Nothing is written until the last step, which lists \
    every change.";

/// One disk as the editor holds it.
struct EdDisk {
    name: String,
    model: String,
    sector_size: u32,
    sectors: u64,
    /// The table on the disk, and the table being edited.
    orig: Option<Table>,
    table: Option<Table>,
    uses: Vec<Use>,
    /// Partitions made here: still blank, so free to resize.
    made_here: Vec<u32>,
}

impl EdDisk {
    fn load(name: &str) -> Option<EdDisk> {
        let (sector_size, sectors) = engine::disk_geometry(name)?;
        let orig = engine::disk_table(name);
        let model = std::process::Command::new("/sbin/sysctl")
            .args(["-n", &format!("kern.disk.{name}.model")])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        Some(EdDisk { name: name.into(), model, sector_size, sectors, table: orig.clone(), orig, uses: Vec::new(), made_here: Vec::new() })
    }

    fn bytes(&self, sectors: u64) -> u64 {
        sectors * self.sector_size as u64
    }

    fn part_name(&self, index: u32) -> String {
        let s = if self.table.as_ref().is_some_and(|t| t.scheme == Scheme::Mbr) { "s" } else { "p" };
        format!("{}{s}{index}", self.name)
    }

    fn use_of(&self, index: u32) -> Option<&Use> {
        self.uses.iter().find(|u| u.index == index)
    }

    fn set_use(&mut self, index: u32, u: Option<Use>) {
        self.uses.retain(|x| x.index != index);
        self.uses.extend(u);
    }
}

/// A row of the editor's list.
#[derive(Clone, Copy, PartialEq)]
enum Row {
    Disk(usize),
    Part(usize, u32),
    /// Free space: first sector and length.
    Free(usize, u64, u64),
}

fn rows(disks: &[EdDisk]) -> Vec<Row> {
    let mut rows = Vec::new();
    for (d, disk) in disks.iter().enumerate() {
        rows.push(Row::Disk(d));
        let Some(t) = &disk.table else { continue };
        let mut items: Vec<(u64, Row)> = t.entries.iter().map(|e| (e.first, Row::Part(d, e.index))).collect();
        // Free space under 1 MiB is only alignment's leftovers.
        let min = part::ALIGN_BYTES / disk.sector_size as u64;
        items.extend(t.free().into_iter().filter(|&(_, n)| n >= min).map(|(f, n)| (f, Row::Free(d, f, n))));
        items.sort_by_key(|&(f, _)| f);
        rows.extend(items.into_iter().map(|(_, r)| r));
    }
    rows
}

/// What a partition is for, as the list shows it.
fn role(u: Option<&Use>, made_here: bool) -> (String, &'static str) {
    match u {
        Some(Use { kind: Kind::Oxfs, mount: Some(m), newfs, grow, .. }) => {
            (m.clone(), if made_here { "new" } else if *newfs { "format" } else if *grow { "grow, keep" } else { "keep" })
        }
        Some(Use { kind: Kind::Efi, newfs, .. }) => ("/boot/efi".into(), if made_here { "new" } else if *newfs { "format" } else { "keep" }),
        Some(Use { kind: Kind::Swap, .. }) => ("swap".into(), if made_here { "new" } else { "" }),
        _ => (String::new(), if made_here { "new" } else { "" }),
    }
}

fn row_text(disks: &[EdDisk], r: Row) -> (String, String) {
    match r {
        Row::Disk(d) => {
            let disk = &disks[d];
            let scheme = disk.table.as_ref().map_or("blank", |t| t.scheme.name());
            (disk.name.clone(), format!("{:>9}  {scheme}  {}", human(disk.bytes(disk.sectors)), disk.model))
        }
        Row::Part(d, i) => {
            let disk = &disks[d];
            let e = disk.table.as_ref().and_then(|t| t.entry(i)).expect("a listed partition");
            let (mount, note) = role(disk.use_of(i), disk.made_here.contains(&i));
            (format!("  {}", disk.part_name(i)), format!("{:>9}  {:<14}{mount:<11}{note}", human(disk.bytes(e.sectors)), e.kind().name()))
        }
        Row::Free(d, _, n) => ("  free".into(), format!("{:>9}", human(disks[d].bytes(n)))),
    }
}

/// The editor, on every disk, the one at `start` first; the layout, or `None` to go back.
pub fn run(ui: &Ui, names: &[String], start: usize) -> Option<Layout> {
    let mut disks: Vec<EdDisk> = names.iter().filter_map(|n| EdDisk::load(n)).collect();
    if disks.is_empty() {
        return None;
    }
    let mut at = rows(&disks).iter().position(|r| *r == Row::Disk(start.min(disks.len() - 1))).unwrap_or(0);
    loop {
        let list = rows(&disks);
        let items: Vec<(String, String)> = list.iter().map(|&r| row_text(&disks, r)).collect();
        let d = Dialog::new("Partition editor", "Lay the disks out. Nothing is written until the last step.", HELP);
        let keys = "↑↓ choose   ←→ button   Enter goes   Esc back   F1 help   F10 shell";
        let (i, b) = ui.menu_buttons(&d, &items, at, &["Create", "Delete", "Modify", "Revert", "Finish"], keys, false)?;
        at = i;
        let r = list[i];
        match (b, r) {
            (0, Row::Disk(d)) if disks[d].table.is_none() => new_table(ui, &mut disks[d]),
            (0, Row::Free(d, first, n)) | (2, Row::Free(d, first, n)) => create(ui, &mut disks, d, first, n),
            (0, Row::Part(d, p)) | (2, Row::Part(d, p)) => modify(ui, &mut disks, d, p),
            (1, Row::Part(d, p)) => delete(ui, &mut disks[d], p),
            (1, Row::Disk(d)) if disks[d].table.is_some() => {
                let text = format!("Delete every partition of {}, and all it holds?", disks[d].name);
                if ui.yesno(&Dialog::new("Delete", &text, HELP), "Delete", "Keep") == Some(true) {
                    disks[d].table = None;
                    disks[d].uses.clear();
                    disks[d].made_here.clear();
                    new_table(ui, &mut disks[d]);
                }
            }
            (3, r) => {
                let d = match r {
                    Row::Disk(d) | Row::Part(d, _) | Row::Free(d, ..) => d,
                };
                let disk = &mut disks[d];
                disk.table = disk.orig.clone();
                disk.uses.clear();
                disk.made_here.clear();
            }
            (4, _) => {
                if let Some(l) = finish(ui, &disks) {
                    return Some(l);
                }
            }
            (0, _) => ui.message(&Dialog::new("Create", "Choose free space to make a partition in, or a blank disk.", HELP)),
            _ => ui.message(&Dialog::new("Partition editor", "Choose a partition for that.", HELP)),
        }
    }
}

/// A partition table for a blank disk (or one emptied): GPT, or MBR for old machines.
fn new_table(ui: &Ui, disk: &mut EdDisk) {
    let text = format!("{} has no partition table. GPT is for every machine since about 2010 (UEFI or BIOS); MBR for older ones, four partitions at most.", disk.name);
    let Some(gpt) = ui.yesno(&Dialog::new("Partition table", &text, HELP), "GPT", "MBR") else { return };
    let scheme = if gpt { Scheme::Gpt } else { Scheme::Mbr };
    match Table::new(scheme, disk.sector_size, disk.sectors, engine::random_guid()) {
        Ok(t) => disk.table = Some(t),
        Err(e) => ui.message(&Dialog::new("Partition table", &format!("{}: {e}", disk.name), "")),
    }
}

/// The types the editor makes, for `scheme`.
fn kinds(scheme: Scheme) -> Vec<(Kind, &'static str, &'static str)> {
    let mut k = vec![
        (Kind::Oxfs, "oxfs", "OxideBSD's file system: /, /usr, /home ..."),
        (Kind::Efi, "efi", "EFI system partition: the boot loader (260M)"),
    ];
    if scheme == Scheme::Gpt {
        k.push((Kind::BiosBoot, "bios", "BIOS boot: Limine's stage 2 on BIOS (512K)"));
    }
    k.push((Kind::Swap, "swap", "Swap space"));
    k
}

/// Asks where an oxfs partition mounts; `None` to go back.
fn ask_mount(ui: &Ui, disks: &[EdDisk], default: &str, allow_root: bool) -> Option<String> {
    let mut f = [Field::new("Mount point", default)];
    loop {
        let d = Dialog::new("Mount point", "Where is it mounted? (/, /usr, /home, ...)", HELP);
        if !ui.form(&d, &mut f) {
            return None;
        }
        let m = f[0].value.trim().trim_end_matches('/');
        let m = if m.is_empty() { "/" } else { m };
        if !m.starts_with('/') || m.contains("//") || m.contains(char::is_whitespace) {
            ui.message(&Dialog::new("Mount point", "A mount point is an absolute path, as /home.", ""));
        } else if m == "/" && !allow_root {
            ui.message(&Dialog::new("Mount point", "/ is always formatted: choose that instead.", ""));
        } else if disks.iter().flat_map(|d| &d.uses).any(|u| u.mount.as_deref() == Some(m)) {
            ui.message(&Dialog::new("Mount point", &format!("Another partition is mounted on {m}: change that one first."), ""));
        } else {
            return Some(m.to_string());
        }
    }
}

/// A partition made in the free space `(first, n)` of disk `d`.
fn create(ui: &Ui, disks: &mut [EdDisk], d: usize, first: u64, n: u64) {
    let Some(scheme) = disks[d].table.as_ref().map(|t| t.scheme) else { return };
    let kinds = kinds(scheme);
    let items: Vec<(String, String)> = kinds.iter().map(|(_, n, w)| (n.to_string(), w.to_string())).collect();
    let free = human(disks[d].bytes(n));
    let Some(k) = ui.menu(&Dialog::new("Create", &format!("What is the partition for? ({free} free)"), HELP), &items, 0) else { return };
    let kind = kinds[k].0;
    let default = match kind {
        Kind::Efi => "260M",
        Kind::BiosBoot => "512K",
        _ => "",
    };
    let mut f = [Field::new("Size", default)];
    let size = loop {
        let text = format!("Its size, as 512K, 20G; empty for all {free}.");
        if !ui.form(&Dialog::new("Create", &text, HELP), &mut f) {
            return;
        }
        let s = f[0].value.trim();
        if s.is_empty() {
            break None;
        }
        match parse_size(s) {
            Some(b) => break Some(b),
            None => ui.message(&Dialog::new("Create", "A size is a number and K, M, G or T.", "")),
        }
    };
    let mount = match kind {
        Kind::Oxfs => {
            let has_root = disks.iter().flat_map(|d| &d.uses).any(|u| u.mount.as_deref() == Some("/"));
            match ask_mount(ui, disks, if has_root { "" } else { "/" }, true) {
                Some(m) => Some(m),
                None => return,
            }
        }
        _ => None,
    };
    let disk = &mut disks[d];
    let ss = disk.sector_size as u64;
    let align = part::ALIGN_BYTES / ss;
    let start = first.div_ceil(align) * align;
    let sectors = size.map(|b| b.div_ceil(part::BLOCK_BYTES) * part::BLOCK_BYTES / ss);
    let swaps = disk.uses.iter().filter(|u| u.kind == Kind::Swap).count();
    let spec = PartSpec { size, kind, mount: mount.clone() };
    let label = if scheme == Scheme::Gpt { engine::label_for(&spec, swaps) } else { String::new() };
    let Some(code) = kind.code(scheme) else { return };
    let guid = if scheme == Scheme::Gpt { engine::random_guid() } else { [0; 16] };
    let t = disk.table.as_mut().expect("a table");
    if sectors.is_some_and(|s| start + s > first + n) {
        ui.message(&Dialog::new("Create", &format!("That's more than the {free} free."), ""));
        return;
    }
    match t.add(code, &label, Some(start), sectors, guid) {
        Ok(index) => {
            disk.made_here.push(index);
            let u = match kind {
                Kind::BiosBoot => None,
                _ => Some(Use { index, kind, mount, newfs: true, grow: false }),
            };
            if kind == Kind::Efi {
                // One EFI system partition: this one.
                for other in disks.iter_mut() {
                    other.uses.retain(|u| u.kind != Kind::Efi);
                }
            }
            disks[d].set_use(index, u);
        }
        Err(e) => ui.message(&Dialog::new("Create", &format!("{}: {e}", disks[d].name), "")),
    }
}

fn delete(ui: &Ui, disk: &mut EdDisk, p: u32) {
    let name = disk.part_name(p);
    let kind = disk.table.as_ref().and_then(|t| t.entry(p)).map(|e| e.kind().name()).unwrap_or_default();
    let text = if disk.made_here.contains(&p) {
        format!("Delete {name}?")
    } else {
        format!("Delete {name} ({kind})? What it holds is lost when the install runs.")
    };
    if ui.yesno(&Dialog::new("Delete", &text, HELP), "Delete", "Keep") != Some(true) {
        return;
    }
    if let Some(t) = disk.table.as_mut() {
        let _ = t.delete(p);
    }
    disk.set_use(p, None);
    disk.made_here.retain(|&i| i != p);
}

/// What partition `p` of disk `d` is for, and for one made here its size.
fn modify(ui: &Ui, disks: &mut [EdDisk], d: usize, p: u32) {
    let Some(e) = disks[d].table.as_ref().and_then(|t| t.entry(p)).cloned() else { return };
    let kind = e.kind();
    let made_here = disks[d].made_here.contains(&p);
    let room_after = {
        let t = disks[d].table.as_ref().expect("a table");
        let limit = t.entries.iter().filter(|o| o.first >= e.end()).map(|o| o.first).min().unwrap_or(t.last_usable + 1);
        limit.saturating_sub(e.end())
    };
    let min = part::ALIGN_BYTES / disks[d].sector_size as u64;
    let mut roles: Vec<(&str, String)> = Vec::new();
    match kind {
        Kind::Oxfs => {
            roles.push(("/", "The root file system (formatted)".into()));
            roles.push(("Mount", "Another mount point, formatted".into()));
            if !made_here {
                roles.push(("Keep", "Another mount point, kept as it is".into()));
                if room_after >= min {
                    roles.push(("Grow", format!("Grown by the {} after it, kept", human(disks[d].bytes(room_after)))));
                }
            }
        }
        Kind::Efi => {
            if !made_here {
                roles.push(("Keep", "The EFI system partition, its files kept (shared)".into()));
            }
            roles.push(("Format", "The EFI system partition, formatted".into()));
        }
        Kind::Swap => roles.push(("Swap", "Swap space".into())),
        Kind::BiosBoot if made_here => {}
        k => {
            let text = format!("A {} partition is left as it is; Delete removes it.", k.name());
            ui.message(&Dialog::new("Modify", &text, HELP));
            return;
        }
    }
    if made_here {
        roles.push(("Size", "Change its size".into()));
    }
    roles.push(("None", "Not used".into()));
    let items: Vec<(String, String)> = roles.iter().map(|(n, w)| (n.to_string(), w.clone())).collect();
    let name = disks[d].part_name(p);
    let Some(r) = ui.menu(&Dialog::new("Modify", &format!("What is {name} for?"), HELP), &items, 0) else { return };
    let u = |kind, mount: Option<String>, newfs, grow| Some(Use { index: p, kind, mount, newfs, grow });
    let current = disks[d].use_of(p).and_then(|u| u.mount.clone()).unwrap_or_default();
    let new = match roles[r].0 {
        "/" => u(Kind::Oxfs, Some("/".into()), true, false),
        "Keep" if kind == Kind::Efi => u(Kind::Efi, None, false, false),
        "Mount" | "Keep" | "Grow" => {
            // Its own mount point isn't another's: asked with it out of the way, and back if the
            // question is.
            let before = disks[d].use_of(p).cloned();
            disks[d].set_use(p, None);
            let Some(m) = ask_mount(ui, disks, &current, false) else {
                disks[d].set_use(p, before);
                return;
            };
            match roles[r].0 {
                "Mount" => u(Kind::Oxfs, Some(m), true, false),
                "Keep" => u(Kind::Oxfs, Some(m), false, false),
                _ => {
                    if let Err(err) = disks[d].table.as_mut().expect("a table").resize(p, None) {
                        ui.message(&Dialog::new("Modify", &format!("{name}: {err}"), ""));
                        return;
                    }
                    u(Kind::Oxfs, Some(m), false, true)
                }
            }
        }
        "Format" => u(Kind::Efi, None, true, false),
        "Swap" => u(Kind::Swap, None, true, false),
        "Size" => {
            resize(ui, &mut disks[d], p, e.sectors);
            return;
        }
        _ => None,
    };
    if let Some(n) = &new {
        // One root and one EFI system partition: taken from any other.
        for (j, other) in disks.iter_mut().enumerate() {
            other.uses.retain(|x| {
                let same = j == d && x.index == p;
                same || !((n.kind == Kind::Efi && x.kind == Kind::Efi) || (n.mount.is_some() && x.mount == n.mount))
            });
        }
    }
    disks[d].set_use(p, new);
}

/// A size for partition `p`, made here: into the free space after it, or smaller.
fn resize(ui: &Ui, disk: &mut EdDisk, p: u32, sectors: u64) {
    let mut f = [Field::new("Size", &format!("{}M", disk.bytes(sectors) >> 20))];
    let text = "Its new size, as 512K, 20G; empty for all the free space after it.";
    if !ui.form(&Dialog::new("Size", text, HELP), &mut f) {
        return;
    }
    let s = f[0].value.trim();
    let want = if s.is_empty() {
        None
    } else {
        match parse_size(s) {
            Some(b) => Some(b.div_ceil(part::BLOCK_BYTES) * part::BLOCK_BYTES / disk.sector_size as u64),
            None => {
                ui.message(&Dialog::new("Size", "A size is a number and K, M, G or T.", ""));
                return;
            }
        }
    };
    if let Err(e) = disk.table.as_mut().expect("a table").resize(p, want) {
        ui.message(&Dialog::new("Size", &format!("{}: {e}", disk.part_name(p)), ""));
    }
}

/// The layout the editor made, checked; `None` to stay in the editor.
fn finish(ui: &Ui, disks: &[EdDisk]) -> Option<Layout> {
    let uses = || disks.iter().flat_map(|d| d.uses.iter());
    if uses().filter(|u| u.mount.as_deref() == Some("/")).count() != 1 {
        ui.message(&Dialog::new("Finish", "One oxfs partition must be /: Modify one, or Create one.", HELP));
        return None;
    }
    let Some((boot, esp)) = disks.iter().find_map(|d| d.uses.iter().find(|u| u.kind == Kind::Efi).map(|u| (d, u))) else {
        ui.message(&Dialog::new("Finish", "One partition must be the EFI system partition, which holds the boot loader (for BIOS too).", HELP));
        return None;
    };
    let t = boot.table.as_ref().expect("a table");
    let esp_bytes = t.entry(esp.index).map_or(0, |e| boot.bytes(e.sectors));
    if esp.newfs && esp_bytes < 33 << 20 {
        ui.message(&Dialog::new("Finish", "The EFI system partition is too small for FAT32: make it 64M or more.", HELP));
        return None;
    }
    if t.scheme == Scheme::Gpt && !t.entries.iter().any(|e| e.kind() == Kind::BiosBoot) {
        let text = format!("{} has no BIOS boot partition: the new system boots on UEFI only. Go on?", boot.name);
        if ui.yesno(&Dialog::new("Finish", &text, HELP), "Go on", "Back") != Some(true) {
            return None;
        }
    }
    let disks: Vec<DiskUse> = disks
        .iter()
        .filter(|d| d.table != d.orig || !d.uses.is_empty())
        .map(|d| DiskUse { disk: d.name.clone(), table: (d.table != d.orig).then(|| d.table.clone()).flatten(), parts: d.uses.clone() })
        .collect();
    Some(Layout::Edited { disks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(t: Option<Table>) -> EdDisk {
        EdDisk { name: "ide0".into(), model: String::new(), sector_size: 512, sectors: 8 << 21, orig: t.clone(), table: t, uses: Vec::new(), made_here: Vec::new() }
    }

    #[test]
    fn rows_in_order() {
        let mut t = Table::new(Scheme::Gpt, 512, 8 << 21, [1; 16]).unwrap();
        t.add(Kind::Efi.code(Scheme::Gpt).unwrap(), "efi", Some(2048), Some(260 << 11), [2; 16]).unwrap();
        t.add(Kind::Oxfs.code(Scheme::Gpt).unwrap(), "x", Some(4 << 21), Some(1 << 21), [3; 16]).unwrap();
        let disks = [disk(Some(t)), disk(None)];
        let r = rows(&disks);
        assert!(matches!(r[0], Row::Disk(0)));
        assert!(matches!(r[1], Row::Part(0, 1)));
        assert!(matches!(r[2], Row::Free(0, ..)));
        assert!(matches!(r[3], Row::Part(0, 2)));
        assert!(matches!(r[4], Row::Free(0, ..)));
        assert!(matches!(r[5], Row::Disk(1)));
        assert_eq!(r.len(), 6);
        let (name, what) = row_text(&disks, r[1]);
        assert_eq!(name, "  ide0p1");
        assert!(what.contains("260 MiB") && what.contains("efi"));
    }

    #[test]
    fn roles() {
        let u = |kind, mount: Option<&str>, newfs, grow| Some(Use { index: 1, kind, mount: mount.map(str::to_string), newfs, grow });
        assert_eq!(role(u(Kind::Oxfs, Some("/home"), false, true).as_ref(), false), ("/home".to_string(), "grow, keep"));
        assert_eq!(role(u(Kind::Efi, None, false, false).as_ref(), false), ("/boot/efi".to_string(), "keep"));
        assert_eq!(role(u(Kind::Oxfs, Some("/"), true, false).as_ref(), true), ("/".to_string(), "new"));
        assert_eq!(role(None, false), (String::new(), ""));
    }
}
