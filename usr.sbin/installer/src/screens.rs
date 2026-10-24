//! The install's screens (OxideBSD-doc `INSTALLER.md` §9.2): every question first -- keyboard,
//! host name, disks, sets, network, time zone, root's password and users -- each with a way back,
//! then one screen saying what is erased and kept (§9.3), then the install itself (`engine`),
//! unattended, under a progress bar. The answers make the same `Config` an `installerconfig`
//! does.

use std::process::{Command, Stdio};

use part::Kind;

use crate::config::{Config, DiskUse, Guided, Iface, Layout, Net, Use, User};
use crate::engine;
use crate::ui::{Check, Dialog, Field, Ui};

const STEPS: [&str; 8] = ["Keyboard", "Host name", "Disks", "Sets", "Network", "Time zone", "Users", "Confirm"];

/// Where a step leads.
enum Flow {
    Next,
    Back,
}

/// Where the screens leave the installer.
pub enum After {
    /// Back to the first screen.
    Welcome,
    Reboot,
}

/// The keyboard layouts `wsconsctl` knows (`keyboard.encoding`).
const KEYMAPS: [(&str, &str); 10] = [
    ("us", "English (US)"),
    ("uk", "English (UK)"),
    ("de", "German"),
    ("fr", "French"),
    ("us.dvorak", "English (US), Dvorak"),
    ("us.colemak", "English (US), Colemak"),
    ("jp", "Japanese"),
    ("no", "Norwegian"),
    ("fi", "Finnish"),
    ("sv", "Swedish"),
];

const ZONE_TAB: &str = "/usr/share/zoneinfo/zone1970.tab";

/// Answers not in the `Config`: where each menu was left, and what was found.
#[derive(Default)]
struct State {
    keymap_at: usize,
    disk_at: usize,
    /// The disks' tables hold a Windows-looking partition (`Kind::MsBasicData`).
    windows: bool,
}

/// `bytes` for people: `260 MiB`, `4.0 GiB`.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 || v >= 100.0 || v.fract() < 0.05 { format!("{v:.0} {}", UNITS[u]) } else { format!("{v:.1} {}", UNITS[u]) }
}

fn sysctl(name: &str) -> Option<String> {
    let out = Command::new("/sbin/sysctl").args(["-n", name]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Asks every question, then installs; where to go after.
pub fn run(ui: &mut Ui) -> After {
    let mut cfg = Config::new();
    let mut st = State::default();
    let mut i = 0;
    loop {
        ui.step = format!("Step {} of {}: {}", i + 1, STEPS.len(), STEPS[i]);
        let flow = match i {
            0 => keyboard(ui, &mut cfg, &mut st),
            1 => hostname(ui, &mut cfg),
            2 => disks(ui, &mut cfg, &mut st),
            3 => sets(ui, &mut cfg),
            4 => network(ui, &mut cfg),
            5 => timezone(ui, &mut cfg, &st),
            6 => users(ui, &mut cfg),
            _ => confirm(ui, &cfg),
        };
        match flow {
            Flow::Next if i + 1 == STEPS.len() => return install(ui, &cfg),
            Flow::Next => i += 1,
            Flow::Back if i == 0 => return After::Welcome,
            Flow::Back => i -= 1,
        }
    }
}

const HELP_KEYBOARD: &str = "The layout of the keyboard: what each key types. It applies at once, so the \
    questions after this one are typed with it, and it is the new system's too (wsconsctl.conf(5)). It can \
    be changed later with wsconsctl(8).";

fn keyboard(ui: &Ui, cfg: &mut Config, st: &mut State) -> Flow {
    let items: Vec<(String, String)> = KEYMAPS.iter().map(|(n, w)| (n.to_string(), w.to_string())).collect();
    let d = Dialog::new("Keyboard", "Choose the keyboard's layout. It applies at once.", HELP_KEYBOARD);
    let Some(i) = ui.menu(&d, &items, st.keymap_at) else { return Flow::Back };
    st.keymap_at = i;
    let map = KEYMAPS[i].0;
    let _ = Command::new("/sbin/wsconsctl").arg(format!("keyboard.encoding={map}")).stdout(Stdio::null()).stderr(Stdio::null()).status();
    cfg.keymap = Some(map.to_string());
    Flow::Next
}

/// A host name as RFC 1123 has them: dot-separated labels of letters, digits and hyphens, none
/// starting or ending with a hyphen, at most 63 characters each and 253 in all.
pub fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

const HELP_HOSTNAME: &str = "The name this machine goes by on the network and in the shell's prompt: \
    letters, digits and hyphens, in dot-separated parts (oxide, or oxide.example.org). It goes into \
    rc.conf(5) as hostname.";

fn hostname(ui: &Ui, cfg: &mut Config) -> Flow {
    let mut f = [Field::new("Host name", cfg.hostname.as_deref().unwrap_or("oxidebsd"))];
    loop {
        let d = Dialog::new("Host name", "Name this machine.", HELP_HOSTNAME);
        if !ui.form(&d, &mut f) {
            return Flow::Back;
        }
        let h = f[0].value.trim().to_string();
        if valid_hostname(&h) {
            cfg.hostname = Some(h);
            return Flow::Next;
        }
        ui.message(&Dialog::new(
            "Host name",
            "That isn't a host name: use letters, digits and hyphens, in parts split by dots, none starting or ending with a hyphen.",
            "",
        ));
    }
}

const HELP_DISKS: &str = "Beside keeps everything on the disk and puts OxideBSD in its largest free \
    space, sharing the EFI system partition if there is one: the other systems stay in the boot \
    menu. Whole erases the disk and gives all of it to OxideBSD. Manual opens the partition \
    editor, on every disk: several oxfs partitions, swap, an install over disks. Shell gives you a shell to \
    partition by hand with gpart(8) (oxfs, efi and swap types), then asks what each partition is \
    for. Nothing is written until the last step, which lists what is erased.";

fn disks(ui: &Ui, cfg: &mut Config, st: &mut State) -> Flow {
    let disks: Vec<String> = engine::disks().into_iter().filter(|(_, k)| k == "disk").map(|(d, _)| d).collect();
    st.windows = disks.iter().filter_map(|d| engine::disk_table(d)).any(|t| t.entries.iter().any(|e| e.kind() == Kind::MsBasicData));
    if disks.is_empty() {
        ui.message(&Dialog::new("Disks", "There's no disk to install on. Choose Shell on the first screen to look into it.", ""));
        return Flow::Back;
    }
    loop {
        let items: Vec<(String, String)> = disks
            .iter()
            .map(|d| {
                let size = sysctl(&format!("kern.disk.{d}.size")).and_then(|s| s.parse().ok()).unwrap_or(0);
                let model = sysctl(&format!("kern.disk.{d}.model")).unwrap_or_default();
                let holds = match engine::disk_table(d) {
                    Some(t) => format!("{}, {} partitions", t.scheme.name(), t.entries.len()),
                    None => "blank".into(),
                };
                (d.clone(), format!("{:>9}  {model}  ({holds})", human(size)))
            })
            .collect();
        let d = Dialog::new("Disks", "Choose the disk to install OxideBSD on.", HELP_DISKS);
        let Some(i) = ui.menu(&d, &items, st.disk_at) else { return Flow::Back };
        st.disk_at = i;
        if let Some(layout) = disk_layout(ui, &disks, i) {
            cfg.layout = layout;
            return Flow::Next;
        }
    }
}

/// The partitions of `t`, a line each, for a dialog's text.
fn summary(disk: &str, t: &part::Table) -> String {
    let suffix = if t.scheme == part::Scheme::Gpt { "p" } else { "s" };
    let mut e: Vec<&part::Entry> = t.entries.iter().collect();
    e.sort_by_key(|e| e.first);
    let lines: Vec<String> = e
        .iter()
        .map(|e| format!("{disk}{suffix}{}: {} {}", e.index, human(e.sectors * t.sector_size as u64), e.kind().name()))
        .collect();
    let free: u64 = t.free().iter().map(|&(_, n)| n).max().unwrap_or(0) * t.sector_size as u64;
    format!("{}; the largest free space is {}.", lines.join(", "), human(free))
}

/// How disk `disks[i]` is laid out: the guided layout beside the others or over the whole disk,
/// the partition editor's layout (on any of the disks), or the partitions made in a shell; `None`
/// to choose another disk.
fn disk_layout(ui: &Ui, disks: &[String], i: usize) -> Option<Layout> {
    let disk = disks[i].as_str();
    let mut at = 0;
    loop {
        let table = engine::disk_table(disk);
        let beside = Layout::Guided { disk: Some(disk.to_string()), how: Guided::Beside };
        let mut items = Vec::new();
        let text = match &table {
            Some(t) => {
                if engine::preview(&beside).is_ok() {
                    let free = t.free().iter().map(|&(_, n)| n).max().unwrap_or(0) * t.sector_size as u64;
                    items.push(("Beside".to_string(), format!("Use the {} free, keep everything else", human(free))));
                }
                format!("{disk} holds {}", summary(disk, t))
            }
            None => format!("{disk} is blank."),
        };
        items.push(("Whole".into(), format!("Erase {disk} and use all of it")));
        items.push(("Manual".into(), "The partition editor: every disk, by hand".into()));
        items.push(("Shell".into(), "Partition by hand with gpart, then choose".into()));
        let d = Dialog::new("Partitioning", &text, HELP_DISKS);
        let c = ui.menu(&d, &items, at)?;
        at = c;
        match items[c].0.as_str() {
            "Beside" => return Some(beside),
            "Whole" => return Some(Layout::Guided { disk: Some(disk.to_string()), how: Guided::Whole }),
            "Manual" => {
                if let Some(l) = crate::editor::run(ui, disks, disks.iter().position(|d| d == disk).unwrap_or(0)) {
                    return Some(l);
                }
            }
            _ => {
                ui.shell();
                if let Some(l) = assign(ui, disk) {
                    return Some(l);
                }
            }
        }
    }
}

const HELP_ASSIGN: &str = "Choose a partition, then what it's for: an oxfs partition is / or \
    another mount point (formatted: what it holds is erased); an EFI system partition holds the \
    boot loader, kept as it is (other systems' boot files stay) or formatted; a swap partition is \
    swap. Partitions of other types are left alone. One must be /, and one the EFI system \
    partition. Done goes on.";

/// What each of the partitions made by hand on `disk` is for; `None` to go back.
fn assign(ui: &Ui, disk: &str) -> Option<Layout> {
    let Some(t) = engine::disk_table(disk) else {
        ui.message(&Dialog::new("Partitions", &format!("{disk} has no partition table: make one with gpart create."), ""));
        return None;
    };
    let suffix = if t.scheme == part::Scheme::Gpt { "p" } else { "s" };
    let mut entries: Vec<&part::Entry> = t.entries.iter().collect();
    entries.sort_by_key(|e| e.first);
    let mut uses: Vec<Option<Use>> = vec![None; entries.len()];
    let mut at = 0;
    loop {
        let mut items = vec![("Done".to_string(), "These are the partitions to install on".to_string())];
        for (e, u) in entries.iter().zip(&uses) {
            let role = match u {
                Some(Use { kind: Kind::Oxfs, mount: Some(m), .. }) => format!("→ {m} (formatted)"),
                Some(Use { kind: Kind::Efi, newfs: false, .. }) => "→ EFI system, kept".into(),
                Some(Use { kind: Kind::Efi, .. }) => "→ EFI system (formatted)".into(),
                Some(Use { kind: Kind::Swap, .. }) => "→ swap".into(),
                _ => "not used".into(),
            };
            let what = format!("{:>9}  {:<12} {role}", human(e.sectors * t.sector_size as u64), e.kind().name());
            items.push((format!("{disk}{suffix}{}", e.index), what));
        }
        let text = format!("What is each partition of {disk} for?");
        let d = Dialog::new("Partitions", &text, HELP_ASSIGN);
        let i = ui.menu(&d, &items, at)?;
        at = i;
        if i == 0 {
            let roots = uses.iter().flatten().filter(|u| u.mount.as_deref() == Some("/")).count();
            let esps = uses.iter().flatten().filter(|u| u.kind == Kind::Efi).count();
            if roots == 1 && esps == 1 {
                let parts = uses.into_iter().flatten().collect();
                return Some(Layout::Edited { disks: vec![DiskUse { disk: disk.to_string(), table: None, parts }] });
            }
            ui.message(&Dialog::new("Partitions", "One oxfs partition must be /, and one partition the EFI system partition.", ""));
            continue;
        }
        let e = entries[i - 1];
        let roles: Vec<(&str, &str)> = match e.kind() {
            Kind::Oxfs => vec![("/", "The root file system"), ("Other", "Another mount point (/usr, /home, ...)"), ("None", "Not used")],
            Kind::Efi => vec![("Keep", "The EFI system partition, its files kept"), ("Format", "The EFI system partition, formatted"), ("None", "Not used")],
            Kind::Swap => vec![("Swap", "Swap space"), ("None", "Not used")],
            k => {
                let text = format!("A {} partition is left alone. OxideBSD uses oxfs, efi and swap ones: gpart modify -t changes a type.", k.name());
                ui.message(&Dialog::new("Partitions", &text, ""));
                continue;
            }
        };
        let items: Vec<(String, String)> = roles.iter().map(|(n, w)| (n.to_string(), w.to_string())).collect();
        let Some(r) = ui.menu(&Dialog::new("Partitions", &items[0].1, HELP_ASSIGN), &items, 0) else { continue };
        let u = |kind, mount: Option<&str>, newfs| Some(Use { index: e.index, kind, mount: mount.map(str::to_string), newfs, grow: false });
        uses[i - 1] = match roles[r].0 {
            "/" => u(Kind::Oxfs, Some("/"), true),
            "Other" => {
                let mut f = [Field::new("Mount point", "/usr")];
                let d = Dialog::new("Partitions", "Where is it mounted?", HELP_ASSIGN);
                if !ui.form(&d, &mut f) || !f[0].value.starts_with('/') || f[0].value == "/" {
                    continue;
                }
                u(Kind::Oxfs, Some(f[0].value.trim_end_matches('/')), true)
            }
            "Keep" => u(Kind::Efi, None, false),
            "Format" => u(Kind::Efi, None, true),
            "Swap" => u(Kind::Swap, None, true),
            _ => None,
        };
        // One of each: a new root or ESP takes the role from another partition.
        dedupe(&mut uses, i - 1);
    }
}

/// After `uses[k]` changed: no other partition keeps the same mount point, or a second EFI
/// system partition.
fn dedupe(uses: &mut [Option<Use>], k: usize) {
    let Some(mine) = uses[k].clone() else { return };
    for (j, other) in uses.iter_mut().enumerate() {
        let clash = match other {
            Some(o) if j != k => (o.mount.is_some() && o.mount == mine.mount) || (o.kind == Kind::Efi && mine.kind == Kind::Efi),
            _ => false,
        };
        if clash {
            *other = None;
        }
    }
}

const HELP_SETS: &str = "The parts of OxideBSD to install, from the install medium: base is the \
    system itself and always goes in; clang is the C and C++ compilers (clang, lld, the headers); \
    tests are the test programs. Sizes are compressed.";

fn sets(ui: &Ui, cfg: &mut Config) -> Flow {
    ui.gauge("Sets", "Looking for the install medium", 0);
    let found = match engine::sets_on_medium() {
        Ok(s) => s,
        Err(e) => {
            ui.message(&Dialog::new("Sets", &format!("The install medium can't be read: {e}"), ""));
            return Flow::Back;
        }
    };
    let first = cfg.sets == ["base.tar.zst"];
    let mut items: Vec<Check> = found
        .iter()
        .map(|s| Check {
            name: s.file.trim_end_matches(".tar.zst").to_string(),
            what: format!("{}, {}", s.description, human(s.bytes)),
            on: s.file == "base.tar.zst" || cfg.sets.contains(&s.file) || (first && s.default),
            fixed: s.file == "base.tar.zst",
        })
        .collect();
    let d = Dialog::new("Sets", "Choose what to install. Space ticks a set.", HELP_SETS);
    if !ui.checklist(&d, &mut items) {
        return Flow::Back;
    }
    cfg.sets = found.iter().zip(&items).filter(|(_, c)| c.on).map(|(s, _)| s.file.clone()).collect();
    Flow::Next
}

/// The machine's network interfaces but the loopback.
fn interfaces() -> Vec<String> {
    let out = Command::new("/sbin/ifconfig").arg("-l").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    out.split_whitespace().filter(|i| !i.starts_with("lo")).map(str::to_string).collect()
}

/// Interface `iface`'s IPv4 address and prefix, as `ifconfig` shows it, if it has one.
fn inet_of(iface: &str) -> Option<String> {
    let out = Command::new("/sbin/ifconfig").arg(iface).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut w = text.split_whitespace();
    while let Some(word) = w.next() {
        if word == "inet" {
            return w.next().map(str::to_string);
        }
    }
    None
}

/// `a.b.c.d`, each part a byte.
pub fn valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

/// `a.b.c.d/n`, `n` at most 32.
pub fn valid_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, n)) => valid_ipv4(a) && n.parse::<u8>().is_ok_and(|n| n <= 32),
        None => false,
    }
}

const HELP_NETWORK: &str = "DHCP asks the network's DHCP server for an address, as most home and \
    office networks want. Static sets an address, the router and a name server by hand. Either is \
    tried here and now, so you see whether it works, and goes into the new system's rc.conf(5) \
    (and resolv.conf(5)).";

fn network(ui: &Ui, cfg: &mut Config) -> Flow {
    let ifaces = interfaces();
    if ifaces.is_empty() {
        ui.message(&Dialog::new("Network", "This machine has no network interface OxideBSD can drive.", ""));
        return Flow::Next;
    }
    cfg.ifaces.retain(|i| ifaces.contains(&i.name));
    let mut k = 0;
    while k < ifaces.len() {
        let name = &ifaces[k];
        let items = vec![
            ("DHCP".to_string(), "Ask the network's DHCP server for an address".to_string()),
            ("Static".into(), "Set the address by hand".into()),
            ("Off".into(), "Leave it off".into()),
        ];
        let text = format!("How does {name} get its address?");
        let d = Dialog::new("Network", &text, HELP_NETWORK);
        let at = match cfg.ifaces.iter().find(|i| &i.name == name).map(|i| &i.net) {
            Some(Net::Static { .. }) => 1,
            Some(Net::Off) => 2,
            _ => 0,
        };
        let Some(c) = ui.menu(&d, &items, at) else {
            if k == 0 {
                return Flow::Back;
            }
            k -= 1;
            continue;
        };
        let net = match c {
            0 => match try_dhcp(ui, name) {
                Some(n) => n,
                None => continue,
            },
            1 => match try_static(ui, cfg, name) {
                Some(n) => n,
                None => continue,
            },
            _ => Net::Off,
        };
        cfg.ifaces.retain(|i| &i.name != name);
        cfg.ifaces.push(Iface { name: name.clone(), net });
        k += 1;
    }
    Flow::Next
}

/// Asks for a lease on `iface` now; DHCP, or `None` to choose again.
fn try_dhcp(ui: &Ui, iface: &str) -> Option<Net> {
    ui.gauge("Network", &format!("Asking {iface}'s DHCP server for an address (up to a minute)"), 0);
    let leased = Command::new("/sbin/dhclient")
        .arg(iface)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    match inet_of(iface).filter(|_| leased) {
        Some(a) => {
            ui.message(&Dialog::new("Network", &format!("{iface} has the address {a}."), ""));
            Some(Net::Dhcp)
        }
        None => {
            let text = format!("No DHCP server answered on {iface}. Keep DHCP for the new system anyway (it asks again at every boot)?");
            ui.yesno(&Dialog::new("Network", &text, HELP_NETWORK), "Keep", "Change").filter(|&k| k).map(|_| Net::Dhcp)
        }
    }
}

/// Asks for `iface`'s address, router and name server, and sets them now; `None` to choose
/// again.
fn try_static(ui: &Ui, cfg: &mut Config, iface: &str) -> Option<Net> {
    let (addr, router) = match cfg.ifaces.iter().find(|i| i.name == iface).map(|i| &i.net) {
        Some(Net::Static { addr, router }) => (addr.clone(), router.clone().unwrap_or_default()),
        _ => (String::new(), String::new()),
    };
    let mut f = [
        Field::new("Address/prefix", &addr),
        Field::new("Router", &router),
        Field::new("Name server", cfg.nameservers.first().map_or("", String::as_str)),
    ];
    loop {
        let text = format!("{iface}'s address, as 192.168.1.20/24; the router and name server may be left empty.");
        let d = Dialog::new("Network", &text, HELP_NETWORK);
        if !ui.form(&d, &mut f) {
            return None;
        }
        let (a, r, n) = (f[0].value.trim().to_string(), f[1].value.trim().to_string(), f[2].value.trim().to_string());
        if !valid_cidr(&a) || (!r.is_empty() && !valid_ipv4(&r)) || (!n.is_empty() && !valid_ipv4(&n)) {
            ui.message(&Dialog::new("Network", "Write the address as four numbers and a prefix length (192.168.1.20/24), the others as four numbers.", ""));
            continue;
        }
        let ok = engine::run("/sbin/ifconfig", &[iface, "inet", &a]).and_then(|_| {
            if r.is_empty() { Ok(()) } else { engine::run("/sbin/route", &["-q", "add", "default", &r]) }
        });
        let text = match ok {
            Ok(()) => format!("{iface} has the address {a}."),
            Err(e) => format!("Setting it now failed ({e}); the new system gets it anyway."),
        };
        ui.message(&Dialog::new("Network", &text, ""));
        cfg.nameservers = if n.is_empty() { Vec::new() } else { vec![n] };
        return Some(Net::Static { addr: a, router: (!r.is_empty()).then_some(r) });
    }
}

/// The zones of `zone1970.tab`, by region: `(region, [(zone, its comment)])`.
fn zones() -> Vec<(String, Vec<(String, String)>)> {
    let text = std::fs::read_to_string(ZONE_TAB).unwrap_or_default();
    let mut regions: std::collections::BTreeMap<String, Vec<(String, String)>> = Default::default();
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = l.split('\t').collect();
        let Some(zone) = f.get(2) else { continue };
        let Some((region, rest)) = zone.split_once('/') else { continue };
        let what = f.get(3).copied().unwrap_or("").to_string();
        regions.entry(region.to_string()).or_default().push((rest.to_string(), what));
    }
    regions.into_iter().map(|(r, mut z)| {
        z.sort();
        (r, z)
    }).collect()
}

const HELP_ZONE: &str = "The local time zone, for the time the system shows. The clock itself \
    keeps UTC. The hardware clock may keep local time instead, as Windows keeps it: answer Local \
    time if Windows is on this machine (or set Windows to keep UTC).";

fn timezone(ui: &Ui, cfg: &mut Config, st: &State) -> Flow {
    let regions = zones();
    loop {
        let mut items = vec![("UTC".to_string(), "Coordinated Universal Time, no daylight saving".to_string())];
        items.extend(regions.iter().map(|(r, z)| (r.clone(), format!("{} zones", z.len()))));
        let cur = cfg.timezone.as_deref().and_then(|z| z.split('/').next()).and_then(|r| items.iter().position(|(n, _)| n == r)).unwrap_or(0);
        let d = Dialog::new("Time zone", "Choose the region.", HELP_ZONE);
        let Some(i) = ui.menu(&d, &items, cur) else { return Flow::Back };
        let zone = if i == 0 {
            "UTC".to_string()
        } else {
            let (region, list) = &regions[i - 1];
            let items: Vec<(String, String)> = list.iter().cloned().collect();
            let cur = cfg.timezone.as_deref().and_then(|z| z.strip_prefix(&format!("{region}/"))).and_then(|z| items.iter().position(|(n, _)| n == z)).unwrap_or(0);
            let text = format!("Choose the zone in {region}.");
            let d = Dialog::new("Time zone", &text, HELP_ZONE);
            let Some(j) = ui.menu(&d, &items, cur) else { continue };
            format!("{region}/{}", items[j].0)
        };
        let (text, first, second) = if st.windows {
            ("Windows looks to be on this machine: it keeps the hardware clock in local time. Does this machine's hardware clock keep local time, or UTC?", "Local", "UTC")
        } else {
            ("Does this machine's hardware clock keep UTC (most do, unless Windows is on it), or local time?", "UTC", "Local")
        };
        let Some(first_chosen) = ui.yesno(&Dialog::new("Hardware clock", text, HELP_ZONE), first, second) else { continue };
        cfg.wall_cmos_clock = (first_chosen && first == "Local") || (!first_chosen && second == "Local");
        cfg.timezone = Some(zone);
        return Flow::Next;
    }
}

/// A login name `pw` takes: a lower-case letter or `_` first, then letters, digits, `_` and `-`,
/// at most 32.
pub fn valid_login(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// The names the base system's `/etc/passwd` takes already (the medium's is the base set's).
fn taken_names() -> Vec<String> {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(':').next().map(str::to_string))
        .collect()
}

const HELP_USERS: &str = "Root is the system's administrator; give it a password. Users are the \
    people who log in: one in the wheel group can become root with su(1) or sudo(8); root itself \
    may not log in at the console then. Users may be left for later (adduser(8), or a first-boot \
    setup): then root logs in at the console, which is marked secure for it in ttys(5).";

fn users(ui: &Ui, cfg: &mut Config) -> Flow {
    let mut f = [Field::secret("Password"), Field::secret("Again")];
    loop {
        let d = Dialog::new("Root's password", "The administrator's (root's) password.", HELP_USERS);
        if !ui.form(&d, &mut f) {
            return Flow::Back;
        }
        if f[0].value != f[1].value {
            ui.message(&Dialog::new("Root's password", "The two passwords differ. Type them again.", ""));
            f[0].value.clear();
            f[1].value.clear();
            continue;
        }
        if f[0].value.is_empty() {
            let text = "Root has no password: anyone at the console can be the administrator. Go on without one?";
            if ui.yesno(&Dialog::new("Root's password", text, HELP_USERS), "Go on", "Back") != Some(true) {
                continue;
            }
            cfg.rootpass = None;
        } else {
            cfg.rootpass = Some(f[0].value.clone());
        }
        if user_list(ui, cfg) {
            return Flow::Next;
        }
    }
}

/// The users to make: added, removed, then Done; `false` to go back to root's password.
fn user_list(ui: &Ui, cfg: &mut Config) -> bool {
    let mut at = 0;
    loop {
        let mut items = vec![("Add".to_string(), "Add a user".to_string()), ("Done".to_string(), "These are the users".to_string())];
        for u in &cfg.users {
            items.push((u.name.clone(), format!("{}{}", u.full_name, if u.wheel { " (wheel)" } else { "" })));
        }
        let text = if cfg.users.is_empty() { "The people who log in." } else { "The people who log in. Choose a user to remove it." };
        let d = Dialog::new("Users", text, HELP_USERS);
        let Some(i) = ui.menu(&d, &items, at) else { return false };
        at = i;
        match i {
            0 => {
                if let Some(u) = add_user(ui, cfg) {
                    cfg.users.push(u);
                }
            }
            1 => {
                if !cfg.users.is_empty() {
                    return true;
                }
                let text = "No users: root logs in at the console instead, which is marked secure for it. Users can be added later (adduser, or a first-boot setup). Go on?";
                if ui.yesno(&Dialog::new("Users", text, HELP_USERS), "Go on", "Back") == Some(true) {
                    return true;
                }
            }
            n => {
                let name = cfg.users[n - 2].name.clone();
                if ui.yesno(&Dialog::new("Users", &format!("Remove {name}?"), ""), "Remove", "Keep") == Some(true) {
                    cfg.users.remove(n - 2);
                    at = 0;
                }
            }
        }
    }
}

fn add_user(ui: &Ui, cfg: &Config) -> Option<User> {
    let mut f = [Field::new("Login name", ""), Field::new("Full name", ""), Field::secret("Password"), Field::secret("Again")];
    loop {
        let d = Dialog::new("Add a user", "", HELP_USERS);
        if !ui.form(&d, &mut f) {
            return None;
        }
        let name = f[0].value.trim().to_string();
        let problem = if !valid_login(&name) {
            Some("A login name is lower-case letters, digits, _ and -, starting with a letter, at most 32.".to_string())
        } else if taken_names().contains(&name) || cfg.users.iter().any(|u| u.name == name) {
            Some(format!("There's a {name} already."))
        } else if f[1].value.contains(':') {
            Some("A full name can't hold a colon.".into())
        } else if f[2].value != f[3].value {
            Some("The two passwords differ.".into())
        } else if f[2].value.is_empty() {
            Some("Give the user a password.".into())
        } else {
            None
        };
        if let Some(p) = problem {
            ui.message(&Dialog::new("Add a user", &p, ""));
            continue;
        }
        let text = format!("May {name} become root (with su and sudo: the wheel group)?");
        let wheel = ui.yesno(&Dialog::new("Add a user", &text, HELP_USERS), "Yes", "No")?;
        return Some(User { name, full_name: f[1].value.trim().to_string(), password: f[2].value.clone(), wheel });
    }
}

const HELP_CONFIRM: &str = "This is what the install does. Lines in copper erase something. \
    Install starts it; Back goes back through the questions. Nothing has been written yet.";

/// Everything the install will do, a line each; lines starting `!` erase something.
fn review_lines(cfg: &Config, disks: &[engine::DiskPreview]) -> Vec<String> {
    let mut l = Vec::new();
    for p in disks {
        if p.erased {
            l.push(format!("!Everything on {} is erased.", p.disk));
        }
        l.push(format!("{}:", p.disk));
        for q in &p.parts {
            l.push(format!("{}  {:<10} {:>9}  {:<14} {}", if q.erases { "!" } else { " " }, q.name, human(q.bytes), q.what, q.fate));
        }
        l.push(String::new());
    }
    let sets: Vec<&str> = cfg.sets.iter().map(|s| s.trim_end_matches(".tar.zst")).collect();
    l.push(format!("Sets: {}", sets.join(", ")));
    l.push(format!(
        "Host name: {}    Keyboard: {}",
        cfg.hostname.as_deref().unwrap_or("oxidebsd"),
        cfg.keymap.as_deref().unwrap_or("us")
    ));
    for i in &cfg.ifaces {
        let how = match &i.net {
            Net::Dhcp => "DHCP".to_string(),
            Net::Static { addr, router } => format!("{addr}{}", router.as_ref().map_or(String::new(), |r| format!(", router {r}"))),
            Net::Off => "off".into(),
        };
        l.push(format!("Network: {} {how}", i.name));
    }
    l.push(format!(
        "Time zone: {}; the hardware clock keeps {}",
        cfg.timezone.as_deref().unwrap_or("UTC"),
        if cfg.wall_cmos_clock { "local time" } else { "UTC" }
    ));
    let mut who = vec![format!("root ({})", if cfg.rootpass.is_some() { "a password" } else { "no password" })];
    who.extend(cfg.users.iter().map(|u| format!("{}{}", u.name, if u.wheel { " (wheel)" } else { "" })));
    l.push(format!("Users: {}", who.join(", ")));
    l.push("Boot: Limine in \\EFI\\OxideBSD and the disk's BIOS boot code; on UEFI a firmware entry.".into());
    l.push("The boot menu lists the other systems found.".into());
    l
}

fn confirm(ui: &Ui, cfg: &Config) -> Flow {
    let p = match engine::preview(&cfg.layout) {
        Ok(p) => p,
        Err(e) => {
            ui.message(&Dialog::new("Confirm", &format!("The disks can't be laid out so: {e}"), ""));
            return Flow::Back;
        }
    };
    let d = Dialog::new("Confirm", "Install OxideBSD so? Nothing has been written yet.", HELP_CONFIRM);
    if ui.review(&d, &review_lines(cfg, &p), "Install", "Back") { Flow::Next } else { Flow::Back }
}

/// The install itself, under a progress bar; then the last screen.
fn install(ui: &mut Ui, cfg: &Config) -> After {
    ui.step = "Installing".into();
    // The steps the engine tells, roughly: a bar that moves at each.
    let expected = 12 + 2 * cfg.sets.len() as u32 + cfg.users.len() as u32;
    let mut n = 0;
    let result = engine::install(cfg, &mut |step| {
        n += 1;
        ui.gauge("Installing", step, (n * 100 / expected).min(99));
    });
    let text = match &result {
        Ok(()) => "OxideBSD is installed. Take the install medium out, then reboot into the new system.".to_string(),
        Err(e) => format!("The install failed: {e}"),
    };
    ui.step = String::new();
    loop {
        let items = vec![
            ("Reboot".to_string(), "Restart the machine".to_string()),
            ("Shell".into(), "A shell on the install medium (the new system is not mounted)".into()),
            ("Back".into(), "The first screen".into()),
        ];
        let title = if result.is_ok() { "Done" } else { "Failed" };
        match ui.menu(&Dialog::new(title, &text, ""), &items, if result.is_ok() { 0 } else { 2 }) {
            Some(0) => return After::Reboot,
            Some(1) => ui.shell(),
            _ => return After::Welcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert!(valid_hostname("oxide") && valid_hostname("a-b.example.org"));
        assert!(!valid_hostname("") && !valid_hostname("-x") && !valid_hostname("a..b") && !valid_hostname("x_y"));
        assert!(valid_cidr("10.0.2.15/24") && !valid_cidr("10.0.2.15") && !valid_cidr("10.0.2.256/24") && !valid_cidr("1.2.3.4/33"));
        assert!(valid_login("alice") && valid_login("_svc") && !valid_login("Alice") && !valid_login("1x") && !valid_login(""));
        assert_eq!(human(260 << 20), "260 MiB");
        assert_eq!(human(4 << 30), "4 GiB");
        assert_eq!(human(3 * (1 << 29)), "1.5 GiB");
    }

    #[test]
    fn one_root() {
        let u = |i, m: &str| Some(Use { index: i, kind: Kind::Oxfs, mount: Some(m.into()), newfs: true, grow: false });
        let mut uses = vec![u(1, "/"), u(2, "/usr"), u(3, "/")];
        dedupe(&mut uses, 2);
        assert_eq!(uses[0], None);
        assert!(uses[1].is_some() && uses[2].is_some());
    }
}
