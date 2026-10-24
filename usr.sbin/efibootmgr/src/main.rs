//! `efibootmgr(8)`: the firmware's boot entries (OxideBSD-doc `EFIRT.md` §6.2), with FreeBSD's
//! options and output, through `/dev/efi`.
//!
//! ```text
//! efibootmgr [-v]
//! efibootmgr -a | -A | -B -b bootnum
//! efibootmgr -c -l loader [-aD] [-b bootnum] [-L label]
//! efibootmgr -E [-d] [-p]
//! efibootmgr -f | -F
//! efibootmgr -n -b bootnum | -N
//! efibootmgr -o bootorder
//! efibootmgr -t timeout | -T
//! efibootmgr -u unix-path
//! ```
//!
//! An entry is a `Boot####` variable of the global GUID (`EFI_LOAD_OPTION`, `lib/libefivar`);
//! `BootOrder` lists the ones the firmware tries, in order, and `BootNext` the one it tries next
//! boot only. `-c` makes one for a loader on a mounted EFI system partition, its device path built
//! from the partition's GPT entry (`esp`), first in `BootOrder`. FreeBSD's `-k` and `-e` (a kernel
//! and environment for FreeBSD's own loader) have no use with Limine and aren't taken.

mod esp;

use std::process::ExitCode;

use efivar::dev::{Efi, NV_BS_RT};
use efivar::{Guid, LOAD_OPTION_ACTIVE, LoadOption, boot_name, devpath, encode_order, parse_boot_number, parse_order};

/// `EFI_OS_INDICATIONS_BOOT_TO_FW_UI`.
const BOOT_TO_FW_UI: u64 = 0x1;

fn global() -> Guid {
    Guid(efivar::guid::KNOWN[0].1)
}

#[derive(Default)]
struct Opts {
    verbose: bool,
    activate: bool,
    deactivate: bool,
    delete: bool,
    create: bool,
    dry_run: bool,
    esp: bool,
    esp_device_path: bool,
    esp_unix_path: bool,
    fw_ui: Option<bool>,
    bootnext: bool,
    delete_bootnext: bool,
    delete_timeout: bool,
    bootnum: Option<u16>,
    loader: Option<String>,
    label: Option<String>,
    order: Option<String>,
    timeout: Option<u16>,
    efidev: Option<String>,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: efibootmgr [-v]
       efibootmgr -a | -A | -B -b bootnum
       efibootmgr -c -l loader [-aD] [-b bootnum] [-L label]
       efibootmgr -E [-d] [-p]
       efibootmgr -f | -F
       efibootmgr -n -b bootnum | -N
       efibootmgr -o bootorder
       efibootmgr -t timeout | -T
       efibootmgr -u unix-path"
    );
    ExitCode::from(1)
}

/// A `u16` variable (`BootCurrent`, `BootNext`, `Timeout`).
fn read_u16(efi: &Efi, name: &str) -> Result<Option<u16>, String> {
    Ok(efi.get_opt(&global(), name).map_err(|e| format!("{name}: {e}"))?.and_then(|(d, _)| d.get(0..2).map(|b| u16::from_le_bytes([b[0], b[1]]))))
}

fn write_u16(efi: &Efi, name: &str, v: u16) -> Result<(), String> {
    efi.set(&global(), name, NV_BS_RT, &v.to_le_bytes()).map_err(|e| format!("{name}: {e}"))
}

fn boot_order(efi: &Efi) -> Result<Vec<u16>, String> {
    Ok(efi.get_opt(&global(), "BootOrder").map_err(|e| format!("BootOrder: {e}"))?.map_or_else(Vec::new, |(d, _)| parse_order(&d)))
}

fn set_boot_order(efi: &Efi, order: &[u16]) -> Result<(), String> {
    efi.set(&global(), "BootOrder", NV_BS_RT, &encode_order(order)).map_err(|e| format!("BootOrder: {e}"))
}

fn entry(efi: &Efi, n: u16) -> Result<Option<LoadOption>, String> {
    let name = boot_name(n);
    match efi.get_opt(&global(), &name).map_err(|e| format!("{name}: {e}"))? {
        Some((d, _)) => Ok(Some(LoadOption::parse(&d).ok_or(format!("{name}: not a load option"))?)),
        None => Ok(None),
    }
}

/// Every `Boot####` the firmware has, by number.
fn entries(efi: &Efi) -> Result<Vec<u16>, String> {
    let mut v: Vec<u16> = efi
        .list()
        .map_err(|e| format!("listing the variables: {e}"))?
        .into_iter()
        .filter(|(g, name)| *g == global() && name.len() == 8)
        .filter_map(|(_, name)| name.strip_prefix("Boot").and_then(parse_boot_number))
        .collect();
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

/// The listing: `BootNext`, `BootCurrent`, `Timeout`, `BootOrder`, then the entries in order
/// (`+` the one booted, `*` an active one); with `verbose`, each one's device path and where it
/// is here, and the entries `BootOrder` leaves out.
fn show(efi: &Efi, verbose: bool) -> Result<(), String> {
    let current = read_u16(efi, "BootCurrent")?;
    if let Some(n) = read_u16(efi, "BootNext")? {
        println!("BootNext   : {n:04X}");
    }
    if let Some(n) = current {
        println!("BootCurrent: {n:04X}");
    }
    if let Some(t) = read_u16(efi, "Timeout")? {
        println!("Timeout    : {t} seconds");
    }
    let order = boot_order(efi)?;
    let names: Vec<String> = order.iter().map(|n| format!("{n:04X}")).collect();
    println!("BootOrder  : {}", names.join(", "));
    let mut shown = order.clone();
    if verbose {
        for n in entries(efi)? {
            if !shown.contains(&n) {
                shown.push(n);
            }
        }
    }
    for n in shown {
        let Some(o) = entry(efi, n)? else { continue };
        println!(
            "{}{}{} {}",
            if current == Some(n) { "+" } else { " " },
            boot_name(n),
            if o.attributes & LOAD_OPTION_ACTIVE != 0 { "*" } else { " " },
            o.description
        );
        if verbose {
            println!("      {}", devpath::to_text(&o.path).unwrap_or_else(|| "(malformed device path)".into()));
            if let Some((dev, under)) = esp::unix_path(&o.path) {
                let file = devpath::file(&o.path).unwrap_or_default().replace('\\', "/");
                println!("         {}:{} {}", dev.trim_start_matches("/dev/"), file, under.unwrap_or_else(|| "(not mounted)".into()));
            }
        }
    }
    Ok(())
}

/// `-c`: a new entry for `loader`, first in `BootOrder`.
fn create(efi: &Efi, o: &Opts) -> Result<(), String> {
    let loader = o.loader.as_deref().ok_or("-c needs -l loader")?;
    let (path, _) = esp::device_path(loader)?;
    let existing = entries(efi)?;
    let n = match o.bootnum {
        Some(n) if existing.contains(&n) => return Err(format!("{} exists already", boot_name(n))),
        Some(n) => n,
        None => (0..=u16::MAX).find(|n| !existing.contains(n)).ok_or("no free entry number")?,
    };
    let label = o.label.clone().unwrap_or_else(|| {
        std::path::Path::new(loader).file_name().map_or("OxideBSD".into(), |f| f.to_string_lossy().into_owned())
    });
    let option = LoadOption { attributes: if o.activate { LOAD_OPTION_ACTIVE } else { 0 }, description: label, path, optional: Vec::new() };
    println!("{}{} {}", boot_name(n), if o.activate { "*" } else { "" }, option.description);
    if o.verbose || o.dry_run {
        println!("      {}", devpath::to_text(&option.path).unwrap_or_default());
    }
    if o.dry_run {
        return Ok(());
    }
    efi.set(&global(), &boot_name(n), NV_BS_RT, &option.encode()).map_err(|e| format!("{}: {e}", boot_name(n)))?;
    let mut order = boot_order(efi)?;
    order.retain(|&x| x != n);
    order.insert(0, n);
    set_boot_order(efi, &order)
}

fn set_active(efi: &Efi, n: u16, active: bool) -> Result<(), String> {
    let mut o = entry(efi, n)?.ok_or(format!("{}: no such entry", boot_name(n)))?;
    if active {
        o.attributes |= LOAD_OPTION_ACTIVE;
    } else {
        o.attributes &= !LOAD_OPTION_ACTIVE;
    }
    efi.set(&global(), &boot_name(n), NV_BS_RT, &o.encode()).map_err(|e| format!("{}: {e}", boot_name(n)))
}

/// `-B`: the entry goes, and out of `BootOrder` (and `BootNext`, if it was that).
fn delete(efi: &Efi, n: u16) -> Result<(), String> {
    entry(efi, n)?.ok_or(format!("{}: no such entry", boot_name(n)))?;
    efi.delete(&global(), &boot_name(n)).map_err(|e| format!("{}: {e}", boot_name(n)))?;
    let mut order = boot_order(efi)?;
    if order.contains(&n) {
        order.retain(|&x| x != n);
        set_boot_order(efi, &order)?;
    }
    if read_u16(efi, "BootNext")? == Some(n) {
        efi.delete(&global(), "BootNext").map_err(|e| format!("BootNext: {e}"))?;
    }
    Ok(())
}

/// `-o`: entry numbers in hex, comma-separated, each one there.
fn set_order(efi: &Efi, list: &str) -> Result<(), String> {
    let mut order = Vec::new();
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let n = parse_boot_number(item).ok_or(format!("{item}: not an entry number"))?;
        entry(efi, n)?.ok_or(format!("{}: no such entry", boot_name(n)))?;
        if order.contains(&n) {
            return Err(format!("{}: twice in the order", boot_name(n)));
        }
        order.push(n);
    }
    set_boot_order(efi, &order)
}

/// `-f`/`-F`: whether the firmware stops in its setup screens next boot (`OsIndications`).
fn set_fw_ui(efi: &Efi, on: bool) -> Result<(), String> {
    let cur = efi
        .get_opt(&global(), "OsIndications")
        .map_err(|e| format!("OsIndications: {e}"))?
        .and_then(|(d, _)| d.get(0..8).map(|b| u64::from_le_bytes(b.try_into().unwrap())))
        .unwrap_or(0);
    let new = if on { cur | BOOT_TO_FW_UI } else { cur & !BOOT_TO_FW_UI };
    efi.set(&global(), "OsIndications", NV_BS_RT, &new.to_le_bytes()).map_err(|e| format!("OsIndications: {e}"))
}

/// `-E`: the EFI system partition the running system was booted from (`BootCurrent`'s entry).
fn show_esp(efi: &Efi, o: &Opts) -> Result<(), String> {
    let n = read_u16(efi, "BootCurrent")?.ok_or("no BootCurrent: the firmware didn't say what it booted")?;
    let e = entry(efi, n)?.ok_or(format!("{}: no such entry", boot_name(n)))?;
    if o.esp_device_path {
        let (part, start, size, guid) = devpath::hard_drive(&e.path).ok_or(format!("{}: not on a GPT partition", boot_name(n)))?;
        let mut dp = devpath::hard_drive_gpt(part, start, size, guid.0);
        dp.extend(devpath::end());
        println!("{}", devpath::to_text(&dp).unwrap_or_default());
        return Ok(());
    }
    let (dev, under) = esp::unix_path(&e.path).ok_or(format!("{}: its partition isn't on this machine's disks", boot_name(n)))?;
    if o.esp_unix_path {
        let file = devpath::file(&e.path).unwrap_or_default().replace('\\', "/");
        let mount = under.as_deref().and_then(|u| u.strip_suffix(&file)).ok_or(format!("{dev}: not mounted"))?;
        println!("{mount}");
    } else {
        println!("{dev}");
    }
    Ok(())
}

fn run(o: &Opts) -> Result<(), String> {
    if let Some(path) = &o.efidev {
        let (dp, _) = esp::device_path(path)?;
        println!("{}", devpath::to_text(&dp).unwrap_or_default());
        return Ok(());
    }
    let writing = o.create && !o.dry_run
        || o.activate
        || o.deactivate
        || o.delete
        || o.bootnext
        || o.delete_bootnext
        || o.order.is_some()
        || o.timeout.is_some()
        || o.delete_timeout
        || o.fw_ui.is_some();
    let efi = Efi::open(writing).map_err(|e| format!("{}: {e}", efivar::dev::DEVICE))?;
    let bootnum = || o.bootnum.ok_or("needs -b bootnum");
    if o.create {
        return create(&efi, o);
    }
    if o.esp {
        return show_esp(&efi, o);
    }
    if o.activate || o.deactivate {
        return set_active(&efi, bootnum()?, o.activate);
    }
    if o.delete {
        return delete(&efi, bootnum()?);
    }
    if o.bootnext {
        let n = bootnum()?;
        entry(&efi, n)?.ok_or(format!("{}: no such entry", boot_name(n)))?;
        return write_u16(&efi, "BootNext", n);
    }
    if o.delete_bootnext {
        return efi.delete(&global(), "BootNext").map_err(|e| format!("BootNext: {e}"));
    }
    if let Some(list) = &o.order {
        return set_order(&efi, list);
    }
    if let Some(t) = o.timeout {
        return write_u16(&efi, "Timeout", t);
    }
    if o.delete_timeout {
        return efi.delete(&global(), "Timeout").map_err(|e| format!("Timeout: {e}"));
    }
    if let Some(on) = o.fw_ui {
        return set_fw_ui(&efi, on);
    }
    show(&efi, o.verbose)
}

fn main() -> ExitCode {
    // SAFETY: back to the default, so `efibootmgr -v | grep -q ...` ends quietly when the reader
    // goes, as the BSDs' tools do, rather than failing a write.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let flags: Vec<char> = match a {
            "--verbose" => vec!['v'],
            "--activate" => vec!['a'],
            "--deactivate" => vec!['A'],
            "--bootnum" => vec!['b'],
            "--delete" => vec!['B'],
            "--create" => vec!['c'],
            "--dry-run" => vec!['D'],
            "--device-path" => vec!['d'],
            "--esp" => vec!['E'],
            "--fw-ui" => vec!['f'],
            "--no-fw-ui" => vec!['F'],
            "--loader" => vec!['l'],
            "--label" => vec!['L'],
            "--bootnext" => vec!['n'],
            "--delete-bootnext" => vec!['N'],
            "--bootorder" => vec!['o'],
            "--unix-path" => vec!['p'],
            "--set-timeout" => vec!['t'],
            "--del-timeout" => vec!['T'],
            "--efidev" => vec!['u'],
            "--kernel" | "--env" => vec!['k'],
            _ if a.len() > 1 && a.starts_with('-') && !a.starts_with("--") => a[1..].chars().collect(),
            _ => return usage(),
        };
        for c in flags {
            let mut value = || {
                i += 1;
                args.get(i).cloned()
            };
            match c {
                'v' => o.verbose = true,
                'a' => o.activate = true,
                'A' => o.deactivate = true,
                'B' => o.delete = true,
                'c' => o.create = true,
                'D' => o.dry_run = true,
                'd' => o.esp_device_path = true,
                'E' => o.esp = true,
                'f' => o.fw_ui = Some(true),
                'F' => o.fw_ui = Some(false),
                'n' => o.bootnext = true,
                'N' => o.delete_bootnext = true,
                'p' => o.esp_unix_path = true,
                'T' => o.delete_timeout = true,
                'b' => match value().as_deref().and_then(parse_boot_number) {
                    Some(n) => o.bootnum = Some(n),
                    None => return usage(),
                },
                'l' => match value() {
                    Some(v) => o.loader = Some(v),
                    None => return usage(),
                },
                'L' => match value() {
                    Some(v) => o.label = Some(v),
                    None => return usage(),
                },
                'o' => match value() {
                    Some(v) => o.order = Some(v),
                    None => return usage(),
                },
                't' => match value().and_then(|v| v.parse().ok()) {
                    Some(v) => o.timeout = Some(v),
                    None => return usage(),
                },
                'u' => match value() {
                    Some(v) => o.efidev = Some(v),
                    None => return usage(),
                },
                'k' | 'e' => {
                    eprintln!("efibootmgr: -{c}: for FreeBSD's loader, which OxideBSD doesn't use");
                    return ExitCode::from(1);
                }
                _ => return usage(),
            }
        }
        i += 1;
    }
    match run(&o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("efibootmgr: {e}");
            ExitCode::from(1)
        }
    }
}
