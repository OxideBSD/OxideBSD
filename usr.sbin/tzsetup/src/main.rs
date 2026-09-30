//! `tzsetup(8)`: chooses the local time zone (OxideBSD-doc `TIMEZONE.md` §5).
//!
//! ```text
//! tzsetup [-nr] [zone]
//! ```
//!
//! `/etc/localtime` becomes a symbolic link to the zone's file under `/usr/share/zoneinfo`
//! (§4.1), after checking the file is a valid `tzfile(5)`. Without a zone, numbered menus offer
//! the regions and zones of `zone1970.tab`, and UTC (§5.2). `-r` re-creates the link from its
//! own target, after a database update; `-n` only says what would be done (§5.3).

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Where the files are. `TZSETUP_ROOT`, if set, prefixes both paths; it exists only so the host
/// tests can run in a scratch directory, and is deliberately not documented in the manual page.
struct Paths {
    localtime: PathBuf,
    zoneinfo: PathBuf,
}

impl Paths {
    fn from_env() -> Paths {
        let root = std::env::var_os("TZSETUP_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
        Paths::under(&root)
    }

    fn under(root: &Path) -> Paths {
        Paths { localtime: root.join("etc/localtime"), zoneinfo: root.join("usr/share/zoneinfo") }
    }
}

/// The link target written: always the absolute database path, whatever `TZSETUP_ROOT` is, so
/// the link means the same thing on the installed system.
const ZONEINFO: &str = "/usr/share/zoneinfo";

/// A zone name must be a relative path inside the database: no empty, `.` or `..` components.
fn check_name(zone: &str) -> Result<(), String> {
    if zone.is_empty() || zone.starts_with('/') || zone.ends_with('/') {
        return Err(format!("{zone}: not a zone name"));
    }
    if zone.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(format!("{zone}: not a zone name"));
    }
    Ok(())
}

/// Checks `data` is a `tzfile(5)` (RFC 8536): the `TZif` magic, a known version, and a version 1
/// data block as long as its header's counts say; for version 2 and later, the second header
/// that follows it.
fn check_tzfile(data: &[u8]) -> Result<(), String> {
    const HEADER: usize = 44;
    let header = |at: usize| -> Result<usize, String> {
        let h = data.get(at..at + HEADER).ok_or("truncated header")?;
        if &h[..4] != b"TZif" {
            return Err("not a tzfile (no TZif magic)".into());
        }
        if !matches!(h[4], 0 | b'2' | b'3' | b'4') {
            return Err(format!("unknown tzfile version {:#04x}", h[4]));
        }
        let count = |i: usize| u32::from_be_bytes(h[20 + i * 4..24 + i * 4].try_into().unwrap()) as usize;
        let (isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt) =
            (count(0), count(1), count(2), count(3), count(4), count(5));
        if typecnt == 0 || charcnt == 0 {
            return Err("tzfile has no local time types".into());
        }
        Ok(timecnt * 5 + typecnt * 6 + charcnt + leapcnt * 8 + isstdcnt + isutcnt)
    };
    let v1 = header(0)?;
    if data.len() < HEADER + v1 {
        return Err("truncated tzfile".into());
    }
    if data[4] != 0 {
        header(HEADER + v1)?;
    }
    Ok(())
}

/// Validates `zone` and reads its file.
fn check_zone(paths: &Paths, zone: &str) -> Result<(), String> {
    check_name(zone)?;
    let file = paths.zoneinfo.join(zone);
    let meta = std::fs::metadata(&file).map_err(|e| format!("{zone}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{zone}: not a zone file"));
    }
    let data = std::fs::read(&file).map_err(|e| format!("{zone}: {e}"))?;
    check_tzfile(&data).map_err(|e| format!("{zone}: {e}"))
}

/// Points `/etc/localtime` at `zone`: a new link beside it, renamed over it, so the old one stays
/// until the new one is complete.
fn install(paths: &Paths, zone: &str, dry_run: bool, out: &mut dyn Write) -> Result<(), String> {
    check_zone(paths, zone)?;
    let target = format!("{ZONEINFO}/{zone}");
    if dry_run {
        let _ = writeln!(out, "ln -sf {target} /etc/localtime");
        return Ok(());
    }
    let tmp = paths.localtime.with_file_name(format!("localtime.tzsetup.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(&target, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &paths.localtime).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", paths.localtime.display())
    })
}

/// The zone the current link names (`-r`): its target, less the database directory.
fn current_zone(paths: &Paths) -> Result<String, String> {
    let target = std::fs::read_link(&paths.localtime)
        .map_err(|e| format!("/etc/localtime: not a link to a zone ({e})"))?;
    let target = target.to_string_lossy().into_owned();
    let zone = if let Some(rest) = target.strip_prefix(&format!("{ZONEINFO}/")) {
        rest.to_string()
    } else if let Some(i) = target.find("share/zoneinfo/").filter(|_| !target.starts_with('/')) {
        // A relative link, `../usr/share/zoneinfo/Zone`.
        target[i + "share/zoneinfo/".len()..].to_string()
    } else {
        return Err(format!("/etc/localtime: {target} is not in {ZONEINFO}"));
    };
    check_name(&zone)?;
    Ok(zone)
}

/// A line of `zone1970.tab`: the zone, its countries' codes, and its comment.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    zone: String,
    countries: Vec<String>,
    comment: String,
}

fn parse_zone_tab(text: &str) -> Vec<Entry> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let zone = f.get(2)?.trim();
            Some(Entry {
                zone: zone.to_string(),
                countries: f[0].split(',').map(|c| c.trim().to_string()).collect(),
                comment: f.get(3).map(|c| c.trim().to_string()).unwrap_or_default(),
            })
        })
        .collect()
}

fn parse_iso3166(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(code, name)| (code.trim().to_string(), name.trim().to_string()))
        .collect()
}

/// Zones by region (the part of the name before the first `/`), each sorted by name.
fn by_region(entries: &[Entry]) -> BTreeMap<String, Vec<Entry>> {
    let mut regions: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    for e in entries {
        if let Some((region, _)) = e.zone.split_once('/') {
            regions.entry(region.to_string()).or_default().push(e.clone());
        }
    }
    for zones in regions.values_mut() {
        zones.sort_by(|a, b| a.zone.cmp(&b.zone));
    }
    regions
}

/// How a zone is shown in its region's menu: `Berlin (Germany: most of Germany)`.
fn label(e: &Entry, names: &BTreeMap<String, String>) -> String {
    let within = e.zone.split_once('/').map_or(e.zone.as_str(), |(_, rest)| rest);
    let country = e.countries.first().and_then(|c| names.get(c)).cloned().unwrap_or_default();
    match (country.is_empty(), e.comment.is_empty()) {
        (true, true) => within.to_string(),
        (false, true) => format!("{within} ({country})"),
        (true, false) => format!("{within} ({})", e.comment),
        (false, false) => format!("{within} ({country}: {})", e.comment),
    }
}

/// Prints `items` numbered from 1, in as many columns as fit in `width`, down each column.
fn print_menu(out: &mut dyn Write, items: &[String], width: usize) {
    let numw = items.len().to_string().len();
    let cell = items.iter().map(|s| s.chars().count()).max().unwrap_or(0) + numw + 4;
    let cols = (width / cell).clamp(1, 4);
    let rows = items.len().div_ceil(cols);
    for r in 0..rows {
        let mut line = String::new();
        for c in 0..cols {
            let i = c * rows + r;
            if i < items.len() {
                let entry = format!("{:>numw$}. {}", i + 1, items[i]);
                if c + 1 < cols && (c + 1) * rows + r < items.len() {
                    line.push_str(&format!("{entry:<cell$}"));
                } else {
                    line.push_str(&entry);
                }
            }
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
}

enum Answer {
    Pick(usize),
    Back,
    Quit,
}

/// Asks for a number from 1 to `n`, `b` or `q`, until one comes; end of input is `q`.
fn ask(input: &mut dyn BufRead, out: &mut dyn Write, prompt: &str, n: usize) -> Answer {
    loop {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut line = String::new();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            let _ = writeln!(out);
            return Answer::Quit;
        }
        match line.trim() {
            "q" | "quit" => return Answer::Quit,
            "b" | "back" => return Answer::Back,
            s => match s.parse::<usize>() {
                Ok(i) if (1..=n).contains(&i) => return Answer::Pick(i - 1),
                _ => {
                    let _ = writeln!(out, "Please enter a number from 1 to {n}, b to go back, or q to quit.");
                }
            },
        }
    }
}

/// Yes or no; end of input is no.
fn confirm(input: &mut dyn BufRead, out: &mut dyn Write, question: &str) -> bool {
    loop {
        let _ = write!(out, "{question} [y/n] ");
        let _ = out.flush();
        let mut line = String::new();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            let _ = writeln!(out);
            return false;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {}
        }
    }
}

/// The menus of §5.2: a region (or UTC), then a zone in it, then confirmation. `None` if the user
/// quits.
fn choose(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    entries: &[Entry],
    names: &BTreeMap<String, String>,
    width: usize,
) -> Option<String> {
    let regions = by_region(entries);
    let mut region_items: Vec<String> = regions.keys().cloned().collect();
    region_items.push("UTC".into());
    loop {
        let _ = writeln!(out, "Select a region:");
        print_menu(out, &region_items, width);
        let region = match ask(input, out, "Region (number, or q to quit): ", region_items.len()) {
            Answer::Pick(i) => i,
            Answer::Back => continue,
            Answer::Quit => return None,
        };
        let zone = if region == region_items.len() - 1 {
            "UTC".to_string()
        } else {
            let zones = &regions[&region_items[region]];
            let items: Vec<String> = zones.iter().map(|e| label(e, names)).collect();
            let _ = writeln!(out, "Select a time zone in {}:", region_items[region]);
            print_menu(out, &items, width);
            match ask(input, out, "Time zone (number, b to go back, q to quit): ", items.len()) {
                Answer::Pick(i) => zones[i].zone.clone(),
                Answer::Back => continue,
                Answer::Quit => return None,
            }
        };
        if confirm(input, out, &format!("Set the time zone to {zone}?")) {
            return Some(zone);
        }
    }
}

/// The terminal's width, or 80.
fn terminal_width() -> usize {
    // SAFETY: an all-zero winsize is valid; TIOCGWINSZ fills it or fails.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0;
    if ok && ws.ws_col > 0 { ws.ws_col as usize } else { 80 }
}

fn usage() -> ExitCode {
    eprintln!("usage: tzsetup [-nr] [zone]");
    ExitCode::from(1)
}

fn run(paths: &Paths, dry_run: bool, refresh: bool, zone: Option<String>) -> Result<(), String> {
    let mut out = std::io::stdout();
    if refresh {
        let zone = current_zone(paths)?;
        return install(paths, &zone, dry_run, &mut out);
    }
    let zone = match zone {
        Some(z) => z,
        None => {
            let read = |f: &str| {
                std::fs::read_to_string(paths.zoneinfo.join(f)).map_err(|e| format!("{ZONEINFO}/{f}: {e}"))
            };
            let entries = parse_zone_tab(&read("zone1970.tab")?);
            let names = read("iso3166.tab").map(|t| parse_iso3166(&t)).unwrap_or_default();
            let stdin = std::io::stdin();
            match choose(&mut stdin.lock(), &mut out, &entries, &names, terminal_width()) {
                Some(z) => z,
                None => return Ok(()),
            }
        }
    };
    install(paths, &zone, dry_run, &mut out)
}

fn main() -> ExitCode {
    let mut dry_run = false;
    let mut refresh = false;
    let mut zone = None;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" => {
                zone = args.next();
                break;
            }
            a if a.starts_with('-') && a.len() > 1 => {
                for c in a[1..].chars() {
                    match c {
                        'n' => dry_run = true,
                        'r' => refresh = true,
                        _ => return usage(),
                    }
                }
            }
            _ => {
                zone = Some(arg);
                break;
            }
        }
    }
    if args.next().is_some() || (refresh && zone.is_some()) {
        return usage();
    }
    match run(&Paths::from_env(), dry_run, refresh, zone) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tzsetup: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid TZif version 2 file: one type ("UTC"), no transitions, in both blocks.
    fn tzif2() -> Vec<u8> {
        let block = |v: u8| {
            let mut b = Vec::new();
            b.extend_from_slice(b"TZif");
            b.push(v);
            b.extend_from_slice(&[0; 15]);
            for c in [0u32, 0, 0, 0, 1, 4] {
                b.extend_from_slice(&c.to_be_bytes());
            }
            b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // utoff 0, isdst 0, desigidx 0
            b.extend_from_slice(b"UTC\0");
            b
        };
        let mut f = block(b'2');
        f.extend(block(b'2'));
        f.extend_from_slice(b"\nUTC0\n");
        f
    }

    fn good_zone() -> Vec<u8> {
        std::fs::read("/usr/share/zoneinfo/Europe/Berlin").unwrap_or_else(|_| tzif2())
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let d = std::env::temp_dir().join(format!("tzsetup-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(d.join("etc")).unwrap();
            std::fs::create_dir_all(d.join("usr/share/zoneinfo/Europe")).unwrap();
            std::fs::write(d.join("usr/share/zoneinfo/Europe/Berlin"), good_zone()).unwrap();
            std::fs::write(d.join("usr/share/zoneinfo/UTC"), tzif2()).unwrap();
            std::fs::write(d.join("usr/share/zoneinfo/Bad"), b"not a zone").unwrap();
            Scratch(d)
        }
        fn paths(&self) -> Paths {
            Paths::under(&self.0)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tzfiles() {
        assert_eq!(check_tzfile(&tzif2()), Ok(()));
        assert_eq!(check_tzfile(&good_zone()), Ok(()));
        let f = tzif2();
        assert!(check_tzfile(&f[..30]).is_err());
        assert!(check_tzfile(&f[..50]).is_err());
        let mut bad = f.clone();
        bad[0] = b'X';
        assert!(check_tzfile(&bad).is_err());
        let mut v9 = f.clone();
        v9[4] = b'9';
        assert!(check_tzfile(&v9).is_err());
        // Version 2 without its second header.
        assert!(check_tzfile(&f[..f.len() / 2]).is_err());
    }

    #[test]
    fn names() {
        assert!(check_name("Europe/Berlin").is_ok());
        assert!(check_name("UTC").is_ok());
        for bad in ["", "/etc/passwd", "../x", "Europe/../../x", "Europe//Berlin", "Europe/", "./UTC"] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn install_and_refresh() {
        let s = Scratch::new("install");
        let p = s.paths();
        let mut out = Vec::new();
        install(&p, "Europe/Berlin", false, &mut out).unwrap();
        assert!(out.is_empty());
        assert_eq!(std::fs::read_link(&p.localtime).unwrap(), PathBuf::from("/usr/share/zoneinfo/Europe/Berlin"));
        // Replacing a regular file too.
        std::fs::remove_file(&p.localtime).unwrap();
        std::fs::write(&p.localtime, b"old").unwrap();
        install(&p, "UTC", false, &mut out).unwrap();
        assert_eq!(std::fs::read_link(&p.localtime).unwrap(), PathBuf::from("/usr/share/zoneinfo/UTC"));
        assert_eq!(current_zone(&p).unwrap(), "UTC");
        // Failures leave the link alone.
        for bad in ["Bad", "Nope/Zone", "../etc", "Europe"] {
            assert!(install(&p, bad, false, &mut out).is_err(), "{bad}");
            assert_eq!(std::fs::read_link(&p.localtime).unwrap(), PathBuf::from("/usr/share/zoneinfo/UTC"));
        }
        // -n.
        install(&p, "Europe/Berlin", true, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime\n");
        assert_eq!(current_zone(&p).unwrap(), "UTC");
        // A relative link is understood; one outside the database isn't.
        std::fs::remove_file(&p.localtime).unwrap();
        std::os::unix::fs::symlink("../usr/share/zoneinfo/Europe/Berlin", &p.localtime).unwrap();
        assert_eq!(current_zone(&p).unwrap(), "Europe/Berlin");
        std::fs::remove_file(&p.localtime).unwrap();
        std::os::unix::fs::symlink("/somewhere/else", &p.localtime).unwrap();
        assert!(current_zone(&p).is_err());
        std::fs::remove_file(&p.localtime).unwrap();
        assert!(current_zone(&p).is_err());
        // No stray temporary links.
        assert!(std::fs::read_dir(s.0.join("etc")).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains("tzsetup")));
    }

    const TAB: &str = "# comment\nDE,DK,NO,SE,SJ\t+5230+01322\tEurope/Berlin\tmost of Germany\n\
                       FR,MC\t+4852+00220\tEurope/Paris\n\
                       US\t+404251-0740023\tAmerica/New_York\tEastern (most areas)\n\
                       AR\t-3436-05827\tAmerica/Argentina/Buenos_Aires\tBuenos Aires (BA, CF)\n";
    const ISO: &str = "# c\nDE\tGermany\nFR\tFrance\nUS\tUnited States\n";

    #[test]
    fn tables() {
        let e = parse_zone_tab(TAB);
        assert_eq!(e.len(), 4);
        assert_eq!(e[0].countries, ["DE", "DK", "NO", "SE", "SJ"]);
        assert_eq!(e[1].comment, "");
        let r = by_region(&e);
        assert_eq!(r.keys().collect::<Vec<_>>(), ["America", "Europe"]);
        assert_eq!(r["America"][0].zone, "America/Argentina/Buenos_Aires");
        let names = parse_iso3166(ISO);
        assert_eq!(label(&e[0], &names), "Berlin (Germany: most of Germany)");
        assert_eq!(label(&e[1], &names), "Paris (France)");
        assert_eq!(label(&r["America"][0], &names), "Argentina/Buenos_Aires (Buenos Aires (BA, CF))");
    }

    fn drive(script: &str) -> (Option<String>, String) {
        let e = parse_zone_tab(TAB);
        let names = parse_iso3166(ISO);
        let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();
        let z = choose(&mut input, &mut out, &e, &names, 80);
        (z, String::from_utf8(out).unwrap())
    }

    #[test]
    fn menus() {
        // Regions: 1 America, 2 Europe, 3 UTC. Europe's zones: 1 Berlin, 2 Paris.
        assert_eq!(drive("2\n1\ny\n").0.as_deref(), Some("Europe/Berlin"));
        assert_eq!(drive("3\ny\n").0.as_deref(), Some("UTC"));
        // Back from the zones, invalid input, then no, then another choice.
        assert_eq!(drive("2\nb\n9\nx\n1\n2\nn\n2\n2\nyes\n").0.as_deref(), Some("Europe/Paris"));
        let (_, out) = drive("9\nq\n");
        assert!(out.contains("Please enter a number from 1 to 3"));
        assert_eq!(drive("q\n").0, None);
        assert_eq!(drive("2\nq\n").0, None);
        // End of input quits.
        assert_eq!(drive("").0, None);
        assert_eq!(drive("2\n1\n").0, None);
    }

    #[test]
    fn columns() {
        let items: Vec<String> = (0..10).map(|i| format!("item{i}")).collect();
        let mut out = Vec::new();
        print_menu(&mut out, &items, 80);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.lines().next().unwrap().starts_with(" 1. item0"));
        let mut out = Vec::new();
        print_menu(&mut out, &items, 10);
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 10);
    }
}
