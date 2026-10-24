//! The answers to an install: from an `installerconfig` file (`installer -f`, OxideBSD-doc
//! `INSTALLER.md` §9.4), or, with the screens, from the user.
//!
//! An `installerconfig` is FreeBSD's: a preamble of shell variable assignments, then optionally a
//! line `#!/bin/sh` and a script run in the new system once it's installed. The preamble is run
//! with `/bin/sh`, as bsdinstall does, so it may use anything the shell can; what's read from it
//! is `PARTITIONS`, `DISTRIBUTIONS`, and OxideBSD's `HOSTNAME`, `KEYMAP` and `ROOTPASS`.

use std::process::Command;

use part::{Kind, Scheme};

/// One partition to make.
#[derive(Clone, Debug, PartialEq)]
pub struct PartSpec {
    /// Its size in bytes; `None` for `auto`, what's left.
    pub size: Option<u64>,
    pub kind: Kind,
    /// Where it's mounted (an oxfs partition): `/`, `/usr`, ...
    pub mount: Option<String>,
}

/// How the disk is laid out.
#[derive(Clone, Debug, PartialEq)]
pub enum Layout {
    /// The guided layout (`INSTALLER.md` §9.5) on this disk, or on the first one.
    Guided(Option<String>),
    /// These partitions, in a new table of `scheme`, on `disk`.
    Explicit { disk: String, scheme: Scheme, parts: Vec<PartSpec> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub layout: Layout,
    /// The sets' file names, `base.tar.zst` first.
    pub sets: Vec<String>,
    pub hostname: Option<String>,
    pub keymap: Option<String>,
    pub rootpass: Option<String>,
    /// The script after the preamble's `#!/bin/sh` line, run in the new system.
    pub script: Option<String>,
}

/// The guided layout's partitions on a blank disk: a BIOS boot partition, an EFI system
/// partition (FreeBSD's 260 MiB), and `/` over the rest.
pub fn guided_parts() -> Vec<PartSpec> {
    vec![
        PartSpec { size: Some(512 << 10), kind: Kind::BiosBoot, mount: None },
        PartSpec { size: Some(260 << 20), kind: Kind::Efi, mount: None },
        PartSpec { size: None, kind: Kind::Oxfs, mount: Some("/".into()) },
    ]
}

/// `512K`, `260M`, `20G`, `1T` or plain bytes.
fn parse_size(s: &str) -> Option<u64> {
    let (digits, shift) = match s.as_bytes().last()?.to_ascii_uppercase() {
        b'K' => (&s[..s.len() - 1], 10),
        b'M' => (&s[..s.len() - 1], 20),
        b'G' => (&s[..s.len() - 1], 30),
        b'T' => (&s[..s.len() - 1], 40),
        _ => (s, 0),
    };
    digits.parse::<u64>().ok()?.checked_mul(1 << shift).filter(|&n| n > 0)
}

/// A partition type's name: OxideBSD's, and FreeBSD's where one means the same.
fn parse_kind(s: &str) -> Option<Kind> {
    match s {
        "bios" | "freebsd-boot" => Some(Kind::BiosBoot),
        "freebsd-swap" => Some(Kind::Swap),
        _ => Kind::parse(s),
    }
}

/// `PARTITIONS`: `DEFAULT`, a disk alone (the guided layout on it), or FreeBSD's
/// `disk [scheme] { size type [mountpoint], ... }`.
pub fn parse_partitions(s: &str) -> Result<Layout, String> {
    let s = s.trim();
    if s.is_empty() || s == "DEFAULT" {
        return Ok(Layout::Guided(None));
    }
    let (head, body) = match s.find('{') {
        Some(i) => {
            let body = s[i + 1..].trim_end();
            let body = body.strip_suffix('}').ok_or("PARTITIONS: no closing }")?;
            (&s[..i], Some(body))
        }
        None => (s, None),
    };
    let words: Vec<&str> = head.split_whitespace().collect();
    let (disk, scheme) = match words.as_slice() {
        [disk] => (disk.to_string(), None),
        [disk, scheme] => (disk.to_string(), Some(*scheme)),
        _ => return Err(format!("PARTITIONS: `{head}`: expected a disk and a scheme")),
    };
    let Some(body) = body else {
        if scheme.is_some() {
            return Err("PARTITIONS: a scheme without partitions".into());
        }
        return Ok(Layout::Guided(Some(disk)));
    };
    let scheme = match scheme.map(|s| s.to_ascii_uppercase()).as_deref() {
        None | Some("GPT") => Scheme::Gpt,
        Some("MBR") => Scheme::Mbr,
        Some(other) => return Err(format!("PARTITIONS: {other}: the schemes are GPT and MBR")),
    };
    let mut parts = Vec::new();
    for item in body.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let w: Vec<&str> = item.split_whitespace().collect();
        let (size, kind, mount) = match w.as_slice() {
            [size, kind] => (*size, *kind, None),
            [size, kind, mount] => (*size, *kind, Some(mount.to_string())),
            _ => return Err(format!("PARTITIONS: `{item}`: expected size type [mountpoint]")),
        };
        let size = if size == "auto" { None } else { Some(parse_size(size).ok_or(format!("PARTITIONS: {size}: not a size"))?) };
        let kind = parse_kind(kind).ok_or(format!("PARTITIONS: {kind}: not a partition type"))?;
        if let Some(m) = &mount {
            if kind != Kind::Oxfs || !m.starts_with('/') {
                return Err(format!("PARTITIONS: `{item}`: only an oxfs partition is mounted, on an absolute path"));
            }
        }
        parts.push(PartSpec { size, kind, mount });
    }
    if parts.iter().filter(|p| p.size.is_none()).count() > 1 {
        return Err("PARTITIONS: only one partition may be auto".into());
    }
    if !parts.iter().any(|p| p.mount.as_deref() == Some("/")) {
        return Err("PARTITIONS: no oxfs partition is mounted on /".into());
    }
    Ok(Layout::Explicit { disk, scheme, parts })
}

/// `DISTRIBUTIONS`: the set files, `base.tar.zst` always among them and first.
pub fn parse_sets(s: &str) -> Vec<String> {
    let mut sets = vec!["base.tar.zst".to_string()];
    for w in s.split_whitespace() {
        if !sets.iter().any(|x| x == w) {
            sets.push(w.to_string());
        }
    }
    sets
}

/// Splits an `installerconfig` into its preamble and the script after `#!/bin/sh`.
pub fn split(text: &str) -> (&str, Option<&str>) {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end() == "#!/bin/sh" {
            return (&text[..at], Some(&text[at..]));
        }
        at += line.len();
    }
    (text, None)
}

/// Reads `installerconfig` file `path`: its preamble run by `/bin/sh` for the variables.
pub fn read(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (preamble, script) = split(&text);
    let pre = "/tmp/installer.preamble";
    std::fs::write(pre, preamble).map_err(|e| format!("{pre}: {e}"))?;
    let out = Command::new("/bin/sh")
        .args(["-c", r#". "$1" && printf '%s\0' "$PARTITIONS" "$DISTRIBUTIONS" "$HOSTNAME" "$KEYMAP" "$ROOTPASS""#, "sh", pre])
        .output()
        .map_err(|e| format!("/bin/sh: {e}"))?;
    let _ = std::fs::remove_file(pre);
    if !out.status.success() {
        return Err(format!("{path}: its preamble failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let values: Vec<String> = out.stdout.split(|&b| b == 0).map(|v| String::from_utf8_lossy(v).into_owned()).collect();
    let get = |i: usize| values.get(i).filter(|v| !v.is_empty()).cloned();
    Ok(Config {
        layout: parse_partitions(&get(0).unwrap_or_default())?,
        sets: parse_sets(&get(1).unwrap_or_default()),
        hostname: get(2),
        keymap: get(3),
        rootpass: get(4),
        script: script.map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions() {
        assert_eq!(parse_partitions("DEFAULT"), Ok(Layout::Guided(None)));
        assert_eq!(parse_partitions(""), Ok(Layout::Guided(None)));
        assert_eq!(parse_partitions("ide0"), Ok(Layout::Guided(Some("ide0".into()))));
        let l = parse_partitions("ide0 GPT { 512K bios, 260M efi, 2G oxfs /, auto oxfs /home, 1G swap }").unwrap();
        let Layout::Explicit { disk, scheme, parts } = l else { panic!() };
        assert_eq!((disk.as_str(), scheme), ("ide0", Scheme::Gpt));
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], PartSpec { size: Some(512 << 10), kind: Kind::BiosBoot, mount: None });
        assert_eq!(parts[3], PartSpec { size: None, kind: Kind::Oxfs, mount: Some("/home".into()) });
        assert_eq!(parts[4].kind, Kind::Swap);
        assert!(matches!(parse_partitions("virt0 MBR { auto oxfs / }"), Ok(Layout::Explicit { scheme: Scheme::Mbr, .. })));
        for bad in [
            "ide0 GPT { auto oxfs /, auto oxfs /usr }",
            "ide0 GPT { 1G oxfs /usr }",
            "ide0 GPT { 1G efi /boot }",
            "ide0 ZFS { auto oxfs / }",
            "ide0 GPT { 1Q oxfs / }",
            "ide0 GPT { auto oxfs /",
            "ide0 GPT",
        ] {
            assert!(parse_partitions(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sets_and_script() {
        assert_eq!(parse_sets("clang.tar.zst base.tar.zst"), ["base.tar.zst", "clang.tar.zst"]);
        assert_eq!(parse_sets(""), ["base.tar.zst"]);
        let (pre, script) = split("PARTITIONS=DEFAULT\n#!/bin/sh\necho hi\n");
        assert_eq!(pre, "PARTITIONS=DEFAULT\n");
        assert_eq!(script, Some("#!/bin/sh\necho hi\n"));
        assert_eq!(split("A=1\n"), ("A=1\n", None));
    }
}
