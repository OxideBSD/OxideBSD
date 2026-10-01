//! `/etc/fstab` (`fstab(5)`): the file systems to mount, one per line, in the BSDs' format.
//!
//! ```text
//! # Device   Mountpoint   FStype   Options   Dump   Pass#
//! oxfs       /            oxfs     rw        1      1
//! tmpfs      /tmp         tmpfs    rw        0      0
//! /usr/src   /mnt/src     nullfs   rw,noauto 0      0
//! ```
//!
//! Fields are separated by blanks; `#` starts a comment. The options are comma-separated; `noauto`
//! keeps `mount -a` from mounting an entry, and `sw` marks a swap device (`mount` ignores it).
//! Dump and pass may be left out (0). As on the BSDs, `\040` in a field is a space.

pub const PATH: &str = "/etc/fstab";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// What to mount: a device, a directory for nullfs, or the file system's name.
    pub spec: String,
    /// Where.
    pub file: String,
    pub vfstype: String,
    pub options: Vec<String>,
    pub freq: u32,
    pub passno: u32,
}

impl Entry {
    pub fn has_option(&self, o: &str) -> bool {
        self.options.iter().any(|x| x == o)
    }
}

fn unescape(field: &str) -> String {
    field.replace("\\040", " ")
}

/// Parses an fstab: the entries, and for each line that isn't one, its number (from 1) and why.
pub fn parse(text: &str) -> (Vec<Entry>, Vec<(usize, String)>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f.len() < 4 || f.len() > 6 {
            errors.push((i + 1, format!("{} fields, not 4 to 6", f.len())));
            continue;
        }
        let num = |k: usize| f.get(k).map_or(Ok(0), |v| v.parse::<u32>());
        let (Ok(freq), Ok(passno)) = (num(4), num(5)) else {
            errors.push((i + 1, "dump and pass must be numbers".into()));
            continue;
        };
        entries.push(Entry {
            spec: unescape(f[0]),
            file: unescape(f[1]),
            vfstype: f[2].to_string(),
            options: f[3].split(',').filter(|o| !o.is_empty()).map(String::from).collect(),
            freq,
            passno,
        });
    }
    (entries, errors)
}

/// Reads `/etc/fstab`; a missing file has no entries.
pub fn read() -> std::io::Result<(Vec<Entry>, Vec<(usize, String)>)> {
    match std::fs::read_to_string(PATH) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), Vec::new())),
        Err(e) => Err(e),
    }
}

/// A mounted file system, from `/proc/mounts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mounted {
    pub spec: String,
    pub file: String,
    pub vfstype: String,
}

/// Parses `/proc/mounts`: `spec file type options dump pass` per line.
pub fn parse_mounted(text: &str) -> Vec<Mounted> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3).then(|| Mounted { spec: unescape(f[0]), file: unescape(f[1]), vfstype: f[2].to_string() })
        })
        .collect()
}

/// What is mounted now.
pub fn mounted() -> Vec<Mounted> {
    parse_mounted(&std::fs::read_to_string("/proc/mounts").unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        let text = "# Device\tMountpoint\tFStype\tOptions\tDump\tPass#\n\
                    oxfs\t/\toxfs\trw\t1\t1\n\
                    \n\
                    tmpfs /tmp tmpfs rw # a comment\n\
                    /usr/my\\040src /mnt/src nullfs rw,noauto 0 0\n";
        let (e, errs) = parse(text);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(e.len(), 3);
        assert_eq!((e[0].spec.as_str(), e[0].file.as_str(), e[0].freq, e[0].passno), ("oxfs", "/", 1, 1));
        assert_eq!((e[1].vfstype.as_str(), e[1].freq, e[1].passno), ("tmpfs", 0, 0));
        assert_eq!(e[2].spec, "/usr/my src");
        assert!(e[2].has_option("noauto") && e[2].has_option("rw") && !e[1].has_option("noauto"));
    }

    #[test]
    fn errors() {
        let (e, errs) = parse("only three fields\nfs /m tmpfs rw x 0\na b c d e f g\nok /ok tmpfs rw\n");
        assert_eq!(e.len(), 1);
        let lines: Vec<usize> = errs.iter().map(|x| x.0).collect();
        assert_eq!(lines, [1, 2, 3]);
    }

    #[test]
    fn proc_mounts() {
        let m = parse_mounted("oxfs / oxfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n/src /mnt nullfs rw 0 0\nbad\n");
        assert_eq!(m.len(), 3);
        assert_eq!((m[2].spec.as_str(), m[2].file.as_str(), m[2].vfstype.as_str()), ("/src", "/mnt", "nullfs"));
    }
}
