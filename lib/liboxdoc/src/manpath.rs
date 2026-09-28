//! Where the manual trees are (MAN.md §8.2), shared by `man`, `apropos` and `makewhatis`.

pub const MAN_CONF: &str = "/etc/man.conf";
pub const DEFAULT_MANPATH: &str = "/usr/share/man:/usr/local/share/man";

/// The `manpath` lines of a man.conf(5) file, in order.
pub fn conf_manpaths(conf: &str) -> Vec<String> {
    std::fs::read_to_string(conf)
        .map(|t| t.lines().filter_map(|l| l.trim().strip_prefix("manpath").map(|p| p.trim().to_string())).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default()
}

/// The manual path: `manpath` (`-M`), else `MANPATH` (a leading, trailing or doubled `:` stands
/// for the default), else man.conf's `manpath` lines, else the built-in default; with the
/// `extra` (`-m`) directories first.
pub fn resolve(conf: Option<&str>, manpath: Option<&str>, extra: &[String]) -> Vec<String> {
    let from_conf = conf_manpaths(conf.unwrap_or(MAN_CONF));
    let default = if from_conf.is_empty() { DEFAULT_MANPATH.to_string() } else { from_conf.join(":") };
    let base = match manpath {
        Some(m) => m.to_string(),
        None => match std::env::var("MANPATH") {
            Ok(m) if !m.is_empty() => {
                if m.starts_with(':') {
                    format!("{default}{m}")
                } else if m.ends_with(':') {
                    format!("{m}{default}")
                } else {
                    m.replace("::", &format!(":{default}:"))
                }
            }
            _ => default,
        },
    };
    let mut dirs: Vec<String> = extra.iter().flat_map(|m| m.split(':').map(String::from).collect::<Vec<_>>()).filter(|d| !d.is_empty()).collect();
    dirs.extend(base.split(':').filter(|d| !d.is_empty()).map(String::from));
    dirs
}
