//! `certctl(8)`'s operations on a trust store, shared with `build.rs`, which runs [`rehash`] on
//! the host over the tree it seeds into oxfs.
//!
//! Layout (FreeBSD's, `certctl(8)` has the detail): certificates come from the directories in
//! [`Config::trust_path`], and those in [`Config::untrust_path`] (plus the administrator's own,
//! copied into [`Config::untrusted_dir`] by [`untrust`]) are excluded. [`rehash`] makes a
//! `<hash>.<n>` link in [`Config::certs_dir`] for each trusted certificate and one in
//! [`Config::untrusted_dir`] for each untrusted one, relative symbolic links so a tree built under
//! a destination directory stays correct, and writes every trusted certificate to
//! [`Config::bundle`].

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{pem, store};

/// Where a trust store lives. Paths are absolute, destination directory already applied.
pub struct Config {
    pub trust_path: Vec<PathBuf>,
    pub untrust_path: Vec<PathBuf>,
    /// OpenSSL's `CApath`, `/etc/ssl/certs`.
    pub certs_dir: PathBuf,
    /// `/etc/ssl/untrusted`.
    pub untrusted_dir: PathBuf,
    /// OpenSSL's `CAfile`, `/etc/ssl/cert.pem`.
    pub bundle: PathBuf,
    /// Report what would change without changing anything.
    pub dry_run: bool,
    /// Report each change.
    pub verbose: bool,
}

impl Config {
    /// The standard layout: `destdir` and `distbase` prefix the base system's paths, `destdir`
    /// and `localbase` the local (ports) ones, as in FreeBSD's `certctl`.
    pub fn standard(destdir: &str, distbase: &str, localbase: &str) -> Config {
        let base = |p: &str| PathBuf::from(format!("{destdir}{distbase}{p}"));
        let local = |p: &str| PathBuf::from(format!("{destdir}{localbase}{p}"));
        Config {
            trust_path: vec![
                base("/usr/share/certs/trusted"),
                local("/share/certs"),
                local("/etc/ssl/certs"),
            ],
            untrust_path: vec![
                base("/usr/share/certs/untrusted"),
                local("/etc/ssl/untrusted"),
                local("/etc/ssl/blacklisted"),
            ],
            certs_dir: base("/etc/ssl/certs"),
            untrusted_dir: base("/etc/ssl/untrusted"),
            bundle: base("/etc/ssl/cert.pem"),
            dry_run: false,
            verbose: false,
        }
    }

    fn note(&self, what: std::fmt::Arguments<'_>) {
        if self.verbose || self.dry_run {
            println!("{what}");
        }
    }
}

/// A certificate file's certificates, in order; empty if it can't be read.
fn read_certs(path: &Path) -> Vec<Vec<u8>> {
    std::fs::read(path).map(|b| pem::decode_all(&b)).unwrap_or_default()
}

/// The certificate files in `dir`, sorted by name: `.pem`, `.crt` and `.cer` files, and
/// `<hash>.<n>` entries. Nothing if `dir` doesn't exist.
fn cert_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.ends_with(".pem")
                || name.ends_with(".crt")
                || name.ends_with(".cer")
                || store::is_link_name(name)
        })
        .collect();
    files.sort();
    files
}

/// `<hash>.<n>` entries in `dir`: `(name, is a symbolic link)`, sorted.
fn link_entries(dir: &Path) -> Vec<(String, bool)> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<(String, bool)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let link = e.file_type().ok()?.is_symlink();
            store::is_link_name(&name).then_some((name, link))
        })
        .collect();
    out.sort();
    out
}

/// `to` relative to the directory `from_dir`, both absolute: what `install -lrs` would link.
pub fn relative(from_dir: &Path, to: &Path) -> PathBuf {
    fn norm(p: &Path) -> Vec<Component<'_>> {
        p.components().filter(|c| !matches!(c, Component::CurDir)).collect()
    }
    let (from, to_c) = (norm(from_dir), norm(to));
    let common = from.iter().zip(&to_c).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for c in &to_c[common..] {
        out.push(c.as_os_str());
    }
    out
}

/// Links `name` in `dir` to the certificate `der` from `source`: a relative symbolic link when
/// `source` holds just that certificate, else a PEM copy of it (one link can't pick a certificate
/// out of a bundle).
fn install(cfg: &Config, dir: &Path, name: &str, source: &Path, der: &[u8], single: bool) -> io::Result<()> {
    let at = dir.join(name);
    cfg.note(format_args!("{} -> {}", at.display(), source.display()));
    if cfg.dry_run {
        return Ok(());
    }
    if single {
        std::os::unix::fs::symlink(relative(dir, source), &at)
    } else {
        std::fs::write(&at, pem::encode(der))
    }
}

/// Every certificate under the directories in `path`, skipping `except`: `(file, der, the file
/// holds only this certificate)`.
fn collect(path: &[PathBuf], except: &Path) -> Vec<(PathBuf, Vec<u8>, bool)> {
    let mut out = Vec::new();
    for dir in path.iter().filter(|d| d.as_path() != except) {
        for file in cert_files(dir) {
            let certs = read_certs(&file);
            let single = certs.len() == 1;
            for der in certs {
                out.push((file.clone(), der, single));
            }
        }
    }
    out
}

/// Rebuilds the links in [`Config::certs_dir`] and [`Config::untrusted_dir`] and the bundle.
/// Returns how many certificates are trusted.
pub fn rehash(cfg: &Config) -> io::Result<usize> {
    if !cfg.dry_run {
        std::fs::create_dir_all(&cfg.certs_dir)?;
        std::fs::create_dir_all(&cfg.untrusted_dir)?;
        // Every <hash>.<n> in certs_dir is ours; in untrusted_dir only the links are, the regular
        // files being the administrator's `certctl untrust` copies.
        for (name, _) in link_entries(&cfg.certs_dir) {
            std::fs::remove_file(cfg.certs_dir.join(name))?;
        }
        for (name, link) in link_entries(&cfg.untrusted_dir) {
            if link {
                std::fs::remove_file(cfg.untrusted_dir.join(name))?;
            }
        }
    }

    // Untrusted: the administrator's copies, and every certificate on the untrust path.
    let mut untrusted: HashSet<Vec<u8>> = HashSet::new();
    let mut taken: HashSet<String> = HashSet::new();
    for (name, link) in link_entries(&cfg.untrusted_dir) {
        if !link {
            untrusted.extend(read_certs(&cfg.untrusted_dir.join(&name)));
            taken.insert(name);
        }
    }
    for (file, der, single) in collect(&cfg.untrust_path, &cfg.untrusted_dir) {
        if untrusted.insert(der.clone())
            && let Some(name) = store::free_name(&der, &taken)
        {
            install(cfg, &cfg.untrusted_dir, &name, &file, &der, single)?;
            taken.insert(name);
        }
    }

    // Trusted: everything on the trust path that isn't untrusted.
    let candidates: Vec<(PathBuf, Vec<u8>, bool)> = collect(&cfg.trust_path, &cfg.certs_dir)
        .into_iter()
        .filter(|(file, der, _)| {
            let skip = untrusted.contains(der);
            if skip {
                cfg.note(format_args!("skipping untrusted {}", file.display()));
            }
            !skip
        })
        .collect();
    let ders: Vec<&[u8]> = candidates.iter().map(|(_, der, _)| der.as_slice()).collect();
    let mut bundle = String::new();
    let mut trusted = 0;
    for ((file, der, single), name) in candidates.iter().zip(store::link_names(&ders)) {
        let Some(name) = name else { continue };
        install(cfg, &cfg.certs_dir, &name, file, der, *single)?;
        bundle.push_str(&pem::encode(der));
        trusted += 1;
    }

    cfg.note(format_args!("{} ({trusted} certificates)", cfg.bundle.display()));
    if !cfg.dry_run {
        // Written aside and renamed over, so a reader never sees a partial bundle.
        let tmp = cfg.bundle.with_extension("pem.new");
        std::fs::write(&tmp, bundle)?;
        std::fs::rename(&tmp, &cfg.bundle)?;
    }
    Ok(trusted)
}

/// `(name, what to show for it)` for each `<hash>.<n>` in `dir`, sorted.
pub fn list(dir: &Path) -> Vec<(String, String)> {
    link_entries(dir)
        .into_iter()
        .map(|(name, _)| {
            let shown = read_certs(&dir.join(&name))
                .first()
                .and_then(|der| crate::name::subject_display(der))
                .unwrap_or_default();
            (name, shown)
        })
        .collect()
}

/// Adds the certificates in `file` to the administrator's untrusted list, as PEM copies in
/// [`Config::untrusted_dir`]. Returns how many were added (already untrusted ones aren't).
pub fn untrust(cfg: &Config, file: &Path) -> io::Result<usize> {
    let certs = read_certs(file);
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no certificate"));
    }
    let entries = link_entries(&cfg.untrusted_dir);
    let mut taken: HashSet<String> = entries.iter().map(|(n, _)| n.clone()).collect();
    let present: HashSet<Vec<u8>> = entries
        .iter()
        .filter(|(_, link)| !link)
        .flat_map(|(n, _)| read_certs(&cfg.untrusted_dir.join(n)))
        .collect();
    let mut added = 0;
    if !cfg.dry_run {
        std::fs::create_dir_all(&cfg.untrusted_dir)?;
    }
    for der in certs.iter().filter(|d| !present.contains(*d)) {
        let Some(name) = store::free_name(der, &taken) else { continue };
        let at = cfg.untrusted_dir.join(&name);
        cfg.note(format_args!("untrusting {} as {}", file.display(), at.display()));
        if !cfg.dry_run {
            std::fs::write(&at, pem::encode(der))?;
        }
        taken.insert(name);
        added += 1;
    }
    Ok(added)
}

/// Why [`trust`] couldn't act.
pub enum TrustError {
    /// Neither a certificate file nor an entry in the untrusted directory.
    NotFound,
    /// Untrusted by a list on the untrust path, not by the administrator: the file to remove.
    SystemList(PathBuf),
    Io(io::Error),
}

/// Takes certificates off the administrator's untrusted list: `what` is a certificate file, or
/// the name of an entry in [`Config::untrusted_dir`] (as `certctl untrusted` shows). Returns how
/// many entries were removed.
pub fn trust(cfg: &Config, what: &str) -> Result<usize, TrustError> {
    let entries = link_entries(&cfg.untrusted_dir);
    let wanted: Vec<Vec<u8>> = if entries.iter().any(|(n, _)| n == what) {
        read_certs(&cfg.untrusted_dir.join(what))
    } else {
        let certs = read_certs(Path::new(what));
        if certs.is_empty() {
            return Err(TrustError::NotFound);
        }
        certs
    };
    let mut removed = 0;
    for (name, link) in &entries {
        let at = cfg.untrusted_dir.join(name);
        if !read_certs(&at).iter().any(|d| wanted.contains(d)) {
            continue;
        }
        if *link {
            let target = std::fs::canonicalize(&at).unwrap_or(at);
            return Err(TrustError::SystemList(target));
        }
        cfg.note(format_args!("trusting {} again", at.display()));
        if !cfg.dry_run {
            std::fs::remove_file(&at).map_err(TrustError::Io)?;
        }
        removed += 1;
    }
    if removed == 0 {
        return Err(TrustError::NotFound);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::relative;
    use std::path::Path;

    #[test]
    fn relative_links() {
        assert_eq!(
            relative(Path::new("/etc/ssl/certs"), Path::new("/usr/share/certs/trusted/A.pem")),
            Path::new("../../../usr/share/certs/trusted/A.pem")
        );
        assert_eq!(relative(Path::new("/a/b"), Path::new("/a/b/c.pem")), Path::new("c.pem"));
    }
}
