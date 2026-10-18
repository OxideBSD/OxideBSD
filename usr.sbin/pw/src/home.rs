//! Home directories: making one from the skeleton, moving one, removing one.

use crate::{EX_CANTCREAT, EX_IOERR, Result, err};
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, lchown};
use std::path::Path;

/// Creates `home` with `mode`, owned by `uid:gid`, and copies `skel` into it. Missing parents
/// are made too, as root's, mode 0755. An existing home is kept, and only skeleton files it
/// doesn't have are added (as FreeBSD's pw does).
pub fn create(home: &str, skel: &str, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let fail = |e: io::Error| err(EX_CANTCREAT, format!("{home}: {e}"));
    if home.is_empty() || home == "/" {
        return err(EX_CANTCREAT, format!("refusing to make `{home}' a home directory"));
    }
    if let Some(parent) = Path::new(home).parent() {
        fs::DirBuilder::new().recursive(true).mode(0o755).create(parent).or_else(fail)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(home) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && Path::new(home).is_dir() => {}
        Err(e) => return fail(e),
    }
    // The umask applied to mkdir; the mode asked for is set exactly.
    fs::set_permissions(home, fs::Permissions::from_mode(mode)).or_else(fail)?;
    lchown(home, Some(uid), Some(gid)).or_else(fail)?;
    if Path::new(skel).is_dir() {
        copy_tree(Path::new(skel), Path::new(home), Some((uid, gid))).or_else(|e| err(EX_IOERR, format!("copying {skel} to {home}: {e}")))?;
    }
    Ok(())
}

/// The name a skeleton file gets in a home: FreeBSD ships `/etc/skel/dot.profile` for
/// `.profile`, so it is visible in the skeleton directory; OpenBSD's plain `.profile` stays.
fn skel_name(name: &std::ffi::OsStr) -> std::ffi::OsString {
    match name.to_str().and_then(|n| n.strip_prefix("dot.")) {
        Some(rest) if !rest.is_empty() => format!(".{rest}").into(),
        _ => name.to_owned(),
    }
}

/// Copies `src`'s contents into `dst` (which exists), skipping anything `dst` already has. With
/// `owner` it is a skeleton: everything is given to that `uid:gid` and `dot.` names are
/// translated; without, a home being moved, which keeps its names and owners.
fn copy_tree(src: &Path, dst: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    for e in fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(if owner.is_some() { skel_name(&e.file_name()) } else { e.file_name() });
        let ty = e.file_type()?;
        if fs::symlink_metadata(&to).is_ok() {
            if ty.is_dir() && to.is_dir() {
                copy_tree(&e.path(), &to, owner)?;
            }
            continue;
        }
        let m = fs::symlink_metadata(e.path())?;
        if ty.is_dir() {
            fs::DirBuilder::new().mode(0o700).create(&to)?;
            fs::set_permissions(&to, fs::Permissions::from_mode(m.mode() & 0o7777))?;
            copy_tree(&e.path(), &to, owner)?;
        } else if ty.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(e.path())?, &to)?;
        } else if ty.is_file() {
            fs::copy(e.path(), &to)?;
        } else {
            // Devices, FIFOs and sockets have no place in a skeleton, nor are they copied.
            continue;
        }
        let (uid, gid) = owner.unwrap_or((m.uid(), m.gid()));
        lchown(&to, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Moves a home (`usermod -m -d`): a rename, or a copy and removal across file systems.
pub fn relocate(from: &str, to: &str, uid: u32, gid: u32) -> Result<()> {
    if Path::new(to).exists() {
        return err(EX_CANTCREAT, format!("{to}: already exists"));
    }
    if let Some(parent) = Path::new(to).parent() {
        fs::DirBuilder::new().recursive(true).mode(0o755).create(parent).or_else(|e| err(EX_CANTCREAT, format!("{to}: {e}")))?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            let mode = fs::metadata(from).map_or(0o755, |m| m.mode() & 0o7777);
            create(to, "", uid, gid, mode)?;
            copy_tree(Path::new(from), Path::new(to), None).or_else(|e| err(EX_IOERR, format!("copying {from} to {to}: {e}")))?;
            fs::remove_dir_all(from).or_else(|e| err(EX_IOERR, format!("{from}: {e}")))
        }
        Err(e) => err(EX_CANTCREAT, format!("moving {from} to {to}: {e}")),
    }
}

/// Removes a deleted user's home (`userdel -r`), but only a directory the user owns: a home
/// shared with others, or `/`, or another user's, stays. Returns why it was kept, if it was.
pub fn remove(home: &str, uid: u32) -> Result<Option<String>> {
    let Ok(m) = fs::symlink_metadata(home) else { return Ok(None) };
    if home.is_empty() || Path::new(home) == Path::new("/") || !m.is_dir() {
        return Ok(Some(format!("{home}: not removing: not a home directory")));
    }
    if m.uid() != uid {
        return Ok(Some(format!("{home}: not removing: owned by uid {}, not {uid}", m.uid())));
    }
    fs::remove_dir_all(home).or_else(|e| err(EX_IOERR, format!("{home}: {e}")))?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_names() {
        assert_eq!(skel_name("dot.profile".as_ref()), ".profile");
        assert_eq!(skel_name(".profile".as_ref()), ".profile");
        assert_eq!(skel_name("dot.".as_ref()), "dot.");
        assert_eq!(skel_name("README".as_ref()), "README");
    }
}
