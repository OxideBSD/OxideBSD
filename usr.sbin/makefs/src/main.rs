//! `makefs(8)`: builds a filesystem image from files on hand (OxideBSD-doc `RAM_FLOOR.md`
//! §4.2.4, §4.4), as FreeBSD's and NetBSD's makefs do. The system's images are built with it on
//! the host; it is installed on the target too.
//!
//! ```text
//! makefs [-t fs-type] [-o fs-options] [-s image-size] [-F specfile] [-T timestamp]
//!        image-file directory|manifest ...
//! ```
//!
//! - `-t oxfs` (the default and, for now, the only type).
//! - `-o label=name`: the volume label (`newfs_oxfs -L`).
//! - `-s size`: the image's size, in bytes or with a `k`, `m` or `g` suffix; without it, just
//!   large enough for the files, with a little room to spare.
//! - `-F specfile`: an mtree(5) specification for the first directory: each entry's type, mode,
//!   owner and time are taken from it, overriding the directory's; a directory it names that
//!   isn't there is made.
//! - `-T timestamp`: every inode's times, in seconds since the epoch, for repeatable images.
//!
//! Each source is a directory, walked whole, or an mtree manifest (a file whose first line
//! begins `#mtree`): every entry is put in the image, a file's contents read from its
//! `contents=` path, or from its own path, relative to the manifest's directory. Sources are
//! merged: a directory may come from several, anything else from only one. Files that are hard
//! links of each other (the same device and inode on the host) stay one inode.
//!
//! Supported: regular files, directories, symbolic links and FIFOs. Device nodes are refused:
//! devfs makes `/dev`.

use mtree::{Entry, Spec, Type};
use oxfs_format::{BLOCK_SIZE, BlockDevice, FormatOptions, Inode, InodeKind, ROOT_INODE, SB_LABEL_LEN, Writer};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: makefs [-t fs-type] [-o fs-options] [-s image-size] [-F specfile] [-T timestamp]\n              image-file directory|manifest ..."
    );
    ExitCode::from(1)
}

/// What an entry of the image holds.
#[derive(Clone, Debug)]
enum Body {
    Dir,
    /// A regular file, read from this host path.
    File(PathBuf),
    Link(Vec<u8>),
    Fifo,
}

/// One entry to be made.
#[derive(Clone, Debug)]
struct Node {
    body: Body,
    mode: u16,
    uid: u32,
    gid: u32,
    time: i64,
    /// The host file's `(device, inode)`: entries sharing it are one inode.
    host_id: Option<(u64, u64)>,
}

/// The image's tree, by path (components joined with `/`, the root empty).
type Tree = BTreeMap<Vec<u8>, Node>;

fn fail<T>(what: impl Into<String>) -> Result<T, String> {
    Err(what.into())
}

/// Adds `node` at `path`, refusing a second definition of anything but a directory. A
/// directory several sources give keeps the first one's attributes; a later one must agree on
/// its mode and owner (dist sets all list the directories they share).
fn insert(tree: &mut Tree, path: Vec<u8>, node: Node) -> Result<(), String> {
    match tree.get_mut(&path) {
        Some(old) if matches!((&old.body, &node.body), (Body::Dir, Body::Dir)) => {
            if (old.mode, old.uid, old.gid) != (node.mode, node.uid, node.gid) {
                return fail(format!(
                    "{}: sources disagree on the directory (mode {:o} owner {}:{}, then mode {:o} owner {}:{})",
                    show(&path), old.mode, old.uid, old.gid, node.mode, node.uid, node.gid
                ));
            }
            Ok(())
        }
        Some(_) => fail(format!("{}: given by more than one source", show(&path))),
        None => {
            tree.insert(path, node);
            Ok(())
        }
    }
}

fn show(path: &[u8]) -> String {
    if path.is_empty() { ".".into() } else { String::from_utf8_lossy(path).into_owned() }
}

/// A node for the host file at `host`, as `lstat` describes it.
fn node_from_host(host: &Path) -> Result<Node, String> {
    let md = std::fs::symlink_metadata(host).map_err(|e| format!("{}: {e}", host.display()))?;
    let ft = md.file_type();
    let body = if ft.is_dir() {
        Body::Dir
    } else if ft.is_file() {
        Body::File(host.to_path_buf())
    } else if ft.is_symlink() {
        let target = std::fs::read_link(host).map_err(|e| format!("{}: {e}", host.display()))?;
        Body::Link(target.as_os_str().as_bytes().to_vec())
    } else if ft.is_fifo() {
        Body::Fifo
    } else {
        return fail(format!("{}: devices and sockets aren't supported", host.display()));
    };
    Ok(Node {
        host_id: matches!(body, Body::File(_)).then(|| (md.dev(), md.ino())),
        body,
        mode: (md.mode() & 0o7777) as u16,
        uid: md.uid(),
        gid: md.gid(),
        time: md.mtime(),
    })
}

/// Walks directory `root` into `tree`.
fn add_directory(tree: &mut Tree, root: &Path) -> Result<(), String> {
    let mut stack = vec![(root.to_path_buf(), Vec::new())];
    while let Some((host, path)) = stack.pop() {
        let node = node_from_host(&host)?;
        let is_dir = matches!(node.body, Body::Dir);
        insert(tree, path.clone(), node)?;
        if !is_dir {
            continue;
        }
        let dir = std::fs::read_dir(&host).map_err(|e| format!("{}: {e}", host.display()))?;
        for entry in dir {
            let entry = entry.map_err(|e| format!("{}: {e}", host.display()))?;
            let mut child = path.clone();
            if !child.is_empty() {
                child.push(b'/');
            }
            child.extend_from_slice(entry.file_name().as_bytes());
            stack.push((entry.path(), child));
        }
    }
    Ok(())
}

/// A uid or gid from an entry: the number, or the name for the two every system has.
fn id(e: &Entry, num: &str, name: &str) -> Result<Option<u32>, String> {
    if let Some(v) = e.get(num) {
        return v.parse().map(Some).map_err(|_| format!("{}: bad {num}={v}", show(&e.path)));
    }
    match e.get(name) {
        None => Ok(None),
        Some("root" | "wheel") => Ok(Some(0)),
        Some(other) => fail(format!("{}: {name}={other} without {num}= (no user database)", show(&e.path))),
    }
}

/// Applies an entry's keywords over `node`.
fn apply(e: &Entry, node: &mut Node) -> Result<(), String> {
    if let Some(mode) = e.get("mode") {
        node.mode = u16::from_str_radix(mode, 8).map_err(|_| format!("{}: bad mode={mode}", show(&e.path)))? & 0o7777;
    }
    if let Some(uid) = id(e, "uid", "uname")? {
        node.uid = uid;
    }
    if let Some(gid) = id(e, "gid", "gname")? {
        node.gid = gid;
    }
    if let Some(t) = e.time() {
        node.time = t;
    }
    Ok(())
}

/// A node for a spec entry with nothing on the host behind it (a directory, link or FIFO).
fn node_from_entry(e: &Entry, body: Body) -> Result<Node, String> {
    let mut node = Node { body, mode: 0o755, uid: 0, gid: 0, time: 0, host_id: None };
    apply(e, &mut node)?;
    Ok(node)
}

/// `-F`: the first directory's entries take the spec's attributes.
fn apply_spec(tree: &mut Tree, spec: &Spec) -> Result<(), String> {
    for e in &spec.entries {
        let kind = e.kind();
        match tree.get_mut(&e.path) {
            Some(node) => {
                let actual = match node.body {
                    Body::Dir => Type::Dir,
                    Body::File(_) => Type::File,
                    Body::Link(_) => Type::Link,
                    Body::Fifo => Type::Fifo,
                };
                if kind.is_some_and(|k| k != actual) {
                    return fail(format!("{}: the spec says {}, it is a {}", show(&e.path), kind.unwrap().name(), actual.name()));
                }
                if let (Body::Link(target), Some(new)) = (&mut node.body, e.link()) {
                    *target = new;
                }
                apply(e, node)?;
            }
            None => {
                let body = match kind {
                    Some(Type::Dir) => Body::Dir,
                    Some(Type::Link) => Body::Link(e.link().ok_or(format!("{}: link without link=", show(&e.path)))?),
                    _ => return fail(format!("{}: in the spec, not in the directory", show(&e.path))),
                };
                let node = node_from_entry(e, body)?;
                tree.insert(e.path.clone(), node);
            }
        }
    }
    Ok(())
}

/// A manifest: every entry, contents from the host relative to `base`.
fn add_manifest(tree: &mut Tree, spec: &Spec, base: &Path) -> Result<(), String> {
    for e in &spec.entries {
        let body = match e.kind() {
            Some(Type::Dir) => Body::Dir,
            Some(Type::Link) => Body::Link(e.link().ok_or(format!("{}: link without link=", show(&e.path)))?),
            Some(Type::Fifo) => Body::Fifo,
            Some(Type::File) => {
                let rel = e.contents().unwrap_or_else(|| e.path.clone());
                Body::File(base.join(Path::new(std::ffi::OsStr::from_bytes(&rel))))
            }
            Some(t) => return fail(format!("{}: type={} isn't supported", show(&e.path), t.name())),
            None => return fail(format!("{}: no type=", show(&e.path))),
        };
        let mut node = node_from_entry(e, body)?;
        node.mode = e.mode().map_or(if matches!(node.body, Body::Dir) { 0o755 } else { 0o644 }, |m| (m & 0o7777) as u16);
        if let Body::File(host) = &node.body {
            let md = std::fs::metadata(host).map_err(|err| format!("{}: {}: {err}", show(&e.path), host.display()))?;
            if !md.is_file() {
                return fail(format!("{}: {} isn't a regular file", show(&e.path), host.display()));
            }
            if e.size().is_some_and(|s| s != md.len()) {
                return fail(format!("{}: size={} but {} has {}", show(&e.path), e.size().unwrap(), host.display(), md.len()));
            }
            node.host_id = Some((md.dev(), md.ino()));
            if e.time().is_none() {
                node.time = md.mtime();
            }
        }
        insert(tree, e.path.clone(), node)?;
    }
    Ok(())
}

/// The parent of every entry must be a directory in the tree.
fn check_parents(tree: &Tree) -> Result<(), String> {
    if !tree.get(&b""[..]).is_some_and(|n| matches!(n.body, Body::Dir)) {
        return fail("no root directory");
    }
    for path in tree.keys().filter(|p| !p.is_empty()) {
        let parent = path.iter().rposition(|&b| b == b'/').map_or(&path[..0], |i| &path[..i]);
        if !tree.get(parent).is_some_and(|n| matches!(n.body, Body::Dir)) {
            return fail(format!("{}: its directory {} isn't in the image", show(path), show(parent)));
        }
    }
    Ok(())
}

/// Blocks a file of `size` bytes takes, index blocks included.
fn file_blocks(size: u64) -> u64 {
    let data = size.div_ceil(BLOCK_SIZE as u64);
    let ptrs = (BLOCK_SIZE / 4) as u64;
    let mut index = 0;
    if data > 12 {
        index += 1;
    }
    if data > 12 + ptrs {
        index += 1 + (data - 12 - ptrs).div_ceil(ptrs);
    }
    data + index
}

/// The image size `-s` didn't give: what the files need, plus a twentieth and 64 blocks.
fn auto_size(tree: &Tree) -> u64 {
    let mut blocks = 0u64;
    let mut seen = std::collections::HashSet::new();
    let mut children: HashMap<&[u8], u64> = HashMap::new();
    for (path, node) in tree {
        if !path.is_empty() {
            let parent = path.iter().rposition(|&b| b == b'/').map_or(&path[..0], |i| &path[..i]);
            *children.entry(parent).or_default() += 1;
        }
        match &node.body {
            Body::File(host) => {
                if node.host_id.is_none_or(|id| seen.insert(id)) {
                    blocks += file_blocks(std::fs::metadata(host).map_or(0, |m| m.len()));
                }
            }
            Body::Link(t) => blocks += file_blocks(t.len() as u64),
            _ => {}
        }
    }
    let records = oxfs_format::RECORDS_PER_BLOCK as u64;
    blocks += children.values().map(|n| file_blocks((n + 2).div_ceil(records) * BLOCK_SIZE as u64)).sum::<u64>();
    blocks += tree.len().div_ceil(oxfs_format::INODES_PER_BLOCK) as u64 + 2;
    let blocks = blocks + blocks / 20 + 64;
    // The superblock and the bitmap.
    (blocks + 1 + blocks.div_ceil(oxfs_format::BITS_PER_BITMAP_BLOCK as u64)) * BLOCK_SIZE as u64
}

/// The image file, a block at a time.
struct Image(File);

impl BlockDevice for Image {
    type Error = std::io::Error;
    fn read_block(&mut self, n: u64, buf: &mut [u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0.read_exact_at(buf, n * BLOCK_SIZE as u64)
    }
    fn write_block(&mut self, n: u64, buf: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0.write_all_at(buf, n * BLOCK_SIZE as u64)
    }
}

fn describe(e: oxfs_format::Error<std::io::Error>) -> String {
    use oxfs_format::Error;
    match e {
        Error::Device(e) => e.to_string(),
        Error::TooSmall => "the image is too small for a file system".into(),
        Error::NoSpace => "the image is full (-s)".into(),
        Error::NoInodes => "out of inodes".into(),
        Error::BadName => "a name is empty or longer than 255 bytes".into(),
        Error::LabelTooLong => "volume label too long".into(),
        Error::Superblock(e) => format!("{e:?}"),
    }
}

fn kind_of(body: &Body) -> InodeKind {
    match body {
        Body::Dir => InodeKind::Dir,
        Body::File(_) => InodeKind::File,
        Body::Link(_) => InodeKind::Symlink,
        Body::Fifo => InodeKind::Fifo,
    }
}

/// Writes `data` as inode `ino`'s contents, a block at a time from `read`.
fn write_contents(
    w: &mut Writer<Image>,
    inode: &mut Inode,
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Result<u64, String> {
    let mut size = 0u64;
    let mut index = 0;
    loop {
        let mut block = [0u8; BLOCK_SIZE];
        let mut got = 0;
        while got < BLOCK_SIZE {
            match read(&mut block[got..]).map_err(|e| e.to_string())? {
                0 => break,
                n => got += n,
            }
        }
        if got == 0 {
            break;
        }
        w.put_block(inode, index, &block).map_err(describe)?;
        size += got as u64;
        index += 1;
        if got < BLOCK_SIZE {
            break;
        }
    }
    Ok(size)
}

/// Makes the image; how many inodes it holds.
fn build(image: &Path, tree: &Tree, size: u64, label: &[u8], timestamp: Option<i64>) -> Result<usize, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(image)
        .map_err(|e| format!("{}: {e}", image.display()))?;
    file.set_len(size).map_err(|e| format!("{}: {e}", image.display()))?;
    let time = |n: &Node| timestamp.unwrap_or(n.time);
    let root = &tree[&b""[..]];
    let opts = FormatOptions { label, inodes: 0, now: time(root) };
    let mut w = Writer::format(Image(file), size / BLOCK_SIZE as u64, &opts).map_err(describe)?;

    let mut numbers: HashMap<Vec<u8>, u32> = HashMap::new();
    numbers.insert(Vec::new(), ROOT_INODE);
    let mut by_host: HashMap<(u64, u64), u32> = HashMap::new();
    let mut dirs = vec![(ROOT_INODE, root)];
    // BTreeMap order puts a directory before everything in it.
    for (path, node) in tree.iter().filter(|(p, _)| !p.is_empty()) {
        let split = path.iter().rposition(|&b| b == b'/');
        let (parent, name) = match split {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (&path[..0], &path[..]),
        };
        let parent = numbers[parent];
        if let Some(&n) = node.host_id.as_ref().and_then(|id| by_host.get(id)) {
            w.link(parent, name, n, time(node)).map_err(describe)?;
            continue;
        }
        let mut inode = Inode::new(kind_of(&node.body), time(node));
        inode.mode = node.mode;
        inode.uid = node.uid;
        inode.gid = node.gid;
        let n = w.create(parent, name, &inode).map_err(|e| format!("{}: {}", show(path), describe(e)))?;
        match &node.body {
            Body::Dir => dirs.push((n, node)),
            Body::File(host) => {
                let mut f = File::open(host).map_err(|e| format!("{}: {e}", host.display()))?;
                let mut inode = w.read_inode(n).map_err(describe)?;
                inode.size = write_contents(&mut w, &mut inode, |b| f.read(b)).map_err(|e| format!("{}: {e}", host.display()))?;
                w.write_inode(n, &inode).map_err(describe)?;
            }
            Body::Link(target) => {
                let mut inode = w.read_inode(n).map_err(describe)?;
                let mut rest = &target[..];
                inode.size = write_contents(&mut w, &mut inode, |b| rest.read(b))?;
                w.write_inode(n, &inode).map_err(describe)?;
            }
            Body::Fifo => {}
        }
        if let Some(id) = node.host_id {
            by_host.insert(id, n);
        }
        numbers.insert(path.clone(), n);
    }
    // Entries going in stamped their directories; give them their own times, and the root its
    // mode and owner.
    for (n, node) in dirs {
        let mut inode = w.read_inode(n).map_err(describe)?;
        let t = time(node);
        (inode.mtime, inode.ctime, inode.atime) = (t, t, t);
        (inode.mode, inode.uid, inode.gid) = (node.mode, node.uid, node.gid);
        w.write_inode(n, &inode).map_err(describe)?;
    }
    let dev = w.finish().map_err(describe)?;
    dev.0.sync_all().map_err(|e| e.to_string())?;
    Ok(numbers.len() + 1)
}

/// `-s`'s argument: bytes, or with a `b` (512), `k`, `m` or `g` suffix.
fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.as_bytes().last()? {
        b'b' | b'B' => (&s[..s.len() - 1], 512),
        b'k' | b'K' => (&s[..s.len() - 1], 1 << 10),
        b'm' | b'M' => (&s[..s.len() - 1], 1 << 20),
        b'g' | b'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

fn main() -> ExitCode {
    let (mut fstype, mut size, mut specfile, mut timestamp) = (String::from("oxfs"), None, None, None);
    let mut label = String::new();
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let opt = match arg.as_str() {
            "-t" | "-o" | "-s" | "-F" | "-T" => arg.clone(),
            _ if arg.starts_with('-') && arg.len() > 1 => return usage(),
            _ => {
                positional.push(arg);
                continue;
            }
        };
        let Some(value) = args.next() else { return usage() };
        match opt.as_str() {
            "-t" => fstype = value,
            "-s" => match parse_size(&value) {
                Some(n) => size = Some(n),
                None => return usage(),
            },
            "-F" => specfile = Some(value),
            "-T" => match value.parse::<i64>() {
                Ok(t) => timestamp = Some(t),
                Err(_) => return usage(),
            },
            _ => {
                for o in value.split(',') {
                    match o.split_once('=') {
                        Some(("label", l)) => label = l.to_string(),
                        _ => {
                            eprintln!("makefs: unknown oxfs option {o}");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
        }
    }
    if fstype != "oxfs" {
        eprintln!("makefs: unsupported file system type {fstype}");
        return ExitCode::from(1);
    }
    if positional.len() < 2 {
        return usage();
    }
    if label.len() > SB_LABEL_LEN {
        eprintln!("makefs: volume label longer than {SB_LABEL_LEN}");
        return ExitCode::from(1);
    }
    let image = PathBuf::from(&positional[0]);
    match run(&image, &positional[1..], specfile.as_deref(), size, label.as_bytes(), timestamp) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("makefs: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(image: &Path, sources: &[String], specfile: Option<&str>, size: Option<u64>, label: &[u8], timestamp: Option<i64>) -> Result<(), String> {
    let mut tree = Tree::new();
    let mut first_dir = true;
    for source in sources {
        let path = Path::new(source);
        let md = std::fs::metadata(path).map_err(|e| format!("{source}: {e}"))?;
        if md.is_dir() {
            let mut part = Tree::new();
            add_directory(&mut part, path)?;
            if first_dir && let Some(specfile) = specfile {
                let text = std::fs::read_to_string(specfile).map_err(|e| format!("{specfile}: {e}"))?;
                let spec = Spec::parse(&text).map_err(|e| format!("{specfile}: {e}"))?;
                apply_spec(&mut part, &spec)?;
            }
            first_dir = false;
            for (p, n) in part {
                insert(&mut tree, p, n)?;
            }
        } else {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{source}: {e}"))?;
            if !text.starts_with("#mtree") {
                return fail(format!("{source}: neither a directory nor an mtree manifest"));
            }
            let spec = Spec::parse(&text).map_err(|e| format!("{source}: {e}"))?;
            add_manifest(&mut tree, &spec, path.parent().unwrap_or(Path::new(".")))?;
        }
    }
    check_parents(&tree)?;
    let size = size.unwrap_or_else(|| auto_size(&tree)) / BLOCK_SIZE as u64 * BLOCK_SIZE as u64;
    let inodes = build(image, &tree, size, label, timestamp)?;
    println!("{}: {size} bytes, {} entries, {inodes} inodes", image.display(), tree.len());
    Ok(())
}
