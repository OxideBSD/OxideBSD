// The install step and the system's images (OxideBSD-doc `RAM_FLOOR.md` §4.3-4.4), included by
// build.rs. Its own file, as build_busybox.rs is, so editing it doesn't touch build.rs.
//
// `distrib/install.mtree` lists everything installed into the system's file tree. It is staged
// into `target/destdir`, split into dist sets by `distrib/sets/lists/*`, and each set described
// by an mtree(5) specification, `target/sets/<set>.mtree`, which the image carries as
// `/etc/mtree/<set>.mtree`. Host builds of makefs(8), fsck_oxfs(8) and mkimg(1) then make
// `target/images/root.img` (the root file system, every set) and `target/images/disk.img` (a GPT
// disk holding it as `rootfs`), checked by fsck_oxfs.

/// The dist sets, in the order an image is made from them.
const SETS: [&str; 3] = ["base", "clang", "tests"];

/// What an installed path is.
#[derive(Clone, Debug)]
enum InstallBody {
    Dir,
    /// A regular file, staged from this host file.
    File(PathBuf),
    Link(String),
    /// Another name for the regular file at this path.
    Hardlink(String),
    /// A set's own specification, `/etc/mtree/<set>.mtree`.
    SetSpec(&'static str),
}

#[derive(Clone, Debug)]
struct Installed {
    body: InstallBody,
    mode: u32,
    uid: u32,
    gid: u32,
    /// Made only as some other entry's directory: an entry of its own may replace it.
    implicit: bool,
}

/// Paths are relative to the root, components joined by `/`; the root is empty.
type InstallTree = std::collections::BTreeMap<String, Installed>;

/// The mode a file gets when the install list gives none: 0755 for something the kernel can run
/// (a `#!` script, or an ELF executable or shared object), 0644 for anything else, as seeding
/// always did.
fn default_file_mode(path: &Path) -> u32 {
    use std::io::Read;
    let mut head = [0u8; 18];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let head = &head[..n];
    if head.starts_with(b"#!") {
        return 0o755;
    }
    if head.len() == 18 && head.starts_with(b"\x7fELF") && matches!(u16::from_le_bytes([head[16], head[17]]), 2 | 3) {
        return 0o755;
    }
    0o644
}

/// A generated list (`src=gen:NAME`): the arrays build.rs writes into `target/generated/*.rs` for
/// oxfs to `include!` -- `(path, include_bytes!("host path"))` for files, `(path, target)` for
/// links, `"path"` for directories.
enum GenList {
    Files(Vec<(String, PathBuf)>),
    Pairs(Vec<(String, String)>),
    Dirs(Vec<String>),
}

/// The Rust string literals in `text`, unescaped.
fn rust_string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut s = String::new();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some(other) => s.push(other),
                    None => break,
                },
                c => s.push(c),
            }
        }
        out.push(s);
    }
    out
}

/// Every generated list in the manifests `env` names (`*_MANIFEST_PATH`).
fn generated_lists(env: &[(&str, &str)]) -> std::collections::HashMap<String, GenList> {
    let mut lists = std::collections::HashMap::new();
    for (name, path) in env.iter().filter(|(n, _)| n.ends_with("_MANIFEST_PATH")) {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{name} {path}: {e}"));
        for chunk in text.split("pub static ").skip(1) {
            let (decl, body) = chunk.split_once('=').unwrap_or_else(|| panic!("{path}: unexpected manifest shape"));
            let list_name = decl.split(':').next().unwrap().trim().to_string();
            let strings = rust_string_literals(body);
            let list = if decl.contains("&[u8]") {
                GenList::Files(strings.chunks(2).map(|p| (p[0].clone(), PathBuf::from(&p[1]))).collect())
            } else if decl.contains("(&str, &str)") {
                GenList::Pairs(strings.chunks(2).map(|p| (p[0].clone(), p[1].clone())).collect())
            } else {
                GenList::Dirs(strings)
            };
            lists.insert(list_name, list);
        }
    }
    lists
}

fn join_rel(base: &str, rel: &str) -> String {
    let rel = rel.trim_start_matches('/');
    if base.is_empty() { rel.to_string() } else { format!("{base}/{rel}") }
}

/// Adds `path` to the tree, with the directories above it made implicitly. A second entry for a
/// path is refused, except an explicit directory over an implicit one.
fn install_insert(tree: &mut InstallTree, path: String, item: Installed) {
    let mut parent = path.as_str();
    while let Some((up, _)) = parent.rsplit_once('/') {
        parent = up;
        tree.entry(parent.to_string())
            .or_insert(Installed { body: InstallBody::Dir, mode: 0o755, uid: 0, gid: 0, implicit: true });
    }
    if !path.is_empty() {
        tree.entry(String::new())
            .or_insert(Installed { body: InstallBody::Dir, mode: 0o755, uid: 0, gid: 0, implicit: true });
    }
    match tree.get(&path) {
        Some(old) if old.implicit && matches!(item.body, InstallBody::Dir) => {}
        Some(old) if matches!((&old.body, &item.body), (InstallBody::Dir, InstallBody::Dir)) && item.implicit => return,
        Some(_) => panic!("distrib/install.mtree: ./{path} is installed twice"),
        None => {}
    }
    tree.insert(path, item);
}

/// Reads `distrib/install.mtree` into a tree of everything installed.
fn read_install_list(root: &Path, env: &[(&str, &str)]) -> InstallTree {
    let list_path = root.join("distrib/install.mtree");
    println!("cargo:rerun-if-changed={}", list_path.display());
    let text = std::fs::read_to_string(&list_path).unwrap_or_else(|e| panic!("{}: {e}", list_path.display()));
    let spec = mtree::Spec::parse_lenient(&text).unwrap_or_else(|e| panic!("{}: {e}", list_path.display()));
    let artifacts: std::collections::HashMap<&str, &str> = env.iter().copied().collect();
    let generated = generated_lists(env);
    let mut tree = InstallTree::new();
    for e in &spec.entries {
        let path = String::from_utf8(e.path.clone()).expect("install.mtree: a non-UTF-8 path");
        let at = || format!("distrib/install.mtree: ./{path}");
        let uid = e.uid().unwrap_or(0);
        let gid = e.gid().unwrap_or(0);
        let source = |src: &str| -> PathBuf {
            if let Some(name) = src.strip_prefix("artifact:") {
                PathBuf::from(artifacts.get(name).unwrap_or_else(|| panic!("{}: no build product {name}", at())))
            } else {
                let p = root.join(src);
                println!("cargo:rerun-if-changed={}", p.display());
                p
            }
        };
        match e.get("type") {
            Some("dir") => {
                let item = Installed { body: InstallBody::Dir, mode: e.mode().unwrap_or(0o755), uid, gid, implicit: false };
                install_insert(&mut tree, path, item);
            }
            Some("file") => {
                if let Some(other) = e.get("hardlink") {
                    let other = other.trim_start_matches("./").to_string();
                    let target = tree.get(&other).unwrap_or_else(|| panic!("{}: hardlink to ./{other}, not installed above", at()));
                    let (mode, uid, gid) = (target.mode, target.uid, target.gid);
                    install_insert(&mut tree, path, Installed { body: InstallBody::Hardlink(other), mode, uid, gid, implicit: false });
                    continue;
                }
                let src = source(e.get("src").unwrap_or_else(|| panic!("{}: a file without src=", at())));
                let mode = e.mode().unwrap_or_else(|| default_file_mode(&src));
                install_insert(&mut tree, path, Installed { body: InstallBody::File(src), mode, uid, gid, implicit: false });
            }
            Some("link") => {
                let target = String::from_utf8(e.link().unwrap_or_else(|| panic!("{}: a link without link=", at()))).unwrap();
                install_insert(&mut tree, path, Installed { body: InstallBody::Link(target), mode: 0o755, uid, gid, implicit: false });
            }
            Some("tree") => {
                let name = e.get("src").and_then(|s| s.strip_prefix("gen:")).unwrap_or_else(|| panic!("{}: a tree without src=gen:", at()));
                match generated.get(name).unwrap_or_else(|| panic!("{}: no generated list {name}", at())) {
                    GenList::Files(files) => {
                        for (rel, src) in files {
                            let mode = default_file_mode(src);
                            let item = Installed { body: InstallBody::File(src.clone()), mode, uid, gid, implicit: false };
                            install_insert(&mut tree, join_rel(&path, rel), item);
                        }
                    }
                    // `*_SYMLINKS` lists are symbolic links, `*_LINKS` second names (oxfs's
                    // seed_tree_symlinks and seed_tree_links).
                    GenList::Pairs(pairs) if name.ends_with("_SYMLINKS") => {
                        for (link, target) in pairs {
                            let item = Installed { body: InstallBody::Link(target.clone()), mode: 0o755, uid, gid, implicit: false };
                            install_insert(&mut tree, join_rel(&path, link), item);
                        }
                    }
                    GenList::Pairs(pairs) => {
                        for (link, existing) in pairs {
                            let existing = join_rel(&path, existing);
                            let t = tree.get(&existing).unwrap_or_else(|| panic!("{}: {name}: ./{existing} not installed", at()));
                            let item = Installed { body: InstallBody::Hardlink(existing.clone()), mode: t.mode, uid: t.uid, gid: t.gid, implicit: false };
                            install_insert(&mut tree, join_rel(&path, link), item);
                        }
                    }
                    GenList::Dirs(dirs) => {
                        for dir in dirs {
                            let item = Installed { body: InstallBody::Dir, mode: 0o755, uid, gid, implicit: true };
                            install_insert(&mut tree, join_rel(&path, dir), item);
                        }
                    }
                }
            }
            other => panic!("{}: unknown type {other:?}", at()),
        }
    }
    for set in SETS {
        let item = Installed { body: InstallBody::SetSpec(set), mode: 0o644, uid: 0, gid: 0, implicit: false };
        install_insert(&mut tree, format!("etc/mtree/{set}.mtree"), item);
    }
    tree
}

/// Whether set-list `pattern` (components, `*` within one, `**` for any number, at least one)
/// matches `path`'s components.
fn set_pattern_matches(pattern: &[&str], path: &[&str]) -> bool {
    fn component(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| component(rest, &s[i..])),
            Some((c, rest)) => s.first() == Some(c) && component(rest, &s[1..]),
        }
    }
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (1..=path.len()).any(|i| set_pattern_matches(rest, &path[i..])),
        Some((p, rest)) => {
            !path.is_empty() && component(p.as_bytes(), path[0].as_bytes()) && set_pattern_matches(rest, &path[1..])
        }
    }
}

/// The set each path belongs to, by `distrib/sets/lists/*`: the most specific matching pattern
/// wins (an exact path, then the longer pattern).
fn assign_sets(root: &Path, tree: &InstallTree) -> std::collections::BTreeMap<String, &'static str> {
    let mut patterns: Vec<(&'static str, String)> = Vec::new();
    for set in SETS {
        let list = root.join("distrib/sets/lists").join(set);
        println!("cargo:rerun-if-changed={}", list.display());
        let text = std::fs::read_to_string(&list).unwrap_or_else(|e| panic!("{}: {e}", list.display()));
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let p = if line == "." { String::new() } else { line.strip_prefix("./").unwrap_or_else(|| panic!("{}: {line}: not ./-relative", list.display())).to_string() };
            patterns.push((set, p));
        }
    }
    let mut out = std::collections::BTreeMap::new();
    let mut unclaimed = Vec::new();
    for path in tree.keys() {
        let comps: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
        let mut best: Option<((bool, usize), &'static str)> = None;
        let mut tied = false;
        for (set, p) in &patterns {
            let pc: Vec<&str> = if p.is_empty() { Vec::new() } else { p.split('/').collect() };
            if !set_pattern_matches(&pc, &comps) {
                continue;
            }
            let rank = (!p.contains('*'), p.len());
            match best {
                Some((r, s)) if r == rank && s != *set => tied = true,
                Some((r, _)) if r >= rank => {}
                _ => {
                    best = Some((rank, set));
                    tied = false;
                }
            }
        }
        match best {
            None => unclaimed.push(format!("./{path}")),
            Some(_) if tied => panic!("distrib/sets/lists: ./{path} is claimed equally by two sets"),
            Some((_, set)) => {
                out.insert(path.clone(), set);
            }
        }
    }
    if !unclaimed.is_empty() {
        panic!("distrib/sets/lists: in no set: {}", unclaimed.join(" "));
    }
    out
}

/// Copies every file into `destdir` (only those whose source is newer or a different size),
/// then makes the hard links.
fn stage_destdir(tree: &InstallTree, destdir: &Path) {
    for (path, item) in tree {
        let dest = destdir.join(path);
        match &item.body {
            InstallBody::Dir => std::fs::create_dir_all(&dest).unwrap_or_else(|e| panic!("{}: {e}", dest.display())),
            InstallBody::File(src) => {
                let s = std::fs::metadata(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
                let fresh = std::fs::metadata(&dest)
                    .is_ok_and(|d| d.len() == s.len() && d.modified().unwrap() >= s.modified().unwrap());
                if !fresh {
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let _ = std::fs::remove_file(&dest);
                    std::fs::copy(src, &dest).unwrap_or_else(|e| panic!("{} -> {}: {e}", src.display(), dest.display()));
                }
            }
            _ => {}
        }
    }
    for (path, item) in tree {
        if let InstallBody::Hardlink(other) = &item.body {
            let dest = destdir.join(path);
            let _ = std::fs::remove_file(&dest);
            std::fs::hard_link(destdir.join(other), &dest).unwrap_or_else(|e| panic!("{}: {e}", dest.display()));
        }
    }
}

/// SHA-256 of `path`, hex, cached in `cache` by `(path, size, mtime)`.
fn file_digest(path: &Path, cache: &mut std::collections::HashMap<String, String>) -> String {
    use sha2::Digest;
    let md = std::fs::metadata(path).unwrap();
    let mtime = md.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let key = format!("{}\t{}\t{mtime}", path.display(), md.len());
    if let Some(d) = cache.get(&key) {
        return d.clone();
    }
    let bytes = std::fs::read(path).unwrap();
    let d: String = sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    cache.insert(key, d.clone());
    d
}

/// Builds a std program of this tree for the host, into `target/host-tools`. The root config's
/// `build-std` can't be turned off, and these programs use `no_std` crates (liboxfs), whose
/// rebuilt `core` would clash with the prebuilt one under std: so std is rebuilt too, with
/// lib/liboxfs's host config.
fn build_host_tool(root: &Path, crate_dir: &str, bin: &str) -> PathBuf {
    let target_dir = root.join("target/host-tools");
    println!("cargo:rerun-if-changed={}", root.join(crate_dir).join("src").display());
    let status = Command::new(cargo_bin())
        .current_dir(root.join(crate_dir))
        .args(["build", "--release", "--target", "x86_64-unknown-linux-gnu", "--config"])
        .arg(root.join("lib/liboxfs/.cargo/config.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER")
        .status()
        .unwrap_or_else(|e| panic!("failed to run cargo for {crate_dir} (host): {e}"));
    assert!(status.success(), "building {crate_dir} for the host failed: {status}");
    target_dir.join("x86_64-unknown-linux-gnu/release").join(bin)
}

fn run_host_tool(tool: &Path, args: &[&std::ffi::OsStr]) {
    let status = Command::new(tool)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", tool.display()));
    assert!(status.success(), "{} {args:?} failed: {status}", tool.display());
}

/// The install step: stages the system, writes each set's specification, and builds the
/// images, all from `env` (the build products and generated lists oxfs is built with).
fn build_sets_and_images(env: &[(&str, &str)]) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in ["regress/oxfs-fixtures", "share/examples", "lib/libmtree/src"] {
        println!("cargo:rerun-if-changed={}", root.join(dir).display());
    }
    let tree = read_install_list(root, env);
    let sets = assign_sets(root, &tree);
    let destdir = root.join("target/destdir");
    stage_destdir(&tree, &destdir);

    // Every inode's time: the source tree's last commit, so a rebuild of the same commit gives
    // the same images (RAM_FLOOR.md §4.3.3).
    let epoch: i64 = Command::new("git")
        .current_dir(root)
        .args(["log", "-1", "--format=%ct"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let sets_dir = root.join("target/sets");
    std::fs::create_dir_all(&sets_dir).unwrap();
    let cache_path = sets_dir.join(".digests");
    let mut cache: std::collections::HashMap<String, String> = std::fs::read_to_string(&cache_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.rsplit_once('\t').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    let mut makefs_inputs = Vec::new();
    for set in SETS {
        // A set carries its own paths and every directory above them, so it can be unpacked
        // or imaged on its own.
        let mut paths: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (path, _) in sets.iter().filter(|(_, s)| **s == set) {
            paths.insert(path);
            let mut p = path.as_str();
            while let Some((up, _)) = p.rsplit_once('/') {
                p = up;
                paths.insert(p);
            }
            paths.insert("");
        }
        let mut spec = mtree::Spec::default();
        let mut makefs = mtree::Spec::default();
        for path in paths {
            let item = &tree[path];
            let mut e = mtree::Entry::new(path.as_bytes());
            e.set("mode", format!("{:04o}", item.mode));
            e.set("uid", item.uid.to_string());
            e.set("gid", item.gid.to_string());
            e.set("time", format!("{epoch}.0"));
            let mut contents = None;
            match &item.body {
                InstallBody::Dir => e.set("type", "dir"),
                InstallBody::Link(target) => {
                    e.set("type", "link");
                    e.set("link", mtree::vis(target.as_bytes()));
                }
                InstallBody::File(_) | InstallBody::Hardlink(_) => {
                    let staged = destdir.join(path);
                    e.set("type", "file");
                    e.set("size", std::fs::metadata(&staged).unwrap().len().to_string());
                    e.set("sha256digest", file_digest(&staged, &mut cache));
                    contents = Some(format!("../destdir/{path}"));
                }
                InstallBody::SetSpec(s) => {
                    e.set("type", "file");
                    contents = Some(format!("{s}.mtree"));
                }
            }
            if let Some(c) = contents {
                let mut m = e.clone();
                m.set("contents", mtree::vis(c.as_bytes()));
                makefs.entries.push(m);
            } else {
                makefs.entries.push(e.clone());
            }
            spec.entries.push(e);
        }
        write_if_changed(&sets_dir.join(format!("{set}.mtree")), spec.write().as_bytes());
        let input = sets_dir.join(format!("{set}.makefs"));
        write_if_changed(&input, makefs.write().as_bytes());
        makefs_inputs.push(input);
    }
    let cache_text: String = cache.iter().map(|(k, v)| format!("{k}\t{v}\n")).collect();
    write_if_changed(&cache_path, cache_text.as_bytes());

    // What the sets hold, without their times: the QEMU runner replaces the dev disk when this
    // changes (RAM_FLOOR.md §4.5.3), and a new commit alone changes only the times.
    let contents: String = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for set in SETS {
            let text = std::fs::read_to_string(sets_dir.join(format!("{set}.mtree"))).unwrap();
            for word in text.split_whitespace().filter(|w| !w.starts_with("time=")) {
                h.update(word.as_bytes());
                h.update(b" ");
            }
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    };
    std::fs::create_dir_all(root.join("target/images")).unwrap();
    write_if_changed(&root.join("target/images/sets.sha256"), format!("{contents}\n").as_bytes());

    let makefs = build_host_tool(root, "usr.sbin/makefs", "makefs");
    let mkimg = build_host_tool(root, "usr.bin/mkimg", "mkimg");
    let fsck = build_host_tool(root, "sbin/fsck_oxfs", "fsck_oxfs");

    // Rebuilt only when a set's contents or a tool changed.
    println!("cargo:rerun-if-env-changed=OXIDEBSD_DISK_MIB");
    let mib: u64 = std::env::var("OXIDEBSD_DISK_MIB").ok().and_then(|s| s.parse().ok()).unwrap_or(1024);
    let images = root.join("target/images");
    std::fs::create_dir_all(&images).unwrap();
    let mut stamp = format!("{mib} {epoch}\n");
    for input in &makefs_inputs {
        stamp += &std::fs::read_to_string(input).unwrap();
    }
    for tool in [&makefs, &mkimg, &fsck] {
        stamp += &format!("{:?}\n", std::fs::metadata(tool).unwrap().modified().unwrap());
    }
    let stamp: String = {
        use sha2::Digest;
        sha2::Sha256::digest(stamp.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    };
    let stamp_path = images.join(".stamp");
    if std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str()) && images.join("disk.img").exists() {
        return;
    }
    let root_img = images.join("root.img");
    let disk_img = images.join("disk.img");
    let size = format!("{mib}m");
    let timestamp = epoch.to_string();
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "-t".as_ref(), "oxfs".as_ref(), "-o".as_ref(), "label=rootfs".as_ref(),
        "-s".as_ref(), size.as_ref(), "-T".as_ref(), timestamp.as_ref(), root_img.as_os_str(),
    ];
    args.extend(makefs_inputs.iter().map(|p| p.as_os_str()));
    run_host_tool(&makefs, &args);
    run_host_tool(&fsck, &["-fn".as_ref(), root_img.as_os_str()]);
    let part = format!("oxfs/rootfs:={}", root_img.display());
    run_host_tool(&mkimg, &["-s".as_ref(), "gpt".as_ref(), "-o".as_ref(), disk_img.as_os_str(), "-p".as_ref(), part.as_ref()]);
    std::fs::write(&stamp_path, stamp).unwrap();
}

/// Writes `path` only when its contents differ, so its mtime means something.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}
