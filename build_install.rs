// The install step and the system's images (OxideBSD-doc `RAM_FLOOR.md` §4.3-4.4), included by
// build.rs. Its own file, as build_busybox.rs is, so editing it doesn't touch build.rs.
//
// `distrib/install.mtree` lists everything installed into the system's file tree. It is staged
// into `target/destdir`, split into dist sets by `distrib/sets/lists/*`, and each set described
// by an mtree(5) specification, `target/sets/<set>.mtree`, which the image carries as
// `/etc/mtree/<set>.mtree`. Host builds of makefs(8), fsck_oxfs(8) and mkimg(1) then make
// `target/images/root.img` (the root file system, every set) and `target/images/disk.img` (a GPT
// disk holding it as `rootfs`), checked by fsck_oxfs. Each set is also archived as
// `target/sets/<set>.tar.zst`, the distribution format.

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
    let zstd = build_zstd(Path::new("cc"), &[], &root.join("target/host-tools/zstd"), None);
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
        let paths: Vec<&str> = paths.into_iter().collect();
        let mut spec = mtree::Spec::default();
        let mut makefs = mtree::Spec::default();
        for &path in &paths {
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
        write_set_archive(set, &paths, &tree, &destdir, &sets_dir, epoch, &zstd);
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

    // The install medium's pieces (INSTALLER.md §3-4), unless OXIDEBSD_NO_INSTALLER is set; the
    // QEMU runner (scripts/mkinstalliso.sh) wraps them and a kernel into install.iso.
    println!("cargo:rerun-if-env-changed=OXIDEBSD_NO_INSTALLER");
    if std::env::var_os("OXIDEBSD_NO_INSTALLER").is_none() {
        let artifact = |name: &str| {
            env.iter().find(|(n, _)| *n == name).map(|(_, p)| Path::new(*p)).unwrap_or_else(|| panic!("no {name}"))
        };
        let (installer, rescue) = (artifact("OXFS_INSTALLER_ELF_PATH"), artifact("OXFS_RESCUE_ELF_PATH"));
        build_mfsroot(root, &tree, &destdir, installer, rescue, epoch, &makefs, &fsck);
        let images = root.join("target/images");
        compress_mfsroot(&images.join("mfsroot.img"), &images.join("mfsroot.uz"), &zstd);
        write_manifest(&sets, &sets_dir);
    }

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

/// `target/images/mfsroot.img` (INSTALLER.md §4): the paths `distrib/mfsroot/list` names, from
/// the installed tree or, marked `rescue`, as names of `/rescue/rescue` (one inode: makefs keeps
/// files of one host inode as one), with their directories, `distrib/mfsroot/etc/*` in place of
/// the tree's files of the same names, and the installer, as an oxfs image just large enough to
/// hold them.
#[allow(clippy::too_many_arguments)]
fn build_mfsroot(root: &Path, tree: &InstallTree, destdir: &Path, installer: &Path, rescue: &Path, epoch: i64, makefs: &Path, fsck: &Path) {
    let dir = root.join("distrib/mfsroot");
    println!("cargo:rerun-if-changed={}", dir.display());
    let list = std::fs::read_to_string(dir.join("list")).unwrap_or_else(|e| panic!("distrib/mfsroot/list: {e}"));
    // Path -> (mode, the file's contents, or None for a directory).
    let mut files: std::collections::BTreeMap<String, (u32, Option<PathBuf>)> = std::collections::BTreeMap::new();
    files.insert("rescue/rescue".into(), (0o755, Some(rescue.to_path_buf())));
    for line in list.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut words = line.split_whitespace();
        let path = words.next().unwrap().trim_start_matches("./");
        if words.next() == Some("rescue") {
            files.insert(path.to_string(), (0o755, Some(rescue.to_path_buf())));
            continue;
        }
        let item = tree.get(path).unwrap_or_else(|| panic!("distrib/mfsroot/list: {line} isn't installed"));
        files.insert(path.to_string(), (item.mode, Some(destdir.join(path))));
    }
    for e in std::fs::read_dir(dir.join("etc")).unwrap().flatten() {
        let name = format!("etc/{}", e.file_name().to_string_lossy());
        let mode = default_file_mode(&e.path());
        files.insert(name, (mode, Some(e.path())));
    }
    files.insert("usr/libexec/installer".into(), (0o755, Some(installer.to_path_buf())));
    for d in ["dev", "proc", "tmp", "mnt", "cdrom", "var/run", "root"] {
        files.insert(d.into(), (if d == "tmp" { 0o1777 } else { 0o755 }, None));
    }
    strip_programs(root, &mut files);
    let paths: Vec<String> = files.keys().cloned().collect();
    for p in paths {
        let mut up = p.as_str();
        while let Some((parent, _)) = up.rsplit_once('/') {
            files.entry(parent.to_string()).or_insert((0o755, None));
            up = parent;
        }
    }
    let mut spec = mtree::Spec::default();
    let mut top = mtree::Entry::new(b"");
    top.set("type", "dir");
    top.set("mode", "0755");
    spec.entries.push(top);
    for (path, (mode, contents)) in &files {
        let mut e = mtree::Entry::new(path.as_bytes());
        e.set("mode", format!("{mode:04o}"));
        e.set("uid", "0");
        e.set("gid", "0");
        e.set("time", format!("{epoch}.0"));
        match contents {
            Some(c) => {
                println!("cargo:rerun-if-changed={}", c.display());
                e.set("type", "file");
                e.set("contents", mtree::vis(c.to_str().unwrap().as_bytes()));
            }
            None => e.set("type", "dir"),
        }
        spec.entries.push(e);
    }
    let images = root.join("target/images");
    std::fs::create_dir_all(&images).unwrap();
    let input = images.join("mfsroot.makefs");
    write_if_changed(&input, spec.write().as_bytes());
    let img = images.join("mfsroot.img");
    let newest = files
        .values()
        .filter_map(|(_, c)| c.as_ref())
        .chain([&input, &makefs.to_path_buf()])
        .filter_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .max();
    if std::fs::metadata(&img).and_then(|m| m.modified()).is_ok_and(|t| newest.is_some_and(|n| t >= n)) {
        return;
    }
    let timestamp = epoch.to_string();
    run_host_tool(
        makefs,
        &["-t".as_ref(), "oxfs".as_ref(), "-o".as_ref(), "label=mfsroot".as_ref(), "-T".as_ref(), timestamp.as_ref(), img.as_os_str(), input.as_os_str()],
    );
    run_host_tool(fsck, &["-fn".as_ref(), img.as_os_str()]);
}

/// The mfsroot's programs without their symbol tables: it lives in memory, and at 64 MB under
/// UEFI the boot loader has to fit it in what the firmware leaves. Each ELF among `files` is
/// replaced by a stripped copy under `target/images/mfsroot-strip`, one per source file, so the
/// rescue tools' many names still share one inode.
fn strip_programs(root: &Path, files: &mut std::collections::BTreeMap<String, (u32, Option<PathBuf>)>) {
    let out = root.join("target/images/mfsroot-strip");
    std::fs::create_dir_all(&out).unwrap();
    let sysroot = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc --print sysroot");
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_string();
    let objcopy = Path::new(&sysroot).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy");
    let mut done: std::collections::BTreeMap<PathBuf, PathBuf> = std::collections::BTreeMap::new();
    for (_, contents) in files.values_mut() {
        let Some(src) = contents.as_ref() else { continue };
        if let Some(copy) = done.get(src) {
            *contents = Some(copy.clone());
            continue;
        }
        let mut magic = [0u8; 4];
        let is_elf = std::fs::File::open(src).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic)).is_ok() && &magic == b"\x7fELF";
        if !is_elf {
            continue;
        }
        let name = src.to_string_lossy().trim_start_matches('/').replace('/', "_");
        let copy = out.join(name);
        let stale = |a: &Path, b: &Path| {
            let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
            m(b).is_none() || m(a) > m(b)
        };
        if stale(src, &copy) {
            run_host_tool(&objcopy, &["--strip-all".as_ref(), src.as_os_str(), copy.as_os_str()]);
        }
        done.insert(src.clone(), copy.clone());
        *contents = Some(copy);
    }
}

/// The mfsroot the install medium carries (INSTALLER.md §4.3): `img` cut into 64 KiB chunks, each
/// compressed by `zstd` alone, in the format `sys/drivers/md.rs` reads ("OXUZIP01").
fn compress_mfsroot(img: &Path, out: &Path, zstd: &Path) {
    const CHUNK: usize = 64 * 1024;
    let fresh = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    if fresh(out).is_some() && fresh(out) >= fresh(img) && fresh(out) >= fresh(zstd) {
        return;
    }
    let data = std::fs::read(img).unwrap_or_else(|e| panic!("{}: {e}", img.display()));
    let chunks: Vec<&[u8]> = data.chunks(CHUNK).collect();
    let mut stored = Vec::new();
    for chunk in &chunks {
        use std::io::Write;
        // The size in the frame, and a window no larger than the chunk: md decodes with one.
        let mut child = Command::new(zstd)
            .args(["-q", "-19", "-c", "--no-check", "--zstd=wlog=16"])
            .arg(format!("--stream-size={}", chunk.len()))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to run {}: {e}", zstd.display()));
        let mut stdin = child.stdin.take().unwrap();
        let input = chunk.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(output.status.success(), "zstd failed on an mfsroot chunk");
        stored.push(if output.stdout.len() < chunk.len() { output.stdout } else { chunk.to_vec() });
    }
    let mut file = Vec::new();
    file.extend_from_slice(b"OXUZIP01");
    file.extend_from_slice(&(CHUNK as u32).to_le_bytes());
    file.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    file.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut at = 24 + 8 * (chunks.len() as u64 + 1);
    for c in &stored {
        file.extend_from_slice(&at.to_le_bytes());
        at += c.len() as u64;
    }
    file.extend_from_slice(&at.to_le_bytes());
    for c in &stored {
        file.extend_from_slice(c);
    }
    std::fs::write(out, file).unwrap();
}

/// `target/sets/MANIFEST` (INSTALLER.md §3.2), FreeBSD's format: per set its archive's name,
/// SHA-256 and number of entries, the set's name, a description, and whether it's chosen by
/// default.
fn write_manifest(sets: &std::collections::BTreeMap<String, &'static str>, sets_dir: &Path) {
    use sha2::Digest;
    let mut text = String::new();
    for set in SETS {
        let archive = sets_dir.join(format!("{set}.tar.zst"));
        let digest: String = sha2::Sha256::digest(std::fs::read(&archive).unwrap()).iter().map(|b| format!("{b:02x}")).collect();
        let entries = sets.values().filter(|s| **s == set).count();
        let (descr, on) = match set {
            "base" => ("Base system (MANDATORY)", "on"),
            "clang" => ("Clang/LLVM, the C and C++ toolchain", "off"),
            _ => ("The test programs", "off"),
        };
        text += &format!("{set}.tar.zst\t{digest}\t{entries}\t{set}\t\"{descr}\"\t{on}\n");
    }
    write_if_changed(&sets_dir.join("MANIFEST"), text.as_bytes());
}

/// One ustar(5) header block. `path` is split into `prefix` and `name` at a `/` when it's longer
/// than 100 bytes; numbers are zero-padded octal. Owners 0 are named `root` and `wheel`.
fn ustar_header(path: &str, item: &Installed, typeflag: u8, size: u64, linkname: &str, mtime: i64) -> [u8; 512] {
    let mut h = [0u8; 512];
    fn put(h: &mut [u8], at: usize, len: usize, bytes: &[u8]) {
        assert!(bytes.len() <= len, "ustar field too long: {:?}", String::from_utf8_lossy(bytes));
        h[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn octal(h: &mut [u8], at: usize, len: usize, value: u64) {
        let text = format!("{value:0width$o}", width = len - 1);
        put(h, at, len - 1, text.as_bytes());
    }
    let (prefix, name) = if path.len() <= 100 {
        ("", path)
    } else {
        let split = path
            .match_indices('/')
            .map(|(i, _)| i)
            .find(|&i| i <= 155 && path.len() - i - 1 <= 100 && i + 1 < path.len())
            .unwrap_or_else(|| panic!("{path}: too long for a ustar name"));
        (&path[..split], &path[split + 1..])
    };
    put(&mut h, 0, 100, name.as_bytes());
    octal(&mut h, 100, 8, u64::from(item.mode & 0o7777));
    octal(&mut h, 108, 8, u64::from(item.uid));
    octal(&mut h, 116, 8, u64::from(item.gid));
    octal(&mut h, 124, 12, size);
    octal(&mut h, 136, 12, mtime.max(0) as u64);
    h[156] = typeflag;
    put(&mut h, 157, 100, linkname.as_bytes());
    put(&mut h, 257, 6, b"ustar\0");
    put(&mut h, 263, 2, b"00");
    if item.uid == 0 {
        put(&mut h, 265, 32, b"root");
    }
    if item.gid == 0 {
        put(&mut h, 297, 32, b"wheel");
    }
    put(&mut h, 345, 155, prefix.as_bytes());
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    put(&mut h, 148, 8, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Writes `target/sets/<set>.tar.zst` (RAM_FLOOR.md §4.3.4): a ustar archive of the set's
/// `paths` in order, every entry dated `epoch`, compressed by the host build of the vendored
/// zstd. Byte-identical for the same set and zstd: rewritten only when the set's specification
/// or zstd changed. Of a file's hard-linked names, the first in the archive holds the data and
/// the others link to it.
fn write_set_archive(set: &str, paths: &[&str], tree: &InstallTree, destdir: &Path, sets_dir: &Path, epoch: i64, zstd: &Path) {
    use std::io::Write;
    let out = sets_dir.join(format!("{set}.tar.zst"));
    let stamp_path = sets_dir.join(format!(".{set}.tar.zst.stamp"));
    let stamp = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(std::fs::read(sets_dir.join(format!("{set}.mtree"))).unwrap());
        h.update(format!("{:?}", std::fs::metadata(zstd).unwrap().modified().unwrap()));
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    if out.exists() && std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str()) {
        return;
    }
    let tmp = sets_dir.join(format!("{set}.tar.zst.tmp"));
    // Multithreaded zstd gives the same bytes whatever the thread count; level 19 keeps zstd's
    // 8 MiB window, so a 64 MB machine can unpack it (no --long).
    let mut child = Command::new(zstd)
        .args(["-q", "-19", "-T0", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::fs::File::create(&tmp).unwrap())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", zstd.display()));
    {
        let mut w = std::io::BufWriter::new(child.stdin.take().unwrap());
        // A linked file's install-list name -> its first name in this archive.
        let mut first_name: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for &path in paths {
            let item = &tree[path];
            let name = if path.is_empty() { "./".to_string() } else { format!("./{path}") };
            let file = |src: &Path, w: &mut std::io::BufWriter<_>| {
                let bytes = std::fs::read(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
                w.write_all(&ustar_header(&name, item, b'0', bytes.len() as u64, "", epoch)).unwrap();
                w.write_all(&bytes).unwrap();
                w.write_all(&vec![0u8; (512 - bytes.len() % 512) % 512]).unwrap();
            };
            match &item.body {
                InstallBody::Dir => {
                    let dir = if path.is_empty() { name.clone() } else { format!("{name}/") };
                    w.write_all(&ustar_header(&dir, item, b'5', 0, "", epoch)).unwrap();
                }
                InstallBody::Link(target) => {
                    w.write_all(&ustar_header(&name, item, b'2', 0, target, epoch)).unwrap();
                }
                InstallBody::File(_) | InstallBody::Hardlink(_) => {
                    let inode = match &item.body {
                        InstallBody::Hardlink(other) => other.as_str(),
                        _ => path,
                    };
                    match first_name.get(inode) {
                        Some(first) => w.write_all(&ustar_header(&name, item, b'1', 0, &format!("./{first}"), epoch)).unwrap(),
                        None => {
                            file(&destdir.join(path), &mut w);
                            first_name.insert(inode, path);
                        }
                    }
                }
                InstallBody::SetSpec(s) => file(&sets_dir.join(format!("{s}.mtree")), &mut w),
            }
        }
        w.write_all(&[0u8; 1024]).unwrap();
        w.flush().unwrap();
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "zstd for {set}.tar.zst failed: {status}");
    std::fs::rename(&tmp, &out).unwrap();
    std::fs::write(&stamp_path, stamp).unwrap();
}

/// Writes `path` only when its contents differ, so its mtime means something.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}
