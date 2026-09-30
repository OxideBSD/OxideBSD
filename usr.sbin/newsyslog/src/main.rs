//! `newsyslog(8)`: rotates log files (OxideBSD-doc `SYSLOG.md` §9), FreeBSD's options.
//!
//! ```text
//! newsyslog [-CFNnrsv] [-a directory] [-d directory] [-f config_file] [-S pidfile]
//!           [-t timefmt] [file ...]
//! ```
//!
//! Reads `newsyslog.conf(5)` (`conf`), decides which logs are due, rotates them (`rotate`),
//! signals each daemon once, and then compresses the new archives, once the daemons have let
//! go of them. Run hourly from cron, and at boot as `newsyslog -CN` to create missing logs.

mod clock;
mod conf;
mod rotate;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use conf::{Compress, Entry, Reason};
use rotate::{Ctx, Notices, Pending};

#[derive(Default)]
struct Opts {
    archive_dir: Option<PathBuf>,
    /// `-C` once: create missing logs flagged `C`; twice: every missing log.
    create: u8,
    destdir: Option<String>,
    force: bool,
    config: Option<PathBuf>,
    /// `-N`: nothing but `-C`'s creation.
    create_only: bool,
    dry_run: bool,
    not_root: bool,
    pidfile: Option<String>,
    no_signal: bool,
    timefmt: Option<String>,
    verbose: bool,
    files: Vec<String>,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: newsyslog [-CFNnrsv] [-a directory] [-d directory] [-f config_file]\n\
         \x20                [-S pidfile] [-t timefmt] [file ...]"
    );
    ExitCode::from(1)
}

fn parse_args(args: &[String]) -> Result<Opts, ExitCode> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            break;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else { break };
        i += 1;
        for (j, c) in flags.char_indices() {
            if "adfSt".contains(c) {
                let value = if j + 1 < flags.len() {
                    flags[j + 1..].to_string()
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    return Err(usage());
                };
                match c {
                    'a' => o.archive_dir = Some(PathBuf::from(value)),
                    'd' => o.destdir = Some(value),
                    'f' => o.config = Some(PathBuf::from(value)),
                    'S' => o.pidfile = Some(value),
                    't' => {
                        o.timefmt = Some(if value.is_empty() || value == "DEFAULT" {
                            rotate::DEFAULT_TIMEFMT.to_string()
                        } else {
                            value
                        })
                    }
                    _ => unreachable!(),
                }
                break;
            }
            match c {
                'C' => o.create = (o.create + 1).min(2),
                'F' => o.force = true,
                'N' => o.create_only = true,
                'n' => o.dry_run = true,
                'r' => o.not_root = true,
                's' => o.no_signal = true,
                'v' => o.verbose = true,
                _ => return Err(usage()),
            }
        }
    }
    o.files = args[i..].to_vec();
    Ok(o)
}

/// The logs to look at: every entry's file (each match, for `G`), under `-d`, narrowed to the
/// files named on the command line; a named file no entry mentions takes `<default>`'s.
fn plan(opts: &Opts, entries: &[Entry], warnings: &mut Vec<String>) -> Vec<(Entry, PathBuf)> {
    let prefix = |p: &str| match &opts.destdir {
        Some(d) => format!("{}{p}", d.trim_end_matches('/')),
        None => p.to_string(),
    };
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| !e.is_default()) {
        let path = prefix(&e.path);
        let paths = if e.flags.glob { conf::glob(&path) } else { vec![path] };
        for p in paths {
            if opts.files.is_empty() || opts.files.contains(&p) {
                out.push((e.clone(), PathBuf::from(p)));
            }
        }
    }
    for f in &opts.files {
        if out.iter().any(|(_, p)| p.as_os_str() == f.as_str()) {
            continue;
        }
        match entries.iter().find(|e| e.is_default()) {
            Some(d) => out.push((Entry { path: f.clone(), ..d.clone() }, PathBuf::from(f))),
            None => warnings.push(format!("{f}: not in the configuration")),
        }
    }
    out
}

/// Creates, decides and rotates. Returns the archives to compress and the daemons to tell.
fn run(ctx: &mut Ctx, opts: &Opts, work: &[(Entry, PathBuf)]) -> (Vec<Pending>, Notices) {
    let mut pending = Vec::new();
    let mut notices = Notices::default();
    for (e, path) in work {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if opts.create >= 2 || (opts.create == 1 && e.flags.create) {
                    if let Err(err) = rotate::create(ctx, e, path, None) {
                        ctx.warnings.push(format!("{}: {err}", path.display()));
                    }
                } else if opts.verbose {
                    ctx.out.push(format!("{}: does not exist, skipped", path.display()));
                }
                continue;
            }
            Err(err) => {
                ctx.warnings.push(format!("{}: {err}", path.display()));
                continue;
            }
        };
        if opts.create_only {
            continue;
        }
        if !meta.is_file() {
            ctx.warnings.push(format!("{}: not a regular file", path.display()));
            continue;
        }
        let reason = if opts.force {
            Some(Reason::Force)
        } else {
            conf::due(e, meta.len(), rotate::last_rotation(ctx, path), ctx.now)
        };
        let Some(reason) = reason else {
            if opts.verbose {
                ctx.out.push(format!("{} <{}>: --> not due", path.display(), e.count));
            }
            continue;
        };
        if opts.verbose {
            ctx.out.push(format!("{} <{}>: size (Kb): {} --> trimming log....", path.display(), e.count, meta.len() / 1024));
        }
        match rotate::rotate(ctx, e, path, reason) {
            Ok(Some(archive)) => {
                if let Some(c) = e.flags.compress.filter(|&c| c != Compress::None) {
                    pending.push(Pending { archive, compress: c });
                }
            }
            Ok(None) => {}
            Err(err) => {
                ctx.warnings.push(format!("{}: {err}", path.display()));
                continue;
            }
        }
        if e.flags.nosignal || opts.no_signal {
            continue;
        }
        if e.flags.run {
            let cmd = e.pidfile.clone().unwrap_or_default();
            if !notices.commands.contains(&cmd) {
                notices.commands.push(cmd);
            }
        } else {
            let pidfile = e.pidfile.clone().unwrap_or_else(|| ctx.default_pidfile.clone());
            notices.signals.insert(pidfile, (e.signal, e.flags.group));
        }
    }
    (pending, notices)
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is as long as passed.
    unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    match name.split_once('.') {
        Some((short, _)) if !short.is_empty() => short.to_string(),
        _ => name,
    }
}

fn flush(ctx: &mut Ctx) {
    for line in ctx.out.drain(..) {
        println!("{line}");
    }
    for w in ctx.warnings.drain(..) {
        eprintln!("newsyslog: {w}");
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // SAFETY: geteuid(2) can't fail.
    if !opts.not_root && !opts.dry_run && unsafe { libc::geteuid() } != 0 {
        eprintln!("newsyslog: must have root privileges");
        return ExitCode::from(1);
    }
    let config_path = opts.config.clone().unwrap_or_else(|| PathBuf::from("/etc/newsyslog.conf"));
    if !Path::new(&config_path).exists() {
        eprintln!("newsyslog: {}: No such file or directory", config_path.display());
        return ExitCode::from(1);
    }
    let config = conf::load(&config_path);
    let mut ctx = Ctx {
        now: syslog::time::epoch(),
        host: hostname(),
        pid: std::process::id(),
        dry_run: opts.dry_run,
        verbose: opts.verbose,
        timefmt: opts.timefmt.clone(),
        archive_dir: opts.archive_dir.clone(),
        default_pidfile: opts.pidfile.clone().unwrap_or_else(|| "/var/run/syslog.pid".into()),
        out: Vec::new(),
        warnings: config.errors,
    };
    let work = plan(&opts, &config.entries, &mut ctx.warnings);
    let (pending, notices) = run(&mut ctx, &opts, &work);
    flush(&mut ctx);
    let told = rotate::notify(&mut ctx, &notices);
    flush(&mut ctx);
    // Give the daemons a moment to reopen their logs before their old ones are compressed.
    if told && !pending.is_empty() && !opts.dry_run {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    for p in &pending {
        rotate::compress(&mut ctx, p);
    }
    flush(&mut ctx);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let d = std::env::temp_dir().join(format!("newsyslog-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
        fn p(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.p(name)).unwrap()
        }
        fn exists(&self, name: &str) -> bool {
            self.p(name).exists()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ctx(now: i64) -> Ctx {
        Ctx {
            now,
            host: "box".into(),
            pid: 7,
            dry_run: false,
            verbose: false,
            timefmt: None,
            archive_dir: None,
            default_pidfile: "/nonexistent/syslog.pid".into(),
            out: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn entries(text: &str) -> Vec<Entry> {
        let c = conf::parse(text);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        c.entries
    }

    fn go(ctx: &mut Ctx, opts: &Opts, e: &[Entry]) -> Vec<Pending> {
        let mut w = Vec::new();
        let work = plan(opts, e, &mut w);
        assert!(w.is_empty(), "{w:?}");
        let (pending, notices) = run(ctx, opts, &work);
        assert!(notices.signals.is_empty() && notices.commands.is_empty());
        assert!(ctx.warnings.is_empty(), "{:?}", ctx.warnings);
        pending
    }

    const T0: i64 = 1_790_000_000;

    #[test]
    fn counts_and_message() {
        let s = Scratch::new("counts");
        std::fs::write(s.p("log"), "first\n").unwrap();
        let e = entries(&format!("{} 640 3 * * N\n", s.p("log").display()));
        let opts = Opts { force: true, ..Default::default() };
        for i in 0..4 {
            let mut c = ctx(T0 + i * 3600);
            go(&mut c, &opts, &e);
            std::fs::OpenOptions::new().append(true).open(s.p("log")).unwrap();
        }
        assert!(s.exists("log.0") && s.exists("log.1") && s.exists("log.2"));
        assert!(!s.exists("log.3"));
        assert_eq!(std::fs::metadata(s.p("log.0")).unwrap().mtime(), T0 + 3 * 3600);
        assert_eq!(std::fs::metadata(s.p("log.2")).unwrap().mtime(), T0 + 3600);
        let log = s.read("log");
        assert!(log.ends_with(" box newsyslog[7]: logfile turned over due to -F request\n"), "{log}");
        assert_eq!(std::fs::metadata(s.p("log")).unwrap().permissions().mode() & 0o7777, 0o640);
        assert!(s.read("log.2").contains("logfile turned over"));
    }

    #[test]
    fn due_by_size_and_binary() {
        let s = Scratch::new("size");
        std::fs::write(s.p("log"), vec![b'x'; 2048]).unwrap();
        let e = entries(&format!("{} 644 2 1 * BN\n", s.p("log").display()));
        go(&mut ctx(T0), &Opts::default(), &e);
        assert_eq!(s.read("log"), "");
        assert_eq!(std::fs::metadata(s.p("log.0")).unwrap().len(), 2048);
        // Under the size now: not due.
        go(&mut ctx(T0 + 60), &Opts::default(), &e);
        assert!(!s.exists("log.1"));
    }

    #[test]
    fn due_by_time_since_last() {
        let s = Scratch::new("time");
        std::fs::write(s.p("log"), "x\n").unwrap();
        let e = entries(&format!("{} 644 5 * 24 N\n", s.p("log").display()));
        go(&mut ctx(T0), &Opts::default(), &e);
        assert!(s.exists("log.0"));
        go(&mut ctx(T0 + 23 * 3600), &Opts::default(), &e);
        assert!(!s.exists("log.1"));
        go(&mut ctx(T0 + 24 * 3600), &Opts::default(), &e);
        assert!(s.exists("log.1"));
    }

    #[test]
    fn dry_run() {
        let s = Scratch::new("dry");
        std::fs::write(s.p("log"), "keep\n").unwrap();
        std::fs::write(s.p("log.0"), "old\n").unwrap();
        let e = entries(&format!("{} 644 3 * * NZ\n", s.p("log").display()));
        let mut c = ctx(T0);
        c.dry_run = true;
        let pending = go(&mut c, &Opts { force: true, dry_run: true, ..Default::default() }, &e);
        assert_eq!(s.read("log"), "keep\n");
        assert_eq!(s.read("log.0"), "old\n");
        assert!(!s.exists("log.1"));
        let text = c.out.join("\n");
        assert!(text.contains(&format!("mv {} {}", s.p("log.0").display(), s.p("log.1").display())), "{text}");
        assert!(text.contains(&format!("mv {} {}", s.p("log").display(), s.p("log.0").display())), "{text}");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn creation() {
        let s = Scratch::new("create");
        let e = entries(&format!(
            "{} 640 3 * * C\n{} 644 3 * * -\n",
            s.p("flagged").display(),
            s.p("plain").display()
        ));
        go(&mut ctx(T0), &Opts { create: 1, create_only: true, ..Default::default() }, &e);
        assert!(s.exists("flagged") && !s.exists("plain"));
        assert_eq!(std::fs::metadata(s.p("flagged")).unwrap().permissions().mode() & 0o7777, 0o640);
        assert_eq!(s.read("flagged"), "");
        // Without -C nothing is made; with -CC everything.
        go(&mut ctx(T0), &Opts::default(), &e);
        assert!(!s.exists("plain"));
        go(&mut ctx(T0), &Opts { create: 2, create_only: true, ..Default::default() }, &e);
        assert!(s.exists("plain"));
    }

    #[test]
    fn time_stamped_names() {
        let s = Scratch::new("stamped");
        std::fs::write(s.p("log"), "x\n").unwrap();
        let e = entries(&format!("{} 644 2 * * N\n", s.p("log").display()));
        let opts = Opts { force: true, ..Default::default() };
        for i in 0..3 {
            let mut c = ctx(T0 + i * 3600);
            c.timefmt = Some(rotate::DEFAULT_TIMEFMT.into());
            go(&mut c, &opts, &e);
        }
        let mut names: Vec<String> = std::fs::read_dir(&s.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let want: Vec<String> = std::iter::once("log".to_string())
            .chain((1..3).map(|i| format!("log.{}", clock::format(rotate::DEFAULT_TIMEFMT, T0 + i * 3600))))
            .collect();
        assert_eq!(names, want);
    }

    #[test]
    fn archive_directory() {
        let s = Scratch::new("archdir");
        std::fs::create_dir(s.p("old")).unwrap();
        std::fs::write(s.p("log"), "x\n").unwrap();
        let e = entries(&format!("{} 644 2 * * N\n", s.p("log").display()));
        let mut c = ctx(T0);
        c.archive_dir = Some("old".into());
        go(&mut c, &Opts { force: true, ..Default::default() }, &e);
        assert!(s.exists("old/log.0") && s.exists("log"));
    }

    #[test]
    fn compression() {
        if rotate::compressor(Compress::Gzip).is_none() {
            eprintln!("no gzip on this host: skipped");
            return;
        }
        let s = Scratch::new("gzip");
        std::fs::write(s.p("log"), "one\n").unwrap();
        let e = entries(&format!("{} 644 3 * * NZ\n", s.p("log").display()));
        let opts = Opts { force: true, ..Default::default() };
        for i in 0..2 {
            let mut c = ctx(T0 + i * 3600);
            let pending = go(&mut c, &opts, &e);
            for p in &pending {
                rotate::compress(&mut c, p);
            }
            assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        }
        assert!(s.exists("log.0.gz") && s.exists("log.1.gz"));
        assert!(!s.exists("log.0") && !s.exists("log.1"));
        assert_eq!(std::fs::metadata(s.p("log.0.gz")).unwrap().mtime(), T0 + 3600);
        assert_eq!(std::fs::metadata(s.p("log.1.gz")).unwrap().mtime(), T0);
        // The next decision reads the compressed archive's time.
        let c = ctx(T0 + 7200);
        assert_eq!(rotate::last_rotation(&c, &s.p("log")), Some(T0 + 3600));
    }

    #[test]
    fn plans() {
        let s = Scratch::new("plan");
        std::fs::write(s.p("a.x"), "").unwrap();
        std::fs::write(s.p("b.x"), "").unwrap();
        let e = entries(&format!(
            "{}/*.x 644 1 * * G\n{} 644 1 * *\n<default> 600 9 * *\n",
            s.0.display(),
            s.p("c").display()
        ));
        let mut w = Vec::new();
        let all = plan(&Opts::default(), &e, &mut w);
        let paths: Vec<_> = all.iter().map(|(_, p)| p.clone()).collect();
        assert_eq!(paths, [s.p("a.x"), s.p("b.x"), s.p("c")]);
        let named = Opts { files: vec![s.p("b.x").display().to_string(), "/elsewhere".into()], ..Default::default() };
        let some = plan(&named, &e, &mut w);
        assert_eq!(some.len(), 2);
        assert_eq!(some[1].0.count, 9);
        assert_eq!(some[1].1, PathBuf::from("/elsewhere"));
        assert!(w.is_empty());
    }

    #[test]
    fn notices() {
        let s = Scratch::new("notices");
        std::fs::write(s.p("a"), "").unwrap();
        std::fs::write(s.p("b"), "").unwrap();
        let e = entries(&format!(
            "{} 644 1 * * - /var/run/d.pid USR1\n{} 644 1 * * U\n",
            s.p("a").display(),
            s.p("b").display()
        ));
        let mut c = ctx(T0);
        let mut w = Vec::new();
        let work = plan(&Opts::default(), &e, &mut w);
        let (_, n) = run(&mut c, &Opts { force: true, ..Default::default() }, &work);
        assert_eq!(n.signals.get("/var/run/d.pid"), Some(&(libc::SIGUSR1, false)));
        assert_eq!(n.signals.get("/nonexistent/syslog.pid"), Some(&(libc::SIGHUP, true)));
        let (_, n) = run(&mut ctx(T0), &Opts { force: true, no_signal: true, ..Default::default() }, &work);
        assert!(n.signals.is_empty());
    }

    #[test]
    fn options() {
        let a = |v: &[&str]| parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).ok().unwrap();
        let o = a(&["-CCnv", "-t", "", "-f/x.conf", "-a", "old", "/var/log/messages"]);
        assert_eq!(o.create, 2);
        assert!(o.dry_run && o.verbose);
        assert_eq!(o.timefmt.as_deref(), Some(rotate::DEFAULT_TIMEFMT));
        assert_eq!(o.config, Some(PathBuf::from("/x.conf")));
        assert_eq!(o.files, ["/var/log/messages"]);
        let o = a(&["-t", "%Y", "-S", "/p"]);
        assert_eq!(o.timefmt.as_deref(), Some("%Y"));
        assert_eq!(o.pidfile.as_deref(), Some("/p"));
        assert!(parse_args(&["-q".to_string()]).is_err());
    }
}
