//! `syslogd(8)`: the system log daemon (OxideBSD-doc `SYSLOG.md` §6), FreeBSD's options.
//!
//! ```text
//! syslogd [-CdFkNnTv] [-a allowed_peer] [-b address[:service]] [-f config_file]
//!         [-l [mode:]path] [-m mark_interval] [-O format] [-P pid_file] [-s]
//! ```
//!
//! One `poll(2)` loop reads the local socket `/dev/log` (and any `-l` sockets), the kernel's
//! `/dev/klog`, UDP port 514 unless `-s`, and TCP and TLS connections when `syslog.conf` asks
//! (`tcp_server`, `tls_server`), and hands each message to the rules of `syslog.conf(5)`
//! (`conf`), which write it out (`action`); TCP and TLS actions' connections live in the same
//! loop (`net`). Signals arrive through a pipe the loop also polls: `SIGHUP` reloads,
//! `SIGTERM`/`SIGINT` end it, `SIGCHLD` reaps pipe commands.
//!
//! Messages from this host, the local socket's and the kernel's, are stamped when they arrive:
//! the sender's stamp is local time from the same clock, a moment earlier, and musl's
//! `syslog(3)` writes it in UTC. Messages from the network keep theirs unless `-T`.

mod action;
mod conf;
mod net;

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

use syslog::msg::{Format, Message};
use syslog::pri::{Facility, Level, Priority};

use action::{Action, Outgoing, Style};

/// The longest message read, as FreeBSD's `MAXLINE`.
const MAXLINE: usize = 8192;

struct Opts {
    allowed: Vec<Peer>,
    bind: Vec<String>,
    create: bool,
    debug: bool,
    foreground: bool,
    config: PathBuf,
    keep_kern: bool,
    sockets: Vec<(u32, PathBuf)>,
    mark_minutes: u64,
    no_network: bool,
    no_lookups: bool,
    format: Format,
    pidfile: PathBuf,
    /// 1: don't receive from the network; 2: don't send either.
    secure: u8,
    receipt_time: bool,
    verbose: u8,
}

/// An `-a` entry: `address[/mask][:service]` or `[*.]domain[:service]`.
#[derive(Debug)]
enum PeerHost {
    Net(Ipv4Addr, u32),
    Domain(String),
}

#[derive(Debug)]
struct Peer {
    host: PeerHost,
    port: Option<u16>,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: syslogd [-CdFkNnTv] [-a allowed_peer] [-b address[:service]] [-f config_file]\n\
         \x20              [-l [mode:]path] [-m mark_interval] [-O format] [-P pid_file] [-s]"
    );
    ExitCode::from(1)
}

fn parse_service(s: &str) -> Option<u16> {
    match s {
        "syslog" => Some(514),
        _ => s.parse().ok(),
    }
}

fn parse_peer(spec: &str) -> Option<Peer> {
    let (host, port) = match spec.rsplit_once(':') {
        Some((h, p)) => (h, Some(parse_service(p)?)),
        None => (spec, None),
    };
    let (addr, bits) = match host.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (host, None),
    };
    if let Ok(ip) = addr.parse::<Ipv4Addr>() {
        let bits = match bits {
            None => 32,
            Some(m) => match m.parse::<Ipv4Addr>() {
                Ok(mask) => u32::from(mask).count_ones(),
                Err(_) => m.parse::<u32>().ok().filter(|&b| b <= 32)?,
            },
        };
        return Some(Peer { host: PeerHost::Net(ip, bits), port });
    }
    if bits.is_some() || host.is_empty() {
        return None;
    }
    Some(Peer { host: PeerHost::Domain(host.to_ascii_lowercase()), port })
}

impl Peer {
    fn allows(&self, addr: &SocketAddr, name: Option<&str>) -> bool {
        if self.port.is_some_and(|p| p != addr.port()) {
            return false;
        }
        match (&self.host, addr.ip()) {
            (PeerHost::Net(net, bits), IpAddr::V4(ip)) => {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                u32::from(ip) & mask == u32::from(*net) & mask
            }
            (PeerHost::Domain(d), _) => {
                let Some(name) = name else { return false };
                let name = name.to_ascii_lowercase();
                match d.strip_prefix("*.") {
                    Some(suffix) => name.ends_with(&format!(".{suffix}")),
                    None => name == *d,
                }
            }
            _ => false,
        }
    }
}

fn parse_args() -> Result<Opts, ExitCode> {
    let mut o = Opts {
        allowed: Vec::new(),
        bind: Vec::new(),
        create: false,
        debug: false,
        foreground: false,
        config: PathBuf::from("/etc/syslog.conf"),
        keep_kern: false,
        sockets: Vec::new(),
        mark_minutes: 20,
        no_network: false,
        no_lookups: false,
        format: Format::Rfc3164,
        pidfile: PathBuf::from("/var/run/syslog.pid"),
        secure: 0,
        receipt_time: false,
        verbose: 0,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        if arg == "--" {
            break;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            return Err(usage());
        };
        for (j, c) in flags.char_indices() {
            if "abflmOP".contains(c) {
                let value = if j + 1 < flags.len() {
                    flags[j + 1..].to_string()
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    return Err(usage());
                };
                match c {
                    'a' => match parse_peer(&value) {
                        Some(p) => o.allowed.push(p),
                        None => {
                            eprintln!("syslogd: bad allowed peer: {value}");
                            return Err(ExitCode::from(1));
                        }
                    },
                    'b' => o.bind.push(value),
                    'f' => o.config = PathBuf::from(value),
                    'l' => {
                        let (mode, path) = match value.split_once(':') {
                            Some((m, p)) if u32::from_str_radix(m, 8).is_ok() => {
                                (u32::from_str_radix(m, 8).unwrap(), p.to_string())
                            }
                            _ => (0o666, value.clone()),
                        };
                        o.sockets.push((mode, PathBuf::from(path)));
                    }
                    'm' => match value.parse() {
                        Ok(m) => o.mark_minutes = m,
                        Err(_) => return Err(usage()),
                    },
                    'O' => {
                        o.format = match value.as_str() {
                            "bsd" | "rfc3164" => Format::Rfc3164,
                            "syslog" | "rfc5424" => Format::Rfc5424,
                            _ => {
                                eprintln!("syslogd: unknown output format: {value}");
                                return Err(ExitCode::from(1));
                            }
                        }
                    }
                    'P' => o.pidfile = PathBuf::from(value),
                    _ => unreachable!(),
                }
                break;
            }
            match c {
                'C' => o.create = true,
                'd' => {
                    o.debug = true;
                    o.foreground = true;
                }
                'F' => o.foreground = true,
                'k' => o.keep_kern = true,
                'N' => o.no_network = true,
                'n' => o.no_lookups = true,
                's' => o.secure = (o.secure + 1).min(2),
                'T' => o.receipt_time = true,
                'v' => o.verbose = (o.verbose + 1).min(2),
                _ => return Err(usage()),
            }
        }
    }
    if i < args.len() {
        return Err(usage());
    }
    Ok(o)
}

/// The write end of the signal pipe, for the handler.
static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    let fd = SIGNAL_PIPE.load(Ordering::Relaxed);
    let b = sig as u8;
    // SAFETY: write(2) is async-signal-safe; the pipe is non-blocking, so a full pipe drops it.
    unsafe { libc::write(fd, (&b as *const u8).cast(), 1) };
}

fn install_signals() -> RawFd {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for two descriptors.
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    SIGNAL_PIPE.store(fds[1], Ordering::Relaxed);
    for sig in [libc::SIGHUP, libc::SIGTERM, libc::SIGINT, libc::SIGCHLD] {
        // SAFETY: installing a handler that only writes to a pipe.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    // SAFETY: ignoring SIGPIPE (§6.6): a dead pipe command shows up as a failed write.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    fds[0]
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is as long as passed.
    unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    // The BSDs log the host's name without its domain.
    match name.split_once('.') {
        Some((short, _)) if !short.is_empty() => short.to_string(),
        _ if name.is_empty() => "localhost".into(),
        _ => name,
    }
}

/// Binds a local log socket at `path`, replacing whatever stale file is there.
fn open_log_socket(path: &std::path::Path, mode: u32) -> std::io::Result<UnixDatagram> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let sock = UnixDatagram::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Where a message came from.
enum Source {
    Local,
    Kernel,
    Remote(SocketAddr),
}

struct Daemon {
    opts: Opts,
    host: String,
    actions: Vec<Action>,
    net_out: Option<UdpSocket>,
    names: std::collections::HashMap<IpAddr, String>,
    /// The configuration's TCP and TLS options, as the listeners were set up from them.
    net: Option<conf::NetOptions>,
    listeners: Vec<net::Listener>,
    inbound: Vec<net::Inbound>,
}

impl Daemon {
    fn style(&self) -> Style {
        Style { format: self.opts.format, verbose: self.opts.verbose, forward: self.opts.secure < 2 && !self.opts.no_network }
    }

    /// Reads the configuration and prepares its actions, closing the old ones.
    fn load(&mut self) {
        let now = syslog::time::epoch();
        let style = self.style();
        for a in &mut self.actions {
            a.flush_repeats(style, self.net_out.as_ref(), now, false);
            a.close();
        }
        self.actions.clear();
        let mut config = conf::load(&self.opts.config);
        let mut problems = std::mem::take(&mut config.errors);
        if config.rules.is_empty() && !problems.is_empty() && !self.opts.config.exists() {
            config = conf::fallback();
        }
        let (net_opts, errors) = conf::NetOptions::from(&config.options);
        problems.extend(errors);
        let mut notes = Vec::new();
        match net::generate_identity(&net_opts, &self.host) {
            Ok(Some(note)) => notes.push(note),
            Ok(None) => {}
            Err(e) => problems.push(format!("tls_gen_cert: {e}")),
        }
        for rule in config.rules {
            let (action, failure) = Action::new(rule, self.opts.create, now, &net_opts);
            problems.extend(failure);
            self.actions.push(action);
        }
        if self.net.as_ref() != Some(&net_opts) {
            self.listeners = self.listen(&net_opts, &mut problems);
            self.net = Some(net_opts);
        }
        for n in notes {
            self.internal(Level::NOTICE, &n);
        }
        for p in problems {
            self.internal(Level::ERR, &p);
        }
        // Stream actions connect now rather than with their first message.
        self.pump_streams(0);
    }

    /// The `tcp_server` and `tls_server` listeners, unless network input is off (`-s`, `-N`).
    fn listen(&self, o: &conf::NetOptions, problems: &mut Vec<String>) -> Vec<net::Listener> {
        let mut out = Vec::new();
        if self.opts.no_network || self.opts.secure > 0 {
            return out;
        }
        if o.tcp_server {
            match net::Listener::bind(o.tcp_bindhost.as_deref(), o.tcp_bindport, None) {
                Ok(l) => out.push(l),
                Err(e) => problems.push(format!("tcp_server: bind port {}: {e}", o.tcp_bindport)),
            }
        }
        if o.tls_server {
            match net::acceptor(o) {
                Ok(a) => match net::Listener::bind(o.tls_bindhost.as_deref(), o.tls_bindport, Some(a)) {
                    Ok(l) => out.push(l),
                    Err(e) => problems.push(format!("tls_server: bind port {}: {e}", o.tls_bindport)),
                },
                Err(e) => problems.push(format!("tls_server: {e}")),
            }
        }
        out
    }

    /// Advances every stream action: after `poll` (`revents` per action, by index) or for its
    /// reconnection timer (`revents` empty).
    fn pump_streams_with(&mut self, revents: &[(usize, i16)], due_only: bool) {
        let now = syslog::time::epoch();
        let mut log = Vec::new();
        for (i, a) in self.actions.iter_mut().enumerate() {
            let ev = revents.iter().find(|(j, _)| *j == i).map(|(_, e)| *e);
            let run = match ev {
                Some(_) => true,
                None => !due_only || a.stream_due().is_some_and(|d| d <= now),
            };
            if run {
                log.extend(a.stream_pump(now, ev.unwrap_or(0)));
            }
        }
        for l in log {
            self.internal(Level::ERR, &l);
        }
    }

    fn pump_streams(&mut self, _revents: i16) {
        self.pump_streams_with(&[], false);
    }

    /// Logs one of syslogd's own messages, as `syslogd: text`.
    fn internal(&mut self, level: Level, text: &str) {
        if self.opts.debug {
            eprintln!("syslogd: {text}");
        }
        let mut msg = Message::new(Priority::new(Facility::SYSLOG, level), Some("syslogd"), text);
        msg.stamp = Some(syslog::time::now());
        self.dispatch(&msg, Origin::Local);
    }

    fn remote_name(&mut self, addr: &SocketAddr) -> String {
        let ip = addr.ip();
        if self.opts.no_lookups {
            return ip.to_string();
        }
        if let Some(n) = self.names.get(&ip) {
            return n.clone();
        }
        let name = reverse_lookup(addr).unwrap_or_else(|| ip.to_string());
        if self.names.len() > 1024 {
            self.names.clear();
        }
        self.names.insert(ip, name.clone());
        name
    }

    /// Takes one received message: decides its priority, host and stamp, and hands it to every
    /// action that selects it.
    fn receive(&mut self, bytes: &[u8], source: Source) {
        let remote = matches!(source, Source::Remote(_));
        let mut msg = Message::parse(bytes, remote);
        match source {
            Source::Kernel => {
                // Lines without a prefix are kern.notice (§3.2); parse left them user.notice.
                if syslog::pri::parse_prefix(bytes).is_none() {
                    msg.priority = Priority::new(Facility::KERN, Level::NOTICE);
                }
                // The kernel's lines are tagged "kernel"; what looked like a tag ("oxfs: ...")
                // is part of the text.
                msg.text = match (&msg.app, &msg.procid) {
                    (Some(a), Some(p)) => format!("{a}[{p}]: {}", msg.text),
                    (Some(a), None) => format!("{a}: {}", msg.text),
                    _ => msg.text.clone(),
                };
                msg.app = Some("kernel".into());
                msg.procid = None;
            }
            _ => {
                // Only the kernel logs as kern, unless -k (§6.2).
                if msg.priority.facility == Facility::KERN && !self.opts.keep_kern {
                    msg.priority.facility = Facility::USER;
                }
            }
        }
        let now_stamp = syslog::time::now();
        match (&source, msg.stamp) {
            (Source::Remote(_), Some(s)) if !self.opts.receipt_time => msg.stamp = Some(s.with_year_near(&now_stamp)),
            _ => msg.stamp = Some(now_stamp),
        }
        if let Source::Remote(addr) = &source {
            msg.host = Some(self.remote_name(addr));
        }
        let from = match source {
            Source::Remote(_) => Origin::Remote,
            _ => Origin::Local,
        };
        self.dispatch(&msg, from);
    }

    fn dispatch(&mut self, msg: &Message, from: Origin) {
        let now = syslog::time::epoch();
        let host = match from {
            Origin::Remote => msg.host.clone().unwrap_or_default(),
            Origin::Local => self.host.clone(),
        };
        let out = Outgoing { msg, stamp: msg.stamp.unwrap_or_else(syslog::time::now), host: &host, source: &host };
        let style = self.style();
        let mut failures = Vec::new();
        for a in &mut self.actions {
            if a.selects(&out, &self.host) {
                failures.extend(a.take(&out, style, self.net_out.as_ref(), now));
            }
        }
        // Reported once: the failed action is now broken, so this can't loop.
        for f in failures {
            self.internal(Level::ERR, &f);
        }
    }

    /// Timers: repeat reports and marks. Returns the seconds until the next one.
    fn tick(&mut self, next_mark: &mut i64) -> i64 {
        let now = syslog::time::epoch();
        let style = self.style();
        let mut failures = Vec::new();
        for a in &mut self.actions {
            failures.extend(a.flush_repeats(style, self.net_out.as_ref(), now, true));
        }
        let interval = self.opts.mark_minutes as i64 * 60;
        if interval > 0 && now >= *next_mark {
            *next_mark = now + interval;
            let mut mark = Message::new(Priority::new(Facility::MARK, Level::INFO), None, "-- MARK --");
            mark.stamp = Some(syslog::time::now());
            let host = self.host.clone();
            let out = Outgoing { msg: &mark, stamp: mark.stamp.unwrap(), host: &host, source: &host };
            for a in &mut self.actions {
                // Only to files nothing has been written to for a whole interval (the BSDs').
                if a.is_file() && now - a.last_write >= interval && a.selects(&out, &host) {
                    failures.extend(a.mark(&out, style, now));
                }
            }
        }
        for f in failures {
            self.internal(Level::ERR, &f);
        }
        self.pump_streams_with(&[], true);
        let mut next = if interval > 0 { *next_mark } else { now + 3600 };
        for a in &self.actions {
            if let Some(due) = a.repeat_due() {
                next = next.min(due);
            }
            if let Some(due) = a.stream_due() {
                next = next.min(due);
            }
        }
        (next - now).clamp(1, 3600)
    }
}

#[derive(Clone, Copy)]
enum Origin {
    Local,
    Remote,
}

fn reverse_lookup(addr: &SocketAddr) -> Option<String> {
    let SocketAddr::V4(v4) = addr else { return None };
    // SAFETY: an all-zero sockaddr_in is valid; getnameinfo writes at most `host.len()` bytes.
    unsafe {
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
        let mut host = [0 as libc::c_char; 256];
        let r = libc::getnameinfo(
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        );
        if r != 0 {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned())
    }
}

/// Opens and locks the pid file, as FreeBSD's `pidfile_open(3)`: a second syslogd finds it
/// locked, and the pid in it, instead of taking `/dev/log` from the first.
fn lock_pidfile(path: &std::path::Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: a valid descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            let pid = std::fs::read_to_string(path).unwrap_or_default();
            return Err(format!("already running, pid {}", pid.trim()));
        }
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(file)
}

/// Makes this process a daemon: into the background, a session of its own, `/` as its
/// directory, standard descriptors on `/dev/null`.
fn daemonize() {
    // SAFETY: single-threaded here, so fork is safe; the parent only exits.
    unsafe {
        match libc::fork() {
            -1 => {
                eprintln!("syslogd: fork: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            0 => {}
            _ => libc::_exit(0),
        }
        libc::setsid();
        libc::chdir(c"/".as_ptr());
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(code) => return code,
    };
    // SAFETY: umask(2) can't fail.
    unsafe { libc::umask(0o022) };
    let signal_fd = install_signals();

    // Checked before anything is bound, then taken again by the daemon (a lock doesn't
    // survive the parent's exit on every system).
    match lock_pidfile(&opts.pidfile) {
        Ok(f) => drop(f),
        Err(e) => {
            eprintln!("syslogd: {e}");
            return ExitCode::from(1);
        }
    }

    // Inputs, all set up before going into the background so that /dev/log exists once the
    // start-up script returns.
    let mut local_socks = Vec::new();
    let mut paths = vec![(0o666, PathBuf::from(syslog::PATH_LOG))];
    paths.extend(opts.sockets.iter().cloned());
    for (mode, path) in &paths {
        match open_log_socket(path, *mode) {
            Ok(s) => local_socks.push((s, path.clone())),
            Err(e) => eprintln!("syslogd: {}: {e}", path.display()),
        }
    }
    let mut early = Vec::new();
    let klog = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(syslog::PATH_KLOG)
    {
        Ok(f) => Some(f),
        Err(e) => {
            early.push(format!("{}: {e}", syslog::PATH_KLOG));
            None
        }
    };
    let mut net_in = Vec::new();
    let mut net_out = None;
    if !opts.no_network {
        if opts.secure == 0 {
            let binds = if opts.bind.is_empty() { vec!["0.0.0.0".to_string()] } else { opts.bind.clone() };
            for b in &binds {
                let (addr, port) = match b.rsplit_once(':') {
                    Some((a, p)) => (a.to_string(), parse_service(p)),
                    None => (b.clone(), Some(syslog::SYSLOG_PORT)),
                };
                let Some(port) = port else {
                    eprintln!("syslogd: bad service in -b {b}");
                    return ExitCode::from(1);
                };
                let addr = if addr.is_empty() || addr == "*" { "0.0.0.0".to_string() } else { addr };
                match UdpSocket::bind((addr.as_str(), port)) {
                    Ok(s) => net_in.push(s),
                    Err(e) => early.push(format!("bind {addr}:{port}: {e}")),
                }
            }
        }
        if opts.secure < 2 {
            // Forwarding goes out of the first receiving socket (so it comes from port 514, as
            // in the BSDs), or a socket of its own.
            net_out = match net_in.first() {
                Some(s) => s.try_clone().ok(),
                None => UdpSocket::bind("0.0.0.0:0").ok(),
            };
        }
    }
    if local_socks.is_empty() {
        eprintln!("syslogd: no local log socket");
        return ExitCode::from(1);
    }

    if !opts.foreground {
        daemonize();
    }
    // Held until exit.
    let _pidfile = match lock_pidfile(&opts.pidfile) {
        Ok(mut f) => {
            use std::io::Write;
            let _ = f.set_len(0);
            let _ = write!(f, "{}\n", std::process::id());
            Some(f)
        }
        Err(e) => {
            eprintln!("syslogd: {e}");
            None
        }
    };

    let mark_minutes = opts.mark_minutes;
    let mut d = Daemon {
        opts,
        host: hostname(),
        actions: Vec::new(),
        net_out,
        names: Default::default(),
        net: None,
        listeners: Vec::new(),
        inbound: Vec::new(),
    };
    d.load();
    d.internal(Level::INFO, "restart");
    for e in early {
        d.internal(Level::ERR, &e);
    }

    let mut buf = vec![0u8; MAXLINE + 1];
    let mut klog = klog;
    let mut klog_partial: Vec<u8> = Vec::new();
    let mut next_mark = syslog::time::epoch() + mark_minutes as i64 * 60;
    loop {
        let timeout = d.tick(&mut next_mark);
        let mut fds = vec![libc::pollfd { fd: signal_fd, events: libc::POLLIN, revents: 0 }];
        for (s, _) in &local_socks {
            fds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let klog_index = fds.len();
        if let Some(k) = &klog {
            fds.push(libc::pollfd { fd: k.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let net_index = fds.len();
        for s in &net_in {
            fds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let listen_index = fds.len();
        for l in &d.listeners {
            fds.push(libc::pollfd { fd: l.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let inbound_index = fds.len();
        for c in &d.inbound {
            let (fd, events) = c.interest();
            fds.push(libc::pollfd { fd, events, revents: 0 });
        }
        // Stream actions: (action index, position in fds).
        let mut streams = Vec::new();
        for (i, a) in d.actions.iter().enumerate() {
            if let Some((fd, events)) = a.stream_interest() {
                streams.push((i, fds.len()));
                fds.push(libc::pollfd { fd, events, revents: 0 });
            }
        }
        // SAFETY: `fds` is valid for its length.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, (timeout * 1000) as i32) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                d.internal(Level::ERR, &format!("poll: {e}"));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            continue;
        }
        if n == 0 {
            continue;
        }

        if fds[0].revents & libc::POLLIN != 0 {
            let mut sigs = [0u8; 32];
            // SAFETY: reading into a buffer of the length passed.
            let got = unsafe { libc::read(signal_fd, sigs.as_mut_ptr().cast(), sigs.len()) };
            for &sig in &sigs[..got.max(0) as usize] {
                match sig as i32 {
                    libc::SIGHUP => {
                        d.load();
                        d.internal(Level::INFO, "restart");
                    }
                    libc::SIGTERM | libc::SIGINT => {
                        d.internal(Level::ERR, &format!("exiting on signal {sig}"));
                        let style = d.style();
                        for a in &mut d.actions {
                            a.flush_repeats(style, d.net_out.as_ref(), syslog::time::epoch(), false);
                            a.close();
                        }
                        for (_, path) in &local_socks {
                            let _ = std::fs::remove_file(path);
                        }
                        let _ = std::fs::remove_file(&d.opts.pidfile);
                        return ExitCode::SUCCESS;
                    }
                    libc::SIGCHLD => {
                        for a in &mut d.actions {
                            a.reap();
                        }
                    }
                    _ => {}
                }
            }
        }

        for (i, (s, _)) in local_socks.iter().enumerate() {
            if fds[1 + i].revents & libc::POLLIN == 0 {
                continue;
            }
            // Drain what's queued, so a burst doesn't wait on poll for each message.
            for _ in 0..64 {
                match s.recv(&mut buf[..MAXLINE]) {
                    Ok(len) => d.receive(&buf[..len], Source::Local),
                    Err(_) => break,
                }
            }
        }

        if klog.is_some() && fds[klog_index].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let k = klog.as_mut().unwrap();
            match k.read(&mut buf[..MAXLINE]) {
                Ok(0) => {}
                Ok(len) => {
                    klog_partial.extend_from_slice(&buf[..len]);
                    while let Some(nl) = klog_partial.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = klog_partial.drain(..=nl).collect();
                        if line.len() > 1 {
                            d.receive(&line[..line.len() - 1], Source::Kernel);
                        }
                    }
                    // A line longer than we'd ever keep: log it in pieces.
                    if klog_partial.len() >= MAXLINE {
                        let line = std::mem::take(&mut klog_partial);
                        d.receive(&line, Source::Kernel);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    d.internal(Level::ERR, &format!("{}: {e}", syslog::PATH_KLOG));
                    klog = None;
                }
            }
        }

        for (i, s) in net_in.iter().enumerate() {
            if fds[net_index + i].revents & libc::POLLIN == 0 {
                continue;
            }
            let Ok((len, from)) = s.recv_from(&mut buf[..MAXLINE]) else { continue };
            if !d.opts.allowed.is_empty() {
                let name = if d.opts.no_lookups { None } else { Some(d.remote_name(&from)) };
                if !d.opts.allowed.iter().any(|p| p.allows(&from, name.as_deref())) {
                    if d.opts.debug {
                        eprintln!("syslogd: rejected datagram from {from}");
                    }
                    continue;
                }
            }
            let bytes = buf[..len].to_vec();
            d.receive(&bytes, Source::Remote(from));
        }

        // New TCP and TLS connections, checked against -a as UDP senders are (§8.2).
        let mut accepted = Vec::new();
        for (i, l) in d.listeners.iter().enumerate() {
            if fds[listen_index + i].revents & libc::POLLIN != 0 {
                for (stream, peer) in l.accept() {
                    accepted.push((stream, peer, l.tls.clone()));
                }
            }
        }
        for (stream, peer, tls) in accepted {
            if !d.opts.allowed.is_empty() {
                let name = if d.opts.no_lookups { None } else { Some(d.remote_name(&peer)) };
                if !d.opts.allowed.iter().any(|p| p.allows(&peer, name.as_deref())) {
                    if d.opts.debug {
                        eprintln!("syslogd: rejected connection from {peer}");
                    }
                    continue;
                }
            }
            match net::Inbound::new(stream, peer, tls.as_deref()) {
                Ok(c) => d.inbound.push(c),
                Err(e) => d.internal(Level::ERR, &e),
            }
        }

        // Messages from them. Connections accepted in this pass have no entry in `fds` yet.
        let polled = fds.len().saturating_sub(inbound_index).min(d.inbound.len());
        let mut i = 0;
        let mut index = 0;
        while index < polled {
            let revents = fds[inbound_index + index].revents;
            index += 1;
            if revents == 0 {
                i += 1;
                continue;
            }
            match d.inbound[i].ready(MAXLINE) {
                net::Inflow::Messages(msgs, open) => {
                    let peer = d.inbound[i].peer;
                    if open {
                        i += 1;
                    } else {
                        d.inbound.remove(i);
                    }
                    for m in msgs {
                        d.receive(&m, Source::Remote(peer));
                    }
                }
                net::Inflow::Failed(e) => {
                    d.inbound.remove(i);
                    d.internal(Level::ERR, &e);
                }
            }
        }

        let ready: Vec<(usize, i16)> =
            streams.iter().filter(|&&(_, f)| fds[f].revents != 0).map(|&(a, f)| (a, fds[f].revents)).collect();
        if !ready.is_empty() {
            d.pump_streams_with(&ready, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers() {
        let p = parse_peer("10.0.2.0/24").unwrap();
        assert!(p.allows(&"10.0.2.15:514".parse().unwrap(), None));
        assert!(!p.allows(&"10.0.3.15:514".parse().unwrap(), None));
        let p = parse_peer("10.0.2.2/255.255.0.0:syslog").unwrap();
        assert!(p.allows(&"10.0.9.9:514".parse().unwrap(), None));
        assert!(!p.allows(&"10.0.9.9:515".parse().unwrap(), None));
        let p = parse_peer("*.example.org").unwrap();
        assert!(p.allows(&"1.2.3.4:514".parse().unwrap(), Some("a.Example.org")));
        assert!(!p.allows(&"1.2.3.4:514".parse().unwrap(), Some("example.org")));
        assert!(!p.allows(&"1.2.3.4:514".parse().unwrap(), None));
        assert!(parse_peer("10.0.0.0/33").is_none());
        assert!(parse_peer("host:notaport").is_none());
    }
}
