//! Carrying out a rule's action (`SYSLOG.md` §6.5, §7.3): files, terminals, pipes, other hosts
//! and logged-in users, with the BSDs' suppression of repeated messages.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, Command, Stdio};

use syslog::msg::{Format, Message, Stamp};
use syslog::pri::Facility;

use crate::conf::{NetOptions, Operator, PropFilter, Property, Rule, Target};
use crate::net::{self, Sender};

/// Seconds before a repeated message is reported, then again for continued repeats (the BSDs'
/// `repeatinterval`).
const REPEAT_INTERVALS: [i64; 3] = [30, 120, 600];

/// How a message is written: the format, `-v`'s level, and whether sending to other hosts is on.
#[derive(Clone, Copy)]
pub struct Style {
    pub format: Format,
    pub verbose: u8,
    pub forward: bool,
}

/// A message on its way out, with everything decided about it.
pub struct Outgoing<'a> {
    pub msg: &'a Message,
    pub stamp: Stamp,
    pub host: &'a str,
    /// Where it came from, for the `source` property: the local host's name, or the sender's.
    pub source: &'a str,
}

/// The last message written, while its repeats are being counted.
struct Previous {
    key: (String, String),
    msg: Message,
    host: String,
    count: u32,
    /// When it (or its last repeat report) was written.
    time: i64,
    /// Index into `REPEAT_INTERVALS`.
    backoff: usize,
}

enum Sink {
    File { file: Option<File>, tty: bool },
    Pipe(Option<Child>),
    Forward { addr: Option<SocketAddr>, last_lookup: i64 },
    /// `@@host` or `@[host]`: a connection and its queue (`net`).
    Stream(Sender),
    /// An action that couldn't be set up (a TLS action whose certificates don't load): broken
    /// until the next reload.
    Unusable,
    Users,
    Wall,
}

pub struct Action {
    pub rule: Rule,
    sink: Sink,
    prev: Option<Previous>,
    /// Set once the action has failed and been reported; cleared by a reload.
    broken: bool,
    /// When a line was last written (for marks).
    pub last_write: i64,
    regex: Option<Regex>,
}

/// What an action reports when it fails: logged once by the caller.
pub type Failure = String;

impl Action {
    /// Prepares `rule`: opens its file (creating it with `create`), resolves its host, sets up its
    /// TLS context from `net`.
    pub fn new(rule: Rule, create: bool, now: i64, net: &NetOptions) -> (Action, Option<Failure>) {
        let mut failure = None;
        let sink = match &rule.target {
            Target::File { path, .. } => match open_log(path, create) {
                Ok((file, tty)) => Sink::File { file: if tty { None } else { Some(file) }, tty },
                Err(e) => {
                    failure = Some(format!("{}: {e}", path.display()));
                    Sink::File { file: None, tty: false }
                }
            },
            Target::Pipe(_) => Sink::Pipe(None),
            Target::Forward { host, port } => {
                let addr = resolve(host, *port);
                if addr.is_none() {
                    failure = Some(format!("{host}: host not found, will retry"));
                }
                Sink::Forward { addr, last_lookup: now }
            }
            Target::Tcp { host, port } => match Sender::new(host, *port, None) {
                Ok(s) => Sink::Stream(s),
                Err(e) => {
                    failure = Some(format!("@@{host}:{port}: {e}"));
                    Sink::Unusable
                }
            },
            Target::Tls { host, port, peer } => match Sender::new(host, *port, Some((peer, net))) {
                Ok(s) => Sink::Stream(s),
                Err(e) => {
                    failure = Some(format!("@[{host}]:{port}: {e}"));
                    Sink::Unusable
                }
            },
            Target::Users(_) => Sink::Users,
            Target::Wall => Sink::Wall,
        };
        let regex = match &rule.prop {
            Some(PropFilter { operator: Operator::Regex { extended }, value, icase, .. }) => {
                match Regex::new(value, *extended, *icase) {
                    Some(r) => Some(r),
                    None => {
                        failure = Some(format!("{}: bad regular expression {value:?}", rule.origin));
                        None
                    }
                }
            }
            _ => None,
        };
        // A file that couldn't be opened, or a TLS action that couldn't be set up, is broken
        // until the next reload; a host not found yet is retried.
        let broken = matches!((&sink, &failure), (Sink::File { .. }, Some(_)))
            || (matches!(rule.target, Target::Tcp { .. } | Target::Tls { .. }) && failure.is_some());
        (Action { rule, sink, prev: None, broken, last_write: now, regex }, failure)
    }

    /// Whether this action takes `out`.
    pub fn selects(&self, out: &Outgoing, local_host: &str) -> bool {
        let pri = out.msg.priority;
        let fac = (pri.facility.0 as usize).min(Facility::COUNT - 1);
        if self.rule.masks[fac] & (1 << pri.level.0) == 0 {
            return false;
        }
        if !self.rule.program.allows(out.msg.app.as_deref()) {
            return false;
        }
        // `+@` is this host.
        let host_filter = &self.rule.host;
        if !host_filter.names.is_empty() {
            let hit = host_filter.names.iter().any(|n| {
                if n == "@" { out.host == local_host } else { n.eq_ignore_ascii_case(out.host) }
            });
            if hit == host_filter.negate {
                return false;
            }
        }
        match &self.rule.prop {
            None => true,
            Some(p) => {
                let subject = match p.property {
                    Property::Msg => out.msg.text.as_str(),
                    Property::ProgramName => out.msg.app.as_deref().unwrap_or(""),
                    Property::HostName => out.host,
                    Property::Source => out.source,
                };
                let hit = match p.operator {
                    Operator::Regex { .. } => self.regex.as_ref().is_some_and(|r| r.matches(subject)),
                    op if p.icase => compare(op, &subject.to_lowercase(), &p.value.to_lowercase()),
                    op => compare(op, subject, &p.value),
                };
                hit != p.negate
            }
        }
    }

    /// Takes a message this action selects: writes it, or counts it as a repeat.
    pub fn take(&mut self, out: &Outgoing, style: Style, net: Option<&UdpSocket>, now: i64) -> Option<Failure> {
        if self.broken {
            return None;
        }
        let key = (out.host.to_string(), format!("{:?}{:?}{}", out.msg.app, out.msg.procid, out.msg.text));
        if let Some(prev) = &mut self.prev {
            if prev.key == key {
                prev.count += 1;
                if now >= prev.time + REPEAT_INTERVALS[prev.backoff] {
                    return self.flush_repeats(style, net, now, true);
                }
                return None;
            }
        }
        let mut failure = self.flush_repeats(style, net, now, false);
        let r = self.write(out, style, net, now);
        failure = failure.or(r);
        self.prev = Some(Previous { key, msg: out.msg.clone(), host: out.host.to_string(), count: 0, time: now, backoff: 0 });
        failure
    }

    /// Reports counted repeats if their time has come (`timer`), or at once when a different
    /// message arrives.
    pub fn flush_repeats(&mut self, style: Style, net: Option<&UdpSocket>, now: i64, timer: bool) -> Option<Failure> {
        if self.broken {
            return None;
        }
        let Some(prev) = &self.prev else { return None };
        if prev.count == 0 || (timer && now < prev.time + REPEAT_INTERVALS[prev.backoff]) {
            return None;
        }
        let count = prev.count;
        let mut note = Message::new(prev.msg.priority, None, &format!("last message repeated {count} time{}", if count == 1 { "" } else { "s" }));
        note.format = prev.msg.format;
        let host = prev.host.clone();
        let out = Outgoing { msg: &note, stamp: syslog::time::now(), host: &host, source: &host };
        let failure = self.write(&out, style, net, now);
        let prev = self.prev.as_mut().unwrap();
        prev.count = 0;
        prev.time = now;
        if timer {
            prev.backoff = (prev.backoff + 1).min(REPEAT_INTERVALS.len() - 1);
        } else {
            prev.backoff = 0;
        }
        failure
    }

    /// Writes a mark: around the repeat counting, so that one mark isn't a repeat of the last.
    pub fn mark(&mut self, out: &Outgoing, style: Style, now: i64) -> Option<Failure> {
        if self.broken {
            return None;
        }
        self.write(out, style, None, now)
    }

    /// The earliest time a repeat report is due, if any.
    pub fn repeat_due(&self) -> Option<i64> {
        self.prev.as_ref().filter(|p| p.count > 0).map(|p| p.time + REPEAT_INTERVALS[p.backoff])
    }

    /// A stream action's descriptor and the `poll` events it waits for.
    pub fn stream_interest(&self) -> Option<(std::os::fd::RawFd, i16)> {
        match &self.sink {
            Sink::Stream(s) if !self.broken => s.interest(),
            _ => None,
        }
    }

    /// Advances a stream action's connection (after `poll`, or for its reconnection timer).
    /// Returns what to log.
    pub fn stream_pump(&mut self, now: i64, revents: i16) -> Vec<Failure> {
        match &mut self.sink {
            Sink::Stream(s) if !self.broken => s.pump(now, revents),
            _ => Vec::new(),
        }
    }

    /// When a stream action's reconnection is due.
    pub fn stream_due(&self) -> Option<i64> {
        match &self.sink {
            Sink::Stream(s) if !self.broken => s.due(),
            _ => None,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self.sink, Sink::File { tty: false, .. })
    }

    /// Reaps a pipe command that has exited; the next message starts it again.
    pub fn reap(&mut self) {
        if let Sink::Pipe(slot) = &mut self.sink {
            if let Some(child) = slot {
                if !matches!(child.try_wait(), Ok(None)) {
                    *slot = None;
                }
            }
        }
    }

    /// Stops a pipe command (closing its input lets it finish) and waits for it.
    pub fn close(&mut self) {
        if let Sink::Pipe(slot) = &mut self.sink {
            if let Some(mut child) = slot.take() {
                drop(child.stdin.take());
                let _ = child.wait();
            }
        }
    }

    fn write(&mut self, out: &Outgoing, style: Style, net: Option<&UdpSocket>, now: i64) -> Option<Failure> {
        let line = match style.format {
            Format::Rfc3164 => out.msg.rfc3164_line(&out.stamp, out.host, &verbose_prefix(out.msg, style.verbose)),
            Format::Rfc5424 => out.msg.rfc5424_line(&out.stamp, out.host),
        };
        self.last_write = now;
        let sync = matches!(self.rule.target, Target::File { sync: true, .. });
        match &mut self.sink {
            Sink::File { file: Some(file), .. } => {
                let mut bytes = line.into_bytes();
                bytes.push(b'\n');
                if let Err(e) = file.write_all(&bytes) {
                    self.broken = true;
                    return Some(format!("{}: {e}", self.target_name()));
                }
                if sync {
                    let _ = file.sync_data();
                }
                None
            }
            Sink::File { file: None, tty: true } => {
                let Target::File { path, .. } = &self.rule.target else { return None };
                write_tty(path.to_str().unwrap_or(""), &format!("{line}\r\n"));
                None
            }
            Sink::File { file: None, tty: false } => None,
            Sink::Pipe(slot) => {
                let Target::Pipe(cmd) = &self.rule.target else { return None };
                if slot.is_none() {
                    match Command::new("/bin/sh")
                        .arg("-c")
                        .arg(cmd)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                    {
                        Ok(child) => *slot = Some(child),
                        Err(e) => return Some(format!("|{cmd}: {e}")),
                    }
                }
                let child = slot.as_mut().unwrap();
                let mut bytes = line.into_bytes();
                bytes.push(b'\n');
                let ok = child.stdin.as_mut().is_some_and(|stdin| stdin.write_all(&bytes).is_ok());
                if !ok {
                    // The command exited: this message is lost, the next one restarts it.
                    let mut child = slot.take().unwrap();
                    drop(child.stdin.take());
                    let _ = child.wait();
                }
                None
            }
            Sink::Forward { addr, last_lookup } => {
                if !style.forward {
                    return None;
                }
                let Target::Forward { host, port } = &self.rule.target else { return None };
                if addr.is_none() && now - *last_lookup >= 60 {
                    *last_lookup = now;
                    *addr = resolve(host, *port);
                }
                let (Some(addr), Some(sock)) = (*addr, net) else { return None };
                let packet = match style.format {
                    Format::Rfc3164 => out.msg.rfc3164_packet(&out.stamp, out.host),
                    Format::Rfc5424 => out.msg.rfc5424_line(&out.stamp, out.host),
                };
                // A network error (no route yet) is not worth breaking the action for.
                let _ = sock.send_to(packet.as_bytes(), addr);
                None
            }
            Sink::Stream(sender) => {
                if !style.forward {
                    return None;
                }
                // TLS carries RFC 5424 messages (RFC 5425); TCP what -O says, as UDP does.
                let message = match (&self.rule.target, style.format) {
                    (Target::Tls { .. }, _) | (_, Format::Rfc5424) => out.msg.rfc5424_line(&out.stamp, out.host),
                    (_, Format::Rfc3164) => out.msg.rfc3164_packet(&out.stamp, out.host),
                };
                let log = sender.send(net::frame(&message), now);
                (!log.is_empty()).then(|| log.join("; "))
            }
            Sink::Unusable => None,
            Sink::Users => {
                let Target::Users(users) = &self.rule.target else { return None };
                let text = wall_text(out, &line);
                for (user, tty) in logged_in() {
                    if users.iter().any(|u| *u == user) {
                        write_tty(&format!("/dev/{tty}"), &text);
                    }
                }
                None
            }
            Sink::Wall => {
                let text = wall_text(out, &line);
                for (_, tty) in logged_in() {
                    write_tty(&format!("/dev/{tty}"), &text);
                }
                None
            }
        }
    }

    fn target_name(&self) -> String {
        match &self.rule.target {
            Target::File { path, .. } => path.display().to_string(),
            Target::Pipe(c) => format!("|{c}"),
            Target::Forward { host, port } => format!("@{host}:{port}"),
            Target::Tcp { host, port } => format!("@@{host}:{port}"),
            Target::Tls { host, port, .. } => format!("@[{host}]:{port}"),
            Target::Users(u) => u.join(","),
            Target::Wall => "*".into(),
        }
    }
}

fn compare(op: Operator, subject: &str, value: &str) -> bool {
    match op {
        Operator::Contains => subject.contains(value),
        Operator::IsEqual => subject == value,
        Operator::StartsWith => subject.starts_with(value),
        Operator::Regex { .. } => false,
    }
}

/// `-v`: `<3.6> `; `-vv`: `<auth.info> `.
fn verbose_prefix(msg: &Message, verbose: u8) -> String {
    let p = msg.priority;
    match verbose {
        0 => String::new(),
        1 => format!("<{}.{}> ", p.facility.0, p.level.0),
        _ => format!("<{}.{}> ", p.facility.name(), p.level.name()),
    }
}

/// What users see: the BSDs' `Message from syslogd@host at time ...` banner, then the line.
fn wall_text(out: &Outgoing, line: &str) -> String {
    format!("\r\n\x07Message from syslogd@{} at {} ...\r\n{}\r\n", out.host, out.stamp.rfc3164(), line)
}

/// Opens a log file for appending; whether it's a terminal. It must exist unless `create`
/// (`-C`, mode 0600).
fn open_log(path: &std::path::Path, create: bool) -> std::io::Result<(File, bool)> {
    let file = OpenOptions::new()
        .append(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)?;
    use std::os::fd::AsRawFd;
    // SAFETY: a valid descriptor.
    let tty = unsafe { libc::isatty(file.as_raw_fd()) } == 1;
    Ok((file, tty))
}

/// Writes to a terminal without ever blocking on it: a stopped terminal loses the message.
fn write_tty(path: &str, text: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        let _ = f.write_all(text.as_bytes());
    }
}

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.find(SocketAddr::is_ipv4)
}

/// `(user, terminal)` for every login session in `utmpx`.
fn logged_in() -> Vec<(String, String)> {
    let mut v = Vec::new();
    let field = |b: &[libc::c_char]| -> String {
        let bytes: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    // SAFETY: the utmpx(3) iteration; each record is copied out before the next call.
    unsafe {
        libc::setutxent();
        loop {
            let ent = libc::getutxent();
            if ent.is_null() {
                break;
            }
            let ent = &*ent;
            if ent.ut_type == libc::USER_PROCESS {
                let tty = field(&ent.ut_line);
                // Only terminal names: nothing that walks out of /dev.
                if !tty.is_empty() && !tty.contains("..") {
                    v.push((field(&ent.ut_user), tty));
                }
            }
        }
        libc::endutxent();
    }
    v
}

/// A compiled POSIX regular expression (`regcomp(3)`), for `regex` and `ereg` filters.
struct Regex(Box<libc::regex_t>);

impl Regex {
    fn new(pattern: &str, extended: bool, icase: bool) -> Option<Regex> {
        let c = std::ffi::CString::new(pattern).ok()?;
        // SAFETY: regcomp initializes the zeroed regex_t.
        let mut re: Box<libc::regex_t> = Box::new(unsafe { std::mem::zeroed() });
        let mut flags = libc::REG_NOSUB;
        if extended {
            flags |= libc::REG_EXTENDED;
        }
        if icase {
            flags |= libc::REG_ICASE;
        }
        (unsafe { libc::regcomp(&mut *re, c.as_ptr(), flags) } == 0).then(|| Regex(re))
    }

    fn matches(&self, s: &str) -> bool {
        let Ok(c) = std::ffi::CString::new(s) else { return false };
        // SAFETY: a compiled regex and a NUL-terminated subject.
        unsafe { libc::regexec(&*self.0, c.as_ptr(), 0, std::ptr::null_mut(), 0) == 0 }
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: compiled by regcomp.
        unsafe { libc::regfree(&mut *self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf;

    fn stamp() -> Stamp {
        Stamp { year: Some(2026), month: 9, day: 29, hour: 12, minute: 0, second: 0, usec: None, offset: Some(0) }
    }

    fn style() -> Style {
        Style { format: Format::Rfc3164, verbose: 0, forward: false }
    }

    #[test]
    fn selection_and_repeats() {
        let dir = std::env::temp_dir().join(format!("syslogd-action-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log");
        let c = conf::parse(&format!(
            "!cron\n*.info;mail.none\t{0}\n!*\n:msg, ereg, \"^a+b$\"\n*.*\t{0}\n",
            path.display()
        ));
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        // Must exist without -C.
        let (a, f) = Action::new(c.rules[0].clone(), false, 0, &NetOptions::default());
        assert!(f.is_some() && a.broken);
        let (mut a, f) = Action::new(c.rules[0].clone(), true, 0, &NetOptions::default());
        assert!(f.is_none(), "{f:?}");
        let (b, f) = Action::new(c.rules[1].clone(), false, 0, &NetOptions::default());
        assert!(f.is_none(), "{f:?}");

        let m = Message::parse(b"<78>cron[1]: tick", false);
        let out = Outgoing { msg: &m, stamp: stamp(), host: "box", source: "box" };
        assert!(a.selects(&out, "box"));
        let m2 = Message::parse(b"<22>cron: mail", false);
        assert!(!a.selects(&Outgoing { msg: &m2, ..out }, "box"));
        let m3 = Message::parse(b"<79>cron: debug", false);
        assert!(!a.selects(&Outgoing { msg: &m3, ..out }, "box"));
        let m4 = Message::parse(b"<14>sshd: x", false);
        assert!(!a.selects(&Outgoing { msg: &m4, ..out }, "box"));
        let m5 = Message::parse(b"<14>sshd: aaab", false);
        assert!(b.selects(&Outgoing { msg: &m5, ..out }, "box"));
        assert!(!b.selects(&Outgoing { msg: &m4, ..out }, "box"));

        for t in 0..4 {
            assert!(a.take(&out, style(), None, t).is_none());
        }
        assert_eq!(a.repeat_due(), Some(30));
        a.flush_repeats(style(), None, 30, true);
        assert_eq!(a.repeat_due(), None);
        a.take(&out, style(), None, 31);
        assert_eq!(a.repeat_due(), Some(30 + 120));
        let other = Message::parse(b"<78>cron[1]: tock", false);
        a.take(&Outgoing { msg: &other, ..out }, style(), None, 40);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Sep 29 12:00:00 box cron[1]: tick");
        assert!(lines[1].ends_with("box last message repeated 3 times"), "{}", lines[1]);
        assert!(lines[2].ends_with("box last message repeated 1 time"), "{}", lines[2]);
        assert_eq!(lines[3], "Sep 29 12:00:00 box cron[1]: tock");
        assert_eq!(lines.len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pipes() {
        let dir = std::env::temp_dir().join(format!("syslogd-pipe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("out");
        let c = conf::parse(&format!("*.*\t|cat >> {}\n", out_path.display()));
        let (mut a, _) = Action::new(c.rules[0].clone(), false, 0, &NetOptions::default());
        let m = Message::parse(b"<14>t: one", false);
        a.take(&Outgoing { msg: &m, stamp: stamp(), host: "h", source: "h" }, style(), None, 0);
        a.close();
        assert_eq!(std::fs::read_to_string(&out_path).unwrap(), "Sep 29 12:00:00 h t: one\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
