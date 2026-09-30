//! Messages (`SYSLOG.md` §6.3-6.4): parsing what arrives on a log socket, in RFC 3164 or RFC 5424
//! form, and writing a message out in either.
//!
//! ```text
//! <13>Sep 29 14:02:11 host tag[42]: text                               RFC 3164
//! <13>1 2026-09-29T14:02:11.004Z host app 42 msgid [sd id="x"] text   RFC 5424
//! ```
//!
//! The host field is only looked for in messages from the network (local senders, like musl's
//! `syslog(3)`, leave it out). A message without a priority is `user.notice`. A time stamp that
//! doesn't parse is dropped, and the receiver stamps the message itself.

use crate::pri::{self, Facility, Level, Priority};

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A time stamp. RFC 3164's carry no year, fraction or offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub year: Option<i32>,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub usec: Option<u32>,
    /// Seconds east of UTC.
    pub offset: Option<i32>,
}

impl Stamp {
    /// `Mmm dd hh:mm:ss`, the day padded with a space.
    pub fn rfc3164(&self) -> String {
        format!(
            "{} {:>2} {:02}:{:02}:{:02}",
            MONTHS[(self.month.clamp(1, 12) - 1) as usize],
            self.day,
            self.hour,
            self.minute,
            self.second
        )
    }

    /// RFC 3339, as RFC 5424 writes it: with the fraction when there is one, and the offset (`Z`
    /// for UTC, or for a stamp without one: give local stamps their offset, see [`crate::time`]).
    pub fn rfc3339(&self) -> String {
        let mut s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year.unwrap_or(1970),
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second
        );
        if let Some(usec) = self.usec {
            s.push_str(&format!(".{usec:06}"));
        }
        match self.offset {
            None | Some(0) => s.push('Z'),
            Some(off) => {
                let sign = if off < 0 { '-' } else { '+' };
                let off = off.unsigned_abs();
                s.push_str(&format!("{sign}{:02}:{:02}", off / 3600, off / 60 % 60));
            }
        }
        s
    }

    /// Gives an RFC 3164 stamp a year: `now`'s, or the one before when the stamp's month is well
    /// after now's (a December message read in January), as the BSDs guess.
    pub fn with_year_near(mut self, now: &Stamp) -> Stamp {
        if self.year.is_none() {
            let year = now.year.unwrap_or(1970);
            self.year = Some(if self.month > now.month + 1 { year - 1 } else { year });
        }
        self
    }
}

/// Which form a message arrived in, or is to be written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Rfc3164,
    Rfc5424,
}

/// A parsed message. `text` has already been made safe to write (control characters as `^X`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub priority: Priority,
    pub stamp: Option<Stamp>,
    pub host: Option<String>,
    /// RFC 3164's tag, RFC 5424's APP-NAME.
    pub app: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    /// RFC 5424 structured data, as received.
    pub sd: Option<String>,
    pub text: String,
    pub format: Format,
}

impl Message {
    /// A message made here (syslogd's own, a kernel line).
    pub fn new(priority: Priority, app: Option<&str>, text: &str) -> Message {
        Message {
            priority,
            stamp: None,
            host: None,
            app: app.map(str::to_string),
            procid: None,
            msgid: None,
            sd: None,
            text: escape(text.as_bytes()),
            format: Format::Rfc3164,
        }
    }

    /// Parses a received message. `with_host`: the sender is remote, so an RFC 3164 header may
    /// carry a host name.
    pub fn parse(bytes: &[u8], with_host: bool) -> Message {
        // A newline ends the message (§6.3); a NUL too, as C senders may include one.
        let end = bytes.iter().position(|&b| b == b'\n' || b == 0).unwrap_or(bytes.len());
        let bytes = &bytes[..end];
        let (priority, rest) = match pri::parse_prefix(bytes) {
            Some((p, rest)) => (p, rest),
            None => (Priority::new(Facility::USER, Level::NOTICE), bytes),
        };
        if let Some(rest) = rest.strip_prefix(b"1 ") {
            if let Some(m) = parse_5424(priority, rest) {
                return m;
            }
        }
        parse_3164(priority, rest, with_host)
    }

    /// `tag[pid]: `, `tag: `, or nothing.
    fn tag(&self) -> String {
        match (&self.app, &self.procid) {
            (Some(app), Some(pid)) => format!("{app}[{pid}]: "),
            (Some(app), None) => format!("{app}: "),
            _ => String::new(),
        }
    }

    /// The line written to a file or terminal in RFC 3164 form, without a newline: `stamp host
    /// tag[pid]: text`. `extra` goes between the host and the tag (`syslogd -v`'s priority).
    pub fn rfc3164_line(&self, stamp: &Stamp, host: &str, extra: &str) -> String {
        format!("{} {} {}{}{}", stamp.rfc3164(), host, extra, self.tag(), self.text)
    }

    /// The line written in RFC 5424 form, without a newline:
    /// `<N>1 timestamp host app procid msgid sd text`.
    pub fn rfc5424_line(&self, stamp: &Stamp, host: &str) -> String {
        let nil = |f: &Option<String>| f.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "-".into());
        let mut s = format!(
            "<{}>1 {} {} {} {} {} {}",
            self.priority.number(),
            stamp.rfc3339(),
            if host.is_empty() { "-" } else { host },
            nil(&self.app),
            nil(&self.procid),
            nil(&self.msgid),
            nil(&self.sd)
        );
        if !self.text.is_empty() {
            s.push(' ');
            s.push_str(&self.text);
        }
        s
    }

    /// An RFC 3164 datagram to forward: `<N>stamp host tag[pid]: text`.
    pub fn rfc3164_packet(&self, stamp: &Stamp, host: &str) -> String {
        format!("<{}>{}", self.priority.number(), self.rfc3164_line(stamp, host, ""))
    }
}

/// Writes control characters other than tab as `^X` (DEL as `^?`), and makes the result valid
/// UTF-8.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\t' => out.push(b),
            0..=0x1f => out.extend_from_slice(&[b'^', b + 0x40]),
            0x7f => out.extend_from_slice(b"^?"),
            _ => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Mmm dd hh:mm:ss ` at the start of `b`: the stamp and the rest.
fn parse_3164_stamp(b: &[u8]) -> Option<(Stamp, &[u8])> {
    if b.len() < 16 || b[3] != b' ' || b[6] != b' ' || b[9] != b':' || b[12] != b':' || b[15] != b' ' {
        return None;
    }
    let month = MONTHS.iter().position(|m| m.as_bytes() == &b[..3])? as u8 + 1;
    let num = |s: &[u8]| -> Option<u8> {
        let t = std::str::from_utf8(s).ok()?.trim_start();
        if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let (day, hour, minute, second) = (num(&b[4..6])?, num(&b[7..9])?, num(&b[10..12])?, num(&b[13..15])?);
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let stamp = Stamp { year: None, month, day, hour, minute, second, usec: None, offset: None };
    Some((stamp, &b[16..]))
}

/// A tag at the start of `b`: `name[pid]: ` or `name: `. Up to 48 characters, none of them a
/// space, colon or bracket.
fn parse_tag(b: &[u8]) -> Option<(String, Option<String>, &[u8])> {
    let name_len = b.iter().position(|&c| matches!(c, b' ' | b':' | b'[')).unwrap_or(b.len());
    if name_len == 0 || name_len > 48 || !b[..name_len].iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    let name = String::from_utf8_lossy(&b[..name_len]).into_owned();
    let mut rest = &b[name_len..];
    let mut pid = None;
    if rest.first() == Some(&b'[') {
        let close = rest.iter().position(|&c| c == b']')?;
        let p = &rest[1..close];
        if p.is_empty() || p.len() > 128 || !p.iter().all(|c| c.is_ascii_graphic()) {
            return None;
        }
        pid = Some(String::from_utf8_lossy(p).into_owned());
        rest = &rest[close + 1..];
    }
    let rest = rest.strip_prefix(b":")?;
    Some((name, pid, rest.strip_prefix(b" ").unwrap_or(rest)))
}

fn parse_3164(priority: Priority, b: &[u8], with_host: bool) -> Message {
    let (stamp, mut rest) = match parse_3164_stamp(b) {
        Some((s, r)) => (Some(s), r),
        None => (None, b),
    };
    let mut host = None;
    // A remote sender's header names its host: a word followed by a space that isn't itself a
    // tag (the BSDs make the same guess, the RFC being descriptive).
    if with_host && stamp.is_some() {
        if let Some(sp) = rest.iter().position(|&c| c == b' ') {
            let word = &rest[..sp];
            if !word.is_empty()
                && !word.ends_with(b":")
                && !word.contains(&b'[')
                && word.iter().all(|&c| c.is_ascii_alphanumeric() || b".-_:".contains(&c))
            {
                host = Some(String::from_utf8_lossy(word).into_owned());
                rest = &rest[sp + 1..];
            }
        }
    }
    let (app, procid, text) = match parse_tag(rest) {
        Some((a, p, t)) => (Some(a), p, t),
        None => (None, None, rest),
    };
    Message {
        priority,
        stamp,
        host,
        app,
        procid,
        msgid: None,
        sd: None,
        text: escape(text),
        format: Format::Rfc3164,
    }
}

/// RFC 3339 as RFC 5424 restricts it.
fn parse_3339(s: &str) -> Option<Stamp> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let year = num(0..4)? as i32;
    let (month, day, hour, minute, second) = (num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut i = 19;
    let mut usec = None;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() || frac.len() > 6 {
            return None;
        }
        usec = Some(frac.parse::<u32>().ok()? * 10u32.pow(6 - frac.len() as u32));
    }
    let offset = match &s[i..] {
        "Z" => 0,
        tz if tz.len() == 6 && (tz.starts_with('+') || tz.starts_with('-')) && &tz[3..4] == ":" => {
            let h: i32 = tz[1..3].parse().ok()?;
            let m: i32 = tz[4..6].parse().ok()?;
            if h > 23 || m > 59 {
                return None;
            }
            let off = h * 3600 + m * 60;
            if tz.starts_with('-') { -off } else { off }
        }
        _ => return None,
    };
    Some(Stamp {
        year: Some(year),
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
        usec,
        offset: Some(offset),
    })
}

/// The structured-data field at the start of `b`: `-`, or one or more `[id param="value" ...]`
/// elements, in which `\"`, `\\` and `\]` are escapes. Returns its length.
fn sd_len(b: &[u8]) -> Option<usize> {
    if b.first() == Some(&b'-') {
        return Some(1);
    }
    let mut i = 0;
    while b.get(i) == Some(&b'[') {
        let mut quoted = false;
        i += 1;
        loop {
            match *b.get(i)? {
                b'\\' if quoted => i += 1,
                b'"' => quoted = !quoted,
                b']' if !quoted => break,
                _ => {}
            }
            i += 1;
        }
        i += 1;
    }
    (i > 0).then_some(i)
}

fn parse_5424(priority: Priority, b: &[u8]) -> Option<Message> {
    let mut rest = b;
    let mut field = || -> Option<Option<String>> {
        let sp = rest.iter().position(|&c| c == b' ')?;
        let f = std::str::from_utf8(&rest[..sp]).ok()?.to_string();
        rest = &rest[sp + 1..];
        if f.is_empty() {
            return None;
        }
        Some((f != "-").then_some(f))
    };
    let stamp_text = field()?;
    let host = field()?;
    let app = field()?;
    let procid = field()?;
    let msgid = field()?;
    let n = sd_len(rest)?;
    let sd = std::str::from_utf8(&rest[..n]).ok()?.to_string();
    let mut text = &rest[n..];
    if !text.is_empty() {
        text = text.strip_prefix(b" ")?;
    }
    let text = text.strip_prefix("\u{feff}".as_bytes()).unwrap_or(text);
    Some(Message {
        priority,
        stamp: stamp_text.as_deref().and_then(parse_3339),
        host,
        app,
        procid,
        msgid,
        sd: (sd != "-").then_some(sd),
        text: escape(text),
        format: Format::Rfc5424,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(month: u8, day: u8, h: u8, m: u8, s: u8) -> Stamp {
        Stamp { year: None, month, day, hour: h, minute: m, second: s, usec: None, offset: None }
    }

    #[test]
    fn musl_syslog() {
        // What musl's syslog(3) sends: no host, a trailing newline.
        let m = Message::parse(b"<38>Sep  9 14:02:11 login[42]: root login on ttyv0\n", false);
        assert_eq!(m.priority, Priority::new(Facility::AUTH, Level::INFO));
        assert_eq!(m.stamp, Some(stamp(9, 9, 14, 2, 11)));
        assert_eq!(m.host, None);
        assert_eq!(m.app.as_deref(), Some("login"));
        assert_eq!(m.procid.as_deref(), Some("42"));
        assert_eq!(m.text, "root login on ttyv0");
        assert_eq!(m.format, Format::Rfc3164);
    }

    #[test]
    fn remote_3164_host() {
        let m = Message::parse(b"<13>Sep 29 01:02:03 alpha.example cron[7]: hi", true);
        assert_eq!(m.host.as_deref(), Some("alpha.example"));
        assert_eq!(m.app.as_deref(), Some("cron"));
        assert_eq!(m.text, "hi");
        // No host: the first word is the tag.
        let m = Message::parse(b"<13>Sep 29 01:02:03 cron: hi", true);
        assert_eq!(m.host, None);
        assert_eq!(m.app.as_deref(), Some("cron"));
        // Local senders never carry one.
        let m = Message::parse(b"<13>Sep 29 01:02:03 alpha cron: hi", false);
        assert_eq!(m.host, None);
        assert_eq!(m.app, None);
        assert_eq!(m.text, "alpha cron: hi");
    }

    #[test]
    fn no_priority_no_stamp() {
        let m = Message::parse(b"just text", false);
        assert_eq!(m.priority, Priority::new(Facility::USER, Level::NOTICE));
        assert_eq!(m.stamp, None);
        assert_eq!(m.app, None);
        assert_eq!(m.text, "just text");
        // A bad stamp is text.
        let m = Message::parse(b"<14>Sep 99 01:02:03 x: y", false);
        assert_eq!(m.stamp, None);
        assert_eq!(m.app, None);
        assert_eq!(m.text, "Sep 99 01:02:03 x: y");
    }

    #[test]
    fn control_characters() {
        let m = Message::parse(b"<14>a\x01b\tc\x7fd\ne", false);
        assert_eq!(m.text, "a^Ab\tc^?d");
        assert_eq!(escape(b"\x1b[0m"), "^[[0m");
    }

    #[test]
    fn rfc5424() {
        let m = Message::parse(
            b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\\]lication\"] \xef\xbb\xbfAn application event",
            true,
        );
        assert_eq!(m.format, Format::Rfc5424);
        assert_eq!(m.priority.number(), 165);
        let s = m.stamp.unwrap();
        assert_eq!((s.year, s.month, s.day, s.hour, s.usec, s.offset), (Some(2003), 10, 11, 22, Some(3000), Some(0)));
        assert_eq!(m.host.as_deref(), Some("mymachine.example.com"));
        assert_eq!(m.app.as_deref(), Some("evntslog"));
        assert_eq!(m.procid, None);
        assert_eq!(m.msgid.as_deref(), Some("ID47"));
        assert_eq!(m.sd.as_deref(), Some("[exampleSDID@32473 iut=\"3\" eventSource=\"App\\]lication\"]"));
        assert_eq!(m.text, "An application event");

        let m = Message::parse(b"<34>1 2003-08-24T05:14:15.000003-07:00 host su - ID47 - msg", true);
        let s = m.stamp.unwrap();
        assert_eq!((s.usec, s.offset), (Some(3), Some(-7 * 3600)));
        assert_eq!(m.sd, None);
        assert_eq!(m.text, "msg");
        // No text at all.
        let m = Message::parse(b"<34>1 - - - - - -", true);
        assert_eq!(m.format, Format::Rfc5424);
        assert_eq!(m.stamp, None);
        assert_eq!(m.text, "");
        // Malformed: falls back to RFC 3164 and keeps everything as text.
        let m = Message::parse(b"<34>1 oops", true);
        assert_eq!(m.format, Format::Rfc3164);
        assert_eq!(m.text, "1 oops");
    }

    #[test]
    fn output() {
        let mut m = Message::parse(b"<38>Sep  9 14:02:11 login[42]: hello", false);
        let s = stamp(9, 9, 14, 2, 11);
        assert_eq!(m.rfc3164_line(&s, "box", ""), "Sep  9 14:02:11 box login[42]: hello");
        assert_eq!(m.rfc3164_line(&s, "box", "<auth.info> "), "Sep  9 14:02:11 box <auth.info> login[42]: hello");
        assert_eq!(m.rfc3164_packet(&s, "box"), "<38>Sep  9 14:02:11 box login[42]: hello");
        let t = Stamp { year: Some(2026), usec: Some(4), offset: Some(2 * 3600), ..s };
        assert_eq!(m.rfc5424_line(&t, "box"), "<38>1 2026-09-09T14:02:11.000004+02:00 box login 42 - - hello");
        m.app = None;
        m.procid = None;
        assert_eq!(m.rfc3164_line(&s, "box", ""), "Sep  9 14:02:11 box hello");
        let t = Stamp { offset: Some(-(5 * 3600 + 30 * 60)), usec: None, ..t };
        assert_eq!(t.rfc3339(), "2026-09-09T14:02:11-05:30");
    }

    #[test]
    fn year_guess() {
        let now = Stamp { year: Some(2027), ..stamp(1, 2, 0, 0, 0) };
        assert_eq!(stamp(12, 31, 23, 59, 59).with_year_near(&now).year, Some(2026));
        assert_eq!(stamp(1, 2, 0, 0, 0).with_year_near(&now).year, Some(2027));
        assert_eq!(stamp(2, 1, 0, 0, 0).with_year_near(&now).year, Some(2027));
    }
}
