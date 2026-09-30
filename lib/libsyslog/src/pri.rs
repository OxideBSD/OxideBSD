//! Priorities: a facility (who is logging) and a level (how bad it is), packed into one number as
//! `facility << 3 | level`, which is what travels in a message's `<N>` prefix. The values are
//! the BSDs', FreeBSD's `LOG_NTP`, `LOG_SECURITY` and `LOG_CONSOLE` included (`SYSLOG.md` §7.7).

/// The low three bits of a priority.
pub const LEVEL_MASK: u32 = 0x07;
/// The facility bits of a priority.
pub const FACILITY_MASK: u32 = 0x03f8;
/// The largest priority a message may carry: facility `local7`, level `debug`.
pub const MAX_PRIORITY: u32 = (23 << 3) | 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(pub u8);

impl Level {
    pub const EMERG: Level = Level(0);
    pub const ALERT: Level = Level(1);
    pub const CRIT: Level = Level(2);
    pub const ERR: Level = Level(3);
    pub const WARNING: Level = Level(4);
    pub const NOTICE: Level = Level(5);
    pub const INFO: Level = Level(6);
    pub const DEBUG: Level = Level(7);

    /// The level named `name`, including the old aliases the BSDs still take.
    pub fn from_name(name: &str) -> Option<Level> {
        let name = name.to_ascii_lowercase();
        let level = match name.as_str() {
            "emerg" | "panic" => 0,
            "alert" => 1,
            "crit" => 2,
            "err" | "error" => 3,
            "warning" | "warn" => 4,
            "notice" => 5,
            "info" => 6,
            "debug" => 7,
            _ => return None,
        };
        Some(Level(level))
    }

    pub fn name(self) -> &'static str {
        ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"][self.0 as usize & 7]
    }
}

/// A facility, by number (`LOG_KERN` is 0, `LOG_USER` 1, ...). [`Facility::MARK`] is internal: it
/// is only `syslogd`'s own periodic mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Facility(pub u8);

/// Facility names in number order; the index is the facility.
const FACILITY_NAMES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "security", "console", "local0-reserved", "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
];

impl Facility {
    pub const KERN: Facility = Facility(0);
    pub const USER: Facility = Facility(1);
    pub const MAIL: Facility = Facility(2);
    pub const DAEMON: Facility = Facility(3);
    pub const AUTH: Facility = Facility(4);
    pub const SYSLOG: Facility = Facility(5);
    pub const LPR: Facility = Facility(6);
    pub const NEWS: Facility = Facility(7);
    pub const CRON: Facility = Facility(9);
    pub const AUTHPRIV: Facility = Facility(10);
    pub const SECURITY: Facility = Facility(13);
    pub const CONSOLE: Facility = Facility(14);
    pub const LOCAL0: Facility = Facility(16);
    /// `INTERNAL_MARK`: `LOG_NFACILITIES`, one past the last real facility.
    pub const MARK: Facility = Facility(24);
    /// How many facilities a selector can name (`mark` included).
    pub const COUNT: usize = 25;

    /// The facility named `name`. `mark` is accepted; `local0-reserved` (15) has no name, as in
    /// the BSDs, which leave that number unassigned.
    pub fn from_name(name: &str) -> Option<Facility> {
        let name = name.to_ascii_lowercase();
        if name == "mark" {
            return Some(Facility::MARK);
        }
        if name == "local0-reserved" {
            return None;
        }
        FACILITY_NAMES.iter().position(|&n| n == name).map(|i| Facility(i as u8))
    }

    pub fn name(self) -> &'static str {
        match self.0 {
            24 => "mark",
            15 => "15",
            n if (n as usize) < FACILITY_NAMES.len() => FACILITY_NAMES[n as usize],
            _ => "?",
        }
    }
}

/// A decoded priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    pub facility: Facility,
    pub level: Level,
}

impl Priority {
    pub const fn new(facility: Facility, level: Level) -> Priority {
        Priority { facility, level }
    }

    pub fn from_number(n: u32) -> Priority {
        Priority { facility: Facility(((n & FACILITY_MASK) >> 3) as u8), level: Level((n & LEVEL_MASK) as u8) }
    }

    pub fn number(self) -> u32 {
        (self.facility.0 as u32) << 3 | self.level.0 as u32
    }
}

/// Parses a `<N>` prefix: the priority and the rest of `bytes`. `None` if `bytes` doesn't start
/// with one, or it's out of range (then the whole of `bytes` is text, and the message is
/// `user.notice`).
pub fn parse_prefix(bytes: &[u8]) -> Option<(Priority, &[u8])> {
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let close = bytes.iter().take(5).position(|&b| b == b'>')?;
    let digits = &bytes[1..close];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: u32 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    if n > MAX_PRIORITY {
        return None;
    }
    Some((Priority::from_number(n), &bytes[close + 1..]))
}

/// Parses `logger -p`'s `facility.level`, or a bare number.
pub fn parse_priority(text: &str) -> Option<Priority> {
    if let Ok(n) = text.parse::<u32>() {
        return (n <= MAX_PRIORITY).then(|| Priority::from_number(n));
    }
    let (fac, lev) = text.split_once('.')?;
    let facility = Facility::from_name(fac).filter(|&f| f != Facility::MARK)?;
    Some(Priority::new(facility, Level::from_name(lev)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let (p, rest) = parse_prefix(b"<13>hello").unwrap();
        assert_eq!(p, Priority::new(Facility::USER, Level::NOTICE));
        assert_eq!(rest, b"hello");
        assert_eq!(parse_prefix(b"<0>x").unwrap().0, Priority::new(Facility::KERN, Level::EMERG));
        assert_eq!(parse_prefix(b"<191>x").unwrap().0.number(), 191);
        assert!(parse_prefix(b"<192>x").is_none());
        assert!(parse_prefix(b"<>x").is_none());
        assert!(parse_prefix(b"<1a>x").is_none());
        assert!(parse_prefix(b"<12345>x").is_none());
        assert!(parse_prefix(b"hello").is_none());
    }

    #[test]
    fn names() {
        assert_eq!(Facility::from_name("security"), Some(Facility(13)));
        assert_eq!(Facility::from_name("NTP"), Some(Facility(12)));
        assert_eq!(Facility::from_name("local7"), Some(Facility(23)));
        assert_eq!(Facility::from_name("mark"), Some(Facility::MARK));
        assert_eq!(Facility::from_name("bogus"), None);
        assert_eq!(Facility(4).name(), "auth");
        assert_eq!(Level::from_name("warn"), Some(Level::WARNING));
        assert_eq!(Level::from_name("panic"), Some(Level::EMERG));
        assert_eq!(Level(3).name(), "err");
    }

    #[test]
    fn logger_priorities() {
        assert_eq!(parse_priority("local3.info").unwrap().number(), (19 << 3) | 6);
        assert_eq!(parse_priority("user.notice").unwrap().number(), 13);
        assert_eq!(parse_priority("30").unwrap().number(), 30);
        assert!(parse_priority("mark.info").is_none());
        assert!(parse_priority("user").is_none());
    }
}
