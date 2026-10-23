//! An event line from `/dev/devctl` (OxideBSD-doc `DEVD.md` §3): `verb class name=value ...`,
//! each value bare or quoted as sh quotes it. devd reads the values itself, so they reach a
//! handler as variables' values, never as shell text.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub verb: String,
    pub class: String,
    /// The fields in the order the line gave them.
    pub fields: Vec<(String, String)>,
}

impl Event {
    /// Field `name`'s value; `verb` and `class` are fields too, for a rule's conditions.
    pub fn get(&self, name: &str) -> Option<&str> {
        match name {
            "verb" => Some(&self.verb),
            "class" => Some(&self.class),
            _ => self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str()),
        }
    }
}

/// A field's name: lower-case letters, digits and `_`, not starting with a digit (§3.1).
pub fn is_field_name(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Parses one line (without its newline); `None` if it isn't one.
pub fn parse(line: &str) -> Option<Event> {
    let mut words = line.splitn(3, ' ');
    let verb = words.next().filter(|w| is_field_name(w))?.to_string();
    let class = words.next().filter(|w| is_field_name(w))?.to_string();
    let mut fields = Vec::new();
    let mut rest = words.next().unwrap_or("").chars().peekable();
    loop {
        while rest.next_if_eq(&' ').is_some() {}
        if rest.peek().is_none() {
            return Some(Event { verb, class, fields });
        }
        let mut name = String::new();
        loop {
            match rest.next()? {
                '=' => break,
                c => name.push(c),
            }
        }
        if !is_field_name(&name) {
            return None;
        }
        // Quoted parts, backslash-escaped characters and bare ones, up to an unquoted space.
        let mut value = String::new();
        while let Some(c) = rest.next_if(|&c| c != ' ') {
            match c {
                '\'' => loop {
                    match rest.next()? {
                        '\'' => break,
                        c => value.push(c),
                    }
                },
                '\\' => value.push(rest.next()?),
                c => value.push(c),
            }
        }
        fields.push((name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        fields.iter().map(|&(n, v)| (n.to_string(), v.to_string())).collect()
    }

    #[test]
    fn bare_and_quoted_values() {
        let e = parse("attach disk name=sata0.1 bus=ahci model='QEMU HARDDISK' sectors=2048").unwrap();
        assert_eq!((e.verb.as_str(), e.class.as_str()), ("attach", "disk"));
        assert_eq!(e.fields, f(&[("name", "sata0.1"), ("bus", "ahci"), ("model", "QEMU HARDDISK"), ("sectors", "2048")]));
        assert_eq!(e.get("model"), Some("QEMU HARDDISK"));
        assert_eq!(e.get("class"), Some("disk"));
        assert_eq!(e.get("port"), None);
    }

    #[test]
    fn a_quote_in_a_value() {
        // The kernel writes ' as '\'' (§3.2).
        let e = parse(r"attach disk model='it'\''s; rm -rf /' name=x").unwrap();
        assert_eq!(e.fields, f(&[("model", "it's; rm -rf /"), ("name", "x")]));
        assert_eq!(parse("attach disk model=''").unwrap().fields, f(&[("model", "")]));
    }

    #[test]
    fn no_fields() {
        assert_eq!(parse("lost devctl").unwrap().fields, Vec::new());
        assert_eq!(parse("lost devctl count=3").unwrap().get("count"), Some("3"));
    }

    #[test]
    fn not_events() {
        for line in ["", "attach", "Attach disk", "attach disk name", "attach disk Name=x", "attach disk m='open", "attach disk 1x=2"] {
            assert_eq!(parse(line), None, "{line}");
        }
    }
}
