//! File modes written as text, as `chmod(1)` takes them: the BSDs' `setmode(3)` and `getmode(3)`.
//!
//! A mode is either **octal**, `0` to `7777`, which sets the permission bits outright, or
//! **symbolic**: comma-separated clauses, each `who` letters then one or more actions.
//!
//! ```text
//! clause  = [ugoa]* action+          u+x   go-w   a=rX   u=rwx,go=rx   g=u   +t
//! action  = op ( [rwxXst]* | [ugo] )
//! op      = + | - | =
//! ```
//!
//! - **who**: `u` the owner (with set-user-ID), `g` the group (with set-group-ID), `o` others,
//!   `a` all three. With no `who`, all three are meant, but the bits in the umask are left out
//!   of what `+`, `-` and `=` set or clear (POSIX).
//! - **perms**: `r`, `w`, `x`; `X`, execute only if the file is a directory or already has an
//!   execute bit; `s`, set-user-ID for `u` and set-group-ID for `g`; `t`, the sticky bit, which
//!   only `o`, `a` or no `who` reach. Or a single `u`, `g` or `o`: a copy of that class's current
//!   `rwx` bits (`g=u`).
//! - **op**: `+` adds, `-` removes, `=` clears the classes' bits (without a `who`, every bit)
//!   and then adds.
//!
//! Actions apply in order, each to the result of the one before.

use core::fmt;

/// A parsed mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Octal: these permission bits, whatever they were.
    Absolute(u32),
    Symbolic(Vec<Action>),
}

/// One `op` of a clause, with the clause's `who`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The classes named, as an `rwx` mask over all three (`0o700` for `u`, ...); 0 for none.
    who: u32,
    op: Op,
    perm: Perm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Add,
    Remove,
    Set,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Perm {
    /// `r`, `w`, `x` as `0o4`/`0o2`/`0o1` in each class; `cond_x` for `X`; `setid` for `s`,
    /// `sticky` for `t`.
    Bits { rwx: u32, cond_x: bool, setid: bool, sticky: bool },
    /// A copy of a class's current bits: the shift of that class (6 for `u`, 3, 0).
    Copy(u32),
}

/// Why a mode couldn't be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err(mode: &str) -> Error {
    Error(format!("invalid file mode: {mode}"))
}

/// Reads a mode, octal or symbolic (`setmode(3)`).
pub fn parse(text: &str) -> Result<Mode, Error> {
    if text.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        if !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return Err(err(text));
        }
        return match u32::from_str_radix(text, 8) {
            Ok(n) if n <= 0o7777 => Ok(Mode::Absolute(n)),
            _ => Err(err(text)),
        };
    }
    let mut actions = Vec::new();
    for clause in text.split(',') {
        let mut chars = clause.chars().peekable();
        let mut who = 0;
        while let Some(&c) = chars.peek() {
            who |= match c {
                'u' => 0o700,
                'g' => 0o070,
                'o' => 0o007,
                'a' => 0o777,
                _ => break,
            };
            chars.next();
        }
        let mut any = false;
        while let Some(c) = chars.next() {
            let op = match c {
                '+' => Op::Add,
                '-' => Op::Remove,
                '=' => Op::Set,
                _ => return Err(err(text)),
            };
            let perm = match chars.peek() {
                Some(&c @ ('u' | 'g' | 'o')) => {
                    chars.next();
                    Perm::Copy(match c {
                        'u' => 6,
                        'g' => 3,
                        _ => 0,
                    })
                }
                _ => {
                    let (mut rwx, mut cond_x, mut setid, mut sticky) = (0, false, false, false);
                    while let Some(&c) = chars.peek() {
                        match c {
                            'r' => rwx |= 0o4,
                            'w' => rwx |= 0o2,
                            'x' => rwx |= 0o1,
                            'X' => cond_x = true,
                            's' => setid = true,
                            't' => sticky = true,
                            _ => break,
                        }
                        chars.next();
                    }
                    Perm::Bits { rwx, cond_x, setid, sticky }
                }
            };
            actions.push(Action { who, op, perm });
            any = true;
        }
        if !any {
            return Err(err(text));
        }
    }
    Ok(Mode::Symbolic(actions))
}

/// `rwx` bits `v` (0-7) in every class of `who`.
fn spread(v: u32, who: u32) -> u32 {
    (v << 6 | v << 3 | v) & who
}

impl Mode {
    /// The permission bits (`0o7777`) a file with mode `old` gets (`getmode(3)`); `is_dir` is
    /// for `X`, `umask` for actions without a `who`. Bits outside `0o7777` in `old` are ignored.
    pub fn apply(&self, old: u32, is_dir: bool, umask: u32) -> u32 {
        let actions = match self {
            Mode::Absolute(bits) => return *bits,
            Mode::Symbolic(actions) => actions,
        };
        let mut mode = old & 0o7777;
        for a in actions {
            let (who, mask) = if a.who == 0 { (0o777, !umask & 0o777) } else { (a.who, 0o777) };
            let mut add = match a.perm {
                Perm::Copy(shift) => spread((mode >> shift) & 0o7, who),
                Perm::Bits { rwx, cond_x, .. } => {
                    let x = if cond_x && (is_dir || mode & 0o111 != 0) { 0o1 } else { 0 };
                    spread(rwx | x, who)
                }
            } & mask;
            if let Perm::Bits { setid, sticky, .. } = a.perm {
                if setid {
                    add |= (if who & 0o700 != 0 { 0o4000 } else { 0 }) | (if who & 0o070 != 0 { 0o2000 } else { 0 });
                }
                if sticky && who & 0o007 != 0 {
                    add |= 0o1000;
                }
            }
            match a.op {
                Op::Add => mode |= add,
                Op::Remove => mode &= !add,
                Op::Set => {
                    // The classes' rwx and set-ID bits; without a `who`, every bit (the umask
                    // limits what is set again, not what is cleared).
                    let mut clear = who;
                    if who & 0o700 != 0 {
                        clear |= 0o4000;
                    }
                    if who & 0o070 != 0 {
                        clear |= 0o2000;
                    }
                    if a.who == 0 {
                        clear = 0o7777;
                    }
                    mode = (mode & !clear) | add;
                }
            }
        }
        mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(m: &str, old: u32) -> u32 {
        parse(m).unwrap_or_else(|e| panic!("{e}")).apply(old, false, 0o022)
    }

    #[test]
    fn octal() {
        assert_eq!(ap("755", 0o000), 0o755);
        assert_eq!(ap("0644", 0o4777), 0o644);
        assert_eq!(ap("4755", 0o644), 0o4755);
        assert_eq!(ap("0", 0o777), 0);
        for bad in ["8", "0778", "17777", "7a", "1-1"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn who_and_ops() {
        assert_eq!(ap("u+x", 0o644), 0o744);
        assert_eq!(ap("go-w", 0o666), 0o644);
        assert_eq!(ap("a=r", 0o777), 0o444);
        assert_eq!(ap("u=rwx,go=rx", 0o000), 0o755);
        assert_eq!(ap("ug+w,o-r", 0o444), 0o660);
        assert_eq!(ap("u-x+w", 0o544), 0o644);
        assert_eq!(ap("a=", 0o777), 0o000);
        assert_eq!(ap("u=", 0o4755), 0o055);
    }

    #[test]
    fn no_who_honors_the_umask() {
        assert_eq!(ap("+w", 0o444), 0o644);
        assert_eq!(ap("=rw", 0o777), 0o644);
        // Without a who, the bits in the umask are left alone by - as well.
        assert_eq!(ap("-w", 0o666), 0o466);
        assert_eq!(ap("+x", 0o644), 0o755);
        // With a who, the umask doesn't matter.
        assert_eq!(ap("a+w", 0o444), 0o666);
        assert_eq!(parse("+w").unwrap().apply(0o444, false, 0o002), 0o664);
    }

    #[test]
    fn copies() {
        assert_eq!(ap("g=u", 0o640), 0o660);
        assert_eq!(ap("o=g", 0o750), 0o755);
        assert_eq!(ap("go=u", 0o700), 0o777);
        assert_eq!(ap("u+g", 0o450), 0o550);
        assert_eq!(ap("a-u", 0o755), 0o000);
    }

    #[test]
    fn conditional_execute() {
        assert_eq!(ap("a+X", 0o644), 0o644);
        assert_eq!(ap("a+X", 0o744), 0o755);
        assert_eq!(parse("a+X").unwrap().apply(0o644, true, 0), 0o755);
        assert_eq!(ap("u=rwX,go=rX", 0o600), 0o644);
    }

    #[test]
    fn set_id_and_sticky() {
        assert_eq!(ap("u+s", 0o755), 0o4755);
        assert_eq!(ap("g+s", 0o755), 0o2755);
        assert_eq!(ap("+s", 0o755), 0o6755);
        assert_eq!(ap("a-s", 0o6755), 0o755);
        assert_eq!(ap("+t", 0o777), 0o1777);
        assert_eq!(ap("o+t", 0o777), 0o1777);
        assert_eq!(ap("u+t", 0o777), 0o777);
        assert_eq!(ap("-t", 0o1777), 0o777);
        assert_eq!(ap("=rwx", 0o1777), 0o755);
        assert_eq!(ap("g=rx", 0o2775), 0o755);
        assert_eq!(ap("o=rx", 0o1777), 0o1775);
    }

    #[test]
    fn errors() {
        for bad in ["", "z+x", "u", "u+q", ",", "u+x,", "+x,,", "ux", "u+x y"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
