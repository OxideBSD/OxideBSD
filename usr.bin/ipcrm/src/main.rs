//! `ipcrm(1)`: removes System V message queues, shared memory segments and semaphore sets, as
//! the BSDs' does.
//!
//! ```text
//! ipcrm [-W] [-v] [-q msqid] [-m shmid] [-s semid] [-Q msgkey] [-M shmkey] [-S semkey] ...
//! ```
//!
//! `-q`, `-m` and `-s` name an object by its identifier, `-Q`, `-M` and `-S` by its key; an
//! identifier of `-1` means every object of that kind the caller can see (FreeBSD's). `-W`
//! removes every object of every kind. A segment still attached goes once the last process
//! detaches. Reads the kernel's tables (`kern.ipc.*`) through `ipcs(1)`'s code.

#[path = "../../ipcs/src/table.rs"]
#[allow(dead_code)]
mod table;

use std::io;
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Msg,
    Shm,
    Sem,
}

impl Kind {
    fn id_name(self) -> &'static str {
        match self {
            Kind::Msg => "msqid",
            Kind::Shm => "shmid",
            Kind::Sem => "semid",
        }
    }

    fn key_name(self) -> &'static str {
        match self {
            Kind::Msg => "msqkey",
            Kind::Shm => "shmkey",
            Kind::Sem => "semkey",
        }
    }

    /// Every identifier of this kind in the kernel's table.
    fn all(self) -> io::Result<Vec<i32>> {
        Ok(match self {
            Kind::Msg => table::read::<table::Msq>("kern.ipc.msqids")?.into_iter().map(|r| r.0).collect(),
            Kind::Shm => table::read::<table::Shm>("kern.ipc.shmsegs")?.into_iter().map(|r| r.0).collect(),
            Kind::Sem => table::read::<table::Sem>("kern.ipc.sema")?.into_iter().map(|r| r.0).collect(),
        })
    }
}

enum Target {
    Id(i32),
    Key(libc::key_t),
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ipcrm [-W] [-v] [-q msqid] [-m shmid] [-s semid]\n\
         \x20            [-Q msgkey] [-M shmkey] [-S semkey] ..."
    );
    ExitCode::from(1)
}

/// A number in decimal, or hexadecimal or octal with C's prefixes, as `strtol(3)` with base 0.
fn number(s: &str) -> Option<i64> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s),
    };
    let v = if let Some(h) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse().ok()?
    };
    Some(if neg { -v } else { v })
}

fn remove_id(kind: Kind, id: i32) -> io::Result<()> {
    // SAFETY: IPC_RMID takes no buffer.
    let r = unsafe {
        match kind {
            Kind::Msg => libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()),
            Kind::Shm => libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()),
            Kind::Sem => libc::semctl(id, 0, libc::IPC_RMID),
        }
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// The identifier of the object with `key`.
fn id_of_key(kind: Kind, key: libc::key_t) -> io::Result<i32> {
    if key == libc::IPC_PRIVATE {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: plain system calls; a size of 0 and no flags only look the key up.
    let id = unsafe {
        match kind {
            Kind::Msg => libc::msgget(key, 0),
            Kind::Shm => libc::shmget(key, 0, 0),
            Kind::Sem => libc::semget(key, 0, 0),
        }
    };
    if id >= 0 { Ok(id) } else { Err(io::Error::last_os_error()) }
}

fn main() -> ExitCode {
    let mut jobs: Vec<(Kind, Target)> = Vec::new();
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            return usage();
        };
        let mut chars = flags.chars();
        while let Some(c) = chars.next() {
            let kind_and_key = match c {
                'q' => (Kind::Msg, false),
                'm' => (Kind::Shm, false),
                's' => (Kind::Sem, false),
                'Q' => (Kind::Msg, true),
                'M' => (Kind::Shm, true),
                'S' => (Kind::Sem, true),
                'v' => {
                    verbose = true;
                    continue;
                }
                'W' => {
                    jobs.extend([Kind::Msg, Kind::Shm, Kind::Sem].map(|k| (k, Target::Id(-1))));
                    continue;
                }
                _ => return usage(),
            };
            let rest: String = chars.by_ref().collect();
            let value = if rest.is_empty() {
                match args.next() {
                    Some(v) => v,
                    None => return usage(),
                }
            } else {
                rest
            };
            let (kind, by_key) = kind_and_key;
            let Some(n) = number(&value) else {
                eprintln!("ipcrm: {value}: not a number");
                return usage();
            };
            jobs.push((kind, if by_key { Target::Key(n as libc::key_t) } else { Target::Id(n as i32) }));
        }
    }
    if jobs.is_empty() {
        return usage();
    }

    let mut failed = false;
    for (kind, target) in jobs {
        let ids = match target {
            Target::Id(-1) => match kind.all() {
                Ok(ids) => ids,
                Err(e) => {
                    eprintln!("ipcrm: {}s: {e}", kind.id_name());
                    failed = true;
                    continue;
                }
            },
            Target::Id(id) => vec![id],
            Target::Key(key) => match id_of_key(kind, key) {
                Ok(id) => vec![id],
                Err(e) => {
                    eprintln!("ipcrm: {}({key}): {e}", kind.key_name());
                    failed = true;
                    continue;
                }
            },
        };
        for id in ids {
            match remove_id(kind, id) {
                Ok(()) if verbose => println!("removed {}({id})", kind.id_name()),
                Ok(()) => {}
                Err(e) => {
                    eprintln!("ipcrm: {}({id}): {e}", kind.id_name());
                    failed = true;
                }
            }
        }
    }
    if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

#[cfg(test)]
mod tests {
    use super::number;

    #[test]
    fn numbers() {
        assert_eq!(number("42"), Some(42));
        assert_eq!(number("-1"), Some(-1));
        assert_eq!(number("0x1f"), Some(31));
        assert_eq!(number("017"), Some(15));
        assert_eq!(number("0"), Some(0));
        assert_eq!(number("x"), None);
    }
}
