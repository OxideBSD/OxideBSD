//! `ipcs(1)`: reports the System V message queues, shared memory segments and semaphore sets,
//! from the kernel's `kern.ipc.msqids`, `kern.ipc.shmsegs` and `kern.ipc.sema` tables, as the
//! BSDs' does (OxideBSD-doc `SYSCTL.md` §5).
//!
//! ```text
//! ipcs [-abcMmopQqSsTt] [-u user]
//! ```
//!
//! Each table holds one record per live object, `{int id; int pad; struct *id_ds}`, the
//! `*id_ds` as `IPC_STAT` fills it; objects of other users are left out for an unprivileged
//! caller when `security.bsd.see_other_uids` is 0. FreeBSD's columns, NetBSD's and OpenBSD's
//! heading line.

mod table;

use std::process::ExitCode;

use table::{Msq, Sem, Shm};

/// What to show.
#[derive(Default)]
struct Opts {
    msg: bool,
    shm: bool,
    sem: bool,
    /// `-b`: the maximum sizes (QBYTES, SEGSZ, NSEMS).
    big: bool,
    /// `-c`: the creator's user and group.
    creator: bool,
    /// `-o`: outstanding usage (CBYTES and QNUM, NATTCH).
    outstanding: bool,
    /// `-p`: process IDs.
    pid: bool,
    /// `-t`: times.
    time: bool,
    /// `-T`, `-M`, `-Q`, `-S`: the system's limits.
    info_msg: bool,
    info_shm: bool,
    info_sem: bool,
    /// `-u`: only this user's objects.
    user: Option<u32>,
}

fn usage() -> ExitCode {
    eprintln!("usage: ipcs [-abcMmopQqSsTt] [-u user]");
    ExitCode::from(1)
}

fn parse_args() -> Result<Opts, ExitCode> {
    let mut o = Opts::default();
    let mut args = std::env::args().skip(1);
    let mut any_kind = false;
    let mut any_info = false;
    while let Some(arg) = args.next() {
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            return Err(usage());
        };
        let mut chars = flags.chars();
        while let Some(c) = chars.next() {
            match c {
                'a' => (o.big, o.creator, o.outstanding, o.pid, o.time) = (true, true, true, true, true),
                'b' => o.big = true,
                'c' => o.creator = true,
                'o' => o.outstanding = true,
                'p' => o.pid = true,
                't' => o.time = true,
                'q' => (o.msg, any_kind) = (true, true),
                'm' => (o.shm, any_kind) = (true, true),
                's' => (o.sem, any_kind) = (true, true),
                'Q' => (o.info_msg, any_info) = (true, true),
                'M' => (o.info_shm, any_info) = (true, true),
                'S' => (o.info_sem, any_info) = (true, true),
                'T' => (o.info_msg, o.info_shm, o.info_sem, any_info) = (true, true, true, true),
                'u' => {
                    let rest: String = chars.by_ref().collect();
                    let name = if rest.is_empty() { args.next().ok_or_else(usage)? } else { rest };
                    match table::uid_of(&name) {
                        Some(uid) => o.user = Some(uid),
                        None => {
                            eprintln!("ipcs: {name}: no such user");
                            return Err(ExitCode::from(1));
                        }
                    }
                }
                _ => return Err(usage()),
            }
        }
    }
    // No kind named: all three, unless only system information was asked for.
    if !any_kind && !any_info {
        (o.msg, o.shm, o.sem) = (true, true, true);
    }
    Ok(o)
}

fn main() -> ExitCode {
    let o = match parse_args() {
        Ok(o) => o,
        Err(code) => return code,
    };
    let mut status = ExitCode::SUCCESS;
    if o.info_msg || o.info_shm || o.info_sem {
        if let Err(e) = print_info(&o) {
            eprintln!("ipcs: kern.ipc: {e}");
            status = ExitCode::from(1);
        }
    }
    if o.msg || o.shm || o.sem {
        println!("IPC status from <running system> as of {}", table::now_string());
    }
    if o.msg {
        match table::read::<Msq>("kern.ipc.msqids") {
            Ok(rows) => print_msq(&o, &rows),
            Err(e) => {
                eprintln!("ipcs: kern.ipc.msqids: {e}");
                status = ExitCode::from(1);
            }
        }
    }
    if o.shm {
        match table::read::<Shm>("kern.ipc.shmsegs") {
            Ok(rows) => print_shm(&o, &rows),
            Err(e) => {
                eprintln!("ipcs: kern.ipc.shmsegs: {e}");
                status = ExitCode::from(1);
            }
        }
    }
    if o.sem {
        match table::read::<Sem>("kern.ipc.sema") {
            Ok(rows) => print_sem(&o, &rows),
            Err(e) => {
                eprintln!("ipcs: kern.ipc.sema: {e}");
                status = ExitCode::from(1);
            }
        }
    }
    status
}

/// `-T`, `-M`, `-Q`, `-S`: the limits, from `kern.ipc`.
fn print_info(o: &Opts) -> std::io::Result<()> {
    let show = |title: &str, vars: &[(&str, &str)]| -> std::io::Result<()> {
        println!("{title}:");
        for (name, what) in vars {
            println!("{:>12}\t{what}", table::read_ulong(&format!("kern.ipc.{name}"))?);
        }
        println!();
        Ok(())
    };
    if o.info_msg {
        show(
            "msginfo",
            &[
                ("msgmax", "msgmax (max characters in a message)"),
                ("msgmni", "msgmni (# of message queues)"),
                ("msgmnb", "msgmnb (max characters in a message queue)"),
            ],
        )?;
    }
    if o.info_shm {
        show(
            "shminfo",
            &[
                ("shmmax", "shmmax (max shared memory segment size)"),
                ("shmmin", "shmmin (min shared memory segment size)"),
                ("shmmni", "shmmni (max number of shared memory identifiers)"),
            ],
        )?;
    }
    if o.info_sem {
        show(
            "seminfo",
            &[
                ("semmni", "semmni (# of semaphore identifiers)"),
                ("semmsl", "semmsl (max # of semaphores per id)"),
                ("semopm", "semopm (max # of operations per semop call)"),
                ("semvmx", "semvmx (semaphore maximum value)"),
            ],
        )?;
    }
    Ok(())
}

/// The heading columns every kind shares, and the creator's.
fn common_title(o: &Opts) -> String {
    let mut s = format!("T {:>12} {:>12} {:<11} {:<8} {:<8}", "ID", "KEY", "MODE", "OWNER", "GROUP");
    if o.creator {
        s += &format!(" {:<8} {:<8}", "CREATOR", "CGROUP");
    }
    s
}

fn common_row(o: &Opts, kind: char, id: i32, perm: &table::IpcPerm, mode: String) -> String {
    let mut s = format!(
        "{kind} {id:>12} {:>12} {mode} {:<8} {:<8}",
        perm.key,
        table::user_name(perm.uid),
        table::group_name(perm.gid)
    );
    if o.creator {
        s += &format!(" {:<8} {:<8}", table::user_name(perm.cuid), table::group_name(perm.cgid));
    }
    s
}

fn wanted(o: &Opts, perm: &table::IpcPerm) -> bool {
    o.user.is_none_or(|uid| perm.uid == uid)
}

fn print_msq(o: &Opts, rows: &[(i32, Msq)]) {
    println!("Message Queues:");
    let mut title = common_title(o);
    if o.outstanding {
        title += &format!(" {:>20} {:>20}", "CBYTES", "QNUM");
    }
    if o.big {
        title += &format!(" {:>20}", "QBYTES");
    }
    if o.pid {
        title += &format!(" {:>12} {:>12}", "LSPID", "LRPID");
    }
    if o.time {
        title += &format!(" {:<8} {:<8} {:<8}", "STIME", "RTIME", "CTIME");
    }
    println!("{title}");
    for (id, q) in rows.iter().filter(|(_, q)| wanted(o, &q.perm)) {
        let mode = table::mode_string(&q.perm, 'q');
        let mut s = common_row(o, 'q', *id, &q.perm, mode);
        if o.outstanding {
            s += &format!(" {:>20} {:>20}", q.cbytes, q.qnum);
        }
        if o.big {
            s += &format!(" {:>20}", q.qbytes);
        }
        if o.pid {
            s += &format!(" {:>12} {:>12}", q.lspid, q.lrpid);
        }
        if o.time {
            s += &format!(" {} {} {}", table::time_string(q.stime), table::time_string(q.rtime), table::time_string(q.ctime));
        }
        println!("{s}");
    }
    println!();
}

fn print_shm(o: &Opts, rows: &[(i32, Shm)]) {
    println!("Shared Memory:");
    let mut title = common_title(o);
    if o.outstanding {
        title += &format!(" {:>12}", "NATTCH");
    }
    if o.big {
        title += &format!(" {:>12}", "SEGSZ");
    }
    if o.pid {
        title += &format!(" {:>12} {:>12}", "CPID", "LPID");
    }
    if o.time {
        title += &format!(" {:<8} {:<8} {:<8}", "ATIME", "DTIME", "CTIME");
    }
    println!("{title}");
    for (id, m) in rows.iter().filter(|(_, m)| wanted(o, &m.perm)) {
        let mode = table::mode_string(&m.perm, 'm');
        let mut s = common_row(o, 'm', *id, &m.perm, mode);
        if o.outstanding {
            s += &format!(" {:>12}", m.nattch);
        }
        if o.big {
            s += &format!(" {:>12}", m.segsz);
        }
        if o.pid {
            s += &format!(" {:>12} {:>12}", m.cpid, m.lpid);
        }
        if o.time {
            s += &format!(" {} {} {}", table::time_string(m.atime), table::time_string(m.dtime), table::time_string(m.ctime));
        }
        println!("{s}");
    }
    println!();
}

fn print_sem(o: &Opts, rows: &[(i32, Sem)]) {
    println!("Semaphores:");
    let mut title = common_title(o);
    if o.big {
        title += &format!(" {:>12}", "NSEMS");
    }
    if o.time {
        title += &format!(" {:<8} {:<8}", "OTIME", "CTIME");
    }
    println!("{title}");
    for (id, s) in rows.iter().filter(|(_, s)| wanted(o, &s.perm)) {
        let mode = table::mode_string(&s.perm, 's');
        let mut line = common_row(o, 's', *id, &s.perm, mode);
        if o.big {
            line += &format!(" {:>12}", s.nsems);
        }
        if o.time {
            line += &format!(" {} {}", table::time_string(s.otime), table::time_string(s.ctime));
        }
        println!("{line}");
    }
    println!();
}
