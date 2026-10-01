//! Running a job (CRON.md §§3.5-3.6, 4.2-4.3). cron forks a runner for each, so the schedule
//! never waits: the runner delays by the jitter, checks the account with PAM, starts
//! `$SHELL -c command` as the user, feeds it its `%` input, and logs what it prints.

use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::db::Entry;

/// `cron`'s options that shape a job's run.
pub struct Settings {
    /// `-j`: at most this many seconds of random delay before a user's job.
    pub jitter: u32,
    /// `-J`: the same for root's.
    pub root_jitter: u32,
    /// `-m`: `MAILTO` for tables that don't set it.
    pub mailto: Option<String>,
}

pub fn log(priority: libc::c_int, msg: &str) {
    let msg = CString::new(msg.replace('\0', "")).unwrap_or_default();
    // SAFETY: a constant format and a NUL-terminated argument.
    unsafe { libc::syslog(priority, c"%s".as_ptr(), msg.as_ptr()) };
}

/// A random number of seconds in `0..=max`.
fn random_delay(max: u32) -> u32 {
    if max == 0 {
        return 0;
    }
    let mut buf = [0u8; 4];
    let got = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf));
    if got.is_err() {
        return 0;
    }
    u32::from_ne_bytes(buf) % (max + 1)
}

static CONV: pam::PamConv = pam::PamConv {
    conv: Some(pam::nullconv),
    appdata_ptr: std::ptr::null_mut(),
};

/// The PAM account check of service `cron` (§4.2): `Err` with the reason if the account may
/// not run jobs now.
fn account_ok(user: &str) -> Result<(), String> {
    let cuser = CString::new(user).map_err(|_| "bad user name".to_string())?;
    let mut h = std::ptr::null_mut();
    // SAFETY: CONV lives for the program; OpenPAM copies the strings.
    let r = unsafe { pam::pam_start(c"cron".as_ptr(), cuser.as_ptr(), &CONV, &mut h) };
    if r != pam::PAM_SUCCESS {
        return Err(format!("pam_start: {}", pam::strerror(h, r)));
    }
    // SAFETY: the handle from pam_start.
    let r = unsafe { pam::pam_acct_mgmt(h, pam::PAM_SILENT) };
    let result = if r == pam::PAM_SUCCESS {
        Ok(())
    } else {
        Err(pam::strerror(h, r))
    };
    unsafe { pam::pam_end(h, r) };
    result
}

/// The job's environment (§3.6): the defaults, the login class's, then the table's, which may
/// replace all but `LOGNAME` and `USER`.
fn environment(e: &Entry, pw: &pwd::Entry, class: &logincap::Class) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vec![
        ("SHELL".into(), "/bin/sh".into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), pw.home.clone()),
        ("LOGNAME".into(), pw.name.clone()),
        ("USER".into(), pw.name.clone()),
    ];
    let set = |env: &mut Vec<(String, String)>, k: &str, v: &str| match env
        .iter_mut()
        .find(|(n, _)| n == k)
    {
        Some(slot) => slot.1 = v.to_string(),
        None => env.push((k.to_string(), v.to_string())),
    };
    for (k, v) in class.environment(&pw.name, &pw.home) {
        set(&mut env, &k, &v);
    }
    for (k, v) in e.env.iter() {
        if k != "LOGNAME" && k != "USER" {
            set(&mut env, k, v);
        }
    }
    env
}

/// Starts a runner for `e`; returns at once in cron.
pub fn start(e: &Entry, settings: &Settings) {
    // SAFETY: cron is single-threaded; the child only runs the job and exits.
    match unsafe { libc::fork() } {
        -1 => log(
            libc::LOG_ERR,
            &format!("(CRON) CAN'T FORK ({})", std::io::Error::last_os_error()),
        ),
        0 => {
            run(e, settings);
            // SAFETY: leaves the runner without running cron's exit handlers.
            unsafe { libc::_exit(0) };
        }
        _ => {}
    }
}

fn run(e: &Entry, settings: &Settings) {
    // A session of its own, so that signals meant for cron's group don't reach jobs.
    // SAFETY: setsid takes no arguments.
    unsafe { libc::setsid() };
    let Some(pw) = pwd::lookup(&e.user) else {
        log(
            libc::LOG_WARNING,
            &format!("({}) ORPHAN (no passwd entry)", e.user),
        );
        return;
    };
    let delay = random_delay(if pw.uid == 0 {
        settings.root_jitter
    } else {
        settings.jitter
    });
    if delay > 0 {
        std::thread::sleep(Duration::from_secs(delay.into()));
    }
    if let Err(why) = account_ok(&pw.name) {
        log(libc::LOG_WARNING, &format!("({}) PAM ({why})", pw.name));
        return;
    }
    let class = logincap::Class::load(pw.login_class());
    let env = environment(e, &pw, &class);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let shell = get("SHELL").unwrap_or_else(|| "/bin/sh".into());
    let mailto = get("MAILTO").or_else(|| settings.mailto.clone());
    // No mail system yet (§4.3): output is logged, unless MAILTO is empty.
    let keep_output = mailto.as_deref() != Some("");

    log(
        libc::LOG_INFO,
        &format!("({}) CMD ({})", pw.name, e.job.command),
    );
    let (reader, writer) = match std::io::pipe() {
        Ok(p) => p,
        Err(err) => {
            log(libc::LOG_ERR, &format!("({}) CAN'T PIPE ({err})", pw.name));
            return;
        }
    };
    let Ok(writer2) = writer.try_clone() else {
        return;
    };
    let dir = if std::path::Path::new(&pw.home).is_dir() {
        pw.home.clone()
    } else {
        "/".into()
    };
    let (name, uid, gid) = (pw.name.clone(), pw.uid, pw.gid);
    let mut cmd = Command::new(&shell);
    cmd.arg("-c")
        .arg(&e.job.command)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(&dir)
        .stdin(if e.job.input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(writer)
        .stderr(writer2);
    // SAFETY: the runner is single-threaded, so the allocation setusercontext does is safe.
    unsafe {
        cmd.pre_exec(move || {
            logincap::setusercontext(&class, &name, uid, gid, logincap::LOGIN_SETALL)
        });
    }
    let child = cmd.spawn();
    // The command holds the pipe's write ends; drop them, or the read never ends.
    drop(cmd);
    let mut child = match child {
        Ok(c) => c,
        Err(err) => {
            log(
                libc::LOG_ERR,
                &format!("({}) CAN'T EXEC ({shell}: {err})", pw.name),
            );
            return;
        }
    };
    if let (Some(input), Some(mut stdin)) = (&e.job.input, child.stdin.take()) {
        let _ = stdin.write_all(input.as_bytes());
    }
    for line in BufReader::new(reader).split(b'\n').map_while(Result::ok) {
        if keep_output {
            log(
                libc::LOG_NOTICE,
                &format!("({}) CMDOUT ({})", pw.name, String::from_utf8_lossy(&line)),
            );
        }
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    fn entry(env: &[(&str, &str)]) -> Entry {
        let (t, _) = libcron::parse("* * * * * true\n", false);
        Entry {
            user: "u".into(),
            job: t.jobs[0].clone(),
            env: Rc::new(
                env.iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            ),
        }
    }

    #[test]
    fn job_environment() {
        let pw = pwd::parse_line("u:*:1000:1000:staff:0:0:A User:/home/u:/bin/sh").unwrap();
        let class = logincap::Class::from_text(
            "staff:\\\n\t:setenv=MAIL=/var/mail/$:timezone=UTC:\n",
            "staff",
        );
        let e = entry(&[
            ("PATH", "/bin"),
            ("USER", "root"),
            ("LOGNAME", "root"),
            ("A", "b"),
        ]);
        let env = environment(&e, &pw, &class);
        let env: Vec<(&str, &str)> = env.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert_eq!(
            env,
            [
                ("SHELL", "/bin/sh"),
                ("PATH", "/bin"),
                ("HOME", "/home/u"),
                ("LOGNAME", "u"),
                ("USER", "u"),
                ("TZ", "UTC"),
                ("MAIL", "/var/mail/u"),
                ("A", "b"),
            ]
        );
    }
}
