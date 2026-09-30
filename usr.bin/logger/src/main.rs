//! `logger(1)`: makes entries in the system log (OxideBSD-doc `SYSLOG.md` §10.1), FreeBSD's
//! options.
//!
//! ```text
//! logger [-46Ais] [-f file] [-H hostname] [-h host] [-P port] [-p pri] [-S addr:port]
//!        [-t tag] [message ...]
//! ```
//!
//! The message is the arguments, or else each line of the file or standard input. It goes to
//! `/dev/log` through `syslog(3)`, as FreeBSD's does, or with `-h` over UDP to another host's
//! syslogd, as RFC 3164.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;

use syslog::pri::{self, Facility, Level, Priority};

struct Opts {
    all_addresses: bool,
    file: Option<String>,
    hostname: Option<String>,
    host: Option<String>,
    port: String,
    priority: Priority,
    source: Option<String>,
    stderr: bool,
    tag: Option<String>,
    pid: bool,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: logger [-46Ais] [-f file] [-H hostname] [-h host] [-P port] [-p pri]\n\
         \x20             [-S addr:port] [-t tag] [message ...]"
    );
    ExitCode::from(1)
}

fn parse_args() -> Result<(Opts, Vec<String>), ExitCode> {
    let mut o = Opts {
        all_addresses: false,
        file: None,
        hostname: None,
        host: None,
        port: "514".into(),
        priority: Priority::new(Facility::USER, Level::NOTICE),
        source: None,
        stderr: false,
        tag: None,
        pid: false,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
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
            if "fHhPpSt".contains(c) {
                let value = if j + 1 < flags.len() {
                    flags[j + 1..].to_string()
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    return Err(usage());
                };
                match c {
                    'f' => o.file = Some(value),
                    'H' => o.hostname = Some(value),
                    'h' => o.host = Some(value),
                    'P' => o.port = value,
                    'p' => match pri::parse_priority(&value) {
                        Some(p) => o.priority = p,
                        None => {
                            eprintln!("logger: unknown priority: {value}");
                            return Err(ExitCode::from(1));
                        }
                    },
                    'S' => o.source = Some(value),
                    't' => o.tag = Some(value),
                    _ => unreachable!(),
                }
                break;
            }
            match c {
                '4' => {}
                '6' => {
                    eprintln!("logger: IPv6 is not supported");
                    return Err(ExitCode::from(1));
                }
                'A' => o.all_addresses = true,
                'i' => o.pid = true,
                's' => o.stderr = true,
                _ => return Err(usage()),
            }
        }
    }
    Ok((o, args[i..].to_vec()))
}

/// The default tag: the login name, as FreeBSD's.
fn login_name() -> String {
    // SAFETY: getlogin returns NULL or a C string owned by the library.
    let p = unsafe { libc::getlogin() };
    if !p.is_null() {
        // SAFETY: non-null, NUL-terminated.
        return unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
    }
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "logger".into())
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is as long as passed.
    unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

enum Dest {
    Local,
    Remote { sock: UdpSocket, addrs: Vec<SocketAddr> },
}

fn port_number(port: &str) -> Option<u16> {
    match port {
        "syslog" => Some(syslog::SYSLOG_PORT),
        _ => port.parse().ok(),
    }
}

fn open(o: &Opts, tag: &str) -> Result<Dest, String> {
    let Some(host) = &o.host else {
        // openlog(3) keeps the pointer: the tag lives as long as the process.
        let ident: &'static std::ffi::CStr = Box::leak(
            std::ffi::CString::new(tag.replace('\0', "")).unwrap().into_boxed_c_str(),
        );
        let mut flags = libc::LOG_NDELAY;
        if o.pid {
            flags |= libc::LOG_PID;
        }
        if o.stderr {
            flags |= libc::LOG_PERROR;
        }
        // SAFETY: `ident` is NUL-terminated and never freed.
        unsafe { libc::openlog(ident.as_ptr(), flags, 0) };
        return Ok(Dest::Local);
    };
    let port = port_number(&o.port).ok_or_else(|| format!("unknown port: {}", o.port))?;
    let mut addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .filter(SocketAddr::is_ipv4)
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host}: no IPv4 address"));
    }
    if !o.all_addresses {
        addrs.truncate(1);
    }
    let bind = match &o.source {
        None => "0.0.0.0:0".to_string(),
        Some(s) if s.contains(':') => s.clone(),
        Some(s) => format!("{s}:0"),
    };
    let sock = UdpSocket::bind(&bind).map_err(|e| format!("{bind}: {e}"))?;
    Ok(Dest::Remote { sock, addrs })
}

fn send(o: &Opts, dest: &Dest, tag: &str, text: &str) -> Result<(), String> {
    let stamp = syslog::time::now();
    let pid = if o.pid { format!("[{}]", std::process::id()) } else { String::new() };
    match dest {
        Dest::Local => {
            let msg = std::ffi::CString::new(text.replace('\0', "")).unwrap();
            // SAFETY: a "%s" format with one C string argument.
            unsafe { libc::syslog(o.priority.number() as libc::c_int, c"%s".as_ptr(), msg.as_ptr()) };
        }
        Dest::Remote { sock, addrs } => {
            if o.stderr {
                let _ = writeln!(std::io::stderr(), "{tag}{pid}: {text}");
            }
            let host = o.hostname.clone().unwrap_or_else(hostname);
            let packet = format!("<{}>{} {host} {tag}{pid}: {text}", o.priority.number(), stamp.rfc3164());
            for a in addrs {
                sock.send_to(packet.as_bytes(), a).map_err(|e| format!("{a}: {e}"))?;
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let (opts, words) = match parse_args() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let tag = opts.tag.clone().unwrap_or_else(login_name);
    let dest = match open(&opts, &tag) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("logger: {e}");
            return ExitCode::from(1);
        }
    };
    let mut status = ExitCode::SUCCESS;
    let mut emit = |text: &str| {
        if let Err(e) = send(&opts, &dest, &tag, text) {
            eprintln!("logger: {e}");
            status = ExitCode::from(1);
        }
    };
    if !words.is_empty() {
        emit(&words.join(" "));
        return status;
    }
    let input: Box<dyn BufRead> = match &opts.file {
        Some(path) => match std::fs::File::open(path) {
            Ok(f) => Box::new(std::io::BufReader::new(f)),
            Err(e) => {
                eprintln!("logger: {path}: {e}");
                return ExitCode::from(1);
            }
        },
        None => Box::new(std::io::stdin().lock()),
    };
    for line in input.split(b'\n') {
        let Ok(line) = line else { break };
        let text = String::from_utf8_lossy(&line);
        if !text.is_empty() {
            emit(&text);
        }
    }
    status
}
