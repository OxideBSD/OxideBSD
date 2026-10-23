//! `dd(1)`: copies and converts blocks of data.
//!
//! ```text
//! dd [operand ...]
//! ```
//!
//! POSIX's dd, operands as the BSDs take them:
//!
//! - `if=file`, `of=file`: the input and output (stdin and stdout by default). The output is
//!   created with mode 0666 less the umask and truncated unless `seek=` or `conv=notrunc`; with
//!   `seek=`, cut at the place writing starts unless `conv=notrunc` (an `of=` file only, never
//!   standard output).
//! - `ibs=n`, `obs=n` (512 each), `bs=n` (both; and, with no conversion but `noerror`,
//!   `notrunc` and `sync`, each block read is written as one block), `cbs=n` (the record size
//!   for `block` and `unblock`).
//! - `skip=n` (`iseek=`) input blocks to pass by, by seeking or else by reading; `seek=n`
//!   (`oseek=`) output blocks to seek past; `count=n` input blocks to copy.
//! - `conv=`: `block` (newline-ended records padded with spaces, or cut, to `cbs` bytes),
//!   `unblock` (`cbs`-byte records with trailing spaces dropped and a newline added), `lcase`,
//!   `ucase`, `swab` (swap each pair of bytes), `noerror` (go on after a read error), `notrunc`,
//!   `sync` (pad every input block to `ibs`, with spaces for `block`/`unblock`, else NULs),
//!   `sparse` (seek over output blocks of NULs), `fsync`, `fdatasync`. EBCDIC conversions
//!   (`ascii`, `ebcdic`, `ibm`...) are not provided.
//! - `iflag=fullblock` (fill each input block, reading again on short reads); `oflag=fsync`,
//!   `oflag=sync` (open the output `O_SYNC`).
//! - `status=noxfer` (no bytes-transferred line), `status=none` (no summary),
//!   `status=progress` (a running count, about once a second).
//!
//! Numbers may end in `b` (512), `k`, `m`, `g`, `t`, `p`, `e` (powers of 1024) or `w` (4), and be
//! multiplied with `x`: `bs=2x512`. The summary on stderr is the BSDs':
//! `in-full+in-partial records in`, the same out, and the bytes and time. An interrupt (SIGINT)
//! writes the summary before dd dies of it.

use std::ffi::{CStr, CString};
use std::io;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[derive(Default, Clone, Copy)]
struct Conv {
    block: bool,
    unblock: bool,
    lcase: bool,
    ucase: bool,
    swab: bool,
    noerror: bool,
    notrunc: bool,
    sync: bool,
    sparse: bool,
    fsync: bool,
    fdatasync: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Full,
    NoXfer,
    None,
    Progress,
}

#[derive(Default)]
struct Stats {
    in_full: u64,
    in_part: u64,
    out_full: u64,
    out_part: u64,
    odd_swab: u64,
    truncated: u64,
    bytes: u64,
}

fn strerror_n(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned()
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// FreeBSD's `get_num`: a number with an optional size suffix, products joined by `x`.
fn parse_num(s: &str) -> Option<u64> {
    let (first, rest) = match s.find(['x', '*']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let split = first.find(|c: char| !c.is_ascii_digit()).unwrap_or(first.len());
    if split == 0 {
        return None;
    }
    let n: u64 = first[..split].parse().ok()?;
    let mult: u64 = match &first[split..] {
        "" => 1,
        "b" | "B" => 512,
        "k" | "K" => 1 << 10,
        "m" | "M" => 1 << 20,
        "g" | "G" => 1 << 30,
        "t" | "T" => 1 << 40,
        "p" | "P" => 1 << 50,
        "e" | "E" => 1 << 60,
        "w" | "W" => 4,
        _ => return None,
    };
    let v = n.checked_mul(mult)?;
    match rest {
        Some(r) => v.checked_mul(parse_num(r)?),
        None => Some(v),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The BSDs' summary.
fn summary(st: &Stats, start: Instant, status: Status) {
    if status == Status::None {
        return;
    }
    let mut s = format!(
        "{}+{} records in\n{}+{} records out\n",
        st.in_full, st.in_part, st.out_full, st.out_part
    );
    if st.odd_swab > 0 {
        s += &format!("{} odd length swab {}\n", st.odd_swab, if st.odd_swab == 1 { "block" } else { "blocks" });
    }
    if st.truncated > 0 {
        s += &format!("{}\n", plural(st.truncated, "truncated block", "truncated blocks"));
    }
    if status != Status::NoXfer {
        let secs = start.elapsed().as_secs_f64();
        let rate = if secs > 0.0 { (st.bytes as f64 / secs) as u64 } else { 0 };
        s += &format!("{} bytes transferred in {:.3} secs ({} bytes/sec)\n", st.bytes, secs, rate);
    }
    eprint!("{s}");
}

fn usage_exit(msg: &str) -> ExitCode {
    eprintln!("dd: {msg}");
    ExitCode::from(1)
}

struct Out {
    fd: i32,
    name: String,
    obs: usize,
    buf: Vec<u8>,
    sparse: bool,
    /// The last block was seeked over (conv=sparse): the file must be extended at the end.
    pending_hole: bool,
}

impl Out {
    /// Writes one output block of `data`. Returns false (having said why) on an error.
    fn write_block(&mut self, data: &[u8], st: &mut Stats) -> bool {
        if data.is_empty() {
            return true;
        }
        if self.sparse && data.iter().all(|&b| b == 0) {
            // SAFETY: lseek on our descriptor.
            if unsafe { libc::lseek(self.fd, data.len() as libc::off_t, libc::SEEK_CUR) } >= 0 {
                self.pending_hole = true;
                st.bytes += data.len() as u64;
                if data.len() == self.obs {
                    st.out_full += 1;
                } else {
                    st.out_part += 1;
                }
                return true;
            }
        }
        let mut off = 0;
        while off < data.len() {
            // SAFETY: the slice is valid for its length.
            let n = unsafe { libc::write(self.fd, data[off..].as_ptr().cast(), data.len() - off) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR && !INTERRUPTED.load(Ordering::SeqCst) {
                    continue;
                }
                eprintln!("dd: {}: {}", self.name, strerror_n(e));
                return false;
            }
            if n == 0 {
                eprintln!("dd: {}: short write", self.name);
                return false;
            }
            off += n as usize;
        }
        self.pending_hole = false;
        st.bytes += data.len() as u64;
        if data.len() == self.obs {
            st.out_full += 1;
        } else {
            st.out_part += 1;
        }
        true
    }

    /// Adds `data` to the output, writing every full `obs` block.
    fn put(&mut self, data: &[u8], st: &mut Stats) -> bool {
        self.buf.extend_from_slice(data);
        let mut start = 0;
        while self.buf.len() - start >= self.obs {
            let block: Vec<u8> = self.buf[start..start + self.obs].to_vec();
            if !self.write_block(&block, st) {
                return false;
            }
            start += self.obs;
        }
        self.buf.drain(..start);
        true
    }

    fn finish(&mut self, st: &mut Stats) -> bool {
        let rest = std::mem::take(&mut self.buf);
        if !self.write_block(&rest, st) {
            return false;
        }
        if self.pending_hole {
            // SAFETY: lseek and ftruncate on our descriptor.
            let pos = unsafe { libc::lseek(self.fd, 0, libc::SEEK_CUR) };
            if pos >= 0 && unsafe { libc::ftruncate(self.fd, pos) } != 0 {
                eprintln!("dd: {}: {}", self.name, strerror_n(errno()));
                return false;
            }
        }
        true
    }
}

pub(crate) fn main() -> ExitCode {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let (mut ibs, mut obs, mut bs, mut cbs) = (512usize, 512usize, None::<usize>, 0usize);
    let (mut skip, mut seek, mut count) = (0u64, 0u64, None::<u64>);
    let mut conv = Conv::default();
    let mut fullblock = false;
    let (mut ofsync, mut osync) = (false, false);
    let mut status = Status::Full;

    for arg in std::env::args().skip(1) {
        let Some((key, val)) = arg.split_once('=') else {
            return usage_exit(&format!("unknown operand {arg}"));
        };
        let num = |v: &str| parse_num(v).ok_or_else(|| format!("{v}: illegal numeric value"));
        let size = |v: &str| match parse_num(v) {
            None => Err(format!("{v}: illegal numeric value")),
            Some(0) => Err(format!("{key} must be between 1 and {}", isize::MAX)),
            Some(n) if n > isize::MAX as u64 => Err(format!("{key} must be between 1 and {}", isize::MAX)),
            Some(n) => Ok(n as usize),
        };
        let r: Result<(), String> = (|| {
            match key {
                "if" => input = Some(val.to_string()),
                "of" => output = Some(val.to_string()),
                "ibs" => ibs = size(val)?,
                "obs" => obs = size(val)?,
                "bs" => bs = Some(size(val)?),
                "cbs" => cbs = size(val)?,
                "skip" | "iseek" => skip = num(val)?,
                "seek" | "oseek" => seek = num(val)?,
                "count" => count = Some(num(val)?),
                "conv" => {
                    for c in val.split(',') {
                        match c {
                            "block" => conv.block = true,
                            "unblock" => conv.unblock = true,
                            "lcase" => conv.lcase = true,
                            "ucase" => conv.ucase = true,
                            "swab" => conv.swab = true,
                            "noerror" => conv.noerror = true,
                            "notrunc" => conv.notrunc = true,
                            "sync" => conv.sync = true,
                            "sparse" => conv.sparse = true,
                            "fsync" => conv.fsync = true,
                            "fdatasync" => conv.fdatasync = true,
                            "ascii" | "oldascii" | "ebcdic" | "oldebcdic" | "ibm" | "oldibm" | "osync"
                            | "pareven" | "parodd" | "parnone" | "parset" => {
                                return Err(format!("conv={c} is not supported"));
                            }
                            _ => return Err(format!("unknown conversion {c}")),
                        }
                    }
                }
                "iflag" => {
                    for f in val.split(',') {
                        match f {
                            "fullblock" => fullblock = true,
                            _ => return Err(format!("unknown iflag {f}")),
                        }
                    }
                }
                "oflag" => {
                    for f in val.split(',') {
                        match f {
                            "fsync" => ofsync = true,
                            "sync" => osync = true,
                            _ => return Err(format!("unknown oflag {f}")),
                        }
                    }
                }
                "status" => {
                    status = match val {
                        "noxfer" => Status::NoXfer,
                        "none" => Status::None,
                        "progress" => Status::Progress,
                        _ => return Err(format!("unknown status {val}")),
                    }
                }
                _ => return Err(format!("unknown operand {key}")),
            }
            Ok(())
        })();
        if let Err(e) = r {
            return usage_exit(&e);
        }
    }
    if conv.block && conv.unblock {
        return usage_exit("block and unblock are mutually exclusive");
    }
    if conv.lcase && conv.ucase {
        return usage_exit("lcase and ucase are mutually exclusive");
    }
    if (conv.block || conv.unblock) && cbs == 0 {
        return usage_exit("record operations require cbs");
    }
    if let Some(b) = bs {
        ibs = b;
        obs = b;
    }
    // bs= with no conversion but these: each block read is one block written.
    let direct = bs.is_some() && !(conv.block || conv.unblock || conv.lcase || conv.ucase || conv.swab);

    // Input.
    let (in_fd, in_name) = match &input {
        Some(p) => {
            let c = CString::new(p.as_str()).unwrap_or_default();
            // SAFETY: a NUL-terminated path.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
            if fd < 0 {
                return usage_exit(&format!("{p}: {}", strerror_n(errno())));
            }
            (fd, p.clone())
        }
        None => (0, "stdin".to_string()),
    };
    // Output.
    let (out_fd, out_name) = match &output {
        Some(p) => {
            let c = CString::new(p.as_str()).unwrap_or_default();
            let mut flags = libc::O_WRONLY | libc::O_CREAT;
            if seek == 0 && !conv.notrunc {
                flags |= libc::O_TRUNC;
            }
            if osync {
                flags |= libc::O_SYNC;
            }
            // SAFETY: a NUL-terminated path.
            let fd = unsafe { libc::open(c.as_ptr(), flags, 0o666 as libc::c_uint) };
            if fd < 0 {
                return usage_exit(&format!("{p}: {}", strerror_n(errno())));
            }
            (fd, p.clone())
        }
        None => (1, "stdout".to_string()),
    };

    // SAFETY: installs a handler that only sets a flag; no SA_RESTART, so a blocked read returns.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigint as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old);
        if old.sa_sigaction != libc::SIG_IGN {
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }
    }

    let start = Instant::now();
    let mut st = Stats::default();
    let fail = |st: &Stats| {
        summary(st, start, status);
        ExitCode::from(1)
    };

    // skip=: seek, or read past.
    if skip > 0 {
        let off = (skip as u128) * (ibs as u128);
        // SAFETY: lseek on our descriptor.
        let ok = off <= i64::MAX as u128 && unsafe { libc::lseek(in_fd, off as libc::off_t, libc::SEEK_CUR) } >= 0;
        if !ok {
            let mut junk = vec![0u8; ibs];
            let mut left = skip;
            while left > 0 {
                // SAFETY: the buffer is ibs bytes.
                let n = unsafe { libc::read(in_fd, junk.as_mut_ptr().cast(), ibs) };
                if n < 0 {
                    if errno() == libc::EINTR && !INTERRUPTED.load(Ordering::SeqCst) {
                        continue;
                    }
                    eprintln!("dd: {in_name}: {}", strerror_n(errno()));
                    return fail(&st);
                }
                if n == 0 {
                    eprintln!("dd: {in_name}: skip reached end of input");
                    break;
                }
                left -= 1;
            }
        }
    }
    // seek=: seek, and cut there.
    if seek > 0 {
        let off = (seek as u128) * (obs as u128);
        // SAFETY: lseek on our descriptor.
        if off > i64::MAX as u128 || unsafe { libc::lseek(out_fd, off as libc::off_t, libc::SEEK_CUR) } < 0 {
            eprintln!("dd: {out_name}: {}", strerror_n(errno()));
            return fail(&st);
        }
        // Only a file dd opened itself (`of=`) is cut there, as on FreeBSD: standard output may be
        // a file the caller opened for update (`1<>file`). A device or pipe can't be cut anyway.
        if !conv.notrunc && output.is_some() {
            let mut sb: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat fills sb.
            if unsafe { libc::fstat(out_fd, &mut sb) } == 0
                && sb.st_mode & libc::S_IFMT == libc::S_IFREG
                && unsafe { libc::ftruncate(out_fd, off as libc::off_t) } != 0
            {
                eprintln!("dd: {out_name}: {}", strerror_n(errno()));
                return fail(&st);
            }
        }
    }

    let mut out = Out { fd: out_fd, name: out_name.clone(), obs, buf: Vec::with_capacity(obs * 2), sparse: conv.sparse, pending_hole: false };
    let mut inbuf = vec![0u8; ibs];
    // block/unblock state: the record being built.
    let mut record: Vec<u8> = Vec::with_capacity(cbs + 1);
    let mut in_record_overflow = false;
    let pad = if conv.block || conv.unblock { b' ' } else { 0 };
    let mut last_progress = Instant::now();
    let mut copied = 0u64;
    let mut ok = true;

    'copy: while count.is_none_or(|c| copied < c) {
        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }
        // One input block.
        let mut n = 0usize;
        let mut read_error = false;
        loop {
            // SAFETY: the buffer has room for ibs - n bytes past n.
            let r = unsafe { libc::read(in_fd, inbuf[n..].as_mut_ptr().cast(), ibs - n) };
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    if INTERRUPTED.load(Ordering::SeqCst) {
                        break 'copy;
                    }
                    continue;
                }
                eprintln!("dd: {in_name}: {}", strerror_n(e));
                if !conv.noerror {
                    ok = false;
                    break 'copy;
                }
                summary(&st, start, status);
                read_error = true;
                // Past the bad block where the input can seek.
                // SAFETY: lseek on our descriptor.
                unsafe { libc::lseek(in_fd, (ibs - n) as libc::off_t, libc::SEEK_CUR) };
                break;
            }
            if r == 0 {
                break;
            }
            n += r as usize;
            if !fullblock || n == ibs {
                break;
            }
        }
        if read_error {
            if !conv.sync {
                copied += 1;
                continue;
            }
            inbuf[n..].fill(0);
            n = ibs;
            st.in_part += 1;
        } else if n == 0 {
            break;
        } else if n == ibs {
            st.in_full += 1;
        } else {
            st.in_part += 1;
        }
        copied += 1;
        if conv.sync && n < ibs {
            inbuf[n..].fill(pad);
            n = ibs;
        }
        let data = &mut inbuf[..n];
        if conv.swab {
            if n % 2 == 1 {
                st.odd_swab += 1;
            }
            for pair in data.chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
        }
        if conv.lcase {
            data.make_ascii_lowercase();
        } else if conv.ucase {
            data.make_ascii_uppercase();
        }
        let wrote = if direct {
            out.write_block(data, &mut st)
        } else if conv.block {
            let mut converted = Vec::with_capacity(n + cbs);
            for &b in data.iter() {
                if b == b'\n' {
                    record.resize(cbs, b' ');
                    converted.append(&mut record);
                    in_record_overflow = false;
                } else if record.len() < cbs {
                    record.push(b);
                } else if !in_record_overflow {
                    in_record_overflow = true;
                    st.truncated += 1;
                }
            }
            out.put(&converted, &mut st)
        } else if conv.unblock {
            let mut converted = Vec::with_capacity(n + n / cbs + 1);
            for &b in data.iter() {
                record.push(b);
                if record.len() == cbs {
                    let end = record.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1);
                    converted.extend_from_slice(&record[..end]);
                    converted.push(b'\n');
                    record.clear();
                }
            }
            out.put(&converted, &mut st)
        } else {
            out.put(data, &mut st)
        };
        if !wrote {
            ok = false;
            break;
        }
        if status == Status::Progress && last_progress.elapsed().as_secs() >= 1 {
            last_progress = Instant::now();
            let secs = start.elapsed().as_secs_f64();
            eprint!(
                "\r  {} bytes transferred {:.3}s, {} bytes/sec",
                st.bytes,
                secs,
                if secs > 0.0 { (st.bytes as f64 / secs) as u64 } else { 0 }
            );
        }
    }
    // What block or unblock still holds.
    if ok && !record.is_empty() {
        let tail = if conv.block {
            record.resize(cbs, b' ');
            std::mem::take(&mut record)
        } else {
            let end = record.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1);
            let mut t = record[..end].to_vec();
            t.push(b'\n');
            t
        };
        ok = out.put(&tail, &mut st);
    }
    if ok {
        ok = out.finish(&mut st);
    }
    if ok && (conv.fsync || ofsync) {
        // SAFETY: fsync on our descriptor.
        if unsafe { libc::fsync(out_fd) } != 0 && errno() != libc::EINVAL {
            eprintln!("dd: {out_name}: {}", strerror_n(errno()));
            ok = false;
        }
    } else if ok && conv.fdatasync {
        // SAFETY: fdatasync on our descriptor.
        if unsafe { libc::fdatasync(out_fd) } != 0 && errno() != libc::EINVAL {
            eprintln!("dd: {out_name}: {}", strerror_n(errno()));
            ok = false;
        }
    }
    if status == Status::Progress {
        eprintln!();
    }
    summary(&st, start, status);
    if INTERRUPTED.load(Ordering::SeqCst) {
        // Die of the signal, as the shell expects.
        // SAFETY: back to the default action, then raise it.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::raise(libc::SIGINT);
        }
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
