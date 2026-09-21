//! A minimal flag/positional-argument scanner -- not full `getopt` (no `--long=value`), but short
//! flags may be clustered (`-rf`, `-la`), since that's how these utilities actually get invoked
//! (`sys/modules/oxfs/src/test_busybox.sh` itself runs `rm -rf`). `argv[0]` (the program's own
//! invoked name) is always skipped; it's never itself a real argument. A literal `--` ends flag
//! parsing for both helpers below.

/// `true` if `argv` contains `short` inside a short-flag cluster (`-r`, `-rf`, ...) or, when
/// `long` is `Some`, a `--<long>` entry. `long: None` for a flag with no real long form -- a
/// `Some(b"")` would otherwise wrongly match a bare `--`.
pub fn has_flag(argv: &[&[u8]], short: u8, long: Option<&[u8]>) -> bool {
    for &arg in argv.iter().skip(1) {
        if arg == b"--" {
            return false;
        }
        if arg.len() > 1 && arg[0] == b'-' && arg[1] != b'-' {
            if arg[1..].contains(&short) {
                return true;
            }
        } else if let Some(l) = long
            && arg.starts_with(b"--")
            && &arg[2..] == l
        {
            return true;
        }
    }
    false
}

/// Every `argv` entry that isn't a flag, in order. A bare `-` (real convention for "stdin") is
/// kept; a literal `--` ends flag parsing (everything after it is positional) and is itself
/// dropped.
pub fn positional_args<'a>(argv: &'a [&'a [u8]]) -> impl Iterator<Item = &'a [u8]> + 'a {
    let mut seen_double_dash = false;
    argv.iter().skip(1).copied().filter(move |&arg| {
        if seen_double_dash {
            return true;
        }
        if arg == b"--" {
            seen_double_dash = true;
            return false;
        }
        arg == b"-" || !arg.starts_with(b"-")
    })
}
