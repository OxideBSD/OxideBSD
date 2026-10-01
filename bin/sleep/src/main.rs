//! `sleep(1)`: waits for the total of its arguments. Each is a number of seconds, which may have
//! a fraction (`0.5`) and a unit, `s`, `m`, `h` or `d` (seconds, minutes, hours, days), as on
//! FreeBSD.

use std::process::ExitCode;
use std::time::Duration;

/// One argument, in seconds.
fn seconds(arg: &str) -> Option<f64> {
    let (number, unit) = match arg.char_indices().last() {
        Some((i, c @ ('s' | 'm' | 'h' | 'd'))) => (&arg[..i], c),
        _ => (arg, 's'),
    };
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let n: f64 = number.parse().ok()?;
    let scale = match unit {
        'm' => 60.0,
        'h' => 3600.0,
        'd' => 86400.0,
        _ => 1.0,
    };
    Some(n * scale)
}

fn total(args: &[String]) -> Option<f64> {
    if args.is_empty() {
        return None;
    }
    args.iter().map(|a| seconds(a)).sum()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: &[String] = if args.first().map(String::as_str) == Some("--") {
        &args[1..]
    } else {
        &args
    };
    let Some(secs) = total(args).filter(|s| s.is_finite()) else {
        eprintln!("usage: sleep number[unit] [...]");
        return ExitCode::from(1);
    };
    std::thread::sleep(Duration::from_secs_f64(secs.min(u64::MAX as f64 / 2.0)));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(args: &[&str]) -> Option<f64> {
        total(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn arguments() {
        assert_eq!(t(&["5"]), Some(5.0));
        assert_eq!(t(&["0.5"]), Some(0.5));
        assert_eq!(t(&["1m", "30"]), Some(90.0));
        assert_eq!(t(&["2h"]), Some(7200.0));
        assert_eq!(t(&["1d", "1s"]), Some(86401.0));
        assert_eq!(t(&[".25s"]), Some(0.25));
        for bad in [
            &[][..],
            &["x"],
            &["-1"],
            &["1x"],
            &["s"],
            &["1e3"],
            &["1.2.3"],
        ] {
            assert_eq!(t(bad), None, "{bad:?}");
        }
    }
}
