//! `unlink(1)`: removes one name with unlink(2), and nothing more (POSIX; rm(1) is the one with
//! options). A directory is refused, as unlink(2) refuses it.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [file] = args.as_slice() else {
        eprintln!("usage: unlink file");
        return ExitCode::from(1);
    };
    match std::fs::remove_file(file) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unlink: {file}: {e}");
            ExitCode::from(1)
        }
    }
}
