//! `link(1)`: makes `file2` a hard link to `file1` with link(2), and nothing more (POSIX; ln(1)
//! is the one with options).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [file1, file2] = args.as_slice() else {
        eprintln!("usage: link file1 file2");
        return ExitCode::from(1);
    };
    match std::fs::hard_link(file1, file2) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("link: {file2}: {e}");
            ExitCode::from(1)
        }
    }
}
