//! `false(1)`: does nothing, unsuccessfully (exit status 1). Its arguments are ignored.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::FAILURE
}
