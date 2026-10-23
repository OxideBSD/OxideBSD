//! `true(1)`: does nothing, successfully. Its arguments are ignored.

use std::process::ExitCode;

pub(crate) fn main() -> ExitCode {
    ExitCode::SUCCESS
}
