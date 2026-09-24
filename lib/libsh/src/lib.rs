//! OxideBSD's shell core: the POSIX Shell Command Language, shared by `/sbin/init_sh` (with the
//! init dialect) and `/bin/sh` (with the interactive shell). See `INIT_SH.md` in OxideBSD-doc.

pub mod arith;
pub mod ast;
mod builtins;
mod exec;
mod expand;
mod interactive;
pub mod jobs;
mod lineedit;
pub mod parse;
pub mod pattern;
mod printf;
mod prompt;
pub mod shell;
mod sys;
mod test;
mod unparse;

pub use parse::{ParseError, parse};
pub use shell::{Interactive, Shell, main, main_with};

/// Whether this build accepts the init dialect (INIT_SH.md §4) -- `/sbin/init_sh` only.
pub const INIT_DIALECT: bool = cfg!(feature = "init-dialect");
