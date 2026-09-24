//! OxideBSD's shell core: the POSIX Shell Command Language, shared by `/sbin/init_sh` (with the
//! init dialect) and, later, `/bin/sh`. See `INIT_SH.md` in OxideBSD-doc.

pub mod arith;
pub mod ast;
mod builtins;
mod exec;
mod expand;
pub mod parse;
pub mod pattern;
mod printf;
pub mod shell;
mod sys;
mod test;

pub use parse::{ParseError, parse};
pub use shell::{Interactive, Shell, main, main_with};

/// Whether this build accepts the init dialect (INIT_SH.md §4) -- `/sbin/init_sh` only.
pub const INIT_DIALECT: bool = cfg!(feature = "init-dialect");
