//! `makewhatis(8)`: builds the manual page index, `oxdoc.db` in each manual tree (MAN.md §7 in
//! OxideBSD-doc).
//!
//! ```text
//! makewhatis [-an] [-C file]
//! makewhatis [-an] dir ...
//! makewhatis [-n] -d dir [file ...]
//! makewhatis [-n] -u dir [file ...]
//! makewhatis -t file ...
//! ```
//!
//! The work is liboxdoc's.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(liboxdoc::makewhatis::main(&args));
}
