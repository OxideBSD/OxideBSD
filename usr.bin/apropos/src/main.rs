//! `apropos(1)` and `whatis(1)`: search the manual page index (MAN.md §7 in OxideBSD-doc).
//!
//! ```text
//! apropos [-afkt] [-C file] [-M path] [-m path] [-O outkey] [-S arch] [-s section] expression ...
//! whatis [-C file] [-M path] [-m path] [-S arch] [-s section] name ...
//! ```
//!
//! The same program under either name; the work is liboxdoc's.

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let prog = if argv0.rsplit('/').next() == Some("whatis") { "whatis" } else { "apropos" };
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(liboxdoc::apropos::main(prog, &args));
}
