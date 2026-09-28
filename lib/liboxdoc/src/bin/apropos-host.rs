//! apropos(1) on the host, for the differential tests; run as `whatis` (by a link's name) it
//! is whatis(1).

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let prog = if argv0.rsplit('/').next().unwrap_or("").contains("whatis") { "whatis" } else { "apropos" };
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(liboxdoc::apropos::main(prog, &args));
}
