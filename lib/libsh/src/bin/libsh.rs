//! The plain POSIX shell over the core, for host testing (INIT_SH.md §8): the differential
//! suite runs scripts through this and through `dash`.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(libsh::main(args));
}
