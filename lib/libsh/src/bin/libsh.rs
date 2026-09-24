//! `/bin/sh` built for the host, for testing (INIT_SH.md §8): the differential
//! suite runs scripts through this and through `dash`.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(libsh::main_with(args, libsh::Interactive::Allow));
}
