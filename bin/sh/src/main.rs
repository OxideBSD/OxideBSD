//! `/bin/sh`: the POSIX shell, over `lib/libsh`.
//!
//! Interactive mode isn't implemented yet, so an interactive invocation (`sh -i`, or `sh` with no
//! script on a terminal) is handed to BusyBox `hush` at `/bin/hush` for now.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(libsh::main_with(args, libsh::Interactive::Exec("/bin/hush")));
}
