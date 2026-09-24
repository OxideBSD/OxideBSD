//! `/bin/sh`: the POSIX shell, over `lib/libsh` -- scripts, `sh -c`, and the interactive shell.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(libsh::main_with(args, libsh::Interactive::Allow));
}
