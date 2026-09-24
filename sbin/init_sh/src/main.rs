//! `/sbin/init_sh`: the interpreter for `/etc/rc`, `/etc/rc.shutdown` and `/etc/rc.d/*` -- POSIX
//! sh plus the init dialect (INIT_SH.md in OxideBSD-doc). Never interactive (§3.2).

fn main() {
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(libsh::main_with(args, libsh::Interactive::Refuse));
}
