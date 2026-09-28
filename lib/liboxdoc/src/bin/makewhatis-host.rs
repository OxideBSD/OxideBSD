//! makewhatis(8) on the host: builds the image's index, and the test trees' (Cargo.toml).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(liboxdoc::makewhatis::main(&args));
}
