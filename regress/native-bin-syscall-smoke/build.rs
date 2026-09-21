fn main() {
    let linker_script = concat!(env!("CARGO_MANIFEST_DIR"), "/linker.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
