use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set");

    cbindgen::generate(&crate_dir)
        .expect("Unable to generate C bindings")
        .write_to_file("libtss.h");
}
