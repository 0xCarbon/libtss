use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Define the path to the C project
    let bin_filename = "ffi_tss_client";
    let lib_filename = "libffi_tss.so";
    let ffi_tss_lib_dir = "../target/release";
    let c_client_dir = "c-client";

    let status = Command::new("make")
        .current_dir(c_client_dir)
        .status()
        .expect("Failed to build");

    if !status.success() {
        panic!("C project build failed");
    }

    let out_dir = env::var("OUT_DIR").unwrap();

    // move the executable to the internal build path
    let mut src_path = PathBuf::from(&c_client_dir).join(bin_filename);
    let mut dest_path = PathBuf::from(&out_dir).join(bin_filename);
    fs::rename(&src_path, &dest_path).expect("Failed to move C executable");

    // copy tss lib to the internal build path
    src_path = PathBuf::from(&ffi_tss_lib_dir).join(lib_filename);
    dest_path = PathBuf::from(&out_dir).join(lib_filename);
    fs::copy(&src_path, &dest_path).expect("Failed to copy TSS lib");
}
