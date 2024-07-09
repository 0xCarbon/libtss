#[cfg(test)]
mod tests {
    use crate::dkls23::dkg_testdatagen;
    use crate::utils::files::read_from_file;
    use crate::utils::hash::sha256_str;
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    pub fn test_dkls_dkg() {
        let out_dir = PathBuf::from(&env::var("OUT_DIR").unwrap());

        let dkls_dkg_input_filename = "dkls_dkg_inputs.txt";
        let dkls_dkg_out_hashes_filename = "dkls_dkg_out_hashes.txt";
        let dkls_dkg_ffi_outputs_filename = "dkls_dkg_ffi_outputs.txt";
        let bin_name = "ffi_tss_client";

        let in_path = out_dir.join(dkls_dkg_input_filename);
        let out_path = out_dir.join(dkls_dkg_out_hashes_filename);
        let ffi_out_path = out_dir.join(dkls_dkg_ffi_outputs_filename);
        let bin_path = out_dir.join(bin_name);

        // Search for dkg data file. If not exists, we run DKLs23 in insecure mode and save the output
        // of each phase as SHA-256 hashes and we save the inputs of each as json strings.
        if !in_path.exists() || !out_path.exists() {
            println!("Running DKLs23 on deterministic mode...");
            dkg_testdatagen::dkg_input_gen(
                in_path.to_str().unwrap(),
                out_path.to_str().unwrap(),
            );
        } else {
            println!("DKLs23 data cached");
        }

        // run the C program
        println!("Running DKLs23 client: using FFI TSS lib");
        let mut command = Command::new(bin_path.to_str().unwrap());
        command.env("LD_LIBRARY_PATH", out_dir.to_str().unwrap());
        command.arg(in_path.to_str().unwrap());
        command.arg(ffi_out_path.to_str().unwrap());
        let _ = match command.output() {
            Ok(output) => output,
            Err(e) => {
                panic!("Failed to run DKG client {}", e);
            }
        };

        let expected_hashes = read_from_file(out_path.to_str().unwrap());
        let lines = read_from_file(ffi_out_path.to_str().unwrap());
        let obtained_hashes: Vec<String> =
            lines.iter().map(|l| sha256_str(l)).collect();

        println!("Validating DKLs23 DKG:");
        assert_eq!(obtained_hashes.len(), expected_hashes.len());
        for i in 0..obtained_hashes.len() {
            assert_eq!(obtained_hashes[i], expected_hashes[i]);
            println!("Phase {}: Passed!", i + 1);
        }
    }
}
