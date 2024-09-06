#[cfg(test)]
mod tests {
    use crate::dkls23::sign_testdatagen;
    use crate::utils::files::read_from_file;
    use crate::utils::hash::sha256_str;
    use ffi_tss::dkls23::protocols::signing::VerifyOut;
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    pub fn test_dkls_sign() {
        let out_dir = PathBuf::from(&env::var("OUT_DIR").unwrap());

        let dkls_sign_input_filename = "dkls_sign_inputs.txt";
        let dkls_sign_out_hashes_filename = "dkls_sign_out_hashes.txt";
        let dkls_sign_ffi_outputs_filename = "dkls_sign_ffi_outputs.txt";
        let bin_name = "ffi_tss_client";

        let in_path = out_dir.join(dkls_sign_input_filename);
        let out_path = out_dir.join(dkls_sign_out_hashes_filename);
        let ffi_out_path = out_dir.join(dkls_sign_ffi_outputs_filename);
        let bin_path = out_dir.join(bin_name);

        // Search for dkg data file. If not exists, we run DKLs23 in insecure mode and save the output
        // of each phase as SHA-256 hashes and we save the inputs of each as json strings.
        if !in_path.exists() || !out_path.exists() {
            println!("DKLs23::Running sign on deterministic mode...");
            sign_testdatagen::sign_input_gen(
                in_path.to_str().unwrap(),
                out_path.to_str().unwrap(),
            );
        } else {
            println!("DKLs23::sign data cached");
        }

        // run the C program
        println!("DKLs23::Running sign on c-client using FFI TSS lib");
        let mut command = Command::new(bin_path.to_str().unwrap());
        command.env("LD_LIBRARY_PATH", out_dir.to_str().unwrap());
        command.arg("sign");
        command.arg(in_path.to_str().unwrap());
        command.arg(ffi_out_path.to_str().unwrap());
        let _ = match command.output() {
            Ok(output) => output,
            Err(e) => {
                panic!("DKLs23::Failed to run sign on c-client {}", e);
            }
        };

        let expected_hashes = read_from_file(out_path.to_str().unwrap());
        let lines = read_from_file(ffi_out_path.to_str().unwrap());
        let obtained_hashes: Vec<String> =
            lines.iter().map(|l| sha256_str(l)).collect();

        println!("DKLs23::Validating Signing:");
        assert_eq!(obtained_hashes.len(), expected_hashes.len());
        for i in 0..obtained_hashes.len() {
            assert_eq!(obtained_hashes[i], expected_hashes[i]);
            println!("DKLs23::Sign Phase {}: Passed!", i + 1);
        }
    }

    #[test]
    pub fn test_dkls_verify_ecdsa_signature() {
        let out_dir = PathBuf::from(&env::var("OUT_DIR").unwrap());
        let dkls_sign_input_filename = "dkls_sign_inputs.txt";
        let dkls_sign_out_hashes_filename = "dkls_sign_out_hashes.txt";
        let dkls_verify_ffi_output_filename = "dkls_verify_ffi_output.txt";
        let dkls_verify_input_filename = "dkls_verify_input.txt";
        let bin_name = "ffi_tss_client";

        let in_path = out_dir.join(dkls_sign_input_filename);
        let out_path = out_dir.join(dkls_sign_out_hashes_filename);
        let ffi_out_path = out_dir.join(dkls_verify_ffi_output_filename);
        let verify_in_path = out_dir.join(dkls_verify_input_filename);
        let bin_path = out_dir.join(bin_name);

        // Search for dkg data file. If not exists, we run DKLs23 in insecure mode and save the output
        // of each phase as SHA-256 hashes and we save the inputs of each as json strings.
        if !in_path.exists() || !out_path.exists() {
            println!("DKLs23::Running sign on deterministic mode...");
            sign_testdatagen::sign_input_gen(
                in_path.to_str().unwrap(),
                out_path.to_str().unwrap(),
            );
        } else {
            println!("DKLs23::sign input data cached");
        }

        if !verify_in_path.exists() {
            println!("DKLs23::Generating ECDSA verify signature input data from sign phase 4...");
            sign_testdatagen::verify_ecdsa_signature_input_gen(
                in_path.to_str().unwrap(), // sign inputs that will be parsed. Only the 4th line is used
                verify_in_path.to_str().unwrap(),
            );
        } else {
            println!("DKLs23::verify input data cached");
        }

        // run the C program
        println!("DKLs23::Running verify ECDSA signature on c-client using FFI TSS lib");
        let mut command = Command::new(bin_path.to_str().unwrap());
        command.env("LD_LIBRARY_PATH", out_dir.to_str().unwrap());
        command.arg("verify");
        command.arg(verify_in_path.to_str().unwrap());
        command.arg(ffi_out_path.to_str().unwrap());
        let _ = match command.output() {
            Ok(output) => output,
            Err(e) => {
                panic!("DKLs23::Failed to run verify on c-client {}", e);
            }
        };

        let verify_out_str = read_from_file(ffi_out_path.to_str().unwrap());
        let verify_out: VerifyOut =
            serde_json::from_str(&verify_out_str[0]).unwrap();
        assert!(verify_out.valid);
        println!("DKLs23::Verify ECDSA signature: Passaed!");
    }
}
