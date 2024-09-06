#[cfg(test)]
mod tests {
    use crate::tss::dkg;
    use crate::connections;
    use ffi_tss::protocols::Parameters;

    #[test]
    pub fn test_dkg() {
        let HOST = "https://alpha-docs.bealore.com";
        let BASE_PATH = "/v1/dkls23/keygen/";
        let dkg_phases_endpoints = [
            base_path + "phase1",
            base_path + "phase2",
            base_path + "phase3",
            base_path + "phase4"
        ];

        let API_KEY = "";
        let client = connections::new_client(HOST, API_KEY);
        let threshold = 2;
        let share_count = 2;

        dkg(Curve::ECDSA, client, dkg_phases_endpoints, threshold, share_count);
    }
}