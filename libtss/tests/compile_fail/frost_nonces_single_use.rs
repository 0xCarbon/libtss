// FROST signing nonces are consumed by `frost_sign` and cannot be reused.
use libtss::frost::{frost_commit, frost_generate_with_dealer, frost_sign};
use libtss::{Ciphersuite, ThresholdConfig};

fn main() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (shares, _) = frost_generate_with_dealer(&config).unwrap();
    let (nonces, commitment) = frost_commit(&shares[0]).unwrap();
    let commitments = vec![commitment];
    let _ = frost_sign(&shares[0], nonces, &commitments, b"first");
    let _ = frost_sign(&shares[0], nonces, &commitments, b"second");
}
