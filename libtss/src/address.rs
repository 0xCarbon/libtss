use crate::keyshare;
use crate::types::Ciphersuite;
use crate::TssError;

/// Extract the Ethereum address from a DKLs23 secp256k1 key share.
///
/// Returns the checksummed hex address (e.g. "0x...").
/// Only valid for Secp256k1ECDSA ciphersuite.
pub fn ethereum_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(party.address.clone())
}

/// Extract the Bitcoin P2WPKH address from a DKLs23 secp256k1 key share.
///
/// Returns a Bech32 segwit v0 address (e.g. "bc1q...").
pub fn bitcoin_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(dkls23_secp256k1::compute_btc_address(&party.pk))
}

/// Extract the Bitcoin P2WPKH address with a custom HRP from a DKLs23 secp256k1 key share.
///
/// Use "bc" for mainnet, "tb" for testnet, "ltc" for Litecoin mainnet.
pub fn bitcoin_address_hrp(
    key_share: &keyshare::KeyShareHandle,
    hrp: &str,
) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(dkls23_secp256k1::compute_btc_address_with_hrp(
        &party.pk, hrp,
    ))
}

/// Extract the Cosmos address from a DKLs23 secp256k1 key share.
///
/// Returns a Bech32 address with "cosmos" HRP (e.g. "cosmos1...").
pub fn cosmos_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(dkls23_secp256k1::compute_cosmos_address(&party.pk))
}

/// Extract the Cosmos address with a custom HRP from a DKLs23 secp256k1 key share.
///
/// Use "osmo" for Osmosis, "juno" for Juno, etc.
pub fn cosmos_address_hrp(
    key_share: &keyshare::KeyShareHandle,
    hrp: &str,
) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(dkls23_secp256k1::compute_cosmos_address_with_hrp(
        &party.pk, hrp,
    ))
}

/// Extract the TRON address from a DKLs23 secp256k1 key share.
///
/// Returns a Base58Check address starting with 'T'.
pub fn tron_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_party(key_share)?;
    Ok(dkls23_secp256k1::compute_tron_address(&party.pk))
}

/// Extract the NEO3 address from a DKLs23 secp256r1 key share.
///
/// Returns a Base58Check address starting with 'N'.
pub fn neo3_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256r1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_r1_party(key_share)?;
    Ok(party.address.clone())
}

/// Extract the Sui secp256r1 address from a DKLs23 secp256r1 key share.
///
/// Returns a 0x-prefixed hex address.
pub fn sui_r1_address(key_share: &keyshare::KeyShareHandle) -> Result<String, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256r1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    let party = keyshare::clone_dkls_r1_party(key_share)?;
    Ok(dkls23_secp256r1::compute_sui_address(&party.pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::derive_child;
    use dkls23_secp256k1::protocols::re_key::re_key;
    use dkls23_secp256k1::protocols::Parameters;

    fn dkls_handle() -> keyshare::KeyShareHandle {
        let parameters = Parameters::new(2, 3).unwrap();
        let secret = k256::Scalar::from(15u64);
        let (parties, pubkeys) = re_key(
            &parameters,
            b"session",
            &secret,
            Some([3u8; 32]),
            dkls23_secp256k1::compute_eth_address,
        );

        keyshare::from_dkls_dkg(parties[0].clone(), pubkeys).unwrap()
    }

    fn dkls_r1_handle() -> keyshare::KeyShareHandle {
        let parameters = Parameters::new(2, 3).unwrap();
        let secret = p256::Scalar::from(15u64);
        let (parties, pubkeys) = dkls23_secp256r1::protocols::re_key::re_key(
            &parameters,
            b"session",
            &secret,
            Some([3u8; 32]),
            dkls23_secp256r1::compute_neo3_address,
        );

        keyshare::from_dkls_r1_dkg(parties[0].clone(), pubkeys).unwrap()
    }

    #[test]
    fn dkls_share_returns_ethereum_address() {
        let handle = dkls_handle();
        let address = ethereum_address(&handle).unwrap();

        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn dkls_share_returns_bitcoin_address() {
        let handle = dkls_handle();
        let address = bitcoin_address(&handle).unwrap();

        assert!(address.starts_with("bc1q"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn dkls_share_returns_cosmos_address() {
        let handle = dkls_handle();
        let address = cosmos_address(&handle).unwrap();
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn dkls_share_returns_cosmos_custom_hrp() {
        let handle = dkls_handle();
        let address = cosmos_address_hrp(&handle, "osmo").unwrap();
        assert!(address.starts_with("osmo1"));
    }

    #[test]
    fn dkls_share_returns_tron_address() {
        let handle = dkls_handle();
        let address = tron_address(&handle).unwrap();
        assert!(address.starts_with('T'));
        assert_eq!(address.len(), 34);
    }

    #[test]
    fn r1_share_returns_neo3_address() {
        let handle = dkls_r1_handle();
        let address = neo3_address(&handle).unwrap();

        assert!(address.starts_with('N'));
        assert_eq!(address.len(), 34);
    }

    #[test]
    fn r1_share_returns_sui_address() {
        let handle = dkls_r1_handle();
        let address = sui_r1_address(&handle).unwrap();

        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 66);
    }

    #[test]
    fn frost_share_rejected() {
        let config = crate::types::ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (shares, pubkey) = crate::frost::frost_generate_with_dealer(&config).unwrap();
        let handle = keyshare::from_frost_dkg(shares.into_iter().next().unwrap(), &pubkey).unwrap();
        assert!(matches!(
            ethereum_address(&handle),
            Err(TssError::ProtocolMismatch)
        ));
        assert!(matches!(
            neo3_address(&handle),
            Err(TssError::ProtocolMismatch)
        ));
    }

    #[test]
    fn k1_suite_rejected_for_r1_address() {
        let handle = dkls_handle();
        assert!(matches!(
            neo3_address(&handle),
            Err(TssError::ProtocolMismatch)
        ));
    }

    #[test]
    fn r1_suite_rejected_for_k1_address() {
        let handle = dkls_r1_handle();
        assert!(matches!(
            ethereum_address(&handle),
            Err(TssError::ProtocolMismatch)
        ));
    }

    #[test]
    fn derived_child_has_different_address() {
        let handle = dkls_handle();
        let child = derive_child(&handle, 1).unwrap();

        assert_ne!(
            ethereum_address(&handle).unwrap(),
            ethereum_address(&child).unwrap()
        );
    }
}
