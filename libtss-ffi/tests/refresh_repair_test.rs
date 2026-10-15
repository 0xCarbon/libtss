//! FFI-level tests for DKLs23 share repair (tss_repair_helper_term,
//! tss_repair_assemble) and complete refresh (tss_refresh_new_dkls).

mod common;

use libtss_ffi::handles::{
    tss_handle_chain_code, tss_handle_group_key, tss_handle_identifier, tss_handle_pubkey_package,
    tss_handle_verifying_share,
};
use libtss_ffi::memory::tss_handle_free;
use libtss_ffi::repair::{tss_repair_assemble, tss_repair_helper_term};
use libtss_ffi::session::{tss_refresh_new, tss_refresh_new_dkls, tss_sign_new};
use libtss_ffi::tss_verify;
use libtss_ffi::types::*;
use sha2::{Digest, Sha256};

const REPAIR_SID: &[u8] = b"ffi-repair-sid";
const REFRESH_SID: &[u8] = b"ffi-refresh-sid";

fn buffer_of(f: impl FnOnce(*mut TssBuffer) -> TssStatus) -> Vec<u8> {
    let mut buf = TssBuffer::empty();
    assert_eq!(f(&mut buf as *mut TssBuffer), TSS_OK);
    common::take_buffer(&mut buf)
}

fn group_key(handle: TssHandle) -> Vec<u8> {
    buffer_of(|out| tss_handle_group_key(handle, out))
}

fn verifying_share(handle: TssHandle) -> Vec<u8> {
    buffer_of(|out| tss_handle_verifying_share(handle, out))
}

fn chain_code(handle: TssHandle) -> Vec<u8> {
    buffer_of(|out| tss_handle_chain_code(handle, out))
}

fn pubkey_package(handle: TssHandle) -> Vec<u8> {
    buffer_of(|out| tss_handle_pubkey_package(handle, out))
}

fn identifier(handle: TssHandle) -> u16 {
    let mut id = 0u16;
    assert_eq!(tss_handle_identifier(handle, &mut id), TSS_OK);
    id
}

fn helper_term(key: TssHandle, helpers: &[u16], target: u16, sid: &[u8]) -> (TssStatus, Vec<u8>) {
    let mut out = TssBuffer::empty();
    let status = tss_repair_helper_term(
        key,
        helpers.as_ptr(),
        helpers.len(),
        target,
        sid.as_ptr(),
        sid.len(),
        &mut out,
    );
    (status, common::take_buffer(&mut out))
}

fn assemble(
    package: &[u8],
    chain: &[u8],
    target: u16,
    terms: &[Vec<u8>],
    sid: &[u8],
) -> (TssStatus, TssHandle) {
    let slices: Vec<TssSlice> = terms.iter().map(|t| common::slice(t)).collect();
    let mut out: TssHandle = 0;
    let status = tss_repair_assemble(
        common::SUITE_SECP256K1_ECDSA,
        common::slice(package),
        common::slice(chain),
        target,
        slices.as_ptr(),
        slices.len(),
        sid.as_ptr(),
        sid.len(),
        &mut out,
    );
    (status, out)
}

fn repair_terms(keys: &[TssHandle], helpers: &[u16], target: u16, sid: &[u8]) -> Vec<Vec<u8>> {
    helpers
        .iter()
        .map(|helper| {
            let (status, term) = helper_term(keys[usize::from(*helper) - 1], helpers, target, sid);
            assert_eq!(status, TSS_OK, "helper {helper}");
            assert_eq!(term.len(), 32);
            term
        })
        .collect()
}

#[test]
fn repair_then_refresh_signs_via_ffi() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 5, 3);
    let lost = keys[1];
    let expected_share = verifying_share(lost);
    let expected_group_key = group_key(lost);
    let expected_chain_code = chain_code(lost);
    tss_handle_free(lost);

    let helpers = [1u16, 3, 4];
    let terms = repair_terms(&keys, &helpers, 2, REPAIR_SID);
    let (status, hollow) = assemble(
        &pubkey_package(keys[0]),
        &expected_chain_code,
        2,
        &terms,
        REPAIR_SID,
    );
    assert_eq!(status, TSS_OK);
    assert_eq!(identifier(hollow), 2);
    assert_eq!(verifying_share(hollow), expected_share);
    assert_eq!(group_key(hollow), expected_group_key);
    assert_eq!(chain_code(hollow), expected_chain_code);

    let hash = Sha256::digest(b"hollow").to_vec();
    let counterparties = [1u16, 3];
    let mut session = 0;
    let mut messages = TssBuffer::empty();
    assert_eq!(
        tss_sign_new(
            hollow,
            common::slice(&hash),
            counterparties.as_ptr(),
            counterparties.len(),
            REPAIR_SID.as_ptr(),
            REPAIR_SID.len(),
            &mut session,
            &mut messages,
        ),
        TSS_ERR_INVALID_SHARE
    );

    let mut group = keys.clone();
    group[1] = hollow;
    let refreshed = common::run_dkls_refresh(&group, REFRESH_SID);

    for (index, key) in refreshed.iter().enumerate() {
        assert_eq!(identifier(*key), index as u16 + 1);
        assert_eq!(group_key(*key), expected_group_key);
        assert_eq!(chain_code(*key), expected_chain_code);
        assert_ne!(verifying_share(*key), verifying_share(group[index]));
    }

    let message = b"after refresh";
    let hash = Sha256::digest(message).to_vec();
    for quorum in [[1u16, 2, 3], [2, 4, 5]] {
        let signers: Vec<(u16, TssHandle)> = quorum
            .iter()
            .map(|id| (*id, refreshed[usize::from(*id) - 1]))
            .collect();
        let signature = common::run_dkls_sign_ids(&signers, &hash);
        assert!(tss_verify(
            common::SUITE_SECP256K1_ECDSA,
            common::slice(message),
            common::slice(&signature),
            common::slice(&expected_group_key),
        ));
    }

    for key in group.iter().chain(refreshed.iter()) {
        tss_handle_free(*key);
    }
}

#[test]
fn repair_helper_term_rejects_bad_inputs() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 3, 2);

    let (status, _) = helper_term(keys[0], &[1, 3], 3, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "helpers contain target");

    let (status, _) = helper_term(keys[0], &[1], 2, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "too few helpers");

    let (status, _) = helper_term(keys[0], &[1, 3], 2, b"");
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "empty session id");

    let (status, _) = helper_term(keys[0], &[1, 4], 2, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_ID, "helper outside the group");

    let (status, _) = helper_term(keys[0], &[0, 3], 2, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_ID, "zero identifier");

    let (status, _) = helper_term(0, &[1, 3], 2, REPAIR_SID);
    assert_eq!(status, TSS_ERR_HANDLE_INVALID);

    let frost = common::run_dkg(common::SUITE_ED25519, 3, 2);
    let (status, _) = helper_term(frost[0], &[1, 3], 2, REPAIR_SID);
    assert_eq!(status, TSS_ERR_PROTO_MISMATCH);

    for key in keys.iter().chain(frost.iter()) {
        tss_handle_free(*key);
    }
}

#[test]
fn repair_assemble_fails_closed() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 3, 2);
    let package = pubkey_package(keys[0]);
    let chain = chain_code(keys[0]);
    let helpers = [1u16, 3];
    let terms = repair_terms(&keys, &helpers, 2, REPAIR_SID);

    let mut tampered = terms.clone();
    tampered[0][0] ^= 0x01;
    let (status, handle) = assemble(&package, &chain, 2, &tampered, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_SHARE);
    assert_eq!(handle, 0);

    let (status, _) = assemble(&package, &chain, 2, &terms[..1], REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "too few terms");

    let (status, _) = assemble(&package, &chain[..31], 2, &terms, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "short chain code");

    let (status, _) = assemble(&package, &chain, 2, &terms, b"");
    assert_eq!(status, TSS_ERR_INVALID_CONFIG, "empty session id");

    let (status, _) = assemble(&package, &chain, 3, &terms, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_SHARE, "terms for another target");

    let (status, _) = assemble(&package[..package.len() - 1], &chain, 2, &terms, REPAIR_SID);
    assert_eq!(status, TSS_ERR_DESERIALIZE, "truncated package");

    let frost = common::run_dkg(common::SUITE_ED25519, 3, 2);
    let (status, _) = assemble(&pubkey_package(frost[0]), &chain, 2, &terms, REPAIR_SID);
    assert_eq!(status, TSS_ERR_PROTO_MISMATCH);

    let (status, hollow) = assemble(&package, &chain, 2, &terms, REPAIR_SID);
    assert_eq!(status, TSS_OK);
    let (status, _) = helper_term(hollow, &[2, 3], 1, REPAIR_SID);
    assert_eq!(status, TSS_ERR_INVALID_SHARE, "hollow share cannot help");

    tss_handle_free(hollow);
    for key in keys.iter().chain(frost.iter()) {
        tss_handle_free(*key);
    }
}

#[test]
fn refresh_new_dkls_rejects_wrong_inputs() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);
    let mut session = 0;
    let mut messages = TssBuffer::empty();

    assert_eq!(
        tss_refresh_new_dkls(keys[0], std::ptr::null(), 0, &mut session, &mut messages),
        TSS_ERR_INVALID_CONFIG
    );
    assert_eq!(
        tss_refresh_new_dkls(
            0,
            REFRESH_SID.as_ptr(),
            REFRESH_SID.len(),
            &mut session,
            &mut messages
        ),
        TSS_ERR_HANDLE_INVALID
    );
    assert_eq!(
        tss_refresh_new(keys[0], std::ptr::null(), 0, &mut session, &mut messages),
        TSS_ERR_PROTO_MISMATCH,
        "the FROST refresh entry point still refuses DKLs23 shares"
    );

    let frost = common::run_dkg(common::SUITE_ED25519, 3, 2);
    assert_eq!(
        tss_refresh_new_dkls(
            frost[0],
            REFRESH_SID.as_ptr(),
            REFRESH_SID.len(),
            &mut session,
            &mut messages
        ),
        TSS_ERR_PROTO_MISMATCH
    );

    for key in keys.iter().chain(frost.iter()) {
        tss_handle_free(*key);
    }
}
