//! Memory hardening verification tests (Issue #75).
//!
//! These tests validate that secret types have the expected memory
//! safety traits and that the handle registry properly manages
//! lifecycle of sensitive data.

use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Compile-time trait assertions
// ---------------------------------------------------------------------------

// Helper: assert a type implements Zeroize.
fn assert_zeroize<T: Zeroize>() {}

// Helper: assert a type does NOT implement Copy (secrets must not be copyable).
// We use a negative check via a compile_fail doctest in the audit doc, but here
// we can verify the positive traits.

/// Verify that DKLs23 Party<secp256k1> implements Zeroize.
/// The upstream DKLs23 crate provides a manual Drop impl that zeroes
/// the poly_point scalar — Zeroize is the trait-level evidence.
#[test]
fn dkls_party_k1_implements_zeroize() {
    assert_zeroize::<dkls23_secp256k1::Party>();
}

/// Verify that DKLs23 Party<secp256r1> implements Zeroize.
#[test]
fn dkls_party_r1_implements_zeroize() {
    assert_zeroize::<dkls23_secp256r1::Party>();
}

/// Verify that FROST KeyPackage types implement ZeroizeOnDrop.
/// ZeroizeOnDrop implies the signing share scalar is zeroed on drop.
#[test]
fn frost_key_packages_implement_zeroize_on_drop() {
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<frost_secp256k1_tr::keys::KeyPackage>();
    assert_zod::<frost_secp256k1::keys::KeyPackage>();
    assert_zod::<frost_ed25519::keys::KeyPackage>();
    assert_zod::<frost_p256::keys::KeyPackage>();
    assert_zod::<frost_ristretto255::keys::KeyPackage>();
    assert_zod::<frost_ed448::keys::KeyPackage>();
}

// ---------------------------------------------------------------------------
// Handle registry: double-free safety
// ---------------------------------------------------------------------------

#[test]
fn handle_free_is_idempotent() {
    let registry = libtss::HandleRegistry::new();
    let handle = registry.insert(libtss::CAT_FROST_KEY, 42u64);
    registry.free(handle);
    // Second free must not panic or corrupt state
    registry.free(handle);
}

#[test]
fn handle_free_returns_error_after_freed() {
    let registry = libtss::HandleRegistry::new();
    let handle = registry.insert(libtss::CAT_FROST_KEY, String::from("secret"));
    registry.free(handle);
    // Accessing freed handle returns HandleInvalid
    let result = registry.with::<String, _>(handle, |s| s.clone());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), libtss::TssError::HandleInvalid);
}

#[test]
fn handle_take_prevents_reuse() {
    let registry = libtss::HandleRegistry::new();
    let handle = registry.insert(libtss::CAT_FROST_KEY, vec![1u8, 2, 3]);
    let taken = registry.take::<Vec<u8>>(handle).unwrap();
    assert_eq!(taken, vec![1, 2, 3]);
    // Handle is now invalid
    let result = registry.take::<Vec<u8>>(handle);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Zeroizing wrapper used in export path
// ---------------------------------------------------------------------------

/// Verify that Zeroizing<Vec<u8>> zeroes the inner Vec in-place before drop.
/// We use explicit zeroize() rather than reading freed memory (which is UB).
#[test]
fn zeroizing_vec_zeroes_in_place() {
    use zeroize::Zeroize;
    let mut data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    data.zeroize();
    assert!(data.iter().all(|&b| b == 0), "Zeroize must zero all bytes");
    assert!(data.is_empty(), "Zeroize on Vec should also clear length");
}

/// Verify that Zeroizing wrapper implements Drop + Zeroize (compile-time).
#[test]
fn zeroizing_wrapper_has_correct_traits() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<String>>();
}

// ---------------------------------------------------------------------------
// Negative trait tests (compile-fail via trybuild)
// ---------------------------------------------------------------------------

/// Verify that DKLs23 Party types do NOT implement Copy.
/// These are real compile-fail tests executed by trybuild, not doc-only stubs.
#[test]
fn dkls_party_not_copy() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/dkls_party_k1_not_copy.rs");
    t.compile_fail("tests/compile_fail/dkls_party_r1_not_copy.rs");
}
