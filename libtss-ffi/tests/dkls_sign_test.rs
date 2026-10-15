//! Exercise ECDSA curve dispatch through the C ABI from DKG through verification.

use libtss::Ciphersuite;
use libtss_ffi::{handles::*, memory::*, session::*, types::*};

struct Buffer(TssBuffer);

impl Buffer {
    fn new() -> Self {
        Self(TssBuffer::empty())
    }

    fn slice(&self) -> TssSlice {
        TssSlice {
            data: self.0.data,
            len: self.0.len,
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        tss_buffer_free(&mut self.0);
    }
}

#[derive(Default)]
struct Party {
    session: TssHandle,
    key: TssHandle,
}

impl Drop for Party {
    fn drop(&mut self) {
        tss_session_free(self.session);
        tss_handle_free(self.key);
    }
}

fn assert_ok(status: TssStatus) {
    assert_eq!(status, TSS_OK, "{}", unsafe {
        std::ffi::CStr::from_ptr(libtss_ffi::error::tss_last_error()).to_string_lossy()
    });
}

fn dkls_sign_roundtrip(suite: Ciphersuite) {
    let mut parties: [Party; 2] = std::array::from_fn(|_| Party::default());
    let mut messages = [Buffer::new(), Buffer::new()];
    let session_id = b"ffi-dkls-dkg";
    for (i, party) in parties.iter_mut().enumerate() {
        assert_ok(tss_dkg_new(
            suite as u8,
            (i + 1) as u16,
            2,
            2,
            session_id.as_ptr(),
            session_id.len(),
            &mut party.session,
            &mut messages[i].0,
        ));
    }

    // With two parties, every outgoing message is for the other party.
    for round in 0..3 {
        let mut next = [Buffer::new(), Buffer::new()];
        for (i, party) in parties.iter_mut().enumerate() {
            let mut public_keys = Buffer::new();
            let mut complete = false;
            assert_ok(tss_dkg_next(
                party.session,
                messages[1 - i].slice(),
                &mut party.key,
                &mut public_keys.0,
                &mut next[i].0,
                &mut complete,
            ));
            assert_eq!(complete, round == 2);
        }
        messages = next;
    }

    let mut group_keys = [Buffer::new(), Buffer::new()];
    for (i, party) in parties.iter().enumerate() {
        assert_ne!(party.key, 0);
        assert_eq!(tss_handle_ciphersuite(party.key), suite as u8);
        assert_ok(tss_handle_group_key(party.key, &mut group_keys[i].0));
    }

    // SHA-256 of the empty message. Signing takes the digest; verification
    // takes the original message and hashes it internally.
    let hash = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    let sign_id = b"ffi-dkls-sign";
    for (i, party) in parties.iter_mut().enumerate() {
        let counterparty = (2 - i) as u16;
        assert_ok(tss_sign_new(
            party.key,
            TssSlice {
                data: hash.as_ptr(),
                len: hash.len(),
            },
            &counterparty,
            1,
            sign_id.as_ptr(),
            sign_id.len(),
            &mut party.session,
            &mut messages[i].0,
        ));
        assert_ne!(party.session, 0);
    }

    for round in 0..3 {
        let mut next = [Buffer::new(), Buffer::new()];
        for (i, party) in parties.iter().enumerate() {
            let mut signature = Buffer::new();
            let mut complete = false;
            assert_ok(tss_sign_next(
                party.session,
                messages[1 - i].slice(),
                &mut signature.0,
                &mut next[i].0,
                &mut complete,
            ));
            assert_eq!(complete, round == 2);
            if complete {
                assert_eq!(signature.0.len, 64);
                for key in &group_keys {
                    assert!(libtss_ffi::tss_verify(
                        suite as u8,
                        TssSlice {
                            data: std::ptr::null(),
                            len: 0,
                        },
                        signature.slice(),
                        key.slice(),
                    ));
                    assert!(!libtss_ffi::tss_verify(
                        suite as u8,
                        TssSlice {
                            data: b"changed".as_ptr(),
                            len: 7,
                        },
                        signature.slice(),
                        key.slice(),
                    ));
                }
                // Signing borrows the share; it must still belong to the caller.
                assert_eq!(tss_handle_ciphersuite(party.key), suite as u8);
            }
        }
        messages = next;
    }
}

#[test]
fn dkls_sign_secp256k1_roundtrip() {
    dkls_sign_roundtrip(Ciphersuite::Secp256k1ECDSA);
}

#[test]
fn dkls_sign_secp256r1_roundtrip() {
    dkls_sign_roundtrip(Ciphersuite::Secp256r1ECDSA);
}
