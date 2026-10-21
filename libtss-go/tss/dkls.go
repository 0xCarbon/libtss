package tss

/*
#include "tss_ffi.h"
*/
import "C"

import "fmt"

// DKLsSplitKey imports an existing ECDSA key as DKLs23 shares (trusted
// dealer). suite is CiphersuiteSecp256k1ECDSA or CiphersuiteSecp256r1ECDSA.
// chainCode is nil (sample a new one) or the key's existing 32-byte BIP-32
// chain code. The group key is the key's own public key.
//
// The caller holds every share: hand each one to its party, erase the key and
// the shares, and have the parties run NewRefreshSessionDKLs before use. The
// secretKey slice is wiped after the call completes (success or error).
func DKLsSplitKey(suite Ciphersuite, secretKey, chainCode []byte, maxSigners, minSigners uint16) ([]*KeyShareHandle, []byte, error) {
	defer WipeBytes(secretKey)
	if maxSigners == 0 {
		return nil, nil, fmt.Errorf("maxSigners must be > 0")
	}
	handles := make([]C.TssHandle, maxSigners)
	var handleCount C.uintptr_t
	var outPkg C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_dkls_split_key(
			C.uint8_t(suite),
			bytesToSlice(secretKey),
			bytesToSlice(chainCode),
			C.uint16_t(maxSigners),
			C.uint16_t(minSigners),
			&handles[0],
			&handleCount,
			&outPkg,
		)
	}); err != nil {
		return nil, nil, err
	}
	count := int(handleCount)
	shares := make([]*KeyShareHandle, count)
	for i := 0; i < count; i++ {
		shares[i] = newKeyShareHandle(handles[i])
	}
	return shares, bufferToBytes(&outPkg), nil
}

// Bolt3Derive derives the BOLT 3 key share for a commitment from a DKLs23
// secp256k1 share: basepoint + SHA256(perCommitmentPoint || basepoint)·G.
// perCommitmentPoint is a 33-byte compressed point; every party derives with
// the same point. The input handle stays valid. A derived share keeps the
// base share's OT state, so a counterparty banned under a derived key is
// banned for the base key too.
func Bolt3Derive(keyShare *KeyShareHandle, perCommitmentPoint []byte) (*KeyShareHandle, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_bolt3_derive(handle, bytesToSlice(perCommitmentPoint), &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

// Bolt3DeriveRevocation derives the BOLT 3 revocation key share for a
// commitment whose 32-byte perCommitmentSecret was revealed. The secret must
// match perCommitmentPoint. The perCommitmentSecret slice is wiped after the
// call completes (success or error).
func Bolt3DeriveRevocation(keyShare *KeyShareHandle, perCommitmentPoint, perCommitmentSecret []byte) (*KeyShareHandle, error) {
	defer WipeBytes(perCommitmentSecret)
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_bolt3_derive_revocation(
			handle,
			bytesToSlice(perCommitmentPoint),
			bytesToSlice(perCommitmentSecret),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

// Bolt3DerivePublicKeys applies Bolt3Derive to a serialized secp256k1 ECDSA
// public key package and returns the derived package.
func Bolt3DerivePublicKeys(pubkeyPackage, perCommitmentPoint []byte) ([]byte, error) {
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_bolt3_derive_pubkey_package(
			bytesToSlice(pubkeyPackage),
			bytesToSlice(perCommitmentPoint),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

// Bolt3DeriveRevocationPublicKeys applies Bolt3DeriveRevocation to a
// serialized secp256k1 ECDSA public key package (no secret needed).
func Bolt3DeriveRevocationPublicKeys(pubkeyPackage, perCommitmentPoint []byte) ([]byte, error) {
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_bolt3_derive_revocation_pubkey_package(
			bytesToSlice(pubkeyPackage),
			bytesToSlice(perCommitmentPoint),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}
