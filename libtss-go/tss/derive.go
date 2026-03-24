package tss

/*
#include <stdlib.h>
#include "tss_ffi.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// DeriveChild derives a child key share using non-hardened BIP-32 derivation.
//
// Supports Secp256k1ECDSA (DKLs23), Secp256r1ECDSA (DKLs23), and
// Secp256k1Taproot (FROST). Returns an error for unsupported ciphersuites.
//
// The original key share remains valid; the returned handle is a new key share.
func DeriveChild(keyShare *KeyShareHandle, childNumber uint32) (*KeyShareHandle, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	if childNumber >= 1<<31 {
		return nil, fmt.Errorf("childNumber must be less than 2^31 (non-hardened)")
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_derive_child(handle, C.uint32_t(childNumber), &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

// DerivePath derives a key share along a BIP-32 path (e.g. "m/44/60/0/0").
//
// Hardened segments (e.g. "m/44'/0'") are rejected. The original key share
// remains valid; the returned handle is a new key share.
func DerivePath(keyShare *KeyShareHandle, path string) (*KeyShareHandle, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	if strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("path must not contain NUL bytes")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_derive_path(handle, cPath, &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}
