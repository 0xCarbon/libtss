package tss

/*
#include "tss_ffi.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const tweakScalarLen = 32

// TweakAdd returns a new key share whose secret is secret + tweak (mod n).
//
// tweak is a 32-byte big-endian scalar, reduced mod n, matching LND's
// per-commitment single tweak. The public key, derivation data, address and
// every verifying share move by the same tweak, so a threshold set of tweaked
// shares signs under the tweaked group key. Supported for Secp256k1ECDSA and
// Secp256r1ECDSA (DKLs23); other ciphersuites return a *TssError with the
// protocol-mismatch code. The original key share remains valid.
func TweakAdd(keyShare *KeyShareHandle, tweak []byte) (*KeyShareHandle, error) {
	return applyTweak(keyShare, tweak, true)
}

// TweakMul returns a new key share whose secret is secret * factor (mod n).
//
// factor is a 32-byte big-endian scalar, reduced mod n; it is the building
// block of LND's revocation (double) tweak. A factor that reduces to zero is
// rejected with a *TssError carrying the tweak error code. Ciphersuite support
// matches TweakAdd.
func TweakMul(keyShare *KeyShareHandle, factor []byte) (*KeyShareHandle, error) {
	return applyTweak(keyShare, factor, false)
}

func applyTweak(keyShare *KeyShareHandle, scalar []byte, add bool) (*KeyShareHandle, error) {
	if keyShare == nil {
		return nil, fmt.Errorf("keyShare is nil")
	}
	if len(scalar) != tweakScalarLen {
		return nil, fmt.Errorf("tweak must be %d bytes, got %d", tweakScalarLen, len(scalar))
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	ptr := (*C.uint8_t)(unsafe.Pointer(&scalar[0]))
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		if add {
			return C.tss_tweak_add(handle, ptr, C.uintptr_t(len(scalar)), &out)
		}

		return C.tss_tweak_mul(handle, ptr, C.uintptr_t(len(scalar)), &out)
	}); err != nil {
		return nil, err
	}

	return newKeyShareHandle(out), nil
}
