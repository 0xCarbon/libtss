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
