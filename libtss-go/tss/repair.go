package tss

/*
#include "tss_ffi.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// RepairHelperTerm computes this party's masked repair term for the lost
// share of target.
//
// helpers is the full helper set (this party included, target excluded) and
// every helper must pass the identical set and sessionID, or the pairwise
// masks do not cancel and RepairAssemble fails closed. The returned 32-byte
// scalar is meant for the target only; no proper subset of the helpers' terms
// reveals anything about the lost share. A hollow share (repaired but not
// yet refreshed) is refused with the invalid-share code rather than emitting
// an unmasked term.
func RepairHelperTerm(keyShare *KeyShareHandle, helpers []Identifier, target Identifier, sessionID []byte) ([]byte, error) {
	if keyShare == nil {
		return nil, fmt.Errorf("keyShare is nil")
	}
	if len(helpers) == 0 {
		return nil, fmt.Errorf("helpers must not be empty")
	}
	if len(sessionID) == 0 {
		return nil, fmt.Errorf("sessionID must not be empty")
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	helpersPtr := (*C.uint16_t)(unsafe.Pointer(&helpers[0]))
	sidPtr := (*C.uint8_t)(unsafe.Pointer(&sessionID[0]))
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_repair_helper_term(
			handle,
			helpersPtr,
			C.uintptr_t(len(helpers)),
			C.uint16_t(target),
			sidPtr,
			C.uintptr_t(len(sessionID)),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

// RepairAssemble rebuilds the lost share of target from the helpers' terms
// as a hollow key share.
//
// pubkeyPackage is the serialized group package (KeyShareHandle.PublicKeyPackageBytes)
// and chainCode the 32-byte BIP-32 chain code, as every helper reports them;
// terms holds at least the threshold number of RepairHelperTerm outputs. The
// sum of the terms is checked against the target's verifying share and a
// mismatch fails with the invalid-share code without creating a handle. The
// result derives addresses and refreshes but cannot sign until a complete
// refresh (NewRefreshSessionDKLs) has run across the whole group.
func RepairAssemble(suite Ciphersuite, pubkeyPackage, chainCode []byte, target Identifier, terms [][]byte, sessionID []byte) (*KeyShareHandle, error) {
	if len(terms) == 0 {
		return nil, fmt.Errorf("terms must not be empty")
	}
	if len(sessionID) == 0 {
		return nil, fmt.Errorf("sessionID must not be empty")
	}
	cSlices, cleanup := buildCSliceArray(terms)
	defer cleanup()
	sidPtr := (*C.uint8_t)(unsafe.Pointer(&sessionID[0]))
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_repair_assemble(
			C.uint8_t(suite),
			bytesToSlice(pubkeyPackage),
			bytesToSlice(chainCode),
			C.uint16_t(target),
			cSlices,
			C.uintptr_t(len(terms)),
			sidPtr,
			C.uintptr_t(len(sessionID)),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}
