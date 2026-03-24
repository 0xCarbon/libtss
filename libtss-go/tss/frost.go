package tss

/*
#include <stdlib.h>
#include <string.h>
#include "tss_ffi.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

func FrostAggregate(suite Ciphersuite, message, commitments, shares, pubkeyPackage []byte) ([]byte, error) {
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_aggregate(
			C.uint8_t(suite),
			bytesToSlice(message),
			bytesToSlice(commitments),
			bytesToSlice(shares),
			bytesToSlice(pubkeyPackage),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func FrostTweakKeyShare(keyShare *KeyShareHandle, merkleRoot []byte) (*KeyShareHandle, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var mrPtr *C.uint8_t
	var mrLen C.uintptr_t
	if len(merkleRoot) > 0 {
		mrPtr = (*C.uint8_t)(unsafe.Pointer(&merkleRoot[0]))
		mrLen = C.uintptr_t(len(merkleRoot))
	}
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_tweak_key_share(handle, mrPtr, mrLen, &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

func FrostTweakPubkeyPackage(pubkeyPackage, merkleRoot []byte) ([]byte, error) {
	var mrPtr *C.uint8_t
	var mrLen C.uintptr_t
	if len(merkleRoot) > 0 {
		mrPtr = (*C.uint8_t)(unsafe.Pointer(&merkleRoot[0]))
		mrLen = C.uintptr_t(len(merkleRoot))
	}
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_tweak_pubkey_package(bytesToSlice(pubkeyPackage), mrPtr, mrLen, &out)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func FrostGenerateDealer(suite Ciphersuite, maxSigners, minSigners uint16) ([]*KeyShareHandle, []byte, error) {
	if maxSigners == 0 {
		return nil, nil, fmt.Errorf("maxSigners must be > 0")
	}
	handles := make([]C.TssHandle, maxSigners)
	var handleCount C.uintptr_t
	var outPkg C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_generate_dealer(
			C.uint8_t(suite),
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

// FrostSplitKey splits a secret key into threshold key shares.
//
// The secretKey slice is wiped after the call completes (success or error).
func FrostSplitKey(suite Ciphersuite, secretKey []byte, maxSigners, minSigners uint16) ([]*KeyShareHandle, []byte, error) {
	defer WipeBytes(secretKey)
	if maxSigners == 0 {
		return nil, nil, fmt.Errorf("maxSigners must be > 0")
	}
	handles := make([]C.TssHandle, maxSigners)
	var handleCount C.uintptr_t
	var outPkg C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_split_key(
			C.uint8_t(suite),
			bytesToSlice(secretKey),
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

func FrostRefreshDealer(pubkeyPackage []byte, participants []Identifier) (map[Identifier][]byte, []byte, error) {
	var pPtr *C.uint16_t
	if len(participants) > 0 {
		pPtr = (*C.uint16_t)(unsafe.Pointer(&participants[0]))
	}
	var outShares C.struct_TssBuffer
	var shareCount C.uintptr_t
	var outPkg C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_refresh_dealer(
			bytesToSlice(pubkeyPackage),
			pPtr,
			C.uintptr_t(len(participants)),
			&outShares,
			&shareCount,
			&outPkg,
		)
	}); err != nil {
		return nil, nil, err
	}
	blob := bufferToBytes(&outShares)
	defer WipeBytes(blob)
	shareMap, err := parseTLVBlobs(blob, int(shareCount))
	if err != nil {
		return nil, nil, err
	}
	return shareMap, bufferToBytes(&outPkg), nil
}

func FrostApplyRefresh(keyShare *KeyShareHandle, refreshData, pubkeyPackage []byte) (*KeyShareHandle, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_apply_refresh(handle, bytesToSlice(refreshData), bytesToSlice(pubkeyPackage), &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

func FrostRepairPart1(keyShare *KeyShareHandle, helpers []Identifier, participant Identifier) (map[Identifier][]byte, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var hPtr *C.uint16_t
	if len(helpers) > 0 {
		hPtr = (*C.uint16_t)(unsafe.Pointer(&helpers[0]))
	}
	var outDeltas C.struct_TssBuffer
	var deltaCount C.uintptr_t
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_repair_part1(
			handle,
			hPtr,
			C.uintptr_t(len(helpers)),
			C.uint16_t(participant),
			&outDeltas,
			&deltaCount,
		)
	}); err != nil {
		return nil, err
	}
	blob := bufferToBytes(&outDeltas)
	return parseTLVBlobs(blob, int(deltaCount))
}

func FrostRepairPart2(suite Ciphersuite, deltas [][]byte) ([]byte, error) {
	if len(deltas) == 0 {
		return nil, fmt.Errorf("deltas must not be empty")
	}
	cSlices, cleanup := buildCSliceArray(deltas)
	defer cleanup()
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_repair_part2(
			C.uint8_t(suite),
			cSlices,
			C.uintptr_t(len(deltas)),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func FrostRepairPart3(sigmas [][]byte, participant Identifier, pubkeyPackage []byte) (*KeyShareHandle, error) {
	if len(sigmas) == 0 {
		return nil, fmt.Errorf("sigmas must not be empty")
	}
	cSlices, cleanup := buildCSliceArray(sigmas)
	defer cleanup()
	var out C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_frost_repair_part3(
			cSlices,
			C.uintptr_t(len(sigmas)),
			C.uint16_t(participant),
			bytesToSlice(pubkeyPackage),
			&out,
		)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}

// buildCSliceArray copies Go byte slices into C-allocated memory and returns
// a C array of TssSlice. This avoids cgo's "Go pointer to Go pointer" restriction.
func buildCSliceArray(data [][]byte) (*C.struct_TssSlice, func()) {
	n := len(data)
	mem := C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.struct_TssSlice{})))
	arr := unsafe.Slice((*C.struct_TssSlice)(mem), n)
	cPtrs := make([]unsafe.Pointer, n)
	for i, d := range data {
		if len(d) > 0 {
			cPtrs[i] = C.CBytes(d)
			arr[i] = C.struct_TssSlice{
				data: (*C.uint8_t)(cPtrs[i]),
				len:  C.uintptr_t(len(d)),
			}
		}
	}
	cleanup := func() {
		for i, p := range cPtrs {
			if p != nil {
				C.memset(p, 0, C.size_t(len(data[i])))
				C.free(p)
			}
		}
		C.free(mem)
	}
	return (*C.struct_TssSlice)(mem), cleanup
}

func parseTLVBlobs(data []byte, count int) (map[Identifier][]byte, error) {
	result := make(map[Identifier][]byte, count)
	pos := 0
	for i := 0; i < count; i++ {
		if pos+6 > len(data) {
			return nil, fmt.Errorf("truncated TLV entry at index %d", i)
		}
		id := Identifier(binary.LittleEndian.Uint16(data[pos:]))
		blobLen := int(binary.LittleEndian.Uint32(data[pos+2:]))
		pos += 6
		if pos+blobLen > len(data) {
			return nil, fmt.Errorf("truncated TLV data at index %d", i)
		}
		result[id] = append([]byte(nil), data[pos:pos+blobLen]...)
		pos += blobLen
	}
	return result, nil
}
