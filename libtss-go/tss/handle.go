package tss

/*
#include "tss_ffi.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type nativeHandle struct {
	mu        sync.Mutex
	handle    C.TssHandle
	isSession bool
}

func newNativeHandle(handle C.TssHandle) *nativeHandle {
	return &nativeHandle{handle: handle}
}

func newSessionNativeHandle(handle C.TssHandle) *nativeHandle {
	return &nativeHandle{handle: handle, isSession: true}
}

func (h *nativeHandle) value() (C.TssHandle, error) {
	if h == nil {
		return 0, invalidLocalHandle()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle == 0 {
		return 0, invalidLocalHandle()
	}
	return h.handle, nil
}

func (h *nativeHandle) free() {
	if h == nil {
		return
	}
	h.mu.Lock()
	handle := h.handle
	isSession := h.isSession
	h.handle = 0
	h.mu.Unlock()
	if handle != 0 {
		if isSession {
			C.tss_session_free(handle)
		} else {
			C.tss_handle_free(handle)
		}
	}
}

type KeyShareHandle struct {
	native *nativeHandle
}

func newKeyShareHandle(handle C.TssHandle) *KeyShareHandle {
	out := &KeyShareHandle{native: newNativeHandle(handle)}
	runtime.SetFinalizer(out, func(h *KeyShareHandle) {
		h.Free()
	})
	return out
}

func (h *KeyShareHandle) Free() {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	h.native.free()
}

func (h *KeyShareHandle) Identifier() (Identifier, error) {
	handle, err := h.native.value()
	if err != nil {
		return 0, err
	}
	var out C.uint16_t
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_identifier(handle, &out)
	}); err != nil {
		return 0, err
	}
	return Identifier(out), nil
}

func (h *KeyShareHandle) VerifyingShare() ([]byte, error) {
	handle, err := h.native.value()
	if err != nil {
		return nil, err
	}
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_verifying_share(handle, &out)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func (h *KeyShareHandle) GroupKey() ([]byte, error) {
	handle, err := h.native.value()
	if err != nil {
		return nil, err
	}
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_group_key(handle, &out)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func (h *KeyShareHandle) PublicKeyPackage() (PublicKeyPackage, error) {
	handle, err := h.native.value()
	if err != nil {
		return PublicKeyPackage{}, err
	}
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_pubkey_package(handle, &out)
	}); err != nil {
		return PublicKeyPackage{}, err
	}
	return decodePublicKeyPackage(bufferToBytes(&out))
}

func (h *KeyShareHandle) Ciphersuite() (Ciphersuite, error) {
	handle, err := h.native.value()
	if err != nil {
		return 0, err
	}
	suite := C.tss_handle_ciphersuite(handle)
	if suite == 255 {
		return 0, invalidLocalHandle()
	}
	return Ciphersuite(suite), nil
}

// ExportKeyShare exports the key share as a serialized byte blob.
//
// The returned bytes contain unencrypted secret key material in
// GC-managed memory. For production use, prefer ExportKeyShareSecure
// which keeps the data in mlock'd memory outside the GC heap.
func ExportKeyShare(keyShare *KeyShareHandle) ([]byte, error) {
	if keyShare == nil {
		return nil, fmt.Errorf("keyShare is nil")
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var out C.struct_TssBuffer
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_export(handle, &out)
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

// ExportKeyShareSecure exports the key share into a SecureBytes
// backed by mlock'd memory. The GC-heap copy is wiped immediately.
func ExportKeyShareSecure(keyShare *KeyShareHandle) (*SecureBytes, error) {
	data, err := ExportKeyShare(keyShare)
	if err != nil {
		return nil, err
	}
	return NewSecureBytes(data), nil
}

// ImportKeyShareSecure imports a key share from SecureBytes (locked memory).
func ImportKeyShareSecure(suite Ciphersuite, secure *SecureBytes) (*KeyShareHandle, error) {
	if secure == nil {
		return nil, fmt.Errorf("secure is nil")
	}
	return ImportKeyShare(suite, secure.Bytes())
}

func ImportKeyShare(suite Ciphersuite, data []byte) (*KeyShareHandle, error) {
	var out C.TssHandle
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	if err := callStatus(func() C.TssStatus {
		return C.tss_handle_import(dataPtr, C.uintptr_t(len(data)), C.uint8_t(suite), &out)
	}); err != nil {
		return nil, err
	}
	return newKeyShareHandle(out), nil
}
