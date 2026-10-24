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

// nativeHandle owns one registry handle. Operations hold the read lock for the
// whole native call, so free (write lock) waits until in-flight calls return
// and the handle is never released while Rust is using it.
type nativeHandle struct {
	mu        sync.RWMutex
	handle    C.TssHandle
	isSession bool
}

func newNativeHandle(handle C.TssHandle) *nativeHandle {
	return &nativeHandle{handle: handle}
}

func newSessionNativeHandle(handle C.TssHandle) *nativeHandle {
	return &nativeHandle{handle: handle, isSession: true}
}

// use runs fn with the live handle while holding the read lock.
func (h *nativeHandle) use(fn func(C.TssHandle) error) error {
	if h == nil {
		return invalidLocalHandle()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.handle == 0 {
		return invalidLocalHandle()
	}
	handle := h.handle
	afterHandleRead()
	return fn(handle)
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

// use runs fn with the live native handle. h stays reachable until fn
// returns, so its finalizer cannot release the handle during the call.
func (h *KeyShareHandle) use(fn func(C.TssHandle) error) error {
	if h == nil {
		return invalidLocalHandle()
	}
	err := h.native.use(fn)
	runtime.KeepAlive(h)
	return err
}

func (h *KeyShareHandle) Identifier() (Identifier, error) {
	var out C.uint16_t
	if err := h.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_identifier(handle, &out)
		})
	}); err != nil {
		return 0, err
	}
	return Identifier(out), nil
}

func (h *KeyShareHandle) VerifyingShare() ([]byte, error) {
	var out C.struct_TssBuffer
	if err := h.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_verifying_share(handle, &out)
		})
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func (h *KeyShareHandle) GroupKey() ([]byte, error) {
	var out C.struct_TssBuffer
	if err := h.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_group_key(handle, &out)
		})
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

// ChainCode returns the 32-byte BIP-32 chain code this share derives children
// with. Pair it with GroupKey to build a BIP-32 xpub whose off-MPC pubkey
// derivation matches the child shares each party derives via DeriveChild /
// DerivePath. For Secp256k1Taproot the chain code is SHA-256 of the group key
// and is re-derived for each child, so an external CKDpub matches only at
// depth 1.
//
// Supported for the BIP-32-capable ciphersuites only (Secp256k1ECDSA,
// Secp256r1ECDSA, Secp256k1Taproot); every other suite returns a *TssError
// with the protocol-mismatch code.
func (h *KeyShareHandle) ChainCode() ([]byte, error) {
	var out C.struct_TssBuffer
	if err := h.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_chain_code(handle, &out)
		})
	}); err != nil {
		return nil, err
	}
	return bufferToBytes(&out), nil
}

func (h *KeyShareHandle) PublicKeyPackage() (PublicKeyPackage, error) {
	var out C.struct_TssBuffer
	if err := h.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_pubkey_package(handle, &out)
		})
	}); err != nil {
		return PublicKeyPackage{}, err
	}
	return decodePublicKeyPackage(bufferToBytes(&out))
}

func (h *KeyShareHandle) Ciphersuite() (Ciphersuite, error) {
	var suite C.uint8_t
	if err := h.use(func(handle C.TssHandle) error {
		suite = C.tss_handle_ciphersuite(handle)
		if suite == 255 {
			return invalidLocalHandle()
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return Ciphersuite(suite), nil
}

// ExportKeyShare exports the key share as a serialized byte blob.
//
// The returned bytes contain unencrypted secret key material in
// GC-managed memory. For production use, prefer ExportKeyShareSecure
// which keeps the data in mlock'd memory outside the GC heap.
func ExportKeyShare(keyShare *KeyShareHandle) ([]byte, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	var out C.struct_TssBuffer
	if err := keyShare.use(func(handle C.TssHandle) error {
		return callStatus(func() C.TssStatus {
			return C.tss_handle_export(handle, &out)
		})
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
	out, err := ImportKeyShare(suite, secure.Bytes())
	runtime.KeepAlive(secure)
	return out, err
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
