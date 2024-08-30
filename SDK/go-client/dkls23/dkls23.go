package dkls23

/*
#include <stdlib.h>
#include <stdint.h>

typedef const char* (*ffi_func) ();
const char* bridge_ffi_func(ffi_func fn, const char* data)
{
    return fn(data);
}

// Declare the external Rust function
extern const char* dkls_dkg_phase1(const char* data);
extern const char* dkls_dkg_phase2(const char* data);
extern const char* dkls_dkg_phase3(const char* data);
extern const char* dkls_dkg_phase4(const char* data);

extern const char* dkls_sign_phase1(const char* data);
extern const char* dkls_sign_phase2(const char* data);
extern const char* dkls_sign_phase3(const char* data);
extern const char* dkls_sign_phase4(const char* data);

extern const char* dkls_verify_ecdsa_signature(const char* data);

extern const char* dkls_derive_from_path(const char* data);
extern const char* dkls_party_derive_from_path(const char* data);
extern const char* dkls_derive_child(const char* data);
extern const char* dkls_party_derive_child(const char* data);

extern const char* dkls_re_key(const char* data);
*/
import "C"
import (
    "unsafe"
)

func callFFIFunc(fn C.ffi_func, data string) string {
    // Convert Go string to C string
    cData := C.CString(data)
    defer C.free(unsafe.Pointer(cData))

    // Call the Rust function
    cResult := C.bridge_ffi_func(fn, cData)
    defer C.free(unsafe.Pointer(cResult))

    // Convert C string to Go string
    return C.GoString(cResult)
}

// Key genenation
func GenerateKeySharesPhase1(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_dkg_phase1), data);
}

func GenerateKeySharesPhase2(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_dkg_phase2), data);
}

func GenerateKeySharesPhase3(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_dkg_phase3), data);
}

func GenerateKeySharesPhase4(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_dkg_phase4), data);
}

// Sign
func SignPhase1(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_sign_phase1), data);
}

func SignPhase2(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_sign_phase2), data);
}

func SignPhase3(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_sign_phase3), data);
}

func SignPhase4(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_sign_phase4), data);
}

// Verify
func VerifyECDSASignature(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_verify_ecdsa_signature), data);
}

// Derivation
func DeriveFromPath(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_derive_from_path), data);
}

func PartyDeriveFromPath(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_party_derive_from_path), data);
}

func DeriveChild(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_derive_child), data);
}

func PartyDeriveChild(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_party_derive_child), data);
}

// Re-key
func ReKey(data string) string {
    return callFFIFunc(C.ffi_func(C.dkls_re_key), data);
}
