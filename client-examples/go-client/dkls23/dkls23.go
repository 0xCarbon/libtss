package dkls23

/*
#include <stdlib.h>
#include <stdint.h>

// Declare the external Rust function
extern const char* dkls_dkg_phase1(const char* data);
*/
import "C"
import (
    "unsafe"
)

func GenerateKeySharesPhase1(data string) string {
    // Convert Go string to C string
    cData := C.CString(data)
    defer C.free(unsafe.Pointer(cData))

    // Call the Rust function
    cResult := C.dkls_dkg_phase1(cData)

    // Convert C string to Go string
    result := C.GoString(cResult)

    // Free the C string returned by Rust
    C.free(unsafe.Pointer(cResult))

    return result
}
