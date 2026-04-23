package tss

/*
#cgo linux LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -l:liblibtss_ffi.a -ldl -lm -lpthread
#cgo darwin LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -llibtss_ffi -lm -framework Security -framework CoreFoundation
#include "tss_ffi.h"
*/
import "C"
import (
	"fmt"

	"github.com/awnumar/memcall"
)

// InitOption controls optional one-time initialization behaviour.
type InitOption uint32

// OptMlock requests mlockall(MCL_CURRENT | MCL_FUTURE) to prevent
// all process pages from being swapped to disk. Requires
// CAP_IPC_LOCK or ulimit -l unlimited.
const OptMlock InitOption = 1

// Init performs optional one-time initialization. It calls the Rust-side
// tss_init() and disables core dumps via memguard.
func Init(opts ...InitOption) error {
	var flags uint32
	for _, opt := range opts {
		flags |= uint32(opt)
	}
	if err := callStatus(func() C.TssStatus {
		return C.tss_init(C.uint32_t(flags))
	}); err != nil {
		return err
	}
	if err := memcall.DisableCoreDumps(); err != nil {
		return fmt.Errorf("DisableCoreDumps: %w", err)
	}
	return nil
}

func Version() string {
	return C.GoString(C.tss_version())
}

// Verify checks a signature against a message and a public key for a given ciphersuite.
// For FROST suites, message is the original message. For Secp256k1ECDSA (DKLs23),
// message is the raw message (SHA-256 hashing is handled internally).
// Returns true if the signature is valid, false otherwise.
func Verify(suite Ciphersuite, message, signature, publicKey []byte) (bool, error) {
	if len(signature) == 0 {
		return false, fmt.Errorf("invalid signature")
	}
	if len(publicKey) == 0 {
		return false, fmt.Errorf("invalid public key")
	}

	msgSlice := bytesToSlice(message)
	sigSlice := bytesToSlice(signature)
	pkSlice := bytesToSlice(publicKey)

	valid := C.tss_verify(C.uint8_t(suite), msgSlice, sigSlice, pkSlice)
	return bool(valid), nil
}
