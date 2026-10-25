//go:build darwin && arm64 && !libtss_local && !libtss_dynamic

package tss

// Links the prebuilt static libtss-ffi archive shipped in native/darwin_arm64.

/*
#cgo LDFLAGS: ${SRCDIR}/native/darwin_arm64/liblibtss_ffi.a -lm -framework Security -framework CoreFoundation
*/
import "C"
