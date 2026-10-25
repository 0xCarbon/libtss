//go:build linux && amd64 && !libtss_local && !libtss_dynamic

package tss

// Links the prebuilt static libtss-ffi archive shipped in native/linux_amd64.

/*
#cgo LDFLAGS: ${SRCDIR}/native/linux_amd64/liblibtss_ffi.a -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
*/
import "C"
