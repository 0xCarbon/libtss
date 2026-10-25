//go:build linux && !android && arm64 && !libtss_local && !libtss_dynamic

package tss

// Links the prebuilt static libtss-ffi archive shipped in native/linux_arm64.

/*
#cgo LDFLAGS: ${SRCDIR}/native/linux_arm64/liblibtss_ffi.a -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
*/
import "C"

import _ "github.com/0xCarbon/libtss-go/tss/native/linux_arm64"
