//go:build darwin && !ios && amd64 && !libtss_local && !libtss_dynamic

package tss

// Links the prebuilt static libtss-ffi archive shipped in native/darwin_amd64.

/*
#cgo LDFLAGS: ${SRCDIR}/native/darwin_amd64/liblibtss_ffi.a -liconv -lSystem -lc -lm
*/
import "C"

import _ "github.com/0xCarbon/libtss-go/tss/native/darwin_amd64"
