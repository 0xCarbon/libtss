//go:build libtss_dynamic

package tss

// Links an installed shared libtss-ffi found through pkg-config
// (libtss_ffi.pc).

/*
#cgo pkg-config: libtss_ffi
*/
import "C"
