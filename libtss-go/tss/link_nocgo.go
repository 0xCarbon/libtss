//go:build !cgo

package tss

// The binding calls libtss-ffi through cgo; build with CGO_ENABLED=1 and a C
// toolchain.
var _ = libtss_go_requires_cgo_set_CGO_ENABLED_1
