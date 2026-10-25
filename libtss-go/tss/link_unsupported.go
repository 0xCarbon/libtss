//go:build !libtss_local && !libtss_dynamic && !(((linux && !android) || (darwin && !ios)) && (amd64 || arm64))

package tss

// No prebuilt libtss-ffi archive exists for this platform. Build with
// -tags libtss_dynamic and an installed shared library (see README.md).
var _ = libtss_ffi_has_no_prebuilt_archive_for_this_platform_use_libtss_dynamic
