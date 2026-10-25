//go:build !libtss_local && !libtss_dynamic && !((linux || darwin) && (amd64 || arm64))

package tss

// No prebuilt libtss-ffi archive exists for this platform. Build with
// -tags libtss_dynamic (installed shared library) or -tags libtss_local
// (source checkout).
var _ = libtss_ffi_has_no_prebuilt_archive_for_this_platform_use_libtss_dynamic_or_libtss_local
