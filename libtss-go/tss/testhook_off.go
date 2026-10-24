//go:build !libtss_testhooks

package tss

// afterHandleRead is a test hook (see testhook_on.go); it is a no-op in
// normal builds.
func afterHandleRead() {}
