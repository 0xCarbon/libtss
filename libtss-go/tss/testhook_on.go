//go:build libtss_testhooks

package tss

// testHookAfterHandleRead, when set, runs after a native handle value has
// been read and before the native call that uses it. Lifetime tests use it
// to force garbage collection and finalizers at that point. Only compiled
// with the libtss_testhooks build tag.
var testHookAfterHandleRead func()

func afterHandleRead() {
	if hook := testHookAfterHandleRead; hook != nil {
		hook()
	}
}
