//go:build libtss_local && !libtss_dynamic

package tss

// Links libtss-ffi from this source checkout (cargo build -p libtss-ffi),
// preferring a debug build over a release build.

/*
#cgo linux LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -l:liblibtss_ffi.a -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
#cgo darwin LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -llibtss_ffi -liconv -lSystem -lc -lm
*/
import "C"
