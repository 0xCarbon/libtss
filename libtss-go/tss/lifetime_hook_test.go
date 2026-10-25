//go:build libtss_testhooks

package tss

import (
	"runtime"
	"testing"
	"time"
)

// forceFinalizers runs at the hook point between reading a native handle and
// the native call that uses it. If the owner were unreachable there and its
// handle not protected, its finalizer would free the handle and the native
// call would fail with an invalid handle.
func forceFinalizers() {
	for i := 0; i < 2; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond) // let the finalizer goroutine run
	}
}

func withForcedFinalizers(t *testing.T) {
	t.Helper()
	testHookAfterHandleRead = forceFinalizers
	t.Cleanup(func() { testHookAfterHandleRead = nil })
}

//go:noinline
func unrootedShare(t *testing.T) *KeyShareHandle {
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	shares[1].Free()
	return shares[0]
}

func TestKeyShareSurvivesFinalizerDuringCall(t *testing.T) {
	withForcedFinalizers(t)
	for i := 0; i < 5; i++ {
		// The share is unreachable once its handle value has been read.
		if _, err := unrootedShare(t).GroupKey(); err != nil {
			t.Fatalf("GroupKey with forced finalizers: %v", err)
		}
		if _, err := unrootedShare(t).Ciphersuite(); err != nil {
			t.Fatalf("Ciphersuite with forced finalizers: %v", err)
		}
	}
}

//go:noinline
func firstSignStep(t *testing.T, s *SignSession, msgs []Message) error {
	// s is not used after this call.
	_, err := s.Next(msgs)
	return err
}

func TestSessionSurvivesFinalizerDuringCall(t *testing.T) {
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer shares[0].Free()
	defer shares[1].Free()
	s1, m1, err := NewSignSession(shares[0], []byte("m"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := NewSignSession(shares[1], []byte("m"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Free()
	withForcedFinalizers(t)
	if err := firstSignStep(t, s2, m1); err != nil {
		t.Fatalf("SignSession.Next with forced finalizers: %v", err)
	}
}
