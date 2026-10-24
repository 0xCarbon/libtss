package tss

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

func TestNilArgumentsReturnErrors(t *testing.T) {
	var share *KeyShareHandle
	checks := map[string]func() error{
		"DKLsRepairHelperTerm": func() error {
			_, err := DKLsRepairHelperTerm(share, []Identifier{1, 2}, 3, []byte("id"))
			return err
		},
		"Bolt3Derive": func() error {
			_, err := Bolt3Derive(share, make([]byte, 33))
			return err
		},
		"Bolt3DeriveRevocation": func() error {
			_, err := Bolt3DeriveRevocation(share, make([]byte, 33), make([]byte, 32))
			return err
		},
		"DeriveChild":    func() error { _, err := DeriveChild(share, 1); return err },
		"DerivePath":     func() error { _, err := DerivePath(share, "m/1"); return err },
		"ExportKeyShare": func() error { _, err := ExportKeyShare(share); return err },
		"NewSignSession": func() error {
			_, _, err := NewSignSession(share, []byte("m"), []Identifier{2}, []byte("s"))
			return err
		},
		"NewRefreshSession": func() error {
			_, _, err := NewRefreshSession(share, []Identifier{1, 2})
			return err
		},
		"NewRefreshSessionDKLs": func() error {
			_, _, err := NewRefreshSessionDKLs(share, []byte("s"))
			return err
		},
		"NewRefreshReceiver": func() error { _, err := NewRefreshReceiver(share); return err },
		"FrostTweakKeyShare": func() error { _, err := FrostTweakKeyShare(share, nil); return err },
		"FrostApplyRefresh": func() error {
			_, err := FrostApplyRefresh(share, []byte{1}, []byte{1})
			return err
		},
		"FrostRepairPart1": func() error {
			_, err := FrostRepairPart1(share, []Identifier{1, 2}, 3)
			return err
		},
		"Identifier":     func() error { _, err := share.Identifier(); return err },
		"GroupKey":       func() error { _, err := share.GroupKey(); return err },
		"Ciphersuite":    func() error { _, err := share.Ciphersuite(); return err },
		"VerifyingShare": func() error { _, err := share.VerifyingShare(); return err },
		"DKGSession.Next": func() error {
			var s *DKGSession
			_, err := s.Next(nil)
			return err
		},
		"SignSession.Next": func() error {
			var s *SignSession
			_, err := s.Next(nil)
			return err
		},
		"RefreshSession.Next": func() error {
			var s *RefreshSession
			_, err := s.Next(nil)
			return err
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if err := check(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseMessagesRejectsMalformedInput(t *testing.T) {
	valid, err := BuildMessages([]Message{{From: 1, To: 2, Data: []byte("abc")}})
	if err != nil {
		t.Fatal(err)
	}
	if msgs, err := ParseMessages(nil); err != nil || len(msgs) != 0 {
		t.Fatalf("empty input: %v, %v", msgs, err)
	}
	if msgs, err := ParseMessages(valid); err != nil || len(msgs) != 1 {
		t.Fatalf("valid input: %v, %v", msgs, err)
	}
	cases := map[string][]byte{
		"truncated header":  valid[:5],
		"truncated payload": valid[:len(valid)-1],
		"trailing bytes":    append(append([]byte(nil), valid...), 1, 2, 3),
		"zero sender":       {0, 0, 2, 0, 0, 0, 0, 0},
	}
	for name, blob := range cases {
		msgs, err := ParseMessages(blob)
		if err == nil {
			t.Errorf("%s: expected an error, got %d messages", name, len(msgs))
			continue
		}
		tssErr, ok := err.(*TssError)
		if !ok || tssErr.Code != 9 { // TSS_ERR_DESERIALIZE
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

// TestHandlesSurviveForcedGC runs DKG and signing while forcing collections
// between and during native calls. Handles must not be finalized while their
// owners are still in use.
func TestHandlesSurviveForcedGC(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				runtime.GC()
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	for _, suite := range []Ciphersuite{CiphersuiteEd25519, CiphersuiteSecp256k1ECDSA} {
		shares, _ := runDKG(t, suite, 3, 2, []byte("go-forced-gc"))
		for i := 0; i < 20; i++ {
			for _, share := range shares {
				if _, err := share.GroupKey(); err != nil {
					t.Fatalf("GroupKey after GC: %v", err)
				}
				if _, err := share.Ciphersuite(); err != nil {
					t.Fatalf("Ciphersuite after GC: %v", err)
				}
			}
		}
		runSignRound(t, suite, []*KeyShareHandle{shares[0], shares[1]}, bytes.Repeat([]byte{7}, 32))
		for _, share := range shares {
			share.Free()
		}
		runtime.GC()
	}
}

// TestUnreferencedHandleIsFinalized checks that a handle dropped without Free
// is released by its finalizer.
func TestUnreferencedHandleIsFinalized(t *testing.T) {
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	native := shares[0].native
	shares = nil
	for i := 0; i < 20; i++ {
		runtime.GC()
		native.mu.RLock()
		freed := native.handle == 0
		native.mu.RUnlock()
		if freed {
			return
		}
	}
	t.Fatal("expected the finalizer to free the dropped handle")
}
