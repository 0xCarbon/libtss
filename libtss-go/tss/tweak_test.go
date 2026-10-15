package tss

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// Mirrors of the C status codes; cgo constants are not reachable from _test.go files.
const (
	tssErrTweakCode         = 13
	tssErrProtoMismatchCode = 8
)

func tweakScalar(value uint64) []byte {
	scalar := make([]byte, tweakScalarLen)
	binary.BigEndian.PutUint64(scalar[tweakScalarLen-8:], value)
	return scalar
}

func tweakAll(t *testing.T, shares []*KeyShareHandle, scalar []byte, add bool) []*KeyShareHandle {
	t.Helper()
	tweaked := make([]*KeyShareHandle, len(shares))
	for i, share := range shares {
		var err error
		if add {
			tweaked[i], err = TweakAdd(share, scalar)
		} else {
			tweaked[i], err = TweakMul(share, scalar)
		}
		if err != nil {
			t.Fatalf("tweak share %d: %v", i+1, err)
		}
	}
	return tweaked
}

func TestDKLs23TweakAddSignsUnderTweakedKey(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("tweak-session"))
	for _, share := range shares {
		defer share.Free()
	}
	tweaked := tweakAll(t, shares, tweakScalar(7), true)
	for _, share := range tweaked {
		defer share.Free()
	}

	parentKey, err := shares[0].GroupKey()
	if err != nil {
		t.Fatalf("GroupKey: %v", err)
	}
	tweakedKey, err := tweaked[0].GroupKey()
	if err != nil {
		t.Fatalf("GroupKey (tweaked): %v", err)
	}
	otherTweakedKey, err := tweaked[1].GroupKey()
	if err != nil {
		t.Fatalf("GroupKey (tweaked, party 2): %v", err)
	}
	if !bytes.Equal(tweakedKey, otherTweakedKey) {
		t.Fatal("tweaked group key differs across parties")
	}
	if bytes.Equal(tweakedKey, parentKey) {
		t.Fatal("tweaked group key equals the parent key")
	}

	msg := []byte("hello tweaked ecdsa")
	hash := sha256.Sum256(msg)
	sig := runSignRound(t, CiphersuiteSecp256k1ECDSA, tweaked, hash[:])

	valid, err := Verify(CiphersuiteSecp256k1ECDSA, msg, sig.Data, tweakedKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("signature by tweaked shares does not verify under the tweaked key")
	}
	valid, err = Verify(CiphersuiteSecp256k1ECDSA, msg, sig.Data, parentKey)
	if err != nil {
		t.Fatalf("Verify (parent key): %v", err)
	}
	if valid {
		t.Fatal("signature by tweaked shares must not verify under the parent key")
	}
}

func TestDKLs23TweakMulByOneIsIdentity(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("tweak-mul-session"))
	for _, share := range shares {
		defer share.Free()
	}

	scaled, err := TweakMul(shares[0], tweakScalar(1))
	if err != nil {
		t.Fatalf("TweakMul: %v", err)
	}
	defer scaled.Free()

	parentKey, _ := shares[0].GroupKey()
	scaledKey, _ := scaled.GroupKey()
	if !bytes.Equal(parentKey, scaledKey) {
		t.Fatal("multiplying by one changed the group key")
	}
}

func TestTweakMulZeroRejected(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("tweak-zero-session"))
	for _, share := range shares {
		defer share.Free()
	}

	_, err := TweakMul(shares[0], tweakScalar(0))
	var tssErr *TssError
	if !errors.As(err, &tssErr) {
		t.Fatalf("TweakMul error = %v, want *TssError", err)
	}
	if tssErr.Code != tssErrTweakCode {
		t.Fatalf("TweakMul error code = %d, want %d", tssErr.Code, tssErrTweakCode)
	}
}

func TestTweakRejectsBadLength(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("tweak-len-session"))
	for _, share := range shares {
		defer share.Free()
	}

	if _, err := TweakAdd(shares[0], make([]byte, 31)); err == nil {
		t.Fatal("TweakAdd accepted a 31-byte scalar")
	}
	if _, err := TweakMul(shares[0], make([]byte, 33)); err == nil {
		t.Fatal("TweakMul accepted a 33-byte scalar")
	}
	if _, err := TweakAdd(nil, tweakScalar(7)); err == nil {
		t.Fatal("TweakAdd accepted a nil key share")
	}
}

func TestTweakUnsupportedSuite(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteEd25519, 3, 2, nil)
	for _, share := range shares {
		defer share.Free()
	}

	_, err := TweakAdd(shares[0], tweakScalar(7))
	var tssErr *TssError
	if !errors.As(err, &tssErr) {
		t.Fatalf("TweakAdd error = %v, want *TssError", err)
	}
	if tssErr.Code != tssErrProtoMismatchCode {
		t.Fatalf("TweakAdd error code = %d, want %d", tssErr.Code, tssErrProtoMismatchCode)
	}
}
