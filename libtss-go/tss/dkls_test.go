package tss

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestDKLsSplitKey(t *testing.T) {
	chainCode := bytes.Repeat([]byte{0x17}, 32)
	for _, suite := range []Ciphersuite{CiphersuiteSecp256k1ECDSA, CiphersuiteSecp256r1ECDSA} {
		secret := bytes.Repeat([]byte{0x42}, 32)
		shares, _, err := DKLsSplitKey(suite, secret, chainCode, 3, 2)
		if err != nil {
			t.Fatalf("DKLsSplitKey(%d): %v", suite, err)
		}
		for _, share := range shares {
			defer share.Free()
		}
		if !bytes.Equal(secret, make([]byte, 32)) {
			t.Fatal("expected the secret key to be wiped")
		}
		groupKey, err := shares[0].GroupKey()
		if err != nil {
			t.Fatalf("GroupKey: %v", err)
		}
		if suite == CiphersuiteSecp256r1ECDSA {
			x, y := elliptic.P256().ScalarBaseMult(bytes.Repeat([]byte{0x42}, 32))
			want := elliptic.MarshalCompressed(elliptic.P256(), x, y)
			if !bytes.Equal(groupKey, want) {
				t.Fatalf("group key %x, want %x", groupKey, want)
			}
		}
		for _, share := range shares {
			code, err := share.ChainCode()
			if err != nil {
				t.Fatalf("ChainCode: %v", err)
			}
			if !bytes.Equal(code, chainCode) {
				t.Fatalf("chain code %x, want %x", code, chainCode)
			}
		}
		refreshed := runDKLsRefresh(t, shares, []byte("go-after-import"))
		for _, share := range refreshed {
			defer share.Free()
		}
		runSignRound(t, suite, []*KeyShareHandle{refreshed[1], refreshed[2]}, bytes.Repeat([]byte{9}, 32))
	}
}

func TestDKLsSplitKeyRejectsInvalidInput(t *testing.T) {
	order := elliptic.P256().Params().N
	tooLarge := new(big.Int).Add(order, big.NewInt(1)).FillBytes(make([]byte, 32))
	cases := map[string]struct {
		suite     Ciphersuite
		secret    []byte
		chainCode []byte
	}{
		"zero":           {CiphersuiteSecp256r1ECDSA, make([]byte, 32), nil},
		"short":          {CiphersuiteSecp256r1ECDSA, bytes.Repeat([]byte{1}, 31), nil},
		"above order":    {CiphersuiteSecp256r1ECDSA, tooLarge, nil},
		"bad chain code": {CiphersuiteSecp256r1ECDSA, bytes.Repeat([]byte{1}, 32), make([]byte, 31)},
		"frost suite":    {CiphersuiteEd25519, bytes.Repeat([]byte{1}, 32), nil},
	}
	for name, c := range cases {
		if _, _, err := DKLsSplitKey(c.suite, c.secret, c.chainCode, 3, 2); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
