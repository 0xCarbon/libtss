package tss

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
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

// BOLT 3, Appendix E: Key Derivation Test Vectors.
const (
	bolt3BaseSecret          = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	bolt3PerCommitmentSecret = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	bolt3PerCommitmentPoint  = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"
	bolt3LocalPublicKey      = "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"
	bolt3RevocationPublicKey = "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBolt3(t *testing.T) {
	shares, pkg, err := DKLsSplitKey(CiphersuiteSecp256k1ECDSA, mustHex(t, bolt3BaseSecret), nil, 3, 2)
	if err != nil {
		t.Fatalf("DKLsSplitKey: %v", err)
	}
	for _, share := range shares {
		defer share.Free()
	}
	point := mustHex(t, bolt3PerCommitmentPoint)

	derived, err := Bolt3Derive(shares[0], point)
	if err != nil {
		t.Fatalf("Bolt3Derive: %v", err)
	}
	defer derived.Free()
	if key, _ := derived.GroupKey(); !bytes.Equal(key, mustHex(t, bolt3LocalPublicKey)) {
		t.Fatalf("local key %x", key)
	}
	revocation, err := Bolt3DeriveRevocation(shares[0], point, mustHex(t, bolt3PerCommitmentSecret))
	if err != nil {
		t.Fatalf("Bolt3DeriveRevocation: %v", err)
	}
	defer revocation.Free()
	if key, _ := revocation.GroupKey(); !bytes.Equal(key, mustHex(t, bolt3RevocationPublicKey)) {
		t.Fatalf("revocation key %x", key)
	}

	for want, derive := range map[string]func([]byte, []byte) ([]byte, error){
		bolt3LocalPublicKey:      Bolt3DerivePublicKeys,
		bolt3RevocationPublicKey: Bolt3DeriveRevocationPublicKeys,
	} {
		raw, err := derive(pkg, point)
		if err != nil {
			t.Fatalf("package derivation: %v", err)
		}
		decoded, err := decodePublicKeyPackage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.VerifyingKey, mustHex(t, want)) {
			t.Fatalf("package key %x, want %s", decoded.VerifyingKey, want)
		}
	}

	if _, err := Bolt3DeriveRevocation(shares[0], point, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("expected a mismatched per-commitment secret to fail")
	}
}
