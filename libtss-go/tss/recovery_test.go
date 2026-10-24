package tss

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

type testCurve struct{ p, a, b, gx, gy, n *big.Int }

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return v
}

var recoveryCurves = map[Ciphersuite]testCurve{
	CiphersuiteSecp256k1ECDSA: {
		p:  hexInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
		a:  big.NewInt(0),
		b:  big.NewInt(7),
		gx: hexInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		gy: hexInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
		n:  hexInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
	},
	CiphersuiteSecp256r1ECDSA: {
		p:  hexInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
		a:  hexInt("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
		b:  hexInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
		gx: hexInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		gy: hexInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
		n:  hexInt("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	},
}

type point struct{ x, y *big.Int } // nil x means the point at infinity

func (c testCurve) add(p1, p2 point) point {
	if p1.x == nil {
		return p2
	}
	if p2.x == nil {
		return p1
	}
	mod := func(v *big.Int) *big.Int { return v.Mod(v, c.p) }
	var lam *big.Int
	if p1.x.Cmp(p2.x) == 0 {
		if mod(new(big.Int).Add(p1.y, p2.y)).Sign() == 0 {
			return point{}
		}
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p1.x, p1.x))
		num.Add(num, c.a)
		den := new(big.Int).ModInverse(mod(new(big.Int).Lsh(p1.y, 1)), c.p)
		lam = mod(num.Mul(num, den))
	} else {
		num := new(big.Int).Sub(p2.y, p1.y)
		den := new(big.Int).ModInverse(mod(new(big.Int).Sub(p2.x, p1.x)), c.p)
		lam = mod(num.Mul(num, den))
	}
	x := new(big.Int).Mul(lam, lam)
	x.Sub(x, p1.x).Sub(x, p2.x)
	mod(x)
	y := new(big.Int).Sub(p1.x, x)
	y.Mul(y, lam).Sub(y, p1.y)
	return point{x, mod(y)}
}

func (c testCurve) mul(k *big.Int, p point) point {
	result := point{}
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = c.add(result, result)
		if k.Bit(i) == 1 {
			result = c.add(result, p)
		}
	}
	return result
}

// recoverCompressed recovers the compressed public key from an r||s
// signature over digest with the given recovery id.
func recoverCompressed(suite Ciphersuite, digest, sig []byte, recoveryID int) []byte {
	c := recoveryCurves[suite]
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	// y^2 = x^3 + ax + b; both field primes are 3 mod 4.
	rhs := new(big.Int).Exp(r, big.NewInt(3), c.p)
	rhs.Add(rhs, new(big.Int).Mul(c.a, r)).Add(rhs, c.b).Mod(rhs, c.p)
	exp := new(big.Int).Rsh(new(big.Int).Add(c.p, big.NewInt(1)), 2)
	y := new(big.Int).Exp(rhs, exp, c.p)
	if int(y.Bit(0)) != recoveryID {
		y.Sub(c.p, y)
	}
	e := new(big.Int).Mod(new(big.Int).SetBytes(digest), c.n)
	rInv := new(big.Int).ModInverse(r, c.n)
	u1 := new(big.Int).Mul(s, rInv)
	u1.Mod(u1, c.n)
	u2 := new(big.Int).Neg(e)
	u2.Mul(u2, rInv).Mod(u2, c.n)
	q := c.add(c.mul(u1, point{r, y}), c.mul(u2, point{c.gx, c.gy}))
	out := make([]byte, 33)
	out[0] = 2 + byte(q.y.Bit(0))
	q.x.FillBytes(out[1:])
	return out
}

// maxRecoverySignatures bounds the attempts to observe both recovery ids;
// each signature shows a given parity with probability 1/2.
const maxRecoverySignatures = 32

func TestDKLsSignaturesReportBothRecoveryIDs(t *testing.T) {
	for _, suite := range []Ciphersuite{CiphersuiteSecp256k1ECDSA, CiphersuiteSecp256r1ECDSA} {
		t.Run(fmt.Sprint(suite), func(t *testing.T) {
			shares, pubkeys := runDKG(t, suite, 2, 2, []byte(fmt.Sprintf("go-recovery-%d", suite)))
			defer shares[0].Free()
			defer shares[1].Free()
			seen := map[int]bool{}
			for attempt := 0; attempt < maxRecoverySignatures && len(seen) < 2; attempt++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("recovery-%d", attempt)))
				sig := signWithID(t, shares, digest[:], []byte(fmt.Sprintf("go-recovery-%d-%d", suite, attempt)))
				if len(sig.Data) != 64 {
					t.Fatalf("signature length %d", len(sig.Data))
				}
				if sig.RecoveryID != 0 && sig.RecoveryID != 1 {
					t.Fatalf("recovery id %d", sig.RecoveryID)
				}
				if got := recoverCompressed(suite, digest[:], sig.Data, sig.RecoveryID); !bytes.Equal(got, pubkeys.VerifyingKey) {
					t.Fatalf("recovered key %x, want %x", got, pubkeys.VerifyingKey)
				}
				seen[sig.RecoveryID] = true
			}
			if len(seen) != 2 {
				t.Fatalf("both recovery ids not observed within %d signatures: %v", maxRecoverySignatures, seen)
			}
		})
	}
}

func TestFROSTSignaturesHaveNoRecoveryID(t *testing.T) {
	cases := map[Ciphersuite]int{
		CiphersuiteSecp256k1Taproot: 64,
		CiphersuiteSecp256k1:        65,
		CiphersuiteEd25519:          64,
		CiphersuiteP256:             65,
		CiphersuiteRistretto255:     64,
		CiphersuiteEd448:            114,
	}
	for suite, length := range cases {
		if got := suite.SignatureLength(); got != length {
			t.Fatalf("suite %d: SignatureLength %d, want %d", suite, got, length)
		}
		shares, _, err := FrostGenerateDealer(suite, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		sig := runSignRound(t, suite, shares, []byte("frost message"))
		if len(sig.Data) != length || sig.RecoveryID != NoRecoveryID {
			t.Fatalf("suite %d: length %d, recovery id %d", suite, len(sig.Data), sig.RecoveryID)
		}
		shares[0].Free()
		shares[1].Free()
	}
}

// signWithID runs DKLs23 signing with a distinct sign id per signature.
func signWithID(t *testing.T, shares []*KeyShareHandle, digest, signID []byte) Signature {
	t.Helper()
	sessions := make([]*SignSession, len(shares))
	round := make([][]Message, len(shares))
	for i, share := range shares {
		other := Identifier(2 - i) // two parties with identifiers 1 and 2
		s, msgs, err := NewSignSession(share, digest, []Identifier{other}, signID)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Free()
		sessions[i], round[i] = s, msgs
	}
	for r := 0; r < 10; r++ {
		next := make([][]Message, len(shares))
		for i, s := range sessions {
			step, err := s.Next(collectPeerMessages(round, i, Identifier(i+1)))
			if err != nil {
				t.Fatal(err)
			}
			if step.Complete {
				return step.Signature
			}
			next[i] = step.Messages
		}
		round = next
	}
	t.Fatal("signing did not complete")
	return Signature{}
}
