package ext_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/0xCarbon/libtss-go/ext"
	"github.com/0xCarbon/libtss-go/tss"
)

func runDKG(ctx context.Context, t *testing.T, suite tss.Ciphersuite, n, threshold int) []*tss.KeyShareHandle {
	t.Helper()
	config := tss.ThresholdConfig{MinSigners: uint16(threshold), MaxSigners: uint16(n), Suite: suite}
	parties := make([]*ext.DKGParty, n)
	for i := range parties {
		p, err := ext.NewDKGParty(config, tss.Identifier(i+1), []byte("ext-dkg-session"))
		if err != nil {
			t.Fatalf("NewDKGParty(%d): %v", i+1, err)
		}
		t.Cleanup(p.Free)
		if p.ID() != tss.Identifier(i+1) {
			t.Fatalf("party %d has an invalid ID", i+1)
		}
		parties[i] = p
	}
	results, err := ext.RunLocalDKG(ctx, parties)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}

	pubkey := results[0].PublicKeyPackage.VerifyingKey
	shares := make([]*tss.KeyShareHandle, 0, n)
	for i, r := range results {
		t.Cleanup(r.KeyShare.Free)
		groupKey, err := r.KeyShare.GroupKey()
		if err != nil {
			t.Fatalf("GroupKey(%d): %v", i+1, err)
		}
		if !bytes.Equal(groupKey, pubkey) {
			t.Fatalf("party %d has a different group key", i+1)
		}
		shares = append(shares, r.KeyShare)
	}
	return shares
}

func runSign(ctx context.Context, t *testing.T, shares []*tss.KeyShareHandle, ids []tss.Identifier) {
	t.Helper()
	suite, err := shares[0].Ciphersuite()
	if err != nil {
		t.Fatalf("Ciphersuite: %v", err)
	}
	pubkey, err := shares[0].GroupKey()
	if err != nil {
		t.Fatalf("GroupKey: %v", err)
	}

	message := []byte("hello ecdsa")
	// DKLs23 signs the hash; FROST signs the raw message.
	toSign := message
	if suite.Protocol() == tss.ProtocolDKLs23 {
		hash := sha256.Sum256(message)
		toSign = hash[:]
	}
	parties := make([]*ext.SignParty, len(ids))
	for i, id := range ids {
		p, err := ext.NewSignParty(shares[i], toSign, ids, []byte("ext-sign-session"))
		if err != nil {
			t.Fatalf("NewSignParty(%d): %v", id, err)
		}
		t.Cleanup(p.Free)
		parties[i] = p
	}
	results, err := ext.RunLocalSign(ctx, parties)
	if err != nil {
		t.Fatalf("sign %v: %v", ids, err)
	}
	for i, sig := range results {
		valid, err := tss.Verify(suite, message, sig.Data, pubkey)
		if err != nil {
			t.Fatalf("Verify(%d): %v", ids[i], err)
		}
		if !valid {
			t.Fatalf("signature from party %d is invalid", ids[i])
		}
	}
}

func runRefresh(ctx context.Context, t *testing.T, shares []*tss.KeyShareHandle, ids []tss.Identifier, dealer tss.Identifier) []*tss.KeyShareHandle {
	t.Helper()
	oldKey, err := shares[0].GroupKey()
	if err != nil {
		t.Fatalf("GroupKey: %v", err)
	}

	parties := make([]*ext.RefreshParty, len(shares))
	for i, share := range shares {
		p, err := ext.NewRefreshParty(share, ids, []byte("ext-refresh-session"), dealer)
		if err != nil {
			t.Fatalf("NewRefreshParty(%d): %v", ids[i], err)
		}
		t.Cleanup(p.Free)
		parties[i] = p
	}
	results, err := ext.RunLocalRefresh(ctx, parties)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	newShares := make([]*tss.KeyShareHandle, len(results))
	for i, r := range results {
		groupKey, err := r.KeyShare.GroupKey()
		if err != nil {
			t.Fatalf("GroupKey(%d): %v", ids[i], err)
		}
		if !bytes.Equal(groupKey, oldKey) {
			t.Fatalf("party %d group key changed after refresh", ids[i])
		}
		newShares[i] = r.KeyShare
	}
	return newShares
}

// pickShare returns the shares for ids (1-based) from shares.
func pickShare(shares []*tss.KeyShareHandle, ids []tss.Identifier) []*tss.KeyShareHandle {
	out := make([]*tss.KeyShareHandle, len(ids))
	for i, id := range ids {
		out[i] = shares[id-1]
	}
	return out
}

func TestDKLs23DKGAndSign(t *testing.T) {
	var dklsSuites = map[string]tss.Ciphersuite{
		"secp256k1": tss.CiphersuiteSecp256k1ECDSA,
		"secp256r1": tss.CiphersuiteSecp256r1ECDSA,
	}
	cases := []struct {
		n, threshold int
		signers      [][]tss.Identifier // signers for each signing run; DKLs23 requires exactly threshold of them
	}{
		{3, 2, [][]tss.Identifier{{1, 2}, {3, 1}, {2, 3}}},
		{4, 3, [][]tss.Identifier{{1, 2, 3}, {2, 1, 4}, {1, 2, 4}}},
	}
	for name, suite := range dklsSuites {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%dof%d", name, c.threshold, c.n), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				shares := runDKG(ctx, t, suite, c.n, c.threshold)
				for _, s := range shares {
					t.Cleanup(s.Free)
				}
				for _, ids := range c.signers {
					t.Run(fmt.Sprint("sign", ids), func(t *testing.T) {
						runSign(ctx, t, pickShare(shares, ids), ids)
					})
				}
			})
		}
	}
}

func TestDKLs23RefreshAndSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	shares := runDKG(ctx, t, tss.CiphersuiteSecp256k1ECDSA, 3, 2)
	for _, s := range shares {
		t.Cleanup(s.Free)
	}
	ids := []tss.Identifier{1, 2, 3}

	newShares := runRefresh(ctx, t, shares, ids, 0)
	for _, s := range newShares {
		t.Cleanup(s.Free)
	}
	for _, signers := range [][]tss.Identifier{{1, 2}, {3, 1}, {2, 3}} {
		t.Run(fmt.Sprint("sign", signers), func(t *testing.T) {
			runSign(ctx, t, pickShare(newShares, signers), signers)
		})
	}
}

func TestEd25519DKGAndSign(t *testing.T) {
	cases := []struct {
		n, threshold int
		signers      [][]tss.Identifier // signers for each signing run; FROST requires at least threshold of them
	}{
		{3, 2, [][]tss.Identifier{{1, 2}, {3, 1}, {2, 3}}},
		{4, 3, [][]tss.Identifier{{1, 2, 3}, {2, 1, 4}, {1, 2, 4}}},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("ed25519/%dof%d", c.threshold, c.n), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			shares := runDKG(ctx, t, tss.CiphersuiteEd25519, c.n, c.threshold)
			for _, s := range shares {
				t.Cleanup(s.Free)
			}
			for _, ids := range c.signers {
				t.Run(fmt.Sprint("sign", ids), func(t *testing.T) {
					runSign(ctx, t, pickShare(shares, ids), ids)
				})
			}
		})
	}

}

func TestEd25519RefreshAndSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	shares := runDKG(ctx, t, tss.CiphersuiteEd25519, 3, 2)
	for _, s := range shares {
		t.Cleanup(s.Free)
	}
	ids := []tss.Identifier{1, 2, 3}

	newShares := runRefresh(ctx, t, shares, ids, 2)
	for _, s := range newShares {
		t.Cleanup(s.Free)
	}
	for _, signers := range [][]tss.Identifier{{1, 2}, {3, 1}, {2, 3}} {
		t.Run(fmt.Sprint("sign", signers), func(t *testing.T) {
			runSign(ctx, t, pickShare(newShares, signers), signers)
		})
	}
}
