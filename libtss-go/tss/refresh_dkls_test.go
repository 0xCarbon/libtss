package tss

import (
	"bytes"
	"testing"
)

func runDKLsRefresh(t *testing.T, shares []*KeyShareHandle, sessionID []byte) []*KeyShareHandle {
	t.Helper()
	n := len(shares)
	sessions := make([]*RefreshSession, n)
	round := make([][]Message, n)
	for i, share := range shares {
		session, messages, err := NewRefreshSessionDKLs(share, sessionID)
		if err != nil {
			t.Fatalf("NewRefreshSessionDKLs(%d): %v", i+1, err)
		}
		sessions[i] = session
		round[i] = messages
		defer session.Free()
	}
	refreshed := make([]*KeyShareHandle, n)
	for {
		nextRound := make([][]Message, n)
		completed := 0
		for i := range sessions {
			step, err := sessions[i].Next(collectPeerMessages(round, i, Identifier(i+1)))
			if err != nil {
				t.Fatalf("refresh Next(%d): %v", i+1, err)
			}
			if step.Complete {
				refreshed[i] = step.KeyShare
				completed++
				continue
			}
			nextRound[i] = step.Messages
		}
		if completed == n {
			return refreshed
		}
		round = nextRound
	}
}

func TestDKLsRefresh(t *testing.T) {
	for _, suite := range []Ciphersuite{CiphersuiteSecp256k1ECDSA, CiphersuiteSecp256r1ECDSA} {
		shares, pubkeys := runDKG(t, suite, 3, 2, []byte("go-refresh-dkg"))
		for _, share := range shares {
			defer share.Free()
		}
		refreshed := runDKLsRefresh(t, shares, []byte("go-refresh-1"))
		for i, share := range refreshed {
			defer share.Free()
			groupKey, err := share.GroupKey()
			if err != nil {
				t.Fatalf("GroupKey: %v", err)
			}
			if !bytes.Equal(groupKey, pubkeys.VerifyingKey) {
				t.Fatalf("suite %d: refresh changed the group key", suite)
			}
			before, _ := shares[i].VerifyingShare()
			after, _ := share.VerifyingShare()
			if bytes.Equal(before, after) {
				t.Fatalf("suite %d: refresh left share %d unchanged", suite, i+1)
			}
		}
		runSignRound(t, suite, []*KeyShareHandle{refreshed[0], refreshed[2]}, bytes.Repeat([]byte{7}, 32))
	}
}

func TestDKLsRefreshRejectsEmptySessionID(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("go-refresh-dkg"))
	for _, share := range shares {
		defer share.Free()
	}
	if _, _, err := NewRefreshSessionDKLs(shares[0], nil); err == nil {
		t.Fatal("expected an error for an empty session ID")
	}
}
