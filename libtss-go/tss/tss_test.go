package tss

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func collectPeerMessages(round [][]Message, idx int, selfID Identifier) []Message {
	var out []Message
	for peer := range round {
		if peer == idx {
			continue
		}
		for _, msg := range round[peer] {
			if msg.To == 0 || msg.To == selfID {
				out = append(out, msg)
			}
		}
	}
	return out
}

func runDKG(t *testing.T, suite Ciphersuite, n, min uint16, sessionID []byte) ([]*KeyShareHandle, PublicKeyPackage) {
	t.Helper()

	sessions := make([]*DKGSession, n)
	round := make([][]Message, n)
	for i := uint16(0); i < n; i++ {
		session, messages, err := NewDKGSession(ThresholdConfig{
			MinSigners: min,
			MaxSigners: n,
			Suite:      suite,
		}, Identifier(i+1), sessionID)
		if err != nil {
			t.Fatalf("NewDKGSession(%d): %v", i+1, err)
		}
		sessions[i] = session
		round[i] = messages
		defer session.Free()
	}

	shares := make([]*KeyShareHandle, n)
	var pubkeys PublicKeyPackage
	for {
		nextRound := make([][]Message, n)
		completed := 0
		for i := range sessions {
			step, err := sessions[i].Next(collectPeerMessages(round, i, Identifier(i+1)))
			if err != nil {
				t.Fatalf("DKG Next(%d): %v", i+1, err)
			}
			if step.Complete {
				shares[i] = step.KeyShare
				pubkeys = step.PublicKeyPackage
				completed++
				continue
			}
			nextRound[i] = step.Messages
		}
		if completed == int(n) {
			return shares, pubkeys
		}
		round = nextRound
	}
}

func runSignRound(t *testing.T, suite Ciphersuite, participants []*KeyShareHandle, message []byte) Signature {
	t.Helper()
	sessions := make([]*SignSession, len(participants))
	round := make([][]Message, len(participants))
	ids := make([]Identifier, len(participants))
	for i, share := range participants {
		id, err := share.Identifier()
		if err != nil {
			t.Fatalf("Identifier(%d): %v", i, err)
		}
		ids[i] = id
	}
	for i, share := range participants {
		var counterparties []Identifier
		var signID []byte
		if suite.Protocol() == ProtocolDKLs23 {
			for j, id := range ids {
				if j != i {
					counterparties = append(counterparties, id)
				}
			}
			signID = []byte("sign-session")
		}
		session, messages, err := NewSignSession(share, message, counterparties, signID)
		if err != nil {
			t.Fatalf("NewSignSession(%d): %v", i, err)
		}
		sessions[i] = session
		round[i] = messages
		defer session.Free()
	}

	for {
		nextRound := make([][]Message, len(participants))
		completed := 0
		var sig Signature
		for i := range sessions {
			step, err := sessions[i].Next(collectPeerMessages(round, i, ids[i]))
			if err != nil {
				t.Fatalf("Sign Next(%d): %v", i, err)
			}
			if step.Complete {
				sig = step.Signature
				completed++
				continue
			}
			nextRound[i] = step.Messages
		}
		if completed == len(participants) {
			sig.Protocol = suite.Protocol()
			return sig
		}
		round = nextRound
	}
}

func TestFROSTEndToEnd(t *testing.T) {
	shares, pubkeys := runDKG(t, CiphersuiteEd25519, 3, 2, nil)
	for _, share := range shares {
		defer share.Free()
	}

	verifyingShare, err := shares[0].VerifyingShare()
	if err != nil {
		t.Fatalf("VerifyingShare: %v", err)
	}
	if string(verifyingShare) == string(pubkeys.VerifyingKey) {
		t.Fatal("expected per-party verifying share to differ from group key")
	}

	sig := runSignRound(t, CiphersuiteEd25519, shares[:2], []byte("hello frost"))

	valid, err := Verify(CiphersuiteEd25519, []byte("hello frost"), sig.Data, pubkeys.VerifyingKey)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatal("Signature validation failed")
	}

	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature")
	}

	exported, err := ExportKeyShare(shares[0])
	if err != nil {
		t.Fatalf("ExportKeyShare: %v", err)
	}
	imported, err := ImportKeyShare(CiphersuiteEd25519, exported)
	if err != nil {
		t.Fatalf("ImportKeyShare: %v", err)
	}
	defer imported.Free()
	if _, err := imported.GroupKey(); err != nil {
		t.Fatalf("GroupKey after import: %v", err)
	}
}

func TestDKLs23EndToEnd(t *testing.T) {
	shares, pubkeys := runDKG(t, CiphersuiteSecp256k1ECDSA, 2, 2, []byte("dkls-session"))
	for _, share := range shares {
		defer share.Free()
	}

	// DKLs23 requires a 32-byte message hash
	msg := []byte("hello ecdsa")
	hasher := sha256.New()
	hasher.Write(msg)
	hash := hasher.Sum(nil)

	sig := runSignRound(t, CiphersuiteSecp256k1ECDSA, shares, hash)

	valid, err := Verify(CiphersuiteSecp256k1ECDSA, msg, sig.Data, pubkeys.VerifyingKey)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatal("Signature validation failed")
	}
	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestFROSTRefreshAndSign(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteEd25519, 3, 2, nil)
	for _, share := range shares {
		defer share.Free()
	}

	// Party 1 acts as the dealer
	participants := []Identifier{1, 2, 3}
	_, dealerMsgs, err := NewRefreshSession(shares[0], participants)
	if err != nil {
		t.Fatalf("NewRefreshSession dealer: %v", err)
	}

	// All parties receive the refresh as receivers
	newShares := make([]*KeyShareHandle, 3)
	for i := 0; i < 3; i++ {
		selfID := Identifier(i + 1)
		receiver, err := NewRefreshReceiver(shares[i])
		if err != nil {
			t.Fatalf("NewRefreshReceiver(%d): %v", i+1, err)
		}
		defer receiver.Free()

		// Filter dealer messages for this party
		var myMsgs []Message
		for _, msg := range dealerMsgs {
			if msg.To == selfID {
				myMsgs = append(myMsgs, msg)
			}
		}

		step, err := receiver.Next(myMsgs)
		if err != nil {
			t.Fatalf("Refresh Next(%d): %v", i+1, err)
		}
		if !step.Complete {
			t.Fatalf("expected refresh to complete in one round for party %d", i+1)
		}
		newShares[i] = step.KeyShare
	}

	for _, share := range newShares {
		defer share.Free()
	}

	sig := runSignRound(t, CiphersuiteEd25519, newShares[:2], []byte("refreshed"))
	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature after refresh")
	}
}

func TestNonceReuseAndFreedHandle(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteEd25519, 2, 2, nil)
	for _, share := range shares {
		defer share.Free()
	}

	sessionA, msgsA, err := NewSignSession(shares[0], []byte("nonce"), nil, nil)
	if err != nil {
		t.Fatalf("NewSignSession A: %v", err)
	}
	defer sessionA.Free()
	sessionB, msgsB, err := NewSignSession(shares[1], []byte("nonce"), nil, nil)
	if err != nil {
		t.Fatalf("NewSignSession B: %v", err)
	}
	defer sessionB.Free()

	stepA, err := sessionA.Next(msgsB)
	if err != nil {
		t.Fatalf("sessionA next1: %v", err)
	}
	stepB, err := sessionB.Next(msgsA)
	if err != nil {
		t.Fatalf("sessionB next1: %v", err)
	}
	if _, err := sessionA.Next(stepB.Messages); err != nil {
		t.Fatalf("sessionA next2: %v", err)
	}
	if _, err := sessionB.Next(stepA.Messages); err != nil {
		t.Fatalf("sessionB next2: %v", err)
	}
	if _, err := sessionA.Next(stepB.Messages); err == nil {
		t.Fatal("expected error on completed session reuse")
	} else {
		var tssErr *TssError
		if !errors.As(err, &tssErr) {
			t.Fatalf("unexpected error type: %#v", err)
		}
	}

	shares[0].Free()
	if _, err := shares[0].Identifier(); err == nil {
		t.Fatal("expected freed handle error")
	}
}

func TestExportKeyShareNilHandle(t *testing.T) {
	if _, err := ExportKeyShare(nil); err == nil {
		t.Fatal("ExportKeyShare(nil) should return error")
	}
	if _, err := ExportKeyShareSecure(nil); err == nil {
		t.Fatal("ExportKeyShareSecure(nil) should return error")
	}
}

func TestAbortCulpritAndBan(t *testing.T) {
	a, msgA, err := NewDKGSession(ThresholdConfig{
		MinSigners: 2,
		MaxSigners: 2,
		Suite:      CiphersuiteSecp256k1Taproot,
	}, 1, []byte("abort-session"))
	if err != nil {
		t.Fatalf("NewDKGSession A: %v", err)
	}
	defer a.Free()
	b, msgB, err := NewDKGSession(ThresholdConfig{
		MinSigners: 2,
		MaxSigners: 2,
		Suite:      CiphersuiteSecp256k1Taproot,
	}, 2, []byte("abort-session"))
	if err != nil {
		t.Fatalf("NewDKGSession B: %v", err)
	}
	defer b.Free()

	if _, err := a.Next(msgB); err != nil {
		t.Fatalf("round1 A: %v", err)
	}
	if _, err := b.Next(msgA); err != nil {
		t.Fatalf("round1 B: %v", err)
	}

	if _, err := a.Next(msgB); err == nil {
		t.Fatal("expected abort on wrong round message")
	} else {
		var abortErr *AbortError
		if !errors.As(err, &abortErr) {
			t.Fatalf("expected AbortError, got %T", err)
		}
		if len(abortErr.Culprits) != 1 || abortErr.Culprits[0] != 2 {
			t.Fatalf("unexpected culprits: %#v", abortErr.Culprits)
		}
	}

	// Test that TssError is properly returned with error codes
	c, msgC, err := NewDKGSession(ThresholdConfig{
		MinSigners: 2,
		MaxSigners: 2,
		Suite:      CiphersuiteSecp256k1ECDSA,
	}, 1, []byte("ban-session"))
	if err != nil {
		t.Fatalf("NewDKGSession C: %v", err)
	}
	defer c.Free()
	d, msgD, err := NewDKGSession(ThresholdConfig{
		MinSigners: 2,
		MaxSigners: 2,
		Suite:      CiphersuiteSecp256k1ECDSA,
	}, 2, []byte("ban-session"))
	if err != nil {
		t.Fatalf("NewDKGSession D: %v", err)
	}
	defer d.Free()

	// Run DKLs23 DKG rounds until done, then try stale messages
	roundC := msgD
	roundD := msgC
	for roundNum := 1; ; roundNum++ {
		stepC, errC := c.Next(roundC)
		stepD, errD := d.Next(roundD)
		if errC != nil || errD != nil {
			// One of the parties errored — verify it's a TssError
			testErr := errC
			if testErr == nil {
				testErr = errD
			}
			var tssErr *TssError
			if !errors.As(testErr, &tssErr) {
				t.Fatalf("expected TssError from DKLs23, got %T: %v", testErr, testErr)
			}
			t.Logf("DKLs23 DKG round %d error (code=%d): %s", roundNum, tssErr.Code, tssErr.Message)
			break
		}
		if stepC.Complete && stepD.Complete {
			// DKG completed, feeding stale messages should fail
			if _, err := c.Next(roundC); err == nil {
				t.Fatal("expected error on completed DKG session")
			} else {
				var tssErr *TssError
				if !errors.As(err, &tssErr) {
					t.Fatalf("expected TssError, got %T", err)
				}
			}
			break
		}
		roundC = stepD.Messages
		roundD = stepC.Messages
	}
}
