package tss

import "testing"

func TestFrostDealerTweakSignAggregate(t *testing.T) {
	shares, pubkeyBytes, err := FrostGenerateDealer(CiphersuiteSecp256k1Taproot, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}
	for _, s := range shares {
		defer s.Free()
	}

	// Tweak 2 shares for signing
	tweaked0, err := FrostTweakKeyShare(shares[0], nil)
	if err != nil {
		t.Fatalf("FrostTweakKeyShare(0): %v", err)
	}
	defer tweaked0.Free()
	tweaked1, err := FrostTweakKeyShare(shares[1], nil)
	if err != nil {
		t.Fatalf("FrostTweakKeyShare(1): %v", err)
	}
	defer tweaked1.Free()

	// Tweak pubkey package
	tweakedPubkey, err := FrostTweakPubkeyPackage(pubkeyBytes, nil)
	if err != nil {
		t.Fatalf("FrostTweakPubkeyPackage: %v", err)
	}

	msg := []byte("hello taproot frost")

	// Start sign sessions (round 1: commitments)
	s0, commitMsgs0, err := NewSignSession(tweaked0, msg, nil, nil)
	if err != nil {
		t.Fatalf("NewSignSession(0): %v", err)
	}
	defer s0.Free()
	s1, commitMsgs1, err := NewSignSession(tweaked1, msg, nil, nil)
	if err != nil {
		t.Fatalf("NewSignSession(1): %v", err)
	}
	defer s1.Free()

	// Round 2: exchange commitments → get signature shares
	step0, err := s0.Next(commitMsgs1)
	if err != nil {
		t.Fatalf("Sign round2(0): %v", err)
	}
	step1, err := s1.Next(commitMsgs0)
	if err != nil {
		t.Fatalf("Sign round2(1): %v", err)
	}
	shareMsgs0 := step0.Messages
	shareMsgs1 := step1.Messages

	// Round 3: exchange shares → complete
	step0, err = s0.Next(shareMsgs1)
	if err != nil {
		t.Fatalf("Sign round3(0): %v", err)
	}
	if !step0.Complete {
		t.Fatal("expected signing to complete after round 3")
	}

	// Test FrostAggregate (coordinator flow) with captured messages
	allCommits := append(commitMsgs0, commitMsgs1...)
	commitBlob, err := BuildMessages(allCommits)
	if err != nil {
		t.Fatalf("BuildMessages commits: %v", err)
	}
	allShares := append(shareMsgs0, shareMsgs1...)
	sharesBlob, err := BuildMessages(allShares)
	if err != nil {
		t.Fatalf("BuildMessages shares: %v", err)
	}

	sig, err := FrostAggregate(CiphersuiteSecp256k1Taproot, msg, commitBlob, sharesBlob, tweakedPubkey)
	if err != nil {
		t.Fatalf("FrostAggregate: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty aggregated signature")
	}
}

func TestFrostDealerRefresh(t *testing.T) {
	shares, pubkeyBytes, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	for _, s := range shares {
		defer s.Free()
	}

	participants := []Identifier{1, 2, 3}
	refreshMap, newPubkey, err := FrostRefreshDealer(pubkeyBytes, participants)
	if err != nil {
		t.Fatalf("FrostRefreshDealer: %v", err)
	}
	if len(refreshMap) != 3 {
		t.Fatalf("expected 3 refresh shares, got %d", len(refreshMap))
	}

	refreshedShares := make([]*KeyShareHandle, 3)
	for i := 0; i < 3; i++ {
		id := Identifier(i + 1)
		refreshData, ok := refreshMap[id]
		if !ok {
			t.Fatalf("missing refresh data for participant %d", id)
		}
		rs, err := FrostApplyRefresh(shares[i], refreshData, newPubkey)
		if err != nil {
			t.Fatalf("FrostApplyRefresh(%d): %v", i+1, err)
		}
		refreshedShares[i] = rs
		defer rs.Free()
	}

	sig := runSignRound(t, CiphersuiteEd25519, refreshedShares[:2], []byte("refreshed dealer"))
	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature after dealer refresh")
	}
}

func TestFrostRepair(t *testing.T) {
	shares, pubkeyBytes, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	for _, s := range shares {
		defer s.Free()
	}

	helpers := []Identifier{1, 2}
	participant := Identifier(3)

	// Part 1: each helper generates deltas for other helpers
	deltaMap0, err := FrostRepairPart1(shares[0], helpers, participant)
	if err != nil {
		t.Fatalf("FrostRepairPart1(1): %v", err)
	}
	deltaMap1, err := FrostRepairPart1(shares[1], helpers, participant)
	if err != nil {
		t.Fatalf("FrostRepairPart1(2): %v", err)
	}

	// Part 2: each helper combines deltas addressed to it from ALL helpers
	sigma0, err := FrostRepairPart2(CiphersuiteEd25519, [][]byte{
		deltaMap0[Identifier(1)], deltaMap1[Identifier(1)],
	})
	if err != nil {
		t.Fatalf("FrostRepairPart2(1): %v", err)
	}
	sigma1, err := FrostRepairPart2(CiphersuiteEd25519, [][]byte{
		deltaMap0[Identifier(2)], deltaMap1[Identifier(2)],
	})
	if err != nil {
		t.Fatalf("FrostRepairPart2(2): %v", err)
	}

	// Part 3: reconstruct the lost share
	repairedShare, err := FrostRepairPart3([][]byte{sigma0, sigma1}, participant, pubkeyBytes)
	if err != nil {
		t.Fatalf("FrostRepairPart3: %v", err)
	}
	defer repairedShare.Free()

	sig := runSignRound(t, CiphersuiteEd25519, []*KeyShareHandle{shares[0], repairedShare}, []byte("repaired"))
	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature with repaired share")
	}
}

func TestFrostSplitKey(t *testing.T) {
	const secretKeyLen = 32
	const testScalarVal = 42
	secretKey := make([]byte, secretKeyLen)
	secretKey[0] = testScalarVal // valid scalar in little-endian

	splitShares, pubkey, err := FrostSplitKey(CiphersuiteEd25519, secretKey, 3, 2)
	if err != nil {
		t.Fatalf("FrostSplitKey: %v", err)
	}
	if len(splitShares) != 3 {
		t.Fatalf("expected 3 split shares, got %d", len(splitShares))
	}
	for _, s := range splitShares {
		defer s.Free()
	}
	if len(pubkey) == 0 {
		t.Fatal("expected non-empty pubkey from split")
	}

	sig := runSignRound(t, CiphersuiteEd25519, splitShares[:2], []byte("split key"))
	if len(sig.Data) == 0 {
		t.Fatal("expected non-empty signature from split key shares")
	}
}
