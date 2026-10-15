package tss

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// Mirrors of the C status codes; cgo constants are not reachable from _test.go files.
const (
	tssErrInvalidConfigCode = 1
	tssErrInvalidIDCode     = 2
	tssErrInvalidShareCode  = 3
	tssErrDeserializeCode   = 9
)

var (
	repairSessionID  = []byte("go-repair-sid")
	refreshSessionID = []byte("go-refresh-sid")
)

func repairTerms(t *testing.T, shares []*KeyShareHandle, helpers []Identifier, target Identifier, sessionID []byte) [][]byte {
	t.Helper()
	terms := make([][]byte, len(helpers))
	for i, helper := range helpers {
		term, err := RepairHelperTerm(shares[helper-1], helpers, target, sessionID)
		if err != nil {
			t.Fatalf("RepairHelperTerm(helper %d): %v", helper, err)
		}
		if len(term) != 32 {
			t.Fatalf("term from helper %d is %d bytes, want 32", helper, len(term))
		}
		terms[i] = term
	}
	return terms
}

func assertTssCode(t *testing.T, err error, code int32, context string) {
	t.Helper()
	var tssErr *TssError
	if !errors.As(err, &tssErr) {
		t.Fatalf("%s: expected *TssError, got %T (%v)", context, err, err)
	}
	if tssErr.Code != code {
		t.Fatalf("%s: code %d (%s), want %d", context, tssErr.Code, tssErr.Message, code)
	}
}

func TestDKLs23RepairAndRefresh(t *testing.T) {
	shares, pubkeys := runDKG(t, CiphersuiteSecp256k1ECDSA, 5, 3, []byte("repair-dkg"))
	const target Identifier = 2

	lostShare, err := shares[target-1].VerifyingShare()
	if err != nil {
		t.Fatalf("VerifyingShare: %v", err)
	}
	chainCode, err := shares[0].ChainCode()
	if err != nil {
		t.Fatalf("ChainCode: %v", err)
	}
	packageBytes, err := shares[0].PublicKeyPackageBytes()
	if err != nil {
		t.Fatalf("PublicKeyPackageBytes: %v", err)
	}
	shares[target-1].Free()

	helpers := []Identifier{1, 3, 4}
	terms := repairTerms(t, shares, helpers, target, repairSessionID)
	hollow, err := RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, target, terms, repairSessionID)
	if err != nil {
		t.Fatalf("RepairAssemble: %v", err)
	}
	defer hollow.Free()

	if id, err := hollow.Identifier(); err != nil || id != target {
		t.Fatalf("hollow identifier = %d, %v; want %d", id, err, target)
	}
	if got, err := hollow.VerifyingShare(); err != nil || !bytes.Equal(got, lostShare) {
		t.Fatalf("hollow verifying share mismatch (err %v)", err)
	}
	if got, err := hollow.GroupKey(); err != nil || !bytes.Equal(got, pubkeys.VerifyingKey) {
		t.Fatalf("hollow group key mismatch (err %v)", err)
	}
	if got, err := hollow.ChainCode(); err != nil || !bytes.Equal(got, chainCode) {
		t.Fatalf("hollow chain code mismatch (err %v)", err)
	}

	hash := sha256.Sum256([]byte("hollow"))
	_, _, err = NewSignSession(hollow, hash[:], []Identifier{1, 3}, []byte("sign"))
	assertTssCode(t, err, tssErrInvalidShareCode, "signing with a hollow share")

	_, err = RepairHelperTerm(hollow, []Identifier{2, 3, 4}, 1, repairSessionID)
	assertTssCode(t, err, tssErrInvalidShareCode, "helping with a hollow share")

	group := append([]*KeyShareHandle(nil), shares...)
	group[target-1] = hollow
	refreshed := runDKLsRefresh(t, group, refreshSessionID)
	for i, share := range refreshed {
		defer share.Free()
		id, err := share.Identifier()
		if err != nil || id != Identifier(i+1) {
			t.Fatalf("refreshed identifier %d = %d, %v", i+1, id, err)
		}
		groupKey, err := share.GroupKey()
		if err != nil || !bytes.Equal(groupKey, pubkeys.VerifyingKey) {
			t.Fatalf("refreshed share %d changed the group key (err %v)", i+1, err)
		}
		got, err := share.ChainCode()
		if err != nil || !bytes.Equal(got, chainCode) {
			t.Fatalf("refreshed share %d changed the chain code (err %v)", i+1, err)
		}
		before, err := group[i].VerifyingShare()
		if err != nil {
			t.Fatalf("VerifyingShare(before %d): %v", i+1, err)
		}
		after, err := share.VerifyingShare()
		if err != nil {
			t.Fatalf("VerifyingShare(after %d): %v", i+1, err)
		}
		if bytes.Equal(before, after) {
			t.Fatalf("refresh did not move share %d", i+1)
		}
	}

	msg := []byte("after repair and refresh")
	digest := sha256.Sum256(msg)
	for _, quorum := range [][]Identifier{{1, 2, 3}, {2, 4, 5}} {
		signers := make([]*KeyShareHandle, len(quorum))
		for i, id := range quorum {
			signers[i] = refreshed[id-1]
		}
		sig := runSignRound(t, CiphersuiteSecp256k1ECDSA, signers, digest[:])
		valid, err := Verify(CiphersuiteSecp256k1ECDSA, msg, sig.Data, pubkeys.VerifyingKey)
		if err != nil || !valid {
			t.Fatalf("quorum %v: signature invalid (err %v)", quorum, err)
		}
	}
}

func TestDKLs23RepairRejectsBadInputs(t *testing.T) {
	shares, _ := runDKG(t, CiphersuiteSecp256k1ECDSA, 3, 2, []byte("repair-negatives"))
	for _, share := range shares {
		defer share.Free()
	}
	chainCode, err := shares[0].ChainCode()
	if err != nil {
		t.Fatalf("ChainCode: %v", err)
	}
	packageBytes, err := shares[0].PublicKeyPackageBytes()
	if err != nil {
		t.Fatalf("PublicKeyPackageBytes: %v", err)
	}
	helpers := []Identifier{1, 3}
	terms := repairTerms(t, shares, helpers, 2, repairSessionID)

	_, err = RepairHelperTerm(shares[0], []Identifier{1, 2}, 2, repairSessionID)
	assertTssCode(t, err, tssErrInvalidConfigCode, "helpers containing the target")
	_, err = RepairHelperTerm(shares[0], []Identifier{1}, 2, repairSessionID)
	assertTssCode(t, err, tssErrInvalidConfigCode, "too few helpers")
	_, err = RepairHelperTerm(shares[0], []Identifier{1, 4}, 2, repairSessionID)
	assertTssCode(t, err, tssErrInvalidIDCode, "helper outside the group")
	if _, err := RepairHelperTerm(shares[0], helpers, 2, nil); err == nil {
		t.Fatal("RepairHelperTerm accepted an empty session id")
	}
	if _, err := RepairHelperTerm(nil, helpers, 2, repairSessionID); err == nil {
		t.Fatal("RepairHelperTerm accepted a nil share")
	}

	tampered := [][]byte{append([]byte(nil), terms[0]...), terms[1]}
	tampered[0][31] ^= 1
	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 2, tampered, repairSessionID)
	assertTssCode(t, err, tssErrInvalidShareCode, "tampered term")

	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 2, terms[:1], repairSessionID)
	assertTssCode(t, err, tssErrInvalidConfigCode, "too few terms")

	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode[:31], 2, terms, repairSessionID)
	assertTssCode(t, err, tssErrInvalidConfigCode, "short chain code")

	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 3, terms, repairSessionID)
	assertTssCode(t, err, tssErrInvalidShareCode, "terms for another target")

	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes[:len(packageBytes)-1], chainCode, 2, terms, repairSessionID)
	assertTssCode(t, err, tssErrDeserializeCode, "truncated package")

	otherSID := repairTerms(t, shares, helpers, 2, []byte("other-sid"))
	mixed := [][]byte{terms[0], otherSID[1]}
	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 2, mixed, repairSessionID)
	assertTssCode(t, err, tssErrInvalidShareCode, "terms from different repair sessions")

	if _, err := RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 2, terms, nil); err == nil {
		t.Fatal("RepairAssemble accepted an empty session id")
	}
	if _, err := RepairAssemble(CiphersuiteSecp256k1ECDSA, packageBytes, chainCode, 2, nil, repairSessionID); err == nil {
		t.Fatal("RepairAssemble accepted no terms")
	}

	frost, _ := runDKG(t, CiphersuiteEd25519, 3, 2, nil)
	for _, share := range frost {
		defer share.Free()
	}
	_, err = RepairHelperTerm(frost[0], helpers, 2, repairSessionID)
	assertTssCode(t, err, tssErrProtoMismatchCode, "FROST share as helper")
	frostPackage, err := frost[0].PublicKeyPackageBytes()
	if err != nil {
		t.Fatalf("PublicKeyPackageBytes(frost): %v", err)
	}
	_, err = RepairAssemble(CiphersuiteSecp256k1ECDSA, frostPackage, chainCode, 2, terms, repairSessionID)
	assertTssCode(t, err, tssErrProtoMismatchCode, "FROST package")
}
