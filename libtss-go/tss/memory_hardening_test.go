package tss

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// SecureBytes lifecycle verification
// ---------------------------------------------------------------------------

func TestSecureBytesFullLifecycle(t *testing.T) {
	// Simulates: export → seal → open → destroy
	secret := []byte("key-material-for-lifecycle-test!!")
	original := make([]byte, len(secret))
	copy(original, secret)

	// Step 1: Create SecureBytes (moves data to locked memory, wipes source)
	sb := NewSecureBytes(secret)
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("NewSecureBytes did not wipe source slice")
	}
	if !bytes.Equal(sb.Bytes(), original) {
		t.Fatal("SecureBytes does not hold expected data")
	}

	// Step 2: Seal into Enclave (encrypted at rest)
	enclave := sb.Seal()
	if sb.Bytes() != nil {
		t.Fatal("Bytes() should be nil after Seal")
	}
	if enclave == nil {
		t.Fatal("Seal returned nil enclave")
	}

	// Step 3: Open the Enclave to recover data
	buf, err := enclave.Open()
	if err != nil {
		t.Fatalf("enclave.Open() failed: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), original) {
		t.Fatalf("round-trip mismatch: got %x, want %x", buf.Bytes(), original)
	}

	// Step 4: Destroy
	buf.Destroy()
}

// ---------------------------------------------------------------------------
// WipeBytes verification
// ---------------------------------------------------------------------------

func TestWipeBytesZeroesAllBytes(t *testing.T) {
	sizes := []int{1, 16, 32, 64, 256, 1024}
	for _, sz := range sizes {
		data := make([]byte, sz)
		for i := range data {
			data[i] = byte(i%255 + 1) // non-zero fill
		}
		WipeBytes(data)
		for i, b := range data {
			if b != 0 {
				t.Errorf("size=%d: byte %d = 0x%02x, want 0x00", sz, i, b)
			}
		}
	}
}

func TestWipeBytesEdgeCases(t *testing.T) {
	// nil and empty must not panic
	WipeBytes(nil)
	WipeBytes([]byte{})
}

// ---------------------------------------------------------------------------
// SecureBytes edge cases
// ---------------------------------------------------------------------------

func TestSecureBytesDestroyIdempotent(t *testing.T) {
	sb := NewSecureBytes([]byte("test-data-padding-32-bytes!!!!!"))
	sb.Destroy()
	sb.Destroy() // must not panic
	sb.Destroy() // triple destroy
}

func TestSecureBytesNilReceiver(t *testing.T) {
	var sb *SecureBytes
	// All methods on nil receiver must not panic
	if sb.Bytes() != nil {
		t.Error("nil.Bytes() should return nil")
	}
	if sb.Size() != 0 {
		t.Error("nil.Size() should return 0")
	}
	sb.Destroy()
	if sb.Seal() != nil {
		t.Error("nil.Seal() should return nil")
	}
}

func TestSecureBytesEmptyData(t *testing.T) {
	sb := NewSecureBytes([]byte{})
	if sb.Bytes() != nil {
		t.Error("empty.Bytes() should return nil")
	}
	if sb.Size() != 0 {
		t.Error("empty.Size() should return 0")
	}
	sb.Destroy() // should not panic
}

// ---------------------------------------------------------------------------
// FrostSplitKey wipes caller's secret key
// ---------------------------------------------------------------------------

func TestFrostSplitKeyWipesSecretKey(t *testing.T) {
	// Generate dealer keys first to get a valid secret key format
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	for _, s := range shares {
		defer s.Free()
	}

	// Export a key share to get serialized bytes, then re-import to
	// demonstrate that FrostSplitKey wipes its input. We use a known
	// 32-byte key for Ed25519.
	secretKey := make([]byte, 32)
	for i := range secretKey {
		secretKey[i] = byte(i + 1) // non-zero fill
	}
	original := make([]byte, len(secretKey))
	copy(original, secretKey)

	// FrostSplitKey will likely fail with our random key, but it should
	// still wipe the input via defer WipeBytes(secretKey).
	_, _, _ = FrostSplitKey(CiphersuiteEd25519, secretKey, 3, 2)

	// Verify the caller's slice was wiped
	if bytes.Equal(secretKey, original) {
		t.Error("FrostSplitKey did not wipe the secretKey slice")
	}
	for i, b := range secretKey {
		if b != 0 {
			t.Errorf("byte %d = 0x%02x, want 0x00 after wipe", i, b)
		}
	}
}

// ---------------------------------------------------------------------------
// Handle double-free safety
// ---------------------------------------------------------------------------

func TestKeyShareHandleDoubleFree(t *testing.T) {
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	// Free all but one
	for _, s := range shares[1:] {
		s.Free()
	}
	// Free the first one twice — must not panic
	shares[0].Free()
	shares[0].Free()
}

func TestKeyShareHandleNilFree(t *testing.T) {
	var h *KeyShareHandle
	h.Free() // nil receiver must not panic
}

// ---------------------------------------------------------------------------
// ExportKeyShareSecure lifecycle
// ---------------------------------------------------------------------------

func TestExportKeyShareSecureLifecycle(t *testing.T) {
	shares, _, err := FrostGenerateDealer(CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	for _, s := range shares {
		defer s.Free()
	}

	// Export securely (into locked memory)
	secure, err := ExportKeyShareSecure(shares[0])
	if err != nil {
		t.Fatalf("ExportKeyShareSecure: %v", err)
	}
	if secure == nil || secure.Size() == 0 {
		t.Fatal("ExportKeyShareSecure returned empty SecureBytes")
	}

	// Re-import from secure bytes
	suite, err := shares[0].Ciphersuite()
	if err != nil {
		t.Fatalf("Ciphersuite: %v", err)
	}
	reimported, err := ImportKeyShareSecure(suite, secure)
	if err != nil {
		t.Fatalf("ImportKeyShareSecure: %v", err)
	}
	defer reimported.Free()

	// Verify the reimported key share has the same identifier
	origID, _ := shares[0].Identifier()
	newID, _ := reimported.Identifier()
	if origID != newID {
		t.Errorf("identifier mismatch: original=%d, reimported=%d", origID, newID)
	}

	// Destroy secure bytes
	secure.Destroy()
	if secure.Bytes() != nil {
		t.Error("SecureBytes.Bytes() should return nil after Destroy")
	}
}

// ---------------------------------------------------------------------------
// Init with mlock
// ---------------------------------------------------------------------------

func TestInitWithMlock(t *testing.T) {
	// Init with mlock may fail without privileges, but must not panic
	err := Init(OptMlock)
	if err != nil {
		t.Logf("Init(OptMlock) failed (expected without CAP_IPC_LOCK): %v", err)
	}
}

func TestInitIdempotent(t *testing.T) {
	// Calling Init multiple times must not panic
	_ = Init()
	_ = Init()
}
