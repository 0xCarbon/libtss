package tss

import (
	"bytes"
	"testing"
)

func TestSecureBytesLifecycle(t *testing.T) {
	data := []byte("secret-key-material-32-bytes!!!!")
	original := make([]byte, len(data))
	copy(original, data)

	sb := NewSecureBytes(data)

	// Source should be wiped
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Error("NewSecureBytes did not wipe source slice")
	}

	// SecureBytes should hold the original data
	if !bytes.Equal(sb.Bytes(), original) {
		t.Errorf("got %x, want %x", sb.Bytes(), original)
	}
	if sb.Size() != len(original) {
		t.Errorf("size = %d, want %d", sb.Size(), len(original))
	}

	sb.Destroy()

	// After destroy, Bytes should return nil
	if sb.Bytes() != nil {
		t.Error("Bytes() should return nil after Destroy")
	}
	if sb.Size() != 0 {
		t.Error("Size() should return 0 after Destroy")
	}

	// Double destroy should not panic
	sb.Destroy()
}

func TestSecureBytesSealOpen(t *testing.T) {
	data := []byte("round-trip-test-data-padding!!!!!")
	original := make([]byte, len(data))
	copy(original, data)

	sb := NewSecureBytes(data)
	enclave := sb.Seal()

	// After seal, SecureBytes is destroyed
	if sb.Bytes() != nil {
		t.Error("Bytes() should return nil after Seal")
	}

	// Open the enclave to recover data
	if enclave == nil {
		t.Fatal("Seal returned nil enclave")
	}
	buf, err := enclave.Open()
	if err != nil {
		t.Fatalf("enclave.Open() failed: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), original) {
		t.Errorf("got %x, want %x", buf.Bytes(), original)
	}
	buf.Destroy()
}

func TestWipeBytes(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	WipeBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestWipeBytesNil(t *testing.T) {
	// Should not panic
	WipeBytes(nil)
	WipeBytes([]byte{})
}

func TestSecureBytesNil(t *testing.T) {
	// Nil SecureBytes should not panic
	var sb *SecureBytes
	if sb.Bytes() != nil {
		t.Error("nil SecureBytes.Bytes() should return nil")
	}
	if sb.Size() != 0 {
		t.Error("nil SecureBytes.Size() should return 0")
	}
	sb.Destroy() // should not panic

	if sb.Seal() != nil {
		t.Error("nil SecureBytes.Seal() should return nil")
	}
}

func TestSecureBytesEmpty(t *testing.T) {
	sb := NewSecureBytes([]byte{})
	if sb.Bytes() != nil {
		t.Error("empty SecureBytes.Bytes() should return nil")
	}
	if sb.Size() != 0 {
		t.Error("empty SecureBytes.Size() should return 0")
	}
	sb.Destroy()
}
