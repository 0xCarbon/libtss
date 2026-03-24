package tss

import "github.com/awnumar/memguard"

// WipeBytes zeroes a byte slice in-place. Best-effort: the Go GC may
// have already copied the data to a different heap page. Use
// SecureBytes for guaranteed protection of sensitive data.
func WipeBytes(b []byte) {
	memguard.WipeBytes(b)
}

// SecureBytes holds sensitive data in mmap'd, mlock'd memory outside
// the Go GC heap. The underlying buffer cannot be copied or moved by
// the garbage collector.
//
// NOT safe for concurrent use — callers must synchronize externally
// or use Seal()/Open() for thread-safe encrypted storage.
type SecureBytes struct {
	buf *memguard.LockedBuffer
}

// NewSecureBytes copies data into a locked memory buffer and zeroes
// the source slice. The caller should not use the source slice after
// this call.
func NewSecureBytes(data []byte) *SecureBytes {
	if len(data) == 0 {
		return &SecureBytes{}
	}
	buf := memguard.NewBufferFromBytes(data)
	return &SecureBytes{buf: buf}
}

// Bytes returns a slice into the locked buffer. The returned slice
// is only valid until Destroy() is called.
func (s *SecureBytes) Bytes() []byte {
	if s == nil || s.buf == nil {
		return nil
	}
	return s.buf.Bytes()
}

// Size returns the number of bytes held.
func (s *SecureBytes) Size() int {
	if s == nil || s.buf == nil {
		return 0
	}
	return s.buf.Size()
}

// Destroy zeroes and unmaps the locked buffer. Idempotent.
func (s *SecureBytes) Destroy() {
	if s == nil || s.buf == nil {
		return
	}
	s.buf.Destroy()
	s.buf = nil
}

// Seal encrypts the buffer contents in place and returns an Enclave
// that can be later opened to recover the data. The SecureBytes is
// destroyed after sealing.
func (s *SecureBytes) Seal() *memguard.Enclave {
	if s == nil || s.buf == nil {
		return nil
	}
	enclave := s.buf.Seal()
	s.buf = nil
	return enclave
}
