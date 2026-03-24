# 06 - FFI Layer

## Architecture: Standard C ABI

The `libtss-ffi` crate exposes the library as a standard C-compatible interface:
`extern "C"` functions with a cbindgen-generated header (`libtss.h`). This is
the universal approach — every language has a mechanism to call C functions.

### Why C ABI (Not Language-Specific FFI)

| Criterion | C ABI | rust2go | PyO3 | wasm-bindgen |
|-----------|-------|---------|------|--------------|
| Languages supported | All | Go only | Python only | JS/TS only |
| Call overhead | ~40-70ns (cgo) | ~2.3ns | ~50ns | ~10ns (WASM) |
| Maintenance | 1 FFI layer | N language-specific layers | N layers | N layers |
| Stability | Decades-old ABI | Niche, Go-version-dependent | Python-version-dependent | Evolving |

The overhead difference (~40ns vs ~2.3ns) is irrelevant for threshold signing:
a single FROST signing round takes ~1ms of cryptographic computation. The FFI
overhead is < 0.01% of total time regardless of approach.

Language-specific optimizations (rust2go for Go, PyO3 for Python, wasm-bindgen
for TS) can be layered on top of the C ABI if profiling justifies it.

## C ABI Conventions

### Naming

All exported symbols use the `tss_` prefix to avoid namespace collisions:

```
tss_dkg_new()
tss_sign_next()
tss_handle_free()
```

### Return Convention

Functions return a status code. Output data is written to caller-provided pointers.

```c
typedef int32_t TssStatus;

#define TSS_OK                 0
#define TSS_ERR_INVALID_CONFIG 1
#define TSS_ERR_INVALID_ID     2
#define TSS_ERR_INVALID_SHARE  3
#define TSS_ERR_INVALID_COMMIT 4
#define TSS_ERR_INVALID_SIG    5
#define TSS_ERR_NONCE_REUSE    6
#define TSS_ERR_HANDLE_INVALID 7
#define TSS_ERR_PROTO_MISMATCH 8
#define TSS_ERR_DESERIALIZE    9
#define TSS_ERR_ABORT          10   // Recoverable protocol abort (safe to retry)
#define TSS_ERR_ABORT_BAN      11   // Ban abort: counterparty MUST be permanently excluded
#define TSS_ERR_TWEAK          13
#define TSS_ERR_SESSION_COMPLETE 14
#define TSS_ERR_INTERNAL_PANIC 255
```

### Buffer Convention

Variable-length output uses library-allocated buffers:

```c
/// Buffer allocated by the library. Caller must free with tss_buffer_free().
typedef struct {
    uint8_t *data;
    size_t len;
} TssBuffer;

/// Free a buffer allocated by the library. Data is zeroed before
/// deallocation to prevent secrets from persisting in freed heap memory.
/// After free, the same TssBuffer instance is reset to empty so that
/// re-calling free on it is a no-op (but freeing a *copy* of the struct
/// that was made before the first free is still a double-free).
void tss_buffer_free(TssBuffer *buf);
```

Language bindings choose whichever pattern fits their FFI model:
- **Go (cgo)**: Library-allocated `TssBuffer` — Go copies bytes, then frees.
- **Rust**: Direct crate dependency — no FFI needed, uses native types.
- **React Native**: Library-allocated `TssBuffer` — native module copies to JS ArrayBuffer, then frees.

### Handle Convention

Opaque handles are `uint64_t` values. They reference Rust-managed state:

```c
typedef uint64_t TssHandle;

/// Free a handle and zero its secret material. Idempotent.
void tss_handle_free(TssHandle handle);
```

### Initialization

```c
#define TSS_INIT_MLOCK 1

/// Perform optional one-time initialization.
/// TSS_INIT_MLOCK: call mlockall() to prevent swap.
/// Requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK.
TssStatus tss_init(uint32_t flags);
```

### Error Messages

When a function returns a non-zero status, an error message is available:

```c
/// Get the error message from the last failed call on this thread.
/// Returns a pointer to a thread-local string. Valid until the next FFI call.
const char* tss_last_error(void);

/// Get the error message length.
size_t tss_last_error_len(void);

/// Copy the last error message into a caller-provided buffer.
/// Returns bytes needed (including NUL). If buf is NULL or buf_len is 0,
/// only the required size is returned. Recommended over tss_last_error
/// as it avoids the TOCTOU window between tss_last_error_len and tss_last_error.
size_t tss_last_error_copy(uint8_t *buf, size_t buf_len);
```

For abort errors, culprit and ban information is available:

```c
/// Get the number of culprits from the last abort error.
size_t tss_abort_culprit_count(void);

/// Get a culprit identifier by index.
uint16_t tss_abort_culprit(size_t index);

/// Get the party that must be banned (only valid after TSS_ERR_ABORT_BAN).
/// Returns the 1-based party index that MUST be permanently excluded from
/// all future sessions. Returns 0 if the last error was not a ban abort.
uint16_t tss_abort_banned_party(void);
```

**Ban abort handling**: When a function returns `TSS_ERR_ABORT_BAN`, the application
MUST call `tss_abort_banned_party()` to identify the offending counterparty and
permanently exclude them from all future signing, refresh, and DKG sessions involving
the same key group. This is a security-critical requirement — the DKLs23 protocol
reuses OT correlations across sessions, and continued interaction with a cheating
party enables gradual private key extraction. See
[05-dkls23-integration.md](../spec/05-dkls23-integration.md#error-handling) for details.

## Message Wire Format

The unified `Message` type is serialized as a concatenated sequence of TLV-framed
messages in `TssBuffer`. Each message has a fixed 8-byte header:

```
┌──────────────┬───────────────┬──────────────┬──────────────────────┐
│ from (2B LE) │ to (2B LE)   │ len (4B LE)  │ data (len bytes)     │
│              │ 0 = broadcast │              │                      │
└──────────────┴───────────────┴──────────────┴──────────────────────┘
```

- `from`: 1-based participant identifier of the sender
- `to`: 1-based recipient identifier, or `0` for broadcast
- `len`: byte length of the `data` payload
- `data`: opaque protocol message content

A `TssBuffer` returned by session functions (`tss_dkg_new`, `tss_dkg_next`, etc.)
contains zero or more concatenated messages in this format.

### Message Helper Functions

```c
/// Count messages in a concatenated message buffer.
size_t tss_message_count(TssSlice messages);

/// Extract a message by index from a concatenated buffer.
/// Returns TSS_OK on success, TSS_ERR_INVALID_CONFIG if index is out of range.
TssStatus tss_message_at(
    TssSlice messages, size_t index,
    uint16_t *out_from, uint16_t *out_to, TssSlice *out_data
);

/// Build a concatenated message buffer from individual messages.
/// Call repeatedly to append messages, then pass the buffer to tss_*_next().
TssStatus tss_message_build(
    TssBuffer *buf,          // in/out: buffer to append to (initialize to {NULL, 0})
    uint16_t from, uint16_t to,
    const uint8_t *data, size_t data_len
);
```

### Go Usage Example

```go
// Parsing output messages
msgs := parseMessages(outBuf) // reads TLV headers, returns []Message
for _, msg := range msgs {
    if msg.To == 0 {
        transport.Broadcast(msg.Data)
    } else {
        transport.SendTo(msg.To, msg.Data)
    }
}

// Building input messages from received data
var buf C.TssBuffer
for _, msg := range received {
    C.tss_message_build(&buf, msg.From, msg.To, msg.Data, msg.Len)
}
defer C.tss_buffer_free(buf)
// pass buf to tss_dkg_next() or tss_sign_next()
```

## Complete C Header

```c
// libtss.h — generated by cbindgen. Do not edit.

#ifndef LIBTSS_H
#define LIBTSS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef int32_t TssStatus;
typedef uint64_t TssHandle;

typedef struct {
    uint8_t *data;
    size_t len;
} TssBuffer;

typedef struct {
    const uint8_t *data;
    size_t len;
} TssSlice;

// --- Initialization ---
TssStatus tss_init(uint32_t flags);

// --- Error Handling ---
const char* tss_last_error(void);
size_t tss_last_error_len(void);
size_t tss_last_error_copy(uint8_t *buf, size_t buf_len);
size_t tss_abort_culprit_count(void);
uint16_t tss_abort_culprit(size_t index);
uint16_t tss_abort_banned_party(void);

// --- Memory ---
void tss_buffer_free(TssBuffer *buf);
void tss_handle_free(TssHandle handle);
void tss_session_free(TssHandle session);

// --- Handle Queries ---
TssStatus tss_handle_identifier(TssHandle handle, uint16_t *out_id);
TssStatus tss_handle_verifying_share(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_group_key(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_pubkey_package(TssHandle handle, TssBuffer *out);
uint8_t   tss_handle_ciphersuite(TssHandle handle);

// --- Message Helpers ---
size_t    tss_message_count(TssSlice messages);
TssStatus tss_message_at(TssSlice messages, size_t index,
                          uint16_t *out_from, uint16_t *out_to, TssSlice *out_data);
TssStatus tss_message_build(TssBuffer *buf, uint16_t from, uint16_t to,
                             const uint8_t *data, size_t data_len);

// ============================================================
// Unified Session API
// ============================================================

// --- DKG ---

/// Create a DKG session and produce first-round messages.
/// session_id: required for DKLs23 (domain separation); NULL for FROST.
/// out_messages: concatenated Message buffer (parse with tss_message_*).
TssStatus tss_dkg_new(
    uint8_t suite, uint16_t self_id,
    uint16_t max_signers, uint16_t min_signers,
    const uint8_t *session_id, size_t session_id_len,
    TssHandle *out_session, TssBuffer *out_messages
);

/// Advance the DKG session with received messages.
/// out_complete: set to true when DKG is finished.
/// When complete: out_key_share is valid, out_pubkey_package is filled.
/// When not complete: out_messages contains messages to send.
TssStatus tss_dkg_next(
    TssHandle session,
    TssSlice messages,
    TssHandle *out_key_share,
    TssBuffer *out_pubkey_package,
    TssBuffer *out_messages,
    bool *out_complete
);

// --- Signing ---

/// Create a signing session and produce first-round messages.
/// counterparties: array of participant IDs in this signing group (DKLs23 needs
///   the full participant set upfront; NULL for FROST, which discovers peers
///   from received messages).
/// sign_id: optional session-unique signing ID for domain separation (DKLs23);
///   NULL for FROST.
TssStatus tss_sign_new(
    TssHandle key_share, TssSlice message,
    const uint16_t *counterparties, size_t counterparties_len,
    const uint8_t *sign_id, size_t sign_id_len,
    TssHandle *out_session, TssBuffer *out_messages
);

/// Advance the signing session with received messages.
/// When complete: out_signature is filled (64-65 bytes).
/// When not complete: out_messages contains messages to send.
TssStatus tss_sign_next(
    TssHandle session,
    TssSlice messages,
    TssBuffer *out_signature,
    TssBuffer *out_messages,
    bool *out_complete
);

// --- Refresh ---

/// Create a share refresh session and produce first-round messages.
/// participants: array of all participant IDs in the refresh group.
TssStatus tss_refresh_new(
    TssHandle key_share,
    const uint16_t *participants, size_t participants_len,
    TssHandle *out_session, TssBuffer *out_messages
);

/// Create a FROST refresh receiver session (non-dealer participant).
/// The receiver waits for messages from the dealer refresh and does
/// not produce initial messages. Use with tss_frost_refresh_dealer.
TssStatus tss_refresh_receiver(
    TssHandle key_share,
    TssHandle *out_session
);

/// Advance the refresh session with received messages.
TssStatus tss_refresh_next(
    TssHandle session,
    TssSlice messages,
    TssHandle *out_key_share,
    TssBuffer *out_pubkey_package,
    TssBuffer *out_messages,
    bool *out_complete
);

// ============================================================
// FROST-Specific Operations
// ============================================================

// --- Aggregation (coordinator-only deployments) ---

/// Aggregate FROST signature shares into a final Schnorr signature.
/// commitments/shares: concatenated Message buffers from signers' rounds 1/2.
TssStatus tss_frost_aggregate(
    uint8_t suite, TssSlice message,
    TssSlice commitments,
    TssSlice shares,
    TssSlice pubkey_package,
    TssBuffer *out_signature
);

// --- Tweaking (BIP-341) ---

TssStatus tss_frost_tweak_key_share(
    TssHandle key_share,
    const uint8_t *merkle_root, size_t merkle_root_len,
    TssHandle *out_tweaked_share
);

TssStatus tss_frost_tweak_pubkey_package(
    TssSlice pubkey_package,
    const uint8_t *merkle_root, size_t merkle_root_len,
    TssBuffer *out_tweaked_package
);

// --- Key Generation (non-interactive) ---

TssStatus tss_frost_generate_dealer(
    uint8_t suite, uint16_t max_signers, uint16_t min_signers,
    TssHandle *out_handles, size_t *out_handle_count,
    TssBuffer *out_pubkey_package
);

TssStatus tss_frost_split_key(
    uint8_t suite, TssSlice secret_key, uint16_t max_signers, uint16_t min_signers,
    TssHandle *out_handles, size_t *out_handle_count,
    TssBuffer *out_pubkey_package
);

// --- Trusted Dealer Refresh ---

TssStatus tss_frost_refresh_dealer(
    TssSlice pubkey_package,
    const uint16_t *participants, size_t participant_count,
    TssBuffer *out_refresh_shares, size_t *out_share_count,
    TssBuffer *out_pubkey_package
);

TssStatus tss_frost_apply_refresh(
    TssHandle key_share, TssSlice refresh_data,
    TssSlice pubkey_package,
    TssHandle *out_key_share
);

// --- Share Repair ---

TssStatus tss_frost_repair_part1(
    TssHandle key_share,
    const uint16_t *helpers, size_t helper_count,
    uint16_t participant,
    TssBuffer *out_deltas, size_t *out_delta_count
);

TssStatus tss_frost_repair_part2(
    uint8_t suite,
    const TssSlice *deltas, size_t delta_count,
    TssBuffer *out_sigma
);

TssStatus tss_frost_repair_part3(
    const TssSlice *sigmas, size_t sigma_count,
    uint16_t participant,
    TssSlice pubkey_package,
    TssHandle *out_key
);

// ============================================================
// Verification & Key Management
// ============================================================

/// Verify a signature. Works for both FROST (Schnorr) and DKLs23 (ECDSA).
bool tss_verify(uint8_t suite, TssSlice message, TssSlice signature, TssSlice public_key);

TssStatus tss_derive_child(TssHandle key_share, uint32_t child_number, TssHandle *out);
TssStatus tss_derive_path(TssHandle key_share, const char *path, TssHandle *out);

// --- Export / Import ---
TssStatus tss_handle_export(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_import(const uint8_t *data, size_t data_len, uint8_t suite, TssHandle *out_handle);

// --- Version ---
const char* tss_version(void);

#endif // LIBTSS_H
```

### Function Count Summary

| Category | Functions | Notes |
|----------|-----------|-------|
| Initialization | 1 | `tss_init` |
| Unified sessions | 8 | dkg (2) + sign (2) + refresh (2) + refresh_receiver (1) + session_free (1) |
| Message helpers | 3 | count, at, build |
| FROST-specific | 9 | aggregate, tweak (2), dealer (2), refresh (2), repair (3) |
| Verification + key mgmt | 5 | verify, derive (2), export, import |
| Handle + memory | 8 | handle queries (4) + handle_free + buffer_free + session_free + version |
| Error | 6 | last_error, last_error_len, last_error_copy, culprit_count, culprit, banned_party |
| **Total** | **~40** | **Core unified path: 11 functions (sessions + messages)** |

The core DKG + signing workflow uses only 7 functions: `tss_dkg_new`, `tss_dkg_next`,
`tss_sign_new`, `tss_sign_next`, `tss_message_count`, `tss_message_at`, `tss_message_build`.
Compared to the previous protocol-specific API which required 14 core functions.

## Rust Implementation Pattern

### Entry Point Pattern

Every `extern "C"` function follows this template:

```rust
#[no_mangle]
pub extern "C" fn tss_dkg_new(
    suite: u8,
    self_id: u16,
    max_signers: u16,
    min_signers: u16,
    session_id: *const u8,
    session_id_len: usize,
    out_session: *mut u64,
    out_messages: *mut TssBuffer,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        assert!(!out_session.is_null());
        assert!(!out_messages.is_null());

        let suite = Ciphersuite::try_from(suite)?;
        let id = Identifier::new(self_id)?;
        let config = ThresholdConfig { min_signers, max_signers, suite };
        let sid = if session_id.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(session_id, session_id_len) })
        };

        let (session, messages) = DkgSession::new(&config, id, sid)?;

        let handle = REGISTRY.insert(session);
        let msg_buf = serialize_messages(&messages);

        unsafe {
            *out_session = handle;
            *out_messages = TssBuffer::from_vec(msg_buf);
        }

        Ok::<_, TssError>(())
    });

    match result {
        Ok(Ok(())) => TSS_OK,
        Ok(Err(e)) => {
            set_last_error_from(&e);
            error_to_status(&e)
        }
        Err(_panic) => {
            set_last_error("internal panic".to_string());
            TSS_ERR_INTERNAL_PANIC
        }
    }
}
```

### Session Next Pattern

```rust
#[no_mangle]
pub extern "C" fn tss_dkg_next(
    session: u64,
    messages: TssSlice,
    out_key_share: *mut u64,
    out_pubkey_package: *mut TssBuffer,
    out_messages: *mut TssBuffer,
    out_complete: *mut bool,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        let received = deserialize_messages(unsafe { messages.as_slice() })?;
        let session: &mut DkgSession = REGISTRY.get_mut(session)?;

        match session.next(&received)? {
            DkgOutput::Continue(msgs) => {
                unsafe {
                    *out_complete = false;
                    *out_messages = TssBuffer::from_vec(serialize_messages(&msgs));
                }
            }
            DkgOutput::Complete { key_share, public_keys } => {
                let key_handle = REGISTRY.insert(key_share);
                let pubkey_bytes = public_keys.serialize()?;
                unsafe {
                    *out_complete = true;
                    *out_key_share = key_handle;
                    *out_pubkey_package = TssBuffer::from_vec(pubkey_bytes);
                }
            }
        }

        Ok::<_, TssError>(())
    });

    match result {
        Ok(Ok(())) => TSS_OK,
        Ok(Err(e)) => {
            set_last_error_from(&e);
            error_to_status(&e)
        }
        Err(_panic) => {
            set_last_error("internal panic".to_string());
            TSS_ERR_INTERNAL_PANIC
        }
    }
}
```

### TssBuffer Allocation

```rust
/// Buffer allocated by the library. Must be freed with tss_buffer_free().
#[repr(C)]
pub struct TssBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl TssBuffer {
    /// Caller must free via `tss_buffer_free`. Uses `into_boxed_slice()`
    /// so allocation size == `len` (guaranteed, unlike `shrink_to_fit`).
    pub fn from_vec(v: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = v.into_boxed_slice();
        let len = boxed.len();
        let data = Box::into_raw(boxed) as *mut u8;
        TssBuffer { data, len }
    }
}

#[no_mangle]
pub extern "C" fn tss_buffer_free(buf: *mut TssBuffer) {
    if buf.is_null() {
        return;
    }
    let buf = unsafe { &mut *buf };
    if !buf.data.is_null() {
        unsafe {
            // Zero the data before freeing
            std::ptr::write_bytes(buf.data, 0, buf.len);
            // Reconstruct the Box<[u8]> for deallocation
            let slice = std::slice::from_raw_parts_mut(buf.data, buf.len);
            let _ = Box::from_raw(slice);
        }
        buf.data = std::ptr::null_mut();
        buf.len = 0;
    }
}
```

### TssSlice (Input Borrowed Data)

```rust
/// Borrowed byte slice from the caller. Library does not free.
#[repr(C)]
pub struct TssSlice {
    pub data: *const u8,
    pub len: usize,
}

impl TssSlice {
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.data, self.len)
        }
    }
}
```

### Thread-Local Error Storage

```rust
thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
    static ABORT_CULPRITS: RefCell<Vec<u16>> = RefCell::new(Vec::new());
    static BANNED_PARTY: RefCell<u16> = RefCell::new(0);
}

fn set_last_error_from(err: &TssError) {
    match err {
        TssError::Abort { culprits, message, ban } => {
            set_last_error(message.clone());
            ABORT_CULPRITS.with(|c| {
                *c.borrow_mut() = culprits.iter().map(|id| id.as_u16()).collect();
            });
            BANNED_PARTY.with(|b| {
                *b.borrow_mut() = ban.map(|id| id.as_u16()).unwrap_or(0);
            });
        }
        other => {
            set_last_error(format!("{other:?}"));
            ABORT_CULPRITS.with(|c| c.borrow_mut().clear());
            BANNED_PARTY.with(|b| *b.borrow_mut() = 0);
        }
    }
}

fn error_to_status(err: &TssError) -> i32 {
    match err {
        TssError::InvalidConfig(_) => TSS_ERR_INVALID_CONFIG,
        TssError::InvalidIdentifier => TSS_ERR_INVALID_ID,
        TssError::InvalidShare => TSS_ERR_INVALID_SHARE,
        TssError::InvalidCommitment => TSS_ERR_INVALID_COMMIT,
        TssError::InvalidSignature => TSS_ERR_INVALID_SIG,
        TssError::NonceReuse => TSS_ERR_NONCE_REUSE,
        TssError::HandleInvalid => TSS_ERR_HANDLE_INVALID,
        TssError::ProtocolMismatch => TSS_ERR_PROTO_MISMATCH,
        TssError::DeserializeFailed(_) => TSS_ERR_DESERIALIZE,
        TssError::TweakError(_) => TSS_ERR_TWEAK,
        TssError::SessionComplete => TSS_ERR_SESSION_COMPLETE,
        TssError::Abort { ban: Some(_), .. } => TSS_ERR_ABORT_BAN,
        TssError::Abort { ban: None, .. } => TSS_ERR_ABORT,
    }
}
```

### Message Serialization (Rust-side)

```rust
/// Serialize a Vec<Message> into the concatenated TLV wire format.
fn serialize_messages(messages: &[Message]) -> Vec<u8> {
    let mut buf = Vec::new();
    for msg in messages {
        buf.extend_from_slice(&msg.from.as_u16().to_le_bytes());
        let to = msg.to.map(|id| id.as_u16()).unwrap_or(0);
        buf.extend_from_slice(&to.to_le_bytes());
        buf.extend_from_slice(&(msg.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&msg.data);
    }
    buf
}

/// Deserialize concatenated TLV wire format into Vec<Message>.
fn deserialize_messages(data: &[u8]) -> Result<Vec<Message>, TssError> {
    let mut messages = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 8 > data.len() {
            return Err(TssError::DeserializeFailed("truncated message header".into()));
        }
        let from = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let to = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        let len = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        pos += 8;
        if pos + len > data.len() {
            return Err(TssError::DeserializeFailed("truncated message data".into()));
        }
        messages.push(Message {
            from: Identifier::new(from)?,
            to: if to == 0 { None } else { Some(Identifier::new(to)?) },
            data: data[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok(messages)
}
```

## Handle Registry

Same design as previously specified (SlotMap with generation counters),
now serving all languages instead of just Go:

```rust
use std::sync::Mutex;
use slotmap::{SlotMap, DefaultKey};

pub struct HandleRegistry {
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    keys: SlotMap<DefaultKey, Box<dyn Any + Send>>,
    sessions: SlotMap<DefaultKey, Box<dyn Any + Send>>,
}
```

Handle encoding (category + generation in u64) prevents use-after-free and
type confusion regardless of which language the caller uses.

## Build System

### Cargo.toml

```toml
[workspace]
members = ["libtss", "libtss-ffi"]

[workspace.dependencies]
frost-core = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-secp256k1-tr = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-secp256k1 = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-ed25519 = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-p256 = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-ristretto255 = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
frost-ed448 = { git = "https://github.com/ZcashFoundation/frost", branch = "main" }
dkls23 = { git = "https://github.com/0xCarbon/DKLs23", branch = "main", features = ["serde"] }
zeroize = { version = "1", features = ["derive"] }
```

```toml
# libtss-ffi/Cargo.toml
[package]
name = "libtss-ffi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "staticlib"]

[dependencies]
libtss = { path = "../libtss" }

[build-dependencies]
cbindgen = "0.27"
```

### cbindgen.toml

```toml
language = "C"
header = "/* libtss.h - Generated by cbindgen. Do not edit. */"
include_guard = "LIBTSS_H"
tab_width = 4
style = "both"

[export]
prefix = "Tss"

[export.rename]
"TssStatus" = "TssStatus"
"TssHandle" = "TssHandle"
"TssBuffer" = "TssBuffer"
"TssSlice" = "TssSlice"
```

### Build & Output

```
cargo build --release
  ├── target/release/liblibtss_ffi.a       (static, for Go cgo)
  ├── target/release/liblibtss_ffi.so      (shared, for dynamic linking)
  └── libtss-ffi/libtss.h                  (C header, for Go + React Native native modules)

# Android targets (for React Native)
cargo build --release --target aarch64-linux-android
cargo build --release --target x86_64-linux-android

# iOS targets (for React Native)
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

### Cross-Compilation Targets

| Target | Use Case |
|--------|----------|
| `x86_64-unknown-linux-gnu` | Linux servers (Go, Rust) |
| `aarch64-unknown-linux-gnu` | Linux ARM (Go, Rust) |
| `aarch64-linux-android` | Android ARM64 (React Native) |
| `x86_64-linux-android` | Android x86_64 (React Native emulator) |
| `aarch64-apple-ios` | iOS ARM64 (React Native) |
| `aarch64-apple-ios-sim` | iOS Simulator ARM64 (React Native) |

## Memory Lifecycle

### Secret Values (Same as Before)

```
Allocation:    Rust system allocator (not GC-managed in any language)
Storage:       HandleRegistry (SlotMap, behind Mutex)
Access:        Only via TssHandle (u64) from any language
Deallocation:  tss_handle_free() → SlotMap::remove() → Drop → Zeroize
```

### Library-Allocated Buffers (TssBuffer)

```
Allocation:    Rust Vec::into_raw_parts() → TssBuffer { data, len }
Transfer:      Pointer returned to caller
Ownership:     Caller owns the buffer after the function returns
Deallocation:  Caller calls tss_buffer_free() when done
```

### Caller-Provided Input (TssSlice)

```
Allocation:    Caller (any language's allocator)
Transfer:      Pointer + length passed to Rust
Ownership:     Rust borrows for the duration of the call only
Deallocation:  Caller frees after the function returns
```

## Concurrency

- The `HandleRegistry` Mutex makes all FFI functions safe to call from multiple threads.
- Different handles can be operated on concurrently from different threads.
- The SAME handle must not be used from multiple threads simultaneously (except `tss_handle_free` which is idempotent).
- Sessions are single-threaded (owned by one thread at a time).
- Thread-local error storage means each thread gets its own error message.
