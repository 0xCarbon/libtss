use js_sys::{Uint16Array, Uint8Array};
use libtss::session::dkg::{DkgOutput, DkgSession};
use libtss::session::refresh::{RefreshOutput, RefreshSession};
use libtss::session::sign::{SignOutput, SignSession};
use libtss::{Ciphersuite, Identifier, ThresholdConfig};
use wasm_bindgen::prelude::*;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;
use crate::message::{decode_messages, encode_messages};

// ─── DKG ─────────────────────────────────────────────────────────────────────

/// Result returned by `WasmDkgSession.create()` and `WasmDkgSession.next()`.
///
/// When `complete` is `true`, call `takeKeyShare()` and `publicKeyPackage` to retrieve results.
/// Otherwise those return `undefined`.
#[wasm_bindgen]
pub struct WasmDkgResult {
    /// TLV-encoded outgoing messages to broadcast/send to counterparties.
    messages: Vec<u8>,
    /// Whether the DKG protocol has completed.
    pub complete: bool,
    key_share: Option<WasmKeyShareHandle>,
    public_key_package: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmDkgResult {
    /// Returns the outgoing messages for this round.
    #[wasm_bindgen(getter)]
    pub fn messages(&self) -> Uint8Array {
        Uint8Array::from(self.messages.as_slice())
    }

    /// Consumes and returns the `WasmKeyShareHandle` when `complete` is `true`.
    ///
    /// Returns `undefined` if `complete` is `false` or already called once.
    /// Call this exactly once after `complete` becomes `true`.
    #[wasm_bindgen(js_name = "takeKeyShare")]
    pub fn take_key_share(&mut self) -> JsValue {
        match self.key_share.take() {
            Some(ks) => ks.into(),
            None => JsValue::UNDEFINED,
        }
    }

    /// Returns the serialized `PublicKeyPackage` bytes when `complete` is `true`, else `undefined`.
    #[wasm_bindgen(getter, js_name = "publicKeyPackage")]
    pub fn public_key_package(&self) -> JsValue {
        match &self.public_key_package {
            Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
            None => JsValue::UNDEFINED,
        }
    }
}

/// A DKG session that advances the key generation protocol round by round.
///
/// Supports both FROST (3 rounds) and DKLs23 (4 phases).
#[wasm_bindgen]
pub struct WasmDkgSession {
    inner: Option<DkgSession>,
}

#[wasm_bindgen]
impl WasmDkgSession {
    /// Create a new DKG session, returning `[WasmDkgSession, WasmDkgResult]` as a JS Array.
    ///
    /// - `suite`: ciphersuite discriminant (0-7)
    /// - `selfId`: this participant's identifier (1-based, non-zero)
    /// - `maxSigners`: total number of participants
    /// - `minSigners`: signing threshold
    /// - `sessionId`: required for DKLs23 suites (6, 7); pass `null` for FROST
    ///
    /// ```js
    /// const [session, result] = WasmDkgSession.create(suite, selfId, max, min, sessionId);
    /// // distribute result.messages to counterparties, then call session.next(...)
    /// ```
    #[wasm_bindgen(static_method_of = WasmDkgSession)]
    pub fn create(
        suite: u8,
        self_id: u16,
        max_signers: u16,
        min_signers: u16,
        session_id: Option<Uint8Array>,
    ) -> Result<js_sys::Array, JsValue> {
        let ciphersuite = map_err(Ciphersuite::try_from(suite))?;
        let config = ThresholdConfig {
            min_signers,
            max_signers,
            suite: ciphersuite,
        };
        let self_identifier = map_err(Identifier::new(self_id))?;
        let sid_bytes: Option<Vec<u8>> = session_id.map(|a| a.to_vec());
        let sid_ref: Option<&[u8]> = sid_bytes.as_deref();

        let (session, messages) = map_err(DkgSession::new(&config, self_identifier, sid_ref))?;
        let encoded = encode_messages(&messages)?;

        let wasm_session = WasmDkgSession {
            inner: Some(session),
        };
        let result = WasmDkgResult {
            messages: encoded.to_vec(),
            complete: false,
            key_share: None,
            public_key_package: None,
        };

        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(wasm_session));
        arr.push(&JsValue::from(result));
        Ok(arr)
    }

    /// Advance the DKG session by one round, consuming the messages received from counterparties.
    ///
    /// `messages` is the TLV-encoded bundle of messages addressed to this participant
    /// from the previous round (filter to only those for you before calling).
    ///
    /// Returns a `WasmDkgResult`. Check `result.complete` — if `true`, retrieve
    /// `result.keyShare` and `result.publicKeyPackage`.
    #[wasm_bindgen]
    pub fn next(&mut self, messages: &Uint8Array) -> Result<WasmDkgResult, JsValue> {
        let session = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("DkgSession is already complete or freed"))?;

        let received = decode_messages(messages)?;
        let output = map_err(session.next(&received))?;

        match output {
            DkgOutput::Continue(msgs) => {
                let encoded = encode_messages(&msgs)?;
                Ok(WasmDkgResult {
                    messages: encoded.to_vec(),
                    complete: false,
                    key_share: None,
                    public_key_package: None,
                })
            }
            DkgOutput::Complete {
                key_share,
                public_keys,
            } => {
                self.inner = None;
                let pkp_bytes = map_err(public_keys.serialize())?;
                Ok(WasmDkgResult {
                    messages: vec![],
                    complete: true,
                    key_share: Some(WasmKeyShareHandle { inner: key_share }),
                    public_key_package: Some(pkp_bytes),
                })
            }
        }
    }

    /// Returns the current round number (1-based).
    #[wasm_bindgen]
    pub fn round(&self) -> u8 {
        self.inner.as_ref().map_or(0, |s| s.round())
    }

    /// Returns `true` when the DKG protocol has completed.
    #[wasm_bindgen(js_name = "isComplete")]
    pub fn is_complete(&self) -> bool {
        self.inner.is_none()
    }
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

/// Result returned by `WasmSignSession` constructors and `next()`.
///
/// When `complete` is `true`, `signature` (and optionally `recoveryId`) are populated.
#[wasm_bindgen]
pub struct WasmSignResult {
    messages: Vec<u8>,
    /// Whether the signing protocol has completed.
    pub complete: bool,
    signature: Option<Vec<u8>>,
    recovery_id: Option<u8>,
}

#[wasm_bindgen]
impl WasmSignResult {
    /// Returns the outgoing messages for this round.
    #[wasm_bindgen(getter)]
    pub fn messages(&self) -> Uint8Array {
        Uint8Array::from(self.messages.as_slice())
    }

    /// Returns the signature bytes when `complete` is `true`, else `undefined`.
    ///
    /// For DKLs23 suites the signature is a 64-byte compact ECDSA signature (r||s).
    /// For FROST suites the format depends on the ciphersuite.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> JsValue {
        match &self.signature {
            Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
            None => JsValue::UNDEFINED,
        }
    }

    /// Returns the recovery ID (0 or 1) for DKLs23 ECDSA signatures when `complete` is `true`.
    ///
    /// Returns `undefined` for FROST signatures or if not yet complete.
    #[wasm_bindgen(getter, js_name = "recoveryId")]
    pub fn recovery_id(&self) -> JsValue {
        match self.recovery_id {
            Some(id) => JsValue::from_f64(id as f64),
            None => JsValue::UNDEFINED,
        }
    }
}

/// A signing session that advances the threshold signing protocol round by round.
///
/// Create with `WasmSignSession.newFrost()` or `WasmSignSession.newDkls()`.
#[wasm_bindgen]
pub struct WasmSignSession {
    inner: Option<SignSession>,
}

#[wasm_bindgen]
impl WasmSignSession {
    /// Create a FROST signing session and emit the first-round commitment.
    ///
    /// `keyShare` must be a FROST key share (ciphersuite 0-5).
    /// `message` is the raw message bytes to sign (not pre-hashed).
    ///
    /// Returns a `[WasmSignSession, WasmSignResult]` JS Array.
    #[wasm_bindgen(static_method_of = WasmSignSession, js_name = "newFrost")]
    pub fn new_frost(
        key_share: &WasmKeyShareHandle,
        message: &Uint8Array,
    ) -> Result<js_sys::Array, JsValue> {
        let msg = message.to_vec();
        let (session, messages) = map_err(SignSession::new_frost(&key_share.inner, &msg))?;
        let encoded = encode_messages(&messages)?;

        let wasm_session = WasmSignSession {
            inner: Some(session),
        };
        let result = WasmSignResult {
            messages: encoded.to_vec(),
            complete: false,
            signature: None,
            recovery_id: None,
        };

        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(wasm_session));
        arr.push(&JsValue::from(result));
        Ok(arr)
    }

    /// Create a DKLs23 secp256k1 signing session (ciphersuite 6).
    ///
    /// - `keyShare`: a DKLs23 secp256k1 key share
    /// - `signId`: unique 32-byte signing session identifier
    /// - `counterparties`: array of co-signer participant IDs (excluding self)
    /// - `messageHash`: 32-byte pre-computed SHA-256 hash of the message to sign
    ///
    /// Returns a `[WasmSignSession, WasmSignResult]` JS Array.
    #[wasm_bindgen(static_method_of = WasmSignSession, js_name = "newDkls")]
    pub fn new_dkls(
        key_share: &WasmKeyShareHandle,
        sign_id: &Uint8Array,
        counterparties: &Uint16Array,
        message_hash: &Uint8Array,
    ) -> Result<js_sys::Array, JsValue> {
        let sign_id_bytes = sign_id.to_vec();
        let hash_bytes = message_hash.to_vec();
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("messageHash must be exactly 32 bytes"));
        }
        let hash_arr: [u8; 32] = hash_bytes.try_into().unwrap();

        let cp_vec = counterparties.to_vec();
        let cp_ids: Result<Vec<Identifier>, _> = cp_vec
            .iter()
            .map(|&id| Identifier::new(id))
            .collect::<Result<Vec<_>, _>>();
        let cp_ids = map_err(cp_ids)?;

        let (session, messages) = map_err(SignSession::new_dkls(
            &key_share.inner,
            sign_id_bytes,
            &cp_ids,
            hash_arr,
        ))?;
        let encoded = encode_messages(&messages)?;

        let wasm_session = WasmSignSession {
            inner: Some(session),
        };
        let result = WasmSignResult {
            messages: encoded.to_vec(),
            complete: false,
            signature: None,
            recovery_id: None,
        };

        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(wasm_session));
        arr.push(&JsValue::from(result));
        Ok(arr)
    }

    /// Create a DKLs23 secp256r1 signing session (ciphersuite 7).
    ///
    /// - `keyShare`: a DKLs23 secp256r1 key share
    /// - `signId`: unique 32-byte signing session identifier
    /// - `counterparties`: array of co-signer participant IDs (excluding self)
    /// - `messageHash`: 32-byte pre-computed hash of the message to sign
    ///
    /// Returns a `[WasmSignSession, WasmSignResult]` JS Array.
    #[wasm_bindgen(static_method_of = WasmSignSession, js_name = "newDklsR1")]
    pub fn new_dkls_r1(
        key_share: &WasmKeyShareHandle,
        sign_id: &Uint8Array,
        counterparties: &Uint16Array,
        message_hash: &Uint8Array,
    ) -> Result<js_sys::Array, JsValue> {
        let sign_id_bytes = sign_id.to_vec();
        let hash_bytes = message_hash.to_vec();
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("messageHash must be exactly 32 bytes"));
        }
        let hash_arr: [u8; 32] = hash_bytes.try_into().unwrap();

        let cp_vec = counterparties.to_vec();
        let cp_ids: Result<Vec<Identifier>, _> = cp_vec
            .iter()
            .map(|&id| Identifier::new(id))
            .collect::<Result<Vec<_>, _>>();
        let cp_ids = map_err(cp_ids)?;

        let (session, messages) = map_err(SignSession::new_dkls_r1(
            &key_share.inner,
            sign_id_bytes,
            &cp_ids,
            hash_arr,
        ))?;
        let encoded = encode_messages(&messages)?;

        let wasm_session = WasmSignSession {
            inner: Some(session),
        };
        let result = WasmSignResult {
            messages: encoded.to_vec(),
            complete: false,
            signature: None,
            recovery_id: None,
        };

        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(wasm_session));
        arr.push(&JsValue::from(result));
        Ok(arr)
    }

    /// Advance the signing session by one round.
    ///
    /// `messages` is the TLV-encoded bundle of messages addressed to this participant.
    ///
    /// Returns a `WasmSignResult`. Check `result.complete` — if `true`, retrieve
    /// `result.signature` (and `result.recoveryId` for DKLs23 ECDSA suites).
    #[wasm_bindgen]
    pub fn next(&mut self, messages: &Uint8Array) -> Result<WasmSignResult, JsValue> {
        let session = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("SignSession is already complete or freed"))?;

        let received = decode_messages(messages)?;
        let output = map_err(session.next(&received))?;

        match output {
            SignOutput::Continue(msgs) => {
                let encoded = encode_messages(&msgs)?;
                Ok(WasmSignResult {
                    messages: encoded.to_vec(),
                    complete: false,
                    signature: None,
                    recovery_id: None,
                })
            }
            SignOutput::Complete(sig) => {
                self.inner = None;
                let recovery_id = sig.recovery_id();
                Ok(WasmSignResult {
                    messages: vec![],
                    complete: true,
                    signature: Some(sig.as_bytes().to_vec()),
                    recovery_id,
                })
            }
        }
    }

    /// Returns the current round number (1-based).
    #[wasm_bindgen]
    pub fn round(&self) -> u8 {
        self.inner.as_ref().map_or(0, |s| s.round())
    }

    /// Returns `true` when the signing protocol has completed.
    #[wasm_bindgen(js_name = "isComplete")]
    pub fn is_complete(&self) -> bool {
        self.inner.is_none()
    }
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

/// Result returned by `WasmRefreshSession.next()`.
///
/// When `complete` is `true`, `keyShare` and `publicKeyPackage` are populated.
#[wasm_bindgen]
pub struct WasmRefreshResult {
    messages: Vec<u8>,
    /// Whether the refresh protocol has completed.
    pub complete: bool,
    key_share: Option<WasmKeyShareHandle>,
    public_key_package: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmRefreshResult {
    /// Returns the outgoing messages for this round (non-empty for the dealer only).
    #[wasm_bindgen(getter)]
    pub fn messages(&self) -> Uint8Array {
        Uint8Array::from(self.messages.as_slice())
    }

    /// Consumes and returns the refreshed `WasmKeyShareHandle` when `complete` is `true`.
    ///
    /// Returns `undefined` if `complete` is `false` or already called once.
    /// Call this exactly once after `complete` becomes `true`.
    #[wasm_bindgen(js_name = "takeKeyShare")]
    pub fn take_key_share(&mut self) -> JsValue {
        match self.key_share.take() {
            Some(ks) => ks.into(),
            None => JsValue::UNDEFINED,
        }
    }

    /// Returns the serialized refreshed `PublicKeyPackage` bytes when `complete` is `true`, else `undefined`.
    #[wasm_bindgen(getter, js_name = "publicKeyPackage")]
    pub fn public_key_package(&self) -> JsValue {
        match &self.public_key_package {
            Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
            None => JsValue::UNDEFINED,
        }
    }
}

/// A FROST key-refresh session.
///
/// One participant acts as the dealer and calls `WasmRefreshSession.createDealer()`.
/// All participants (including the dealer) then call `next()` with their refresh share message.
///
/// Only supported for FROST ciphersuites (0-5). DKLs23 does not support refresh.
#[wasm_bindgen]
pub struct WasmRefreshSession {
    inner: Option<RefreshSession>,
}

#[wasm_bindgen]
impl WasmRefreshSession {
    /// Create a dealer refresh session and emit P2P refresh-share messages.
    ///
    /// - `keyShare`: the dealer's current FROST key share
    /// - `participants`: array of all participant IDs (including the dealer)
    ///
    /// Returns a `[WasmRefreshSession, WasmRefreshResult]` JS Array.
    /// The dealer must also call `next()` with its own message from `result.messages`.
    #[wasm_bindgen(static_method_of = WasmRefreshSession, js_name = "createDealer")]
    pub fn create_dealer(
        key_share: &WasmKeyShareHandle,
        participants: &Uint16Array,
    ) -> Result<js_sys::Array, JsValue> {
        let ids: Result<Vec<Identifier>, _> = participants
            .to_vec()
            .iter()
            .map(|&id| Identifier::new(id))
            .collect::<Result<Vec<_>, _>>();
        let ids = map_err(ids)?;

        let (session, messages) =
            map_err(RefreshSession::new_frost(&key_share.inner, &ids))?;
        let encoded = encode_messages(&messages)?;

        let wasm_session = WasmRefreshSession {
            inner: Some(session),
        };
        let result = WasmRefreshResult {
            messages: encoded.to_vec(),
            complete: false,
            key_share: None,
            public_key_package: None,
        };

        let arr = js_sys::Array::new();
        arr.push(&JsValue::from(wasm_session));
        arr.push(&JsValue::from(result));
        Ok(arr)
    }

    /// Create a receiver (non-dealer) refresh session.
    ///
    /// `keyShare` is the participant's current FROST key share.
    /// Call `next()` with the refresh-share message received from the dealer.
    #[wasm_bindgen(static_method_of = WasmRefreshSession, js_name = "createReceiver")]
    pub fn create_receiver(key_share: &WasmKeyShareHandle) -> Result<WasmRefreshSession, JsValue> {
        let session = map_err(RefreshSession::new_frost_receiver(&key_share.inner))?;
        Ok(WasmRefreshSession {
            inner: Some(session),
        })
    }

    /// Apply a received refresh-share message and complete the refresh.
    ///
    /// `messages` must contain the single P2P refresh-share message addressed to this participant
    /// (dealer sends one to each participant, including themselves).
    ///
    /// Returns a `WasmRefreshResult` with `complete = true` and the new key share.
    #[wasm_bindgen]
    pub fn next(&mut self, messages: &Uint8Array) -> Result<WasmRefreshResult, JsValue> {
        let session = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("RefreshSession is already complete or freed"))?;

        let received = decode_messages(messages)?;
        let output = map_err(session.next(&received))?;

        match output {
            RefreshOutput::Continue(msgs) => {
                let encoded = encode_messages(&msgs)?;
                Ok(WasmRefreshResult {
                    messages: encoded.to_vec(),
                    complete: false,
                    key_share: None,
                    public_key_package: None,
                })
            }
            RefreshOutput::Complete {
                key_share,
                public_keys,
            } => {
                self.inner = None;
                let pkp_bytes = map_err(public_keys.serialize())?;
                Ok(WasmRefreshResult {
                    messages: vec![],
                    complete: true,
                    key_share: Some(WasmKeyShareHandle { inner: key_share }),
                    public_key_package: Some(pkp_bytes),
                })
            }
        }
    }

    /// Returns the current round number (1-based).
    #[wasm_bindgen]
    pub fn round(&self) -> u8 {
        self.inner.as_ref().map_or(0, |s| s.round())
    }

    /// Returns `true` when the refresh protocol has completed.
    #[wasm_bindgen(js_name = "isComplete")]
    pub fn is_complete(&self) -> bool {
        self.inner.is_none()
    }
}
