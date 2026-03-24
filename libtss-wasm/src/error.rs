use libtss::TssError;
use wasm_bindgen::JsValue;

/// Convert a `TssError` into a JavaScript `Error` object with extra properties:
/// - `code`: string discriminant (e.g. "InvalidConfig", "Abort")
/// - `message`: human-readable description
/// - `culprits`: Array of participant IDs (numbers) — populated for Abort errors
/// - `bannedParty`: number or null — populated when a party should be banned
pub(crate) fn tss_error_to_js(err: TssError) -> JsValue {
    let (code, message, culprits, banned_party) = match &err {
        TssError::InvalidConfig(msg) => ("InvalidConfig", msg.clone(), vec![], None),
        TssError::InvalidIdentifier => (
            "InvalidIdentifier",
            "invalid identifier (must be non-zero u16)".to_string(),
            vec![],
            None,
        ),
        TssError::InvalidShare => ("InvalidShare", "invalid share".to_string(), vec![], None),
        TssError::InvalidCommitment => (
            "InvalidCommitment",
            "invalid commitment".to_string(),
            vec![],
            None,
        ),
        TssError::InvalidSignature => (
            "InvalidSignature",
            "invalid signature".to_string(),
            vec![],
            None,
        ),
        TssError::NonceReuse => ("NonceReuse", "nonce reuse detected".to_string(), vec![], None),
        TssError::HandleInvalid => (
            "HandleInvalid",
            "handle is no longer valid".to_string(),
            vec![],
            None,
        ),
        TssError::ProtocolMismatch => (
            "ProtocolMismatch",
            "operation not supported for this ciphersuite/protocol".to_string(),
            vec![],
            None,
        ),
        TssError::DeserializeFailed(msg) => ("DeserializeFailed", msg.clone(), vec![], None),
        TssError::TweakError(msg) => ("TweakError", msg.clone(), vec![], None),
        TssError::SessionComplete => (
            "SessionComplete",
            "session already completed".to_string(),
            vec![],
            None,
        ),
        TssError::Abort {
            culprits,
            message,
            ban,
        } => {
            let culprit_ids: Vec<u32> = culprits.iter().map(|id| id.as_u16() as u32).collect();
            let banned: Option<u32> = ban.map(|id| id.as_u16() as u32);
            ("Abort", message.clone(), culprit_ids, banned)
        }
    };

    // Build a JS Error object with extra properties
    let error_ctor = js_sys::Error::new(&message);
    let js_err: JsValue = error_ctor.into();

    // Set .code property
    let _ = js_sys::Reflect::set(
        &js_err,
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );

    // Set .culprits as a JS Array of numbers
    let arr = js_sys::Array::new();
    for &id in &culprits {
        arr.push(&JsValue::from_f64(id as f64));
    }
    let _ = js_sys::Reflect::set(&js_err, &JsValue::from_str("culprits"), &arr);

    // Set .bannedParty as number or null
    let banned_val = match banned_party {
        Some(id) => JsValue::from_f64(id as f64),
        None => JsValue::NULL,
    };
    let _ = js_sys::Reflect::set(&js_err, &JsValue::from_str("bannedParty"), &banned_val);

    js_err
}

/// Convert a `Result<T, TssError>` to a `Result<T, JsValue>`.
#[inline]
pub(crate) fn map_err<T>(result: Result<T, TssError>) -> Result<T, JsValue> {
    result.map_err(tss_error_to_js)
}
