use js_sys::Uint8Array;
use libtss::{deserialize_messages, serialize_messages, Identifier, Message};
use wasm_bindgen::prelude::*;

use crate::error::map_err;

/// A single decoded TSS protocol message.
///
/// `to` is 0 for broadcast messages (delivered to all participants except the sender).
#[wasm_bindgen]
pub struct WasmMessage {
    /// Sender participant ID (1-based).
    pub from: u16,
    /// Recipient participant ID, or 0 for broadcast.
    pub to: u16,
    data: Vec<u8>,
}

#[wasm_bindgen]
impl WasmMessage {
    /// Returns the message payload bytes.
    #[wasm_bindgen(js_name = "data")]
    pub fn data(&self) -> Uint8Array {
        Uint8Array::from(self.data.as_slice())
    }
}

/// Returns the number of TLV-framed messages in the concatenated buffer.
///
/// Use this to iterate over a message bundle produced by session `next()` calls.
#[wasm_bindgen(js_name = "messageCount")]
pub fn message_count(data: &Uint8Array) -> Result<u32, JsValue> {
    let bytes = data.to_vec();
    let messages = map_err(deserialize_messages(&bytes))?;
    Ok(messages.len() as u32)
}

/// Decode and return the message at position `index` in the TLV bundle.
///
/// Returns an error if `index` is out of range or the buffer is malformed.
#[wasm_bindgen(js_name = "messageAt")]
pub fn message_at(data: &Uint8Array, index: u32) -> Result<WasmMessage, JsValue> {
    let bytes = data.to_vec();
    let messages = map_err(deserialize_messages(&bytes))?;
    let idx = index as usize;
    if idx >= messages.len() {
        return Err(JsValue::from_str(&format!(
            "index {} out of range (count={})",
            index,
            messages.len()
        )));
    }
    let msg = &messages[idx];
    Ok(WasmMessage {
        from: msg.from.as_u16(),
        to: msg.to.map_or(0, |id| id.as_u16()),
        data: msg.data.clone(),
    })
}

/// Build a single TLV-framed message from `from`, `to`, and payload `data`.
///
/// Set `to` to 0 for a broadcast message.
/// Returns the serialized bytes ready for transmission.
#[wasm_bindgen(js_name = "messageBuild")]
pub fn message_build(from: u16, to: u16, data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    let from_id = map_err(Identifier::new(from))?;
    let to_id = if to == 0 {
        None
    } else {
        Some(map_err(Identifier::new(to))?)
    };

    let msg = Message {
        from: from_id,
        to: to_id,
        data: data.to_vec(),
    };

    let bytes = map_err(serialize_messages(std::slice::from_ref(&msg)))?;
    Ok(Uint8Array::from(bytes.as_slice()))
}

/// Concatenate two TLV message bundles into a single buffer.
///
/// Use this to merge messages from multiple rounds or sources before passing
/// to a session's `next()` call.
#[wasm_bindgen(js_name = "messagesConcat")]
pub fn messages_concat(a: &Uint8Array, b: &Uint8Array) -> Uint8Array {
    let mut buf = a.to_vec();
    buf.extend_from_slice(&b.to_vec());
    Uint8Array::from(buf.as_slice())
}

/// Helper: decode a TLV buffer into a `Vec<Message>` for internal session use.
pub(crate) fn decode_messages(data: &Uint8Array) -> Result<Vec<Message>, JsValue> {
    let bytes = data.to_vec();
    map_err(deserialize_messages(&bytes))
}

/// Helper: encode a `Vec<Message>` into a TLV buffer for return to JS.
pub(crate) fn encode_messages(messages: &[Message]) -> Result<Uint8Array, JsValue> {
    let bytes = map_err(serialize_messages(messages))?;
    Ok(Uint8Array::from(bytes.as_slice()))
}
