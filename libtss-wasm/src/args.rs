//! Validation of JavaScript numbers before they are narrowed to Rust integers.
//!
//! wasm-bindgen converts a JS number passed to a `u8`/`u16`/`u32` parameter
//! (or an array passed to `&[u16]`) by truncation and wrapping, so
//! `minSigners = 65538` would arrive as `2` and `2.9` as `2`. Entry points
//! take the raw `JsValue` instead and check that it is a number, an integer,
//! and in range; anything else throws a `RangeError` (a `TypeError` for a
//! value that is not a number or an array).

use js_sys::{Array, ArrayBuffer, RangeError, TypeError};
use libtss::{Ciphersuite, Identifier};
use wasm_bindgen::JsValue;

use crate::error::map_err;

fn range_error(name: &str, min: u32, max: u32) -> JsValue {
    RangeError::new(&format!("{name} must be an integer in [{min}, {max}]")).into()
}

/// The integer value of `value` in `min..=max`.
fn integer(value: &JsValue, name: &str, min: u32, max: u32) -> Result<u32, JsValue> {
    let number = value
        .as_f64()
        .ok_or_else(|| JsValue::from(TypeError::new(&format!("{name} must be a number"))))?;
    if number.fract() != 0.0 || number < f64::from(min) || number > f64::from(max) {
        return Err(range_error(name, min, max));
    }
    // In range and integral, so the conversion is exact.
    Ok(number as u32)
}

pub(crate) fn u16_arg(value: &JsValue, name: &str) -> Result<u16, JsValue> {
    integer(value, name, 0, u32::from(u16::MAX)).map(|v| v as u16)
}

pub(crate) fn u32_arg(value: &JsValue, name: &str) -> Result<u32, JsValue> {
    integer(value, name, 0, u32::MAX)
}

pub(crate) fn suite_arg(value: &JsValue) -> Result<Ciphersuite, JsValue> {
    let suite = integer(value, "suite", 0, u32::from(u8::MAX))? as u8;
    map_err(Ciphersuite::try_from(suite))
}

pub(crate) fn identifier_arg(value: &JsValue, name: &str) -> Result<Identifier, JsValue> {
    let id = integer(value, name, 1, u32::from(u16::MAX))? as u16;
    map_err(Identifier::new(id))
}

/// Identifiers from a JS array or typed array of numbers.
pub(crate) fn identifiers_arg(value: &JsValue, name: &str) -> Result<Vec<Identifier>, JsValue> {
    if !Array::is_array(value) && !ArrayBuffer::is_view(value) {
        return Err(TypeError::new(&format!("{name} must be an array of numbers")).into());
    }
    Array::from(value)
        .iter()
        .map(|item| identifier_arg(&item, name))
        .collect()
}
