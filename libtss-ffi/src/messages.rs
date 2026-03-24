use crate::ffi_entry;
use crate::types::{TssBuffer, TssSlice, TssStatus};

fn raw_slice<'a>(data: *const u8, len: usize) -> Result<&'a [u8], libtss::TssError> {
    if data.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(libtss::TssError::InvalidConfig("null data pointer".into()));
    }
    Ok(unsafe { core::slice::from_raw_parts(data, len) })
}

pub(crate) fn checked_slice<'a>(slice: TssSlice) -> Result<&'a [u8], libtss::TssError> {
    raw_slice(slice.data, slice.len)
}

type MessageParts<'a> = (u16, u16, &'a [u8]);

fn next_message<'a>(
    data: &'a [u8],
    offset: &mut usize,
) -> Result<Option<MessageParts<'a>>, libtss::TssError> {
    if *offset == data.len() {
        return Ok(None);
    }
    if data.len() - *offset < 8 {
        return Err(libtss::TssError::DeserializeFailed(
            "truncated message header".into(),
        ));
    }
    let from = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    let to = u16::from_le_bytes([data[*offset + 2], data[*offset + 3]]);
    let len = u32::from_le_bytes([
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]) as usize;
    *offset += 8;

    if from == 0 {
        return Err(libtss::TssError::DeserializeFailed(
            "invalid sender identifier".into(),
        ));
    }
    if data.len() - *offset < len {
        return Err(libtss::TssError::DeserializeFailed(
            "truncated message data".into(),
        ));
    }
    let payload = &data[*offset..*offset + len];
    *offset += len;
    Ok(Some((from, to, payload)))
}

pub(crate) fn serialize_messages(messages: &[libtss::Message]) -> Vec<u8> {
    let mut out = Vec::new();
    for msg in messages {
        out.extend_from_slice(&msg.from.as_u16().to_le_bytes());
        out.extend_from_slice(
            &msg.to
                .map(libtss::Identifier::as_u16)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(&(msg.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&msg.data);
    }
    out
}

pub(crate) fn deserialize_messages(data: &[u8]) -> Result<Vec<libtss::Message>, libtss::TssError> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while let Some((from, to, payload)) = next_message(data, &mut offset)? {
        messages.push(libtss::Message {
            from: libtss::Identifier::new(from)?,
            to: if to == 0 {
                None
            } else {
                Some(libtss::Identifier::new(to)?)
            },
            data: payload.to_vec(),
        });
    }
    Ok(messages)
}

#[no_mangle]
pub extern "C" fn tss_message_count(messages: TssSlice) -> usize {
    crate::error::clear_last_error();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = checked_slice(messages)?;
        let mut offset = 0;
        let mut count = 0;
        while next_message(bytes, &mut offset)?.is_some() {
            count += 1;
        }
        Ok::<_, libtss::TssError>(count)
    }));
    match result {
        Ok(Ok(count)) => count,
        Ok(Err(err)) => {
            crate::error::set_last_error_from(&err);
            0
        }
        Err(_) => {
            crate::error::set_last_error("internal panic");
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn tss_message_at(
    messages: TssSlice,
    index: usize,
    out_from: *mut u16,
    out_to: *mut u16,
    out_data: *mut TssSlice,
) -> TssStatus {
    ffi_entry!({
        let out_from = unsafe { out_from.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_from is null".into()))?;
        let out_to = unsafe { out_to.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_to is null".into()))?;
        let out_data = unsafe { out_data.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_data is null".into()))?;
        let bytes = checked_slice(messages)?;
        let mut offset = 0;
        let mut current = 0;
        while let Some((from, to, payload)) = next_message(bytes, &mut offset)? {
            if current == index {
                *out_from = from;
                *out_to = to;
                *out_data = TssSlice::from_slice(payload);
                return Ok(());
            }
            current += 1;
        }
        Err(libtss::TssError::InvalidConfig(
            "message index out of range".into(),
        ))
    })
}

#[no_mangle]
pub extern "C" fn tss_message_build(
    buf: *mut TssBuffer,
    from: u16,
    to: u16,
    data: *const u8,
    data_len: usize,
) -> TssStatus {
    ffi_entry!({
        let buf = unsafe { buf.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("buffer pointer is null".into()))?;
        let from_id = libtss::Identifier::new(from)?;
        let to_id = if to == 0 {
            None
        } else {
            Some(libtss::Identifier::new(to)?)
        };
        let payload = raw_slice(data, data_len)?;
        let mut bytes = unsafe { buf.take_vec() };

        bytes.extend_from_slice(&from_id.as_u16().to_le_bytes());
        bytes.extend_from_slice(
            &to_id
                .map(libtss::Identifier::as_u16)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);

        *buf = TssBuffer::from_vec(bytes);
        Ok(())
    })
}
