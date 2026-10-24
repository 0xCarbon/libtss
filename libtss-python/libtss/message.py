"""Message encoding/decoding using the native TLV wire format."""

from __future__ import annotations

import ctypes

from libtss._ffi import (
    TssBuffer,
    TssSlice,
    buffer_to_bytes,
    get_lib,
    check_identifier,
    make_slice,
    wipe_ctypes_array,
)
from libtss.errors import check_status
from libtss.types import Message


def encode(messages: list[Message]) -> bytes:
    """Encode messages into the native concatenated TLV format.

    ``sender`` must be an identifier in [1, 65535]; ``to`` is ``None``
    (broadcast) or an identifier in [1, 65535]. Raises ``TypeError`` or
    ``ValueError`` otherwise.
    """
    if not messages:
        return b""
    routes = [
        (
            check_identifier(m.sender, "sender"),
            0 if m.to is None else check_identifier(m.to, "to"),
        )
        for m in messages
    ]

    lib = get_lib()
    buf = TssBuffer()
    success = False

    try:
        for msg, (sender, to) in zip(messages, routes):
            data_arr = (ctypes.c_uint8 * len(msg.data)).from_buffer_copy(msg.data)
            try:
                status = lib.tss_message_build(
                    ctypes.byref(buf),
                    sender,
                    to,
                    data_arr,
                    len(msg.data),
                )
                check_status(status)
            finally:
                wipe_ctypes_array(data_arr)
        success = True
    finally:
        if not success and buf.data:
            lib.tss_buffer_free(ctypes.byref(buf))

    return buffer_to_bytes(buf)


def decode(data: bytes) -> list[Message]:
    """Decode a native concatenated TLV buffer into messages."""
    if not data:
        return []

    lib = get_lib()
    sl = make_slice(data)
    count = lib.tss_message_count(sl)

    if count == 0:
        raise ValueError("Failed to parse message bundle: malformed TLV data")

    messages: list[Message] = []
    for i in range(count):
        out_from = ctypes.c_uint16()
        out_to = ctypes.c_uint16()
        out_data = TssSlice()
        status = lib.tss_message_at(
            sl, i,
            ctypes.byref(out_from),
            ctypes.byref(out_to),
            ctypes.byref(out_data),
        )
        check_status(status)

        payload = ctypes.string_at(out_data.data, out_data.len) if out_data.data else b""
        to_val = out_to.value if out_to.value != 0 else None
        messages.append(Message(sender=out_from.value, to=to_val, data=payload))

    return messages
