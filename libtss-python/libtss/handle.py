"""KeyShareHandle — opaque handle to a key share in the native registry."""

from __future__ import annotations

import ctypes
import threading
from typing import TYPE_CHECKING

from libtss._ffi import TssBuffer, buffer_to_bytes, get_lib, wipe_ctypes_array
from libtss.errors import check_status
from libtss.types import Ciphersuite, Protocol

if TYPE_CHECKING:
    from libtss.secure import SecureBytes


class KeyShareHandle:
    """Opaque handle to a key share stored in the native libtss handle registry.

    Use as a context manager or call :meth:`close` explicitly to free.
    Secret material is zeroed when the handle is freed.
    """

    __slots__ = ("_handle", "_closed", "_lock")

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._closed = False
        self._lock = threading.Lock()

    def __enter__(self) -> KeyShareHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("KeyShareHandle is closed")

    @property
    def raw(self) -> int:
        """The raw native handle value (for session constructors)."""
        self._check()
        return self._handle

    @property
    def identifier(self) -> int:
        """1-based participant identifier for this key share."""
        self._check()
        out = ctypes.c_uint16()
        status = get_lib().tss_handle_identifier(self._handle, ctypes.byref(out))
        check_status(status)
        return out.value

    @property
    def ciphersuite(self) -> Ciphersuite:
        """Ciphersuite this key share belongs to."""
        self._check()
        raw = get_lib().tss_handle_ciphersuite(self._handle)
        return Ciphersuite(raw)

    @property
    def protocol(self) -> Protocol:
        """Threshold signing protocol determined by this key share's ciphersuite."""
        return self.ciphersuite.protocol

    @property
    def group_verifying_key(self) -> bytes:
        """Group public key (combined verification key) as raw bytes."""
        self._check()
        buf = TssBuffer()
        status = get_lib().tss_handle_group_key(self._handle, ctypes.byref(buf))
        check_status(status)
        return buffer_to_bytes(buf)

    @property
    def verifying_share(self) -> bytes:
        """Public verification key for this specific share."""
        self._check()
        buf = TssBuffer()
        status = get_lib().tss_handle_verifying_share(self._handle, ctypes.byref(buf))
        check_status(status)
        return buffer_to_bytes(buf)

    @property
    def public_key_package(self) -> bytes:
        """Full serialized public key package (group key + all verifying shares)."""
        self._check()
        buf = TssBuffer()
        status = get_lib().tss_handle_pubkey_package(self._handle, ctypes.byref(buf))
        check_status(status)
        return buffer_to_bytes(buf)

    def export_bytes(self) -> bytes:
        """Export the key share as a serialized byte blob.

        **Security:** The output contains unencrypted secret key material.
        You MUST encrypt the bytes before persisting to disk or transmitting
        over a network.  Prefer :meth:`export_secure` which keeps the data
        in locked memory outside the GC heap.
        """
        self._check()
        buf = TssBuffer()
        status = get_lib().tss_handle_export(self._handle, ctypes.byref(buf))
        check_status(status)
        return buffer_to_bytes(buf)

    def export_secure(self) -> SecureBytes:
        """Export the key share into locked memory outside the GC heap.

        The intermediate mutable ``bytearray`` on the GC heap is wiped
        by the ``SecureBytes`` constructor (or in the ``finally`` block
        on error).

        Returns:
            A :class:`~libtss.secure.SecureBytes` holding the serialized key share.
        """
        from libtss.secure import SecureBytes, wipe_bytearray

        self._check()
        buf = TssBuffer()
        status = get_lib().tss_handle_export(self._handle, ctypes.byref(buf))
        check_status(status)

        lib = get_lib()
        if not buf.data or buf.len == 0:
            lib.tss_buffer_free(ctypes.byref(buf))
            return SecureBytes(b"")

        raw: bytearray | None = None
        try:
            raw = bytearray(buf.len)
            ctypes.memmove((ctypes.c_uint8 * buf.len).from_buffer(raw), buf.data, buf.len)
        finally:
            lib.tss_buffer_free(ctypes.byref(buf))

        try:
            return SecureBytes(raw)
        except Exception:
            wipe_bytearray(raw)
            raise

    @classmethod
    def import_bytes(cls, data: bytes | bytearray, suite: Ciphersuite) -> KeyShareHandle:
        """Import a previously exported key share from serialized bytes.

        If ``data`` is a ``bytearray``, it is zeroed after import.
        """
        if not data:
            raise ValueError("data must not be empty")

        out = ctypes.c_uint64()
        arr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        try:
            status = get_lib().tss_handle_import(arr, len(data), int(suite), ctypes.byref(out))
            check_status(status)
        finally:
            wipe_ctypes_array(arr)
            if isinstance(data, bytearray):
                from libtss.secure import wipe_bytearray
                wipe_bytearray(data)

        return cls(out.value)

    @classmethod
    def import_secure(cls, secure: SecureBytes, suite: Ciphersuite) -> KeyShareHandle:
        """Import a key share from a :class:`~libtss.secure.SecureBytes`.

        The data is read from locked memory via ``memoryview``.  A temporary
        ctypes array copy is created for the FFI call and wiped afterwards.
        """
        mv = secure.memoryview()
        if len(mv) == 0:
            raise ValueError("SecureBytes must not be empty")

        out = ctypes.c_uint64()
        arr = (ctypes.c_uint8 * len(mv)).from_buffer_copy(mv)
        try:
            status = get_lib().tss_handle_import(arr, len(mv), int(suite), ctypes.byref(out))
            check_status(status)
        finally:
            wipe_ctypes_array(arr)
        return cls(out.value)

    def close(self) -> None:
        """Free the native handle and zero secret material. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        get_lib().tss_handle_free(self._handle)
        self._handle = 0

    def __repr__(self) -> str:
        state = "closed" if self._closed else f"handle={self._handle}"
        return f"KeyShareHandle({state})"
