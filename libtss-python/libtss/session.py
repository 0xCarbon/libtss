"""Protocol-agnostic session classes: DKG, Sign, Refresh."""

from __future__ import annotations

import ctypes
import threading

from libtss import message as _msg
from libtss._ffi import (
    TssBuffer,
    TssSlice,
    buffer_to_bytes,
    get_lib,
    make_slice,
    wipe_ctypes_array,
)
from libtss.errors import check_status
from libtss.handle import KeyShareHandle
from libtss.types import (
    Ciphersuite,
    DkgResult,
    Message,
    RefreshResult,
    SignResult,
)


# ── DKG Session ──────────────────────────────────────────────────────────────

class DkgSession:
    """Protocol-agnostic distributed key generation session.

    Wraps either FROST DKG (3 rounds) or DKLs23 DKG (4 phases) internally.
    Use :meth:`create` to start, then call :meth:`next` in a loop.
    """

    __slots__ = ("_handle", "_closed", "_lock")

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._closed = False
        self._lock = threading.Lock()

    def __enter__(self) -> DkgSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    @classmethod
    def create(
        cls,
        suite: Ciphersuite,
        self_id: int,
        max_signers: int,
        min_signers: int,
        session_id: bytes | None = None,
    ) -> tuple[DkgSession, list[Message]]:
        """Create a DKG session and produce first-round messages.

        Args:
            suite: Ciphersuite determining protocol, curve, and hash.
            self_id: 1-based identifier for this participant.
            max_signers: Total number of share holders (n).
            min_signers: Minimum signers required (t), must be >= 2.
            session_id: Session identifier for domain separation.
                Required for DKLs23; optional for FROST.

        Returns:
            A tuple of (session, first_round_messages).
        """
        lib = get_lib()
        out_session = ctypes.c_uint64()
        out_messages = TssBuffer()

        sid_arr = None
        if session_id:
            sid_arr = (ctypes.c_uint8 * len(session_id)).from_buffer_copy(session_id)
            sid_ptr = sid_arr
            sid_len = len(session_id)
        else:
            sid_ptr = None
            sid_len = 0

        try:
            status = lib.tss_dkg_new(
                int(suite), self_id, max_signers, min_signers,
                sid_ptr, sid_len,
                ctypes.byref(out_session), ctypes.byref(out_messages),
            )
            check_status(status)
        finally:
            wipe_ctypes_array(sid_arr)

        msg_bytes = buffer_to_bytes(out_messages)
        messages = _msg.decode(msg_bytes)
        return cls(out_session.value), messages

    def next(self, messages: list[Message]) -> DkgResult:
        """Advance the protocol with received messages.

        Returns a :class:`DkgResult` — check ``result.complete`` to know
        if the protocol has finished.
        """
        if self._closed:
            raise RuntimeError("DkgSession is already complete or closed")

        lib = get_lib()
        encoded = _msg.encode(messages)
        sl = make_slice(encoded)

        out_key_share = ctypes.c_uint64()
        out_pkg = TssBuffer()
        out_msgs = TssBuffer()
        out_complete = ctypes.c_bool()

        status = lib.tss_dkg_next(
            self._handle, sl,
            ctypes.byref(out_key_share), ctypes.byref(out_pkg),
            ctypes.byref(out_msgs), ctypes.byref(out_complete),
        )
        check_status(status)

        if out_complete.value:
            pkg_bytes = buffer_to_bytes(out_pkg)
            buffer_to_bytes(out_msgs)  # free empty buffer
            self._closed = True
            self._handle = 0
            return DkgResult(
                complete=True,
                key_share=KeyShareHandle(out_key_share.value),
                public_key_package=pkg_bytes,
            )

        buffer_to_bytes(out_pkg)  # free empty buffer
        msg_bytes = buffer_to_bytes(out_msgs)
        return DkgResult(complete=False, messages=_msg.decode(msg_bytes))

    def close(self) -> None:
        """Free the native session handle. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        get_lib().tss_session_free(self._handle)
        self._handle = 0


# ── Sign Session ─────────────────────────────────────────────────────────────

class SignSession:
    """Protocol-agnostic signing session.

    Wraps either FROST signing (3 rounds) or DKLs23 signing (4 phases).
    Use :meth:`create` to start, then call :meth:`next` in a loop.
    """

    __slots__ = ("_handle", "_closed", "_lock")

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._closed = False
        self._lock = threading.Lock()

    def __enter__(self) -> SignSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    @classmethod
    def create(
        cls,
        key_share: KeyShareHandle,
        msg: bytes,
        counterparties: list[int] | None = None,
        sign_id: bytes | None = None,
    ) -> tuple[SignSession, list[Message]]:
        """Create a signing session and produce first-round messages.

        Args:
            key_share: Key share handle from DKG or import.
            msg: The message to sign. For FROST, raw message bytes.
                For DKLs23, must be a 32-byte hash.
            counterparties: Co-signer IDs (required for DKLs23, ignored for FROST).
            sign_id: Session nonce (required for DKLs23, ignored for FROST).

        Returns:
            A tuple of (session, first_round_messages).
        """
        lib = get_lib()
        msg_sl = make_slice(msg)

        if counterparties:
            cp_arr = (ctypes.c_uint16 * len(counterparties))(*counterparties)
            cp_ptr = cp_arr
            cp_len = len(counterparties)
        else:
            cp_ptr = None
            cp_len = 0

        sid_arr = None
        if sign_id:
            sid_arr = (ctypes.c_uint8 * len(sign_id)).from_buffer_copy(sign_id)
            sid_ptr = sid_arr
            sid_len = len(sign_id)
        else:
            sid_ptr = None
            sid_len = 0

        out_session = ctypes.c_uint64()
        out_messages = TssBuffer()

        try:
            status = lib.tss_sign_new(
                key_share.raw, msg_sl,
                cp_ptr, cp_len,
                sid_ptr, sid_len,
                ctypes.byref(out_session), ctypes.byref(out_messages),
            )
            check_status(status)
        finally:
            wipe_ctypes_array(sid_arr)
            wipe_ctypes_array(getattr(msg_sl, "_backing", None))

        msg_bytes = buffer_to_bytes(out_messages)
        messages = _msg.decode(msg_bytes)
        return cls(out_session.value), messages

    def next(self, messages: list[Message]) -> SignResult:
        """Advance the protocol with received messages.

        Returns a :class:`SignResult` — check ``result.complete``.
        """
        if self._closed:
            raise RuntimeError("SignSession is already complete or closed")

        lib = get_lib()
        encoded = _msg.encode(messages)
        sl = make_slice(encoded)

        out_sig = TssBuffer()
        out_msgs = TssBuffer()
        out_complete = ctypes.c_bool()

        status = lib.tss_sign_next(
            self._handle, sl,
            ctypes.byref(out_sig), ctypes.byref(out_msgs),
            ctypes.byref(out_complete),
        )
        check_status(status)

        if out_complete.value:
            sig_bytes = buffer_to_bytes(out_sig)
            buffer_to_bytes(out_msgs)  # free empty buffer
            self._closed = True
            self._handle = 0
            return SignResult(complete=True, signature=sig_bytes)

        buffer_to_bytes(out_sig)  # free empty buffer
        msg_bytes = buffer_to_bytes(out_msgs)
        return SignResult(complete=False, messages=_msg.decode(msg_bytes))

    def close(self) -> None:
        """Free the native session handle. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        get_lib().tss_session_free(self._handle)
        self._handle = 0


# ── Refresh Session ──────────────────────────────────────────────────────────

class RefreshSession:
    """Key share refresh session (FROST only).

    Use :meth:`create_dealer` for the refresh initiator and
    :meth:`create_receiver` for other participants.
    """

    __slots__ = ("_handle", "_closed", "_lock")

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._closed = False
        self._lock = threading.Lock()

    def __enter__(self) -> RefreshSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    @classmethod
    def create_dealer(
        cls,
        key_share: KeyShareHandle,
        participants: list[int],
    ) -> tuple[RefreshSession, list[Message]]:
        """Create a refresh dealer session and produce P2P refresh messages.

        Args:
            key_share: Current key share handle.
            participants: 1-based IDs of participants to include in refresh.

        Returns:
            A tuple of (session, p2p_messages).
        """
        lib = get_lib()
        p_arr = (ctypes.c_uint16 * len(participants))(*participants)

        out_session = ctypes.c_uint64()
        out_messages = TssBuffer()

        status = lib.tss_refresh_new(
            key_share.raw,
            p_arr, len(participants),
            ctypes.byref(out_session), ctypes.byref(out_messages),
        )
        check_status(status)

        msg_bytes = buffer_to_bytes(out_messages)
        messages = _msg.decode(msg_bytes)
        return cls(out_session.value), messages

    @classmethod
    def create_receiver(cls, key_share: KeyShareHandle) -> RefreshSession:
        """Create a refresh receiver session (no outgoing messages).

        Args:
            key_share: Current key share handle.
        """
        lib = get_lib()
        out_session = ctypes.c_uint64()

        status = lib.tss_refresh_receiver(key_share.raw, ctypes.byref(out_session))
        check_status(status)

        return cls(out_session.value)

    def next(self, messages: list[Message]) -> RefreshResult:
        """Advance the protocol with received messages.

        Returns a :class:`RefreshResult` — check ``result.complete``.
        """
        if self._closed:
            raise RuntimeError("RefreshSession is already complete or closed")

        lib = get_lib()
        encoded = _msg.encode(messages)
        sl = make_slice(encoded)

        out_key_share = ctypes.c_uint64()
        out_pkg = TssBuffer()
        out_msgs = TssBuffer()
        out_complete = ctypes.c_bool()

        status = lib.tss_refresh_next(
            self._handle, sl,
            ctypes.byref(out_key_share), ctypes.byref(out_pkg),
            ctypes.byref(out_msgs), ctypes.byref(out_complete),
        )
        check_status(status)

        if out_complete.value:
            pkg_bytes = buffer_to_bytes(out_pkg)
            buffer_to_bytes(out_msgs)  # free empty buffer
            self._closed = True
            self._handle = 0
            return RefreshResult(
                complete=True,
                key_share=KeyShareHandle(out_key_share.value),
                public_key_package=pkg_bytes,
            )

        buffer_to_bytes(out_pkg)  # free empty buffer
        msg_bytes = buffer_to_bytes(out_msgs)
        return RefreshResult(complete=False, messages=_msg.decode(msg_bytes))

    def close(self) -> None:
        """Free the native session handle. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        get_lib().tss_session_free(self._handle)
        self._handle = 0
