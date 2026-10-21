"""DKLs23-specific operations."""

from __future__ import annotations

import ctypes

from libtss._ffi import (
    TssBuffer,
    buffer_to_bytes,
    get_lib,
    make_slice,
    wipe_ctypes_array,
)
from libtss.errors import check_status
from libtss.handle import KeyShareHandle
from libtss.types import Ciphersuite


def split_key(
    suite: Ciphersuite,
    secret_key: bytes | bytearray,
    max_signers: int,
    min_signers: int,
    chain_code: bytes | None = None,
) -> tuple[list[KeyShareHandle], bytes]:
    """Import an existing ECDSA key as DKLs23 shares (trusted dealer).

    ``suite`` is ``SECP256K1_ECDSA`` or ``SECP256R1_ECDSA``; ``secret_key`` is
    a 32-byte big-endian scalar; ``chain_code`` is the key's existing 32-byte
    BIP-32 chain code, or ``None`` to sample a new one. The group key is the
    key's own public key.

    The caller holds every share: hand each one to its party, erase the key
    and the shares, and have the parties run
    :meth:`RefreshSession.create_dkls` before use. If ``secret_key`` is a
    ``bytearray``, it is zeroed after the call.

    Returns (handles, public_key_package).
    """
    handles_arr = (ctypes.c_uint64 * max_signers)()
    handle_count = ctypes.c_size_t()
    out_pkg = TssBuffer()

    sl = make_slice(secret_key)
    try:
        status = get_lib().tss_dkls_split_key(
            int(suite), sl, make_slice(chain_code), max_signers, min_signers,
            handles_arr, ctypes.byref(handle_count), ctypes.byref(out_pkg),
        )
        check_status(status)
    finally:
        wipe_ctypes_array(getattr(sl, "_backing", None))
        if isinstance(secret_key, bytearray):
            from libtss.secure import wipe_bytearray
            wipe_bytearray(secret_key)

    pkg_bytes = buffer_to_bytes(out_pkg)
    handles = [KeyShareHandle(handles_arr[i]) for i in range(handle_count.value)]
    return handles, pkg_bytes
