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
    sl = None
    try:
        if (
            not isinstance(min_signers, int)
            or not isinstance(max_signers, int)
            or not 2 <= min_signers <= max_signers <= 255
        ):
            raise ValueError("DKLs23 requires 2 <= min_signers <= max_signers <= 255")
        handles_arr = (ctypes.c_uint64 * max_signers)()
        handle_count = ctypes.c_size_t()
        out_pkg = TssBuffer()
        sl = make_slice(secret_key)
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


def bolt3_derive(key_share: KeyShareHandle, per_commitment_point: bytes) -> KeyShareHandle:
    """BOLT 3 derivation of a DKLs23 secp256k1 key share for a commitment.

    Computes ``basepoint + SHA256(per_commitment_point || basepoint)·G``; every
    party derives with the same 33-byte compressed point. A derived share keeps
    the base share's OT state, so a counterparty banned under a derived key is
    banned for the base key too.
    """
    out = ctypes.c_uint64()
    check_status(get_lib().tss_bolt3_derive(
        key_share.raw, make_slice(per_commitment_point), ctypes.byref(out),
    ))
    return KeyShareHandle(out.value)


def bolt3_derive_revocation(
    key_share: KeyShareHandle,
    per_commitment_point: bytes,
    per_commitment_secret: bytes | bytearray,
) -> KeyShareHandle:
    """BOLT 3 revocation derivation for a commitment whose 32-byte
    ``per_commitment_secret`` was revealed; the secret must match the point.
    If ``per_commitment_secret`` is a ``bytearray``, it is zeroed after the
    call."""
    out = ctypes.c_uint64()
    secret = None
    try:
        secret = make_slice(per_commitment_secret)
        check_status(get_lib().tss_bolt3_derive_revocation(
            key_share.raw, make_slice(per_commitment_point), secret,
            ctypes.byref(out),
        ))
    finally:
        wipe_ctypes_array(getattr(secret, "_backing", None))
        if isinstance(per_commitment_secret, bytearray):
            from libtss.secure import wipe_bytearray
            wipe_bytearray(per_commitment_secret)
    return KeyShareHandle(out.value)


def bolt3_derive_public_keys(public_keys: bytes, per_commitment_point: bytes) -> bytes:
    """:func:`bolt3_derive` on a serialized secp256k1 ECDSA public key package."""
    out = TssBuffer()
    check_status(get_lib().tss_bolt3_derive_pubkey_package(
        make_slice(public_keys), make_slice(per_commitment_point), ctypes.byref(out),
    ))
    return buffer_to_bytes(out)


def bolt3_derive_revocation_public_keys(
    public_keys: bytes, per_commitment_point: bytes,
) -> bytes:
    """:func:`bolt3_derive_revocation` on a public key package (no secret)."""
    out = TssBuffer()
    check_status(get_lib().tss_bolt3_derive_revocation_pubkey_package(
        make_slice(public_keys), make_slice(per_commitment_point), ctypes.byref(out),
    ))
    return buffer_to_bytes(out)
