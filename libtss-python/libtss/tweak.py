"""Scalar tweaks for DKLs23 ECDSA key shares.

These are the building blocks of LND's per-commitment key derivation: the
additive "single" tweak (``k + tweak``) and the multiplicative half of the
revocation ("double") tweak (``k * factor``).
"""

from __future__ import annotations

import ctypes

from libtss._ffi import get_lib, wipe_ctypes_array
from libtss.errors import check_status
from libtss.handle import KeyShareHandle

SCALAR_LEN = 32


def tweak_add(key_share: KeyShareHandle, tweak: bytes) -> KeyShareHandle:
    """Apply an additive scalar tweak to a key share: ``k' = k + tweak mod n``.

    The public key, BIP-32 derivation data, address and every verifying
    share move by the same map, so the tweaked shares sign under the
    tweaked group key (``pk' = pk + tweak * G``). This is LND's
    per-commitment "single tweak".

    Supports Secp256k1ECDSA and Secp256r1ECDSA (DKLs23) only; other
    ciphersuites raise :class:`~libtss.TssError` with code
    ``TSS_ERR_PROTO_MISMATCH`` (8). A tweak whose result is the identity
    point raises :class:`~libtss.TssError` with code ``TSS_ERR_TWEAK`` (13).

    The original key share remains valid; the returned handle is a new
    key share that must be closed independently.

    Args:
        key_share: Handle to the parent key share.
        tweak: Exactly 32 bytes, big-endian scalar, reduced mod n.

    Returns:
        A new :class:`~libtss.KeyShareHandle` for the tweaked share.

    Raises:
        ValueError: If ``tweak`` is not exactly 32 bytes (checked before
            any native call).
    """
    return _apply_scalar_tweak("tss_tweak_add", key_share, tweak, "tweak")


def tweak_mul(key_share: KeyShareHandle, factor: bytes) -> KeyShareHandle:
    """Apply a multiplicative scalar tweak to a key share: ``k' = k * factor mod n``.

    The public key, BIP-32 derivation data, address and every verifying
    share move by the same map, so the tweaked shares sign under the
    tweaked group key (``pk' = factor * pk``). This is the multiplicative
    step of LND's revocation ("double") tweak.

    Supports Secp256k1ECDSA and Secp256r1ECDSA (DKLs23) only; other
    ciphersuites raise :class:`~libtss.TssError` with code
    ``TSS_ERR_PROTO_MISMATCH`` (8). A factor that reduces to zero, or a
    result that is the identity point, raises :class:`~libtss.TssError`
    with code ``TSS_ERR_TWEAK`` (13).

    The original key share remains valid; the returned handle is a new
    key share that must be closed independently.

    Args:
        key_share: Handle to the parent key share.
        factor: Exactly 32 bytes, big-endian scalar, reduced mod n.

    Returns:
        A new :class:`~libtss.KeyShareHandle` for the tweaked share.

    Raises:
        ValueError: If ``factor`` is not exactly 32 bytes (checked before
            any native call).
    """
    return _apply_scalar_tweak("tss_tweak_mul", key_share, factor, "factor")


def _apply_scalar_tweak(
    ffi_function: str,
    key_share: KeyShareHandle,
    scalar: bytes,
    param_name: str,
) -> KeyShareHandle:
    if len(scalar) != SCALAR_LEN:
        raise ValueError(
            f"{param_name} must be exactly {SCALAR_LEN} bytes, got {len(scalar)}"
        )

    out = ctypes.c_uint64()
    scalar_arr = (ctypes.c_uint8 * SCALAR_LEN).from_buffer_copy(scalar)
    try:
        status = getattr(get_lib(), ffi_function)(
            key_share.raw, scalar_arr, SCALAR_LEN, ctypes.byref(out),
        )
        check_status(status)
        return KeyShareHandle(out.value)
    finally:
        wipe_ctypes_array(scalar_arr)
