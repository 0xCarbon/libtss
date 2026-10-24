"""BIP-32 key derivation for threshold signing key shares."""

from __future__ import annotations

import ctypes

from libtss._ffi import checked_int, get_lib
from libtss.errors import check_status
from libtss.handle import KeyShareHandle


def derive_child(key_share: KeyShareHandle, child_number: int) -> KeyShareHandle:
    """Derive a child key share using non-hardened BIP-32 derivation.

    Supports Secp256k1ECDSA (DKLs23), Secp256r1ECDSA (DKLs23), and
    Secp256k1Taproot (FROST). Raises :class:`~libtss.TssError` for
    unsupported ciphersuites (e.g. Ed25519).

    The original key share remains valid; the returned handle is a new
    key share.

    Args:
        key_share: Handle to the parent key share.
        child_number: Non-hardened child index (must be < 2^31).

    Returns:
        A new :class:`~libtss.KeyShareHandle` for the derived child.
    """
    child_number = checked_int(child_number, "child_number", 0, (1 << 31) - 1)
    out = ctypes.c_uint64()
    status = get_lib().tss_derive_child(
        key_share.raw, child_number, ctypes.byref(out),
    )
    check_status(status)
    return KeyShareHandle(out.value)


def derive_path(key_share: KeyShareHandle, path: str) -> KeyShareHandle:
    """Derive a key share along a BIP-32 path (e.g. ``"m/44/60/0/0"``).

    Hardened segments (e.g. ``"m/44'/0'"``\ ) are rejected.

    Args:
        key_share: Handle to the root key share.
        path: BIP-32 derivation path string.

    Returns:
        A new :class:`~libtss.KeyShareHandle` for the derived key.
    """
    if "\0" in path:
        raise ValueError("path must not contain NUL bytes")
    out = ctypes.c_uint64()
    status = get_lib().tss_derive_path(
        key_share.raw, path.encode("utf-8"), ctypes.byref(out),
    )
    check_status(status)
    return KeyShareHandle(out.value)
