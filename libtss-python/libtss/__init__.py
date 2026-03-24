"""libtss — Python bindings for the libtss threshold signing library.

Provides unified DKG, Sign, and Refresh sessions for FROST (RFC 9591)
and DKLs23 threshold signing protocols.

Example::

    from libtss import Ciphersuite, DkgSession, SignSession, verify

    # DKG (2-of-3 Ed25519)
    s1, msgs1 = DkgSession.create(Ciphersuite.ED25519, 1, 3, 2)
    s2, msgs2 = DkgSession.create(Ciphersuite.ED25519, 2, 3, 2)
    s3, msgs3 = DkgSession.create(Ciphersuite.ED25519, 3, 3, 2)
    # ... exchange messages, call next() until complete ...

    # Sign
    session, msgs = SignSession.create(key_share, b"hello world")
    # ... exchange messages, call next() until complete ...
    assert verify(Ciphersuite.ED25519, b"hello world", signature, pubkey)
"""

from __future__ import annotations

from libtss._ffi import get_lib
from libtss.errors import TssAbortError, TssError
from libtss.handle import KeyShareHandle
from libtss.secure import SecureBytes, init, wipe_bytearray
from libtss.session import DkgSession, RefreshSession, SignSession
from libtss.types import (
    Ciphersuite,
    DkgResult,
    Message,
    Protocol,
    RefreshResult,
    SignResult,
)


def version() -> str:
    """Return the libtss library version string."""
    v = get_lib().tss_version()
    return v.decode("utf-8") if v else "unknown"


def verify(
    suite: Ciphersuite,
    message: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """Verify a signature against a message and public key.

    Args:
        suite: Ciphersuite that was used for signing.
        message: The original message bytes.
        signature: The signature bytes.
        public_key: Compressed SEC1-encoded public key bytes.

    Returns:
        True if the signature is valid, False otherwise.
    """
    from libtss._ffi import make_slice

    return get_lib().tss_verify(
        int(suite),
        make_slice(message),
        make_slice(signature),
        make_slice(public_key),
    )


__all__ = [
    "Ciphersuite",
    "DkgResult",
    "DkgSession",
    "KeyShareHandle",
    "Message",
    "Protocol",
    "RefreshResult",
    "RefreshSession",
    "SecureBytes",
    "SignResult",
    "SignSession",
    "TssAbortError",
    "TssError",
    "init",
    "verify",
    "version",
    "wipe_bytearray",
]
