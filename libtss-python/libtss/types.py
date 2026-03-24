"""Public types: enums, message, and result dataclasses."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libtss.handle import KeyShareHandle


class Protocol(enum.IntEnum):
    """Threshold signing protocol."""
    FROST = 0
    DKLS23 = 1


class Ciphersuite(enum.IntEnum):
    """Ciphersuite identifier (curve + hash combination)."""
    SECP256K1_TAPROOT = 0    # FROST secp256k1 BIP-340 x-only
    SECP256K1 = 1            # FROST secp256k1 compressed
    ED25519 = 2              # FROST Ed25519
    P256 = 3                 # FROST NIST P-256
    RISTRETTO255 = 4         # FROST ristretto255
    ED448 = 5                # FROST Ed448
    SECP256K1_ECDSA = 6      # DKLs23 secp256k1 ECDSA
    SECP256R1_ECDSA = 7      # DKLs23 secp256r1 ECDSA

    @property
    def protocol(self) -> Protocol:
        if self in (Ciphersuite.SECP256K1_ECDSA, Ciphersuite.SECP256R1_ECDSA):
            return Protocol.DKLS23
        return Protocol.FROST


@dataclass(frozen=True, slots=True)
class Message:
    """A protocol message produced or consumed by libtss sessions.

    Route based on ``to``: ``None`` means broadcast to all other participants,
    otherwise send to that specific participant via a confidential channel.
    Do NOT parse or modify ``data``.
    """
    sender: int       # 1-based sender identifier
    to: int | None    # 1-based recipient, or None for broadcast
    data: bytes       # opaque payload

    def __repr__(self) -> str:
        dest = str(self.to) if self.to is not None else "broadcast"
        return f"Message(from={self.sender}, to={dest}, len={len(self.data)})"


@dataclass(frozen=True, slots=True)
class DkgResult:
    """Result of a DKG session round."""
    complete: bool
    messages: list[Message] | None = None
    key_share: KeyShareHandle | None = None
    public_key_package: bytes | None = None


@dataclass(frozen=True, slots=True)
class SignResult:
    """Result of a signing session round."""
    complete: bool
    messages: list[Message] | None = None
    signature: bytes | None = None


@dataclass(frozen=True, slots=True)
class RefreshResult:
    """Result of a refresh session round."""
    complete: bool
    messages: list[Message] | None = None
    key_share: KeyShareHandle | None = None
    public_key_package: bytes | None = None
