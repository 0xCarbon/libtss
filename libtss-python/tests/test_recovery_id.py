"""Signing reports the ECDSA recovery id for DKLs23 and checks lengths.

The recovery id is checked by recovering the group key from the signature
with a small pure-Python implementation of public key recovery.
"""

from __future__ import annotations

import hashlib

import pytest

from libtss import Ciphersuite, Message, SignSession, TssError, dkls, frost

# (p, a, b, Gx, Gy, n) for the two DKLs23 curves.
CURVES = {
    Ciphersuite.SECP256K1_ECDSA: (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0,
        7,
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    ),
    Ciphersuite.SECP256R1_ECDSA: (
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
}

# Signing attempts while waiting to observe both recovery ids; each attempt
# shows a given parity with probability 1/2.
MAX_SIGNATURES = 32


def _add(curve, p1, p2):
    p, a = curve[0], curve[1]
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % p == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, p) % p
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
    x = (lam * lam - p1[0] - p2[0]) % p
    return x, (lam * (p1[0] - x) - p1[1]) % p


def _mul(curve, k, point):
    result = None
    while k:
        if k & 1:
            result = _add(curve, result, point)
        point = _add(curve, point, point)
        k >>= 1
    return result


def _recover(suite, digest: bytes, signature: bytes, recovery_id: int) -> bytes:
    """Compressed public key recovered from ``signature`` over ``digest``."""
    curve = CURVES[suite]
    p, a, b, gx, gy, n = curve
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    # Both field primes are 3 mod 4, so the square root is a single power.
    y = pow((r * r * r + a * r + b) % p, (p + 1) // 4, p)
    if y % 2 != recovery_id:
        y = p - y
    e = int.from_bytes(digest, "big") % n
    r_inv = pow(r, -1, n)
    q = _add(curve, _mul(curve, s * r_inv % n, (r, y)), _mul(curve, (-e * r_inv) % n, (gx, gy)))
    return bytes([2 + (q[1] & 1)]) + q[0].to_bytes(32, "big")


def _sign(shares, message: bytes, sign_id: bytes | None):
    """Run signing; returns the SignResult of the first completed party."""
    ids = [share.identifier for share in shares]
    sessions = {}
    outgoing: dict[int, list[Message]] = {}
    for share in shares:
        pid = share.identifier
        counterparties = [i for i in ids if i != pid] if sign_id else None
        session, messages = SignSession.create(
            share, message, counterparties=counterparties, sign_id=sign_id
        )
        sessions[pid] = session
        outgoing[pid] = messages
    for _ in range(10):
        nxt = {}
        for pid, session in list(sessions.items()):
            inbound = [
                m
                for sender, msgs in outgoing.items()
                if sender != pid
                for m in msgs
                if m.to in (None, pid)
            ]
            result = session.next(inbound)
            if result.complete:
                for other in sessions.values():
                    other.close()
                return result
            nxt[pid] = result.messages
        outgoing = nxt
    raise AssertionError("signing did not complete")


@pytest.mark.parametrize("suite", [Ciphersuite.SECP256K1_ECDSA, Ciphersuite.SECP256R1_ECDSA])
def test_dkls_signatures_report_both_recovery_ids(suite):
    shares, _ = dkls.split_key(suite, bytearray(b"\x42" * 32), 2, 2)
    group_key = shares[0].group_verifying_key
    seen = set()
    for attempt in range(MAX_SIGNATURES):
        digest = hashlib.sha256(b"recovery-%d" % attempt).digest()
        result = _sign(shares, digest, b"py-recovery-%d-%d" % (suite, attempt))
        assert len(result.signature) == 64
        assert result.recovery_id in (0, 1)
        assert _recover(suite, digest, result.signature, result.recovery_id) == group_key
        seen.add(result.recovery_id)
        if seen == {0, 1}:
            break
    assert seen == {0, 1}, f"both recovery ids observed within {MAX_SIGNATURES} signatures"
    for share in shares:
        share.close()


@pytest.mark.parametrize(
    ("suite", "length"),
    [
        (Ciphersuite.SECP256K1_TAPROOT, 64),
        (Ciphersuite.SECP256K1, 65),
        (Ciphersuite.ED25519, 64),
        (Ciphersuite.P256, 65),
        (Ciphersuite.RISTRETTO255, 64),
        (Ciphersuite.ED448, 114),
    ],
)
def test_frost_signatures_have_no_recovery_id(suite, length):
    assert suite.signature_length == length
    shares, _ = frost.generate_dealer(suite, 2, 2)
    result = _sign(shares, b"frost message", None)
    assert len(result.signature) == length
    assert result.recovery_id is None
    for share in shares:
        share.close()


def test_close_waits_for_an_in_flight_next(monkeypatch):
    """next() holds the session lock during the native call and close()
    takes the same lock, so close cannot free the native session underneath
    a running call."""
    import threading

    from libtss._ffi import get_lib

    shares, _ = frost.generate_dealer(Ciphersuite.ED25519, 2, 2)
    session, _ = SignSession.create(shares[0], b"message")

    lib = get_lib()
    real = lib.tss_sign_next_recoverable
    in_call = threading.Event()
    resume = threading.Event()
    closer_started = []

    def slow_next(*args):
        in_call.set()
        resume.wait(timeout=5)
        return real(*args)

    monkeypatch.setattr(lib, "tss_sign_next_recoverable", slow_next)
    outcome = []

    def call_next():
        # No inbound messages: the native call runs and reports an error.
        try:
            session.next([])
        except TssError as error:
            outcome.append(error)

    caller = threading.Thread(target=call_next)
    caller.start()
    assert in_call.wait(timeout=5)

    closer = threading.Thread(target=lambda: (closer_started.append(1), session.close()))
    closer.start()
    closer.join(timeout=0.2)
    assert closer_started and closer.is_alive(), "close() must wait for the in-flight call"
    assert not session._closed

    resume.set()
    caller.join(timeout=5)
    closer.join(timeout=5)
    assert not caller.is_alive() and not closer.is_alive()
    assert len(outcome) == 1
    assert session._closed
    with pytest.raises(RuntimeError):
        session.next([])
    for share in shares:
        share.close()
