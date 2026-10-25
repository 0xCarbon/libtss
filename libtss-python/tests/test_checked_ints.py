"""Integer arguments are range-checked before they reach the C API.

ctypes would otherwise wrap 65538 to 2 or 65539 to 3, silently turning an
invalid identifier or threshold into a different valid one. Public wrappers
raise ``ValueError`` for out-of-range integers and ``TypeError`` for
non-integers (including ``bool``, ``float`` and ``str``); integer-like
objects implementing ``__index__`` are accepted.
"""

from __future__ import annotations

import pytest

from libtss import Ciphersuite, DkgSession, KeyShareHandle, Message, dkls, frost, verify
from libtss import message as msg

# (bad value, exact exception type)
BAD = [
    (65538, ValueError),
    (-1, ValueError),
    (1.5, TypeError),
    (True, TypeError),
    ("2", TypeError),
]
# Identifiers additionally reject 0.
BAD_ID = [*BAD, (0, ValueError)]
BAD_SUITE = [
    (256, ValueError),
    (-1, ValueError),
    (2.9, TypeError),
    (True, TypeError),
    ("2", TypeError),
]


class Index:
    """Integer-like object, such as a numpy integer."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __index__(self) -> int:
        return self.value


@pytest.fixture(scope="module")
def share():
    handles, _ = frost.generate_dealer(Ciphersuite.ED25519, 3, 2)
    yield handles[0]
    for handle in handles:
        handle.close()


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_repair_helper_term_rejects_bad_helper(share, bad, exc):
    with pytest.raises(exc):
        dkls.repair_helper_term(share, [1, bad], 3, b"repair")


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_repair_helper_term_rejects_bad_target(share, bad, exc):
    with pytest.raises(exc):
        dkls.repair_helper_term(share, [1, 2], bad, b"repair")


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_repair_assemble_rejects_bad_target(bad, exc):
    with pytest.raises(exc):
        dkls.repair_assemble(Ciphersuite.SECP256K1_ECDSA, b"\x00", bad, [])


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_message_encode_rejects_bad_sender(bad, exc):
    with pytest.raises(exc):
        msg.encode([Message(sender=bad, to=1, data=b"\x01")])


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_message_encode_rejects_bad_recipient(bad, exc):
    with pytest.raises(exc):
        msg.encode([Message(sender=1, to=bad, data=b"\x01")])


@pytest.mark.parametrize(("bad", "exc"), BAD)
def test_frost_generate_dealer_rejects_bad_min_signers(bad, exc):
    with pytest.raises(exc):
        frost.generate_dealer(Ciphersuite.ED25519, 3, bad)


@pytest.mark.parametrize(("bad", "exc"), BAD)
def test_frost_generate_dealer_rejects_bad_max_signers(bad, exc):
    with pytest.raises(exc):
        frost.generate_dealer(Ciphersuite.ED25519, bad, 2)


@pytest.mark.parametrize(("bad", "exc"), BAD)
def test_frost_split_key_rejects_bad_thresholds_and_wipes_the_secret(bad, exc):
    for max_signers, min_signers in ((3, bad), (bad, 2)):
        secret = bytearray(range(1, 33))
        with pytest.raises(exc):
            frost.split_key(Ciphersuite.ED25519, secret, max_signers, min_signers)
        assert secret == bytearray(32)


@pytest.mark.parametrize(("bad", "exc"), BAD)
def test_dkg_create_rejects_bad_thresholds(bad, exc):
    with pytest.raises(exc):
        DkgSession.create(Ciphersuite.ED25519, 1, 3, bad)
    with pytest.raises(exc):
        DkgSession.create(Ciphersuite.ED25519, 1, bad, 2)


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_dkg_create_rejects_bad_self_id(bad, exc):
    with pytest.raises(exc):
        DkgSession.create(Ciphersuite.ED25519, bad, 3, 2)


@pytest.mark.parametrize(("bad", "exc"), BAD_ID)
def test_sign_and_refresh_reject_bad_identifiers(share, bad, exc):
    from libtss import RefreshSession, SignSession

    with pytest.raises(exc):
        SignSession.create(share, b"msg", counterparties=[2, bad])
    with pytest.raises(exc):
        RefreshSession.create_dealer(share, [1, bad])
    with pytest.raises(exc):
        frost.repair_part1(share, [1, bad], 3)
    with pytest.raises(exc):
        frost.repair_part1(share, [1, 2], bad)


@pytest.mark.parametrize(("bad", "exc"), BAD_SUITE)
def test_public_wrappers_reject_bad_suites(share, bad, exc):
    exported = bytearray(share.export_bytes())
    with pytest.raises(exc):
        KeyShareHandle.import_bytes(exported, bad)
    assert exported == bytearray(len(exported)), "rejected import must wipe the input"
    with pytest.raises(exc):
        frost.generate_dealer(bad, 3, 2)
    secret = bytearray(range(1, 33))
    with pytest.raises(exc):
        frost.split_key(bad, secret, 3, 2)
    assert secret == bytearray(32)
    with pytest.raises(exc):
        frost.aggregate(bad, b"m", b"", b"", b"")
    with pytest.raises(exc):
        frost.repair_part2(bad, [])
    with pytest.raises(exc):
        dkls.split_key(bad, bytearray(32), 3, 2)
    with pytest.raises(exc):
        dkls.repair_assemble(bad, b"\x00", 1, [])
    with pytest.raises(exc):
        DkgSession.create(bad, 1, 3, 2)
    with pytest.raises(exc):
        verify(bad, b"m", b"s", b"k")


def test_fractional_suite_is_not_truncated():
    # 2.9 must not become Ed25519 (2).
    with pytest.raises(TypeError):
        frost.generate_dealer(2.9, 3, 2)


def test_integer_like_values_are_accepted():
    handles, _ = frost.generate_dealer(Index(int(Ciphersuite.ED25519)), Index(3), Index(2))
    try:
        assert len(handles) == 3
        assert handles[0].ciphersuite == Ciphersuite.ED25519
        encoded = msg.encode([Message(sender=Index(1), to=Index(2), data=b"\x01")])
        assert msg.decode(encoded) == [Message(sender=1, to=2, data=b"\x01")]
    finally:
        for handle in handles:
            handle.close()
