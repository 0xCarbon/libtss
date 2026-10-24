"""Integer arguments are range-checked before they reach the C API.

ctypes would otherwise wrap 65538 to 2 or 65539 to 3, silently turning an
invalid identifier or threshold into a different valid one.
"""

from __future__ import annotations

import ctypes

import pytest

from libtss import Ciphersuite, DkgSession, Message, dkls, frost
from libtss import message as msg

BAD = [65538, -1, 1.5, True]
# ctypes wraps converter errors in ArgumentError.
REJECTED = (TypeError, ValueError, ctypes.ArgumentError)


@pytest.fixture(scope="module")
def share():
    handles, _ = frost.generate_dealer(Ciphersuite.ED25519, 3, 2)
    yield handles[0]
    for handle in handles:
        handle.close()


@pytest.mark.parametrize("bad", BAD)
def test_repair_helper_term_rejects_bad_helper(share, bad):
    with pytest.raises(REJECTED):
        dkls.repair_helper_term(share, [1, bad], 3, b"repair")


@pytest.mark.parametrize("bad", BAD)
def test_repair_helper_term_rejects_bad_target(share, bad):
    with pytest.raises(REJECTED):
        dkls.repair_helper_term(share, [1, 2], bad, b"repair")


@pytest.mark.parametrize("bad", BAD)
def test_repair_assemble_rejects_bad_target(bad):
    with pytest.raises(REJECTED):
        dkls.repair_assemble(Ciphersuite.SECP256K1_ECDSA, b"\x00", bad, [])


@pytest.mark.parametrize("bad", BAD)
def test_message_encode_rejects_bad_sender(bad):
    with pytest.raises(REJECTED):
        msg.encode([Message(sender=bad, to=1, data=b"\x01")])


@pytest.mark.parametrize("bad", BAD)
def test_message_encode_rejects_bad_recipient(bad):
    with pytest.raises(REJECTED):
        msg.encode([Message(sender=1, to=bad, data=b"\x01")])


@pytest.mark.parametrize("bad", BAD)
def test_frost_generate_dealer_rejects_bad_min_signers(bad):
    with pytest.raises(REJECTED):
        frost.generate_dealer(Ciphersuite.ED25519, 3, bad)


@pytest.mark.parametrize("bad", BAD)
def test_frost_generate_dealer_rejects_bad_max_signers(bad):
    with pytest.raises(REJECTED):
        frost.generate_dealer(Ciphersuite.ED25519, bad, 2)


@pytest.mark.parametrize("bad", BAD)
def test_frost_split_key_rejects_bad_thresholds_and_wipes_the_secret(bad):
    for max_signers, min_signers in ((3, bad), (bad, 2)):
        secret = bytearray(range(1, 33))
        with pytest.raises(REJECTED):
            frost.split_key(Ciphersuite.ED25519, secret, max_signers, min_signers)
        assert secret == bytearray(32)


@pytest.mark.parametrize("bad", BAD)
def test_dkg_create_rejects_bad_thresholds(bad):
    with pytest.raises(REJECTED):
        DkgSession.create(Ciphersuite.ED25519, 1, 3, bad)
    with pytest.raises(REJECTED):
        DkgSession.create(Ciphersuite.ED25519, 1, bad, 2)
    with pytest.raises(REJECTED):
        DkgSession.create(Ciphersuite.ED25519, bad, 3, 2)
