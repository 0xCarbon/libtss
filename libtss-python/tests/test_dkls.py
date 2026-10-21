"""DKLs23 key import and complete refresh through the Python binding."""

from __future__ import annotations

import pytest

from libtss import Ciphersuite, RefreshSession, TssError
from libtss import dkls

SUITES = [Ciphersuite.SECP256K1_ECDSA, Ciphersuite.SECP256R1_ECDSA]


def _refresh(shares, session_id):
    sessions = {}
    outgoing = {}
    for i, share in enumerate(shares, start=1):
        session, messages = RefreshSession.create_dkls(share, session_id)
        sessions[i] = session
        outgoing[i] = messages
    refreshed = {}
    for _ in range(3):
        nxt = {}
        for pid, session in sessions.items():
            inbound = [
                m
                for sender, msgs in outgoing.items()
                if sender != pid
                for m in msgs
                if m.to in (None, 0, pid)
            ]
            result = session.next(inbound)
            if result.complete:
                refreshed[pid] = result.key_share
            else:
                nxt[pid] = result.messages
        outgoing = nxt
    for session in sessions.values():
        session.close()
    return [refreshed[pid] for pid in sorted(refreshed)]


@pytest.mark.parametrize("suite", SUITES)
def test_import_keeps_key_and_chain_code_and_refreshes(suite):
    secret = bytearray(b"\x42" * 32)
    chain_code = b"\x17" * 32
    shares, _ = dkls.split_key(suite, secret, 3, 2, chain_code)
    assert secret == bytearray(32)
    keys = {share.group_verifying_key for share in shares}
    assert len(keys) == 1
    for share in shares:
        assert share.chain_code == chain_code

    refreshed = _refresh(shares, b"py-refresh")
    assert len(refreshed) == 3
    for old, new in zip(shares, refreshed):
        assert new.group_verifying_key == old.group_verifying_key
        assert new.verifying_share != old.verifying_share


def test_import_rejects_invalid_input():
    with pytest.raises(TssError):
        dkls.split_key(Ciphersuite.SECP256K1_ECDSA, bytes(32), 3, 2)
    with pytest.raises(TssError):
        dkls.split_key(Ciphersuite.SECP256K1_ECDSA, b"\x01" * 32, 3, 2, b"\x00" * 31)
    with pytest.raises(TssError):
        dkls.split_key(Ciphersuite.ED25519, b"\x01" * 32, 3, 2)


def test_refresh_requires_session_id():
    shares, _ = dkls.split_key(Ciphersuite.SECP256K1_ECDSA, b"\x01" * 32, 2, 2)
    with pytest.raises(ValueError):
        RefreshSession.create_dkls(shares[0], b"")


# BOLT 3, Appendix E: Key Derivation Test Vectors.
BOLT3_BASE_SECRET = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
BOLT3_SECRET = bytes.fromhex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
BOLT3_POINT = bytes.fromhex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486")
BOLT3_LOCAL = bytes.fromhex("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5")
BOLT3_REVOCATION = bytes.fromhex("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0")


def _package_key(raw: bytes) -> bytes:
    # suite (1) + min_signers (2) + verifying key length (4) + verifying key
    length = int.from_bytes(raw[3:7], "little")
    return raw[7:7 + length]


def test_bolt3_matches_the_bolt3_vectors():
    shares, package = dkls.split_key(Ciphersuite.SECP256K1_ECDSA, BOLT3_BASE_SECRET, 3, 2)
    assert dkls.bolt3_derive(shares[0], BOLT3_POINT).group_verifying_key == BOLT3_LOCAL
    revocation = dkls.bolt3_derive_revocation(shares[0], BOLT3_POINT, BOLT3_SECRET)
    assert revocation.group_verifying_key == BOLT3_REVOCATION
    assert _package_key(dkls.bolt3_derive_public_keys(package, BOLT3_POINT)) == BOLT3_LOCAL
    assert (
        _package_key(dkls.bolt3_derive_revocation_public_keys(package, BOLT3_POINT))
        == BOLT3_REVOCATION
    )
    with pytest.raises(TssError):
        dkls.bolt3_derive_revocation(shares[0], BOLT3_POINT, b"\x01" * 32)
