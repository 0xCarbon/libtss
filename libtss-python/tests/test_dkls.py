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
