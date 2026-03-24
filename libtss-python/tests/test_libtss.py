"""Integration tests for the libtss Python bindings.

Requires the native library to be built:
    cargo build --release -p libtss-ffi
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the package is importable from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import libtss
from libtss import (
    Ciphersuite,
    DkgSession,
    KeyShareHandle,
    Message,
    Protocol,
    RefreshSession,
    SignSession,
    TssError,
    verify,
    version,
)
from libtss import frost


# ── Helpers ──────────────────────────────────────────────────────────────────


def _collect_for(participant_id: int, all_messages: dict[int, list[Message]]) -> list[Message]:
    """Collect messages destined for a given participant (broadcast + P2P)."""
    result = []
    for sender_id, msgs in all_messages.items():
        if sender_id == participant_id:
            continue
        for m in msgs:
            if m.to is None or m.to == participant_id:
                result.append(m)
    return result


def run_dkg(
    suite: Ciphersuite,
    n: int,
    t: int,
    session_id: bytes | None = None,
) -> tuple[list[KeyShareHandle], bytes]:
    """Run a full DKG protocol and return key shares + public key package."""
    sessions: dict[int, DkgSession] = {}
    outgoing: dict[int, list[Message]] = {}

    for i in range(1, n + 1):
        s, msgs = DkgSession.create(suite, i, n, t, session_id=session_id)
        sessions[i] = s
        outgoing[i] = msgs

    # Run rounds until all complete
    key_shares: list[KeyShareHandle] = []
    pkg: bytes = b""

    for _ in range(10):  # safety limit
        new_outgoing: dict[int, list[Message]] = {}
        all_complete = True

        for pid, session in list(sessions.items()):
            incoming = _collect_for(pid, outgoing)
            result = session.next(incoming)

            if result.complete:
                assert result.key_share is not None
                assert result.public_key_package is not None
                key_shares.append(result.key_share)
                pkg = result.public_key_package
                del sessions[pid]
            else:
                assert result.messages is not None
                new_outgoing[pid] = result.messages
                all_complete = False

        outgoing = new_outgoing
        if all_complete or not sessions:
            break

    assert len(key_shares) == n, f"DKG incomplete: got {len(key_shares)}/{n} shares"
    # Sort by identifier for predictable ordering
    key_shares.sort(key=lambda ks: ks.identifier)
    return key_shares, pkg


def run_sign(
    key_shares: list[KeyShareHandle],
    message: bytes,
    signer_ids: list[int] | None = None,
    sign_id: bytes | None = None,
) -> bytes:
    """Run a full signing protocol with a subset of shares."""
    if signer_ids is None:
        shares = key_shares
    else:
        shares = [ks for ks in key_shares if ks.identifier in signer_ids]

    is_dkls = shares[0].protocol == Protocol.DKLS23

    sessions: dict[int, SignSession] = {}
    outgoing: dict[int, list[Message]] = {}

    for ks in shares:
        pid = ks.identifier
        if is_dkls:
            counterparties = [s.identifier for s in shares if s.identifier != pid]
            s, msgs = SignSession.create(ks, message, counterparties=counterparties, sign_id=sign_id)
        else:
            s, msgs = SignSession.create(ks, message)
        sessions[pid] = s
        outgoing[pid] = msgs

    signature: bytes = b""
    for _ in range(10):
        new_outgoing: dict[int, list[Message]] = {}

        for pid, session in list(sessions.items()):
            incoming = _collect_for(pid, outgoing)
            result = session.next(incoming)

            if result.complete:
                assert result.signature is not None
                signature = result.signature
                del sessions[pid]
            else:
                assert result.messages is not None
                new_outgoing[pid] = result.messages

        outgoing = new_outgoing
        if not sessions:
            break

    assert signature, "Signing incomplete"
    return signature


# ── Tests ────────────────────────────────────────────────────────────────────


class TestVersion:
    def test_version_string(self):
        v = version()
        assert isinstance(v, str)
        assert len(v) > 0


class TestCiphersuite:
    def test_protocol_mapping(self):
        assert Ciphersuite.ED25519.protocol == Protocol.FROST
        assert Ciphersuite.SECP256K1.protocol == Protocol.FROST
        assert Ciphersuite.SECP256K1_TAPROOT.protocol == Protocol.FROST
        assert Ciphersuite.SECP256K1_ECDSA.protocol == Protocol.DKLS23
        assert Ciphersuite.SECP256R1_ECDSA.protocol == Protocol.DKLS23


class TestDkgAndSign:
    def test_frost_dkg_2of3_ed25519(self):
        shares, pkg = run_dkg(Ciphersuite.ED25519, 3, 2)
        assert len(shares) == 3
        assert len(pkg) > 0

        # All shares have same group key
        gk = shares[0].group_verifying_key
        for ks in shares[1:]:
            assert ks.group_verifying_key == gk

        # Clean up
        for ks in shares:
            ks.close()

    def test_frost_sign_2of3_ed25519(self):
        shares, pkg = run_dkg(Ciphersuite.ED25519, 3, 2)
        msg = b"test message for signing"

        sig = run_sign(shares, msg, signer_ids=[1, 2])
        assert len(sig) > 0

        # Verify
        assert verify(Ciphersuite.ED25519, msg, sig, shares[0].group_verifying_key)

        for ks in shares:
            ks.close()

    def test_frost_sign_3of5_ed25519(self):
        shares, pkg = run_dkg(Ciphersuite.ED25519, 5, 3)
        msg = b"threshold signing test"

        sig = run_sign(shares, msg, signer_ids=[1, 3, 5])
        assert verify(Ciphersuite.ED25519, msg, sig, shares[0].group_verifying_key)

        # Different subset
        sig2 = run_sign(shares, msg, signer_ids=[2, 4, 5])
        assert verify(Ciphersuite.ED25519, msg, sig2, shares[0].group_verifying_key)

        for ks in shares:
            ks.close()

    def test_frost_dkg_secp256k1(self):
        shares, pkg = run_dkg(Ciphersuite.SECP256K1, 3, 2)
        msg = b"secp256k1 test"

        sig = run_sign(shares, msg, signer_ids=[1, 3])
        assert verify(Ciphersuite.SECP256K1, msg, sig, shares[0].group_verifying_key)

        for ks in shares:
            ks.close()

    def test_dkls_dkg_2of2(self):
        import hashlib

        shares, pkg = run_dkg(
            Ciphersuite.SECP256K1_ECDSA, 2, 2,
            session_id=b"dkls-test-session",
        )
        assert len(shares) == 2
        assert shares[0].protocol == Protocol.DKLS23

        raw_msg = b"dkls ecdsa test"
        msg_hash = hashlib.sha256(raw_msg).digest()
        sig = run_sign(shares, msg_hash, sign_id=b"sign-session-1")
        assert len(sig) > 0
        # verify() expects the raw message (hashes internally)
        assert verify(Ciphersuite.SECP256K1_ECDSA, raw_msg, sig, shares[0].group_verifying_key)

        for ks in shares:
            ks.close()


class TestKeyShareHandle:
    def test_export_import_roundtrip(self):
        shares, _ = run_dkg(Ciphersuite.ED25519, 3, 2)
        original = shares[0]

        exported = original.export_bytes()
        assert len(exported) > 0

        imported = KeyShareHandle.import_bytes(exported, Ciphersuite.ED25519)
        assert imported.identifier == original.identifier
        assert imported.ciphersuite == original.ciphersuite
        assert imported.group_verifying_key == original.group_verifying_key

        imported.close()
        for ks in shares:
            ks.close()

    def test_properties(self):
        shares, _ = run_dkg(Ciphersuite.ED25519, 3, 2)
        ks = shares[0]

        assert ks.identifier == 1
        assert ks.ciphersuite == Ciphersuite.ED25519
        assert ks.protocol == Protocol.FROST
        assert len(ks.group_verifying_key) > 0
        assert len(ks.verifying_share) > 0
        assert len(ks.public_key_package) > 0

        for s in shares:
            s.close()

    def test_context_manager(self):
        shares, _ = run_dkg(Ciphersuite.ED25519, 3, 2)
        with shares[0] as ks:
            _ = ks.identifier

        with pytest.raises(RuntimeError):
            _ = ks.identifier

        for s in shares[1:]:
            s.close()

    def test_double_close_is_safe(self):
        shares, _ = run_dkg(Ciphersuite.ED25519, 3, 2)
        ks = shares[0]
        ks.close()
        ks.close()  # should not raise

        for s in shares[1:]:
            s.close()


class TestDealerKeygen:
    def test_generate_dealer(self):
        handles, pkg = frost.generate_dealer(Ciphersuite.ED25519, 3, 2)
        assert len(handles) == 3
        assert len(pkg) > 0

        msg = b"dealer keygen test"
        sig = run_sign(handles, msg, signer_ids=[1, 2])
        assert verify(Ciphersuite.ED25519, msg, sig, handles[0].group_verifying_key)

        for h in handles:
            h.close()

    def test_split_key_and_sign(self):
        # Generate a dummy 32-byte secret key
        import os as _os
        secret = _os.urandom(32)

        handles, pkg = frost.split_key(Ciphersuite.SECP256K1, secret, 3, 2)
        assert len(handles) == 3

        msg = b"split key signing test"
        sig = run_sign(handles, msg, signer_ids=[2, 3])
        assert verify(Ciphersuite.SECP256K1, msg, sig, handles[0].group_verifying_key)

        for h in handles:
            h.close()


class TestRefresh:
    def test_frost_refresh_preserves_signing(self):
        shares, pkg = run_dkg(Ciphersuite.ED25519, 3, 2)
        original_gk = shares[0].group_verifying_key

        # Party 1 acts as dealer: produces P2P refresh messages for all
        pids = [1, 2, 3]
        dealer_session, dealer_msgs = RefreshSession.create_dealer(shares[0], pids)
        # Free the dealer session — we'll use a receiver instead (matching Rust pattern)
        dealer_session.close()

        # ALL participants (including dealer) create receiver sessions
        sessions: dict[int, RefreshSession] = {}
        for ks in shares:
            sessions[ks.identifier] = RefreshSession.create_receiver(ks)

        # Each participant applies refresh with their P2P message from the dealer
        new_shares: list[KeyShareHandle] = []
        for pid, session in sessions.items():
            my_msgs = [m for m in dealer_msgs if m.to == pid]
            result = session.next(my_msgs)
            assert result.complete
            assert result.key_share is not None
            new_shares.append(result.key_share)

        assert len(new_shares) == 3

        # Group key unchanged
        new_shares.sort(key=lambda ks: ks.identifier)
        for ns in new_shares:
            assert ns.group_verifying_key == original_gk

        # Can sign with refreshed shares
        msg = b"post-refresh signing"
        sig = run_sign(new_shares, msg, signer_ids=[1, 3])
        assert verify(Ciphersuite.ED25519, msg, sig, original_gk)

        for ks in shares:
            ks.close()
        for ks in new_shares:
            ks.close()


class TestErrors:
    def test_invalid_config(self):
        with pytest.raises(TssError):
            DkgSession.create(Ciphersuite.ED25519, 1, 3, 0)  # min_signers=0

    def test_closed_handle_raises(self):
        shares, _ = run_dkg(Ciphersuite.ED25519, 3, 2)
        ks = shares[0]
        ks.close()
        with pytest.raises(RuntimeError, match="closed"):
            _ = ks.identifier

        for s in shares[1:]:
            s.close()


class TestMessage:
    def test_roundtrip(self):
        from libtss import message

        msgs = [
            Message(sender=1, to=None, data=b"broadcast data"),
            Message(sender=2, to=1, data=b"p2p data"),
        ]
        encoded = message.encode(msgs)
        decoded = message.decode(encoded)

        assert len(decoded) == 2
        assert decoded[0].sender == 1
        assert decoded[0].to is None
        assert decoded[0].data == b"broadcast data"
        assert decoded[1].sender == 2
        assert decoded[1].to == 1
        assert decoded[1].data == b"p2p data"
