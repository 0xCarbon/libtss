"""FROST-specific operations not part of the unified session API."""

from __future__ import annotations

import ctypes
import struct

from libtss._ffi import (
    TssBuffer,
    TssSlice,
    buffer_to_bytes,
    get_lib,
    make_slice,
    wipe_ctypes_array,
)
from libtss.errors import check_status
from libtss.handle import KeyShareHandle
from libtss.types import Ciphersuite


def aggregate(
    suite: Ciphersuite,
    message: bytes,
    commitments: bytes,
    shares: bytes,
    pubkey_package: bytes,
) -> bytes:
    """Aggregate FROST signature shares into a final Schnorr signature.

    For coordinator-only deployments where a non-signing coordinator
    aggregates shares.
    """
    out_sig = TssBuffer()
    status = get_lib().tss_frost_aggregate(
        int(suite),
        make_slice(message),
        make_slice(commitments),
        make_slice(shares),
        make_slice(pubkey_package),
        ctypes.byref(out_sig),
    )
    check_status(status)
    return buffer_to_bytes(out_sig)


def tweak_key_share(
    key_share: KeyShareHandle,
    merkle_root: bytes = b"",
) -> KeyShareHandle:
    """Apply a BIP-341 Taproot tweak to a key share.

    Only valid for ``Ciphersuite.SECP256K1_TAPROOT``.
    Pass empty bytes for keypath-only.
    """
    out = ctypes.c_uint64()
    mr_arr = None
    if merkle_root:
        mr_arr = (ctypes.c_uint8 * len(merkle_root)).from_buffer_copy(merkle_root)
        mr_ptr = mr_arr
    else:
        mr_ptr = None

    try:
        status = get_lib().tss_frost_tweak_key_share(
            key_share.raw, mr_ptr, len(merkle_root), ctypes.byref(out),
        )
        check_status(status)
        return KeyShareHandle(out.value)
    finally:
        wipe_ctypes_array(mr_arr)


def tweak_pubkey_package(
    pubkey_package: bytes,
    merkle_root: bytes = b"",
) -> bytes:
    """Apply a BIP-341 Taproot tweak to a public key package.

    Only valid for ``Ciphersuite.SECP256K1_TAPROOT``.
    """
    out = TssBuffer()
    if merkle_root:
        mr_arr = (ctypes.c_uint8 * len(merkle_root)).from_buffer_copy(merkle_root)
        mr_ptr = mr_arr
    else:
        mr_ptr = None

    status = get_lib().tss_frost_tweak_pubkey_package(
        make_slice(pubkey_package), mr_ptr, len(merkle_root), ctypes.byref(out),
    )
    check_status(status)
    return buffer_to_bytes(out)


def generate_dealer(
    suite: Ciphersuite,
    max_signers: int,
    min_signers: int,
) -> tuple[list[KeyShareHandle], bytes]:
    """Generate key shares via trusted dealer (for testing or migration).

    Returns (handles, public_key_package).
    """
    handles_arr = (ctypes.c_uint64 * max_signers)()
    handle_count = ctypes.c_size_t()
    out_pkg = TssBuffer()

    status = get_lib().tss_frost_generate_dealer(
        int(suite), max_signers, min_signers,
        handles_arr, ctypes.byref(handle_count), ctypes.byref(out_pkg),
    )
    check_status(status)

    pkg_bytes = buffer_to_bytes(out_pkg)
    handles = [KeyShareHandle(handles_arr[i]) for i in range(handle_count.value)]
    return handles, pkg_bytes


def split_key(
    suite: Ciphersuite,
    secret_key: bytes | bytearray,
    max_signers: int,
    min_signers: int,
) -> tuple[list[KeyShareHandle], bytes]:
    """Split an existing secret key into threshold shares via trusted dealer.

    **Memory hardening:** If ``secret_key`` is a ``bytearray``, it is zeroed
    after the FFI call completes.  The intermediate ``TssSlice`` backing array
    is also zeroed via ``TssSlice.__del__``.  Prefer passing a ``bytearray``
    to avoid leaving the secret on the GC heap.

    Returns (handles, public_key_package).
    """
    handles_arr = (ctypes.c_uint64 * max_signers)()
    handle_count = ctypes.c_size_t()
    out_pkg = TssBuffer()

    sl = make_slice(secret_key)

    try:
        status = get_lib().tss_frost_split_key(
            int(suite), sl, max_signers, min_signers,
            handles_arr, ctypes.byref(handle_count), ctypes.byref(out_pkg),
        )
        check_status(status)
    finally:
        # Wipe the slice backing immediately rather than waiting for GC.
        wipe_ctypes_array(getattr(sl, "_backing", None))
        # Wipe the input if mutable.
        if isinstance(secret_key, bytearray):
            from libtss.secure import wipe_bytearray
            wipe_bytearray(secret_key)

    pkg_bytes = buffer_to_bytes(out_pkg)
    handles = [KeyShareHandle(handles_arr[i]) for i in range(handle_count.value)]
    return handles, pkg_bytes


def _parse_id_blobs(raw: bytes, count: int) -> dict[int, bytes]:
    """Parse the native id-blob format: repeated (id:u16 LE, len:u32 LE, data).

    Returns a dict keyed by participant ID.
    """
    result: dict[int, bytes] = {}
    pos = 0
    for i in range(count):
        if pos + 6 > len(raw):
            raise ValueError(
                f"Truncated id-blob at index {i}: need 6 header bytes, "
                f"have {len(raw) - pos}"
            )
        pid = struct.unpack_from("<H", raw, pos)[0]
        pos += 2
        blen = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        if pos + blen > len(raw):
            raise ValueError(
                f"Truncated id-blob data at index {i}: need {blen} bytes, "
                f"have {len(raw) - pos}"
            )
        result[pid] = raw[pos : pos + blen]
        pos += blen
    return result


def refresh_dealer(
    pubkey_package: bytes,
    participants: list[int],
) -> tuple[dict[int, bytes], bytes]:
    """Trusted dealer refresh: generates refreshing shares without interaction.

    Returns (refresh_shares_by_participant_id, updated_public_key_package).
    """
    p_arr = (ctypes.c_uint16 * len(participants))(*participants)
    out_shares = TssBuffer()
    share_count = ctypes.c_size_t()
    out_pkg = TssBuffer()

    status = get_lib().tss_frost_refresh_dealer(
        make_slice(pubkey_package),
        p_arr, len(participants),
        ctypes.byref(out_shares), ctypes.byref(share_count),
        ctypes.byref(out_pkg),
    )
    check_status(status)

    raw_shares = buffer_to_bytes(out_shares)
    pkg_bytes = buffer_to_bytes(out_pkg)
    shares = _parse_id_blobs(raw_shares, share_count.value)
    return shares, pkg_bytes


def apply_refresh(
    key_share: KeyShareHandle,
    refresh_data: bytes,
    pubkey_package: bytes,
) -> KeyShareHandle:
    """Apply a trusted-dealer refreshing share to an existing key share."""
    out = ctypes.c_uint64()
    status = get_lib().tss_frost_apply_refresh(
        key_share.raw,
        make_slice(refresh_data),
        make_slice(pubkey_package),
        ctypes.byref(out),
    )
    check_status(status)
    return KeyShareHandle(out.value)


def repair_part1(
    key_share: KeyShareHandle,
    helpers: list[int],
    participant: int,
) -> dict[int, bytes]:
    """Share repair part 1: generate repair deltas (called by each helper).

    Returns per-helper delta blobs keyed by helper ID.
    """
    h_arr = (ctypes.c_uint16 * len(helpers))(*helpers)
    out_deltas = TssBuffer()
    delta_count = ctypes.c_size_t()

    status = get_lib().tss_frost_repair_part1(
        key_share.raw,
        h_arr, len(helpers),
        participant,
        ctypes.byref(out_deltas), ctypes.byref(delta_count),
    )
    check_status(status)

    raw = buffer_to_bytes(out_deltas)
    return _parse_id_blobs(raw, delta_count.value)


def repair_part2(suite: Ciphersuite, deltas: list[bytes]) -> bytes:
    """Share repair part 2: sum received deltas into sigma."""
    slices = (TssSlice * len(deltas))()
    # Keep references to prevent GC of backing arrays
    backing = []
    for i, d in enumerate(deltas):
        arr = (ctypes.c_uint8 * len(d)).from_buffer_copy(d)
        backing.append(arr)
        slices[i].data = arr
        slices[i].len = len(d)

    out_sigma = TssBuffer()
    try:
        status = get_lib().tss_frost_repair_part2(
            int(suite), slices, len(deltas), ctypes.byref(out_sigma),
        )
        check_status(status)
        return buffer_to_bytes(out_sigma)
    finally:
        for arr in backing:
            wipe_ctypes_array(arr)


def repair_part3(
    sigmas: list[bytes],
    participant: int,
    pubkey_package: bytes,
) -> KeyShareHandle:
    """Share repair part 3: reconstruct key share from sigmas."""
    slices = (TssSlice * len(sigmas))()
    backing = []
    for i, s in enumerate(sigmas):
        arr = (ctypes.c_uint8 * len(s)).from_buffer_copy(s)
        backing.append(arr)
        slices[i].data = arr
        slices[i].len = len(s)

    out_key = ctypes.c_uint64()
    try:
        status = get_lib().tss_frost_repair_part3(
            slices, len(sigmas), participant,
            make_slice(pubkey_package),
            ctypes.byref(out_key),
        )
        check_status(status)
        return KeyShareHandle(out_key.value)
    finally:
        for arr in backing:
            wipe_ctypes_array(arr)
