"""Tests for memory hardening: SecureBytes, wipe_bytearray, TssSlice zeroing.

These tests verify the in-process memory hardening behaviour and do NOT
require the native library (except where noted).
"""

from __future__ import annotations

import ctypes
import sys

import pytest


# ── wipe_bytearray ──────────────────────────────────────────────────────────


class TestWipeBytearray:
    def test_zeros_bytearray(self):
        from libtss.secure import wipe_bytearray

        ba = bytearray(b"\xDE\xAD\xBE\xEF\xCA\xFE")
        wipe_bytearray(ba)
        assert all(b == 0 for b in ba)

    def test_none_is_safe(self):
        from libtss.secure import wipe_bytearray

        wipe_bytearray(None)

    def test_empty_is_safe(self):
        from libtss.secure import wipe_bytearray

        wipe_bytearray(bytearray())


# ── SecureBytes ─────────────────────────────────────────────────────────────


class TestSecureBytes:
    def test_basic_lifecycle(self):
        from libtss.secure import SecureBytes

        data = bytearray(b"secret-key-material-32-bytes!!!!")
        original = bytes(data)
        sb = SecureBytes(data)

        # Source bytearray should be wiped.
        assert all(b == 0 for b in data)

        # SecureBytes holds the original data.
        assert bytes(sb.memoryview()) == original
        assert sb.size == len(original)
        assert len(sb) == len(original)

        sb.destroy()

        # After destroy, accessors raise.
        assert sb.is_destroyed
        assert sb.size == 0
        assert len(sb) == 0
        with pytest.raises(RuntimeError):
            sb.memoryview()
        with pytest.raises(RuntimeError):
            sb.to_bytes()

    def test_double_destroy_is_safe(self):
        from libtss.secure import SecureBytes

        sb = SecureBytes(b"data")
        sb.destroy()
        sb.destroy()  # idempotent — must not raise

    def test_context_manager(self):
        from libtss.secure import SecureBytes

        with SecureBytes(b"context-test") as sb:
            mv = sb.memoryview()
            assert bytes(mv) == b"context-test"
        # After __exit__, should be destroyed.
        assert sb.is_destroyed

    def test_memoryview_is_zero_copy(self):
        """memoryview must reference the underlying secure memory, not a copy."""
        from libtss.secure import SecureBytes

        sb = SecureBytes(b"\x01\x02\x03\x04")
        mv = sb.memoryview()
        # Mutation through the memoryview should be visible.
        mv[0] = 0xFF
        mv2 = sb.memoryview()
        assert mv2[0] == 0xFF
        sb.destroy()

    def test_to_bytes_returns_copy(self):
        from libtss.secure import SecureBytes

        sb = SecureBytes(b"\xAA\xBB\xCC")
        b = sb.to_bytes()
        assert b == b"\xAA\xBB\xCC"
        assert isinstance(b, bytes)
        sb.destroy()

    def test_empty_data(self):
        from libtss.secure import SecureBytes

        sb = SecureBytes(b"")
        assert sb.size == 0
        assert not sb.is_destroyed
        sb.destroy()

    def test_none_raises(self):
        from libtss.secure import SecureBytes

        with pytest.raises(ValueError):
            SecureBytes(None)

    def test_bytes_input_not_wiped(self):
        """Immutable bytes cannot be wiped; SecureBytes should not crash."""
        from libtss.secure import SecureBytes

        data = b"immutable-secret"
        sb = SecureBytes(data)
        # The original bytes is immutable — we cannot verify it was wiped,
        # but the constructor should not raise.
        assert bytes(sb.memoryview()) == data
        sb.destroy()

    def test_repr(self):
        from libtss.secure import SecureBytes

        sb = SecureBytes(b"hello")
        r = repr(sb)
        assert "size=5" in r
        sb.destroy()
        assert "destroyed" in repr(sb)


# ── TssSlice auto-zeroing ──────────────────────────────────────────────────


class TestTssSliceZeroing:
    def test_make_slice_stores_backing(self):
        """make_slice should store the backing array for auto-zeroing."""
        from libtss._ffi import make_slice

        sl = make_slice(b"\xDE\xAD\xBE\xEF")
        assert sl._backing is not None
        assert len(sl._backing) == 4

    def test_del_zeroes_backing(self):
        """When a TssSlice is deleted, its backing array should be zeroed."""
        from libtss._ffi import make_slice

        sl = make_slice(b"\x01\x02\x03\x04")
        backing = sl._backing
        # Backing should contain the original data.
        assert bytes(backing) == b"\x01\x02\x03\x04"

        # Trigger __del__.
        sl.__del__()

        # Backing should now be zeroed.
        assert all(b == 0 for b in backing)

    def test_empty_slice_no_backing(self):
        from libtss._ffi import make_slice

        sl = make_slice(None)
        assert sl._backing is None

    def test_empty_bytes_no_backing(self):
        from libtss._ffi import make_slice

        sl = make_slice(b"")
        assert sl._backing is None


# ── wipe_ctypes_array ───────────────────────────────────────────────────────


class TestWipeCtypesArray:
    def test_wipe_array(self):
        from libtss._ffi import wipe_ctypes_array

        arr = (ctypes.c_uint8 * 4)(0xDE, 0xAD, 0xBE, 0xEF)
        wipe_ctypes_array(arr)
        assert all(arr[i] == 0 for i in range(4))

    def test_wipe_none_is_safe(self):
        from libtss._ffi import wipe_ctypes_array

        wipe_ctypes_array(None)

    def test_wipe_empty_is_safe(self):
        from libtss._ffi import wipe_ctypes_array

        arr = (ctypes.c_uint8 * 0)()
        wipe_ctypes_array(arr)


# ── init() ──────────────────────────────────────────────────────────────────


class TestInit:
    def test_init_no_mlock(self):
        """init() without mlock should be a no-op that does not raise."""
        from libtss.secure import init

        init()  # no mlock — should not raise

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="RLIMIT_CORE not available on Windows",
    )
    def test_init_checks_import(self):
        """Verify init function is importable and callable."""
        from libtss import init as init_fn

        assert callable(init_fn)
