"""Low-level ctypes bindings to liblibtss_ffi."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
from ctypes import (
    POINTER,
    Structure,
    c_bool,
    c_char_p,
    c_int32,
    c_size_t,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
)

# Capture at module level so __del__ can use them during interpreter shutdown.
_memset = ctypes.memset
_addressof = ctypes.addressof


# ── Structs ──────────────────────────────────────────────────────────────────

class TssSlice(Structure):
    """Slice pointing into a ctypes-allocated backing array.

    Memory hardening: when a ``TssSlice`` is created via :func:`make_slice`,
    the backing ``(c_uint8 * N)`` array is stored on ``_backing``.  When
    the slice is garbage-collected its ``__del__`` zeroes that backing array
    so intermediate copies of sensitive data do not linger on the Python heap.
    """

    _fields_ = [
        ("data", POINTER(c_uint8)),
        ("len", c_size_t),
    ]

    # Class-level references survive interpreter teardown.
    _memset = staticmethod(_memset)
    _addressof = staticmethod(_addressof)

    _backing: ctypes.Array | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._backing = None

    def __del__(self) -> None:
        backing = getattr(self, "_backing", None)
        if backing is not None and len(backing) > 0:
            try:
                self._memset(self._addressof(backing), 0, len(backing))
            except Exception:
                pass
            self._backing = None


class TssBuffer(Structure):
    _fields_ = [
        ("data", POINTER(c_uint8)),
        ("len", c_size_t),
    ]


TssStatus = c_int32
TssHandle = c_uint64

# ── Status codes ─────────────────────────────────────────────────────────────

TSS_OK = 0
TSS_ERR_INVALID_CONFIG = 1
TSS_ERR_INVALID_ID = 2
TSS_ERR_INVALID_SHARE = 3
TSS_ERR_INVALID_COMMIT = 4
TSS_ERR_INVALID_SIG = 5
TSS_ERR_NONCE_REUSE = 6
TSS_ERR_HANDLE_INVALID = 7
TSS_ERR_PROTO_MISMATCH = 8
TSS_ERR_DESERIALIZE = 9
TSS_ERR_ABORT = 10
TSS_ERR_ABORT_BAN = 11
TSS_ERR_TWEAK = 13
TSS_ERR_SESSION_COMPLETE = 14
TSS_ERR_INTERNAL_PANIC = 255


# ── Library loading ──────────────────────────────────────────────────────────

def _find_lib() -> str:
    """Locate the liblibtss_ffi shared library."""
    # 1. Explicit env var
    env = os.environ.get("LIBTSS_LIB")
    if env and os.path.isfile(env):
        return env

    system = platform.system()
    if system == "Linux":
        names = ["liblibtss_ffi.so"]
    elif system == "Darwin":
        names = ["liblibtss_ffi.dylib"]
    elif system == "Windows":
        names = ["libtss_ffi.dll"]
    else:
        names = ["liblibtss_ffi.so"]

    # 2. Look in common build output directories relative to the repo
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_dirs = [
        os.path.join(script_dir, "..", "..", "target", "release"),
        os.path.join(script_dir, "..", "..", "target", "debug"),
    ]
    for d in search_dirs:
        for name in names:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                return path

    # 3. System search
    found = ctypes.util.find_library("libtss_ffi")
    if found:
        return found

    raise OSError(
        "Cannot find liblibtss_ffi shared library. "
        "Set LIBTSS_LIB env var or run 'cargo build --release -p libtss-ffi'."
    )


_lib: ctypes.CDLL | None = None


def get_lib() -> ctypes.CDLL:
    """Return the loaded shared library, loading it lazily on first call."""
    global _lib
    if _lib is None:
        _lib = ctypes.CDLL(_find_lib())
        _declare_signatures(_lib)
    return _lib


# ── Function signatures ──────────────────────────────────────────────────────

def _declare_signatures(lib: ctypes.CDLL) -> None:
    """Declare all FFI function signatures for type safety."""

    # Init (memory hardening)
    lib.tss_init.restype = TssStatus
    lib.tss_init.argtypes = [c_uint32]

    # Version
    lib.tss_version.restype = c_char_p
    lib.tss_version.argtypes = []

    # Verify
    lib.tss_verify.restype = c_bool
    lib.tss_verify.argtypes = [c_uint8, TssSlice, TssSlice, TssSlice]

    # Error handling
    lib.tss_last_error.restype = c_char_p
    lib.tss_last_error.argtypes = []

    lib.tss_last_error_len.restype = c_size_t
    lib.tss_last_error_len.argtypes = []

    lib.tss_last_error_copy.restype = c_size_t
    lib.tss_last_error_copy.argtypes = [POINTER(c_uint8), c_size_t]

    lib.tss_abort_culprit_count.restype = c_size_t
    lib.tss_abort_culprit_count.argtypes = []

    lib.tss_abort_culprit.restype = c_uint16
    lib.tss_abort_culprit.argtypes = [c_size_t]

    lib.tss_abort_banned_party.restype = c_uint16
    lib.tss_abort_banned_party.argtypes = []

    # Memory
    lib.tss_buffer_free.restype = None
    lib.tss_buffer_free.argtypes = [POINTER(TssBuffer)]

    lib.tss_handle_free.restype = None
    lib.tss_handle_free.argtypes = [c_uint64]

    lib.tss_session_free.restype = None
    lib.tss_session_free.argtypes = [c_uint64]

    # Messages
    lib.tss_message_count.restype = c_size_t
    lib.tss_message_count.argtypes = [TssSlice]

    lib.tss_message_at.restype = TssStatus
    lib.tss_message_at.argtypes = [
        TssSlice, c_size_t,
        POINTER(c_uint16), POINTER(c_uint16), POINTER(TssSlice),
    ]

    lib.tss_message_build.restype = TssStatus
    lib.tss_message_build.argtypes = [
        POINTER(TssBuffer), c_uint16, c_uint16,
        POINTER(c_uint8), c_size_t,
    ]

    # Handle operations
    lib.tss_handle_identifier.restype = TssStatus
    lib.tss_handle_identifier.argtypes = [c_uint64, POINTER(c_uint16)]

    lib.tss_handle_ciphersuite.restype = c_uint8
    lib.tss_handle_ciphersuite.argtypes = [c_uint64]

    lib.tss_handle_verifying_share.restype = TssStatus
    lib.tss_handle_verifying_share.argtypes = [c_uint64, POINTER(TssBuffer)]

    lib.tss_handle_group_key.restype = TssStatus
    lib.tss_handle_group_key.argtypes = [c_uint64, POINTER(TssBuffer)]

    lib.tss_handle_pubkey_package.restype = TssStatus
    lib.tss_handle_pubkey_package.argtypes = [c_uint64, POINTER(TssBuffer)]

    lib.tss_handle_export.restype = TssStatus
    lib.tss_handle_export.argtypes = [c_uint64, POINTER(TssBuffer)]

    lib.tss_handle_import.restype = TssStatus
    lib.tss_handle_import.argtypes = [
        POINTER(c_uint8), c_size_t, c_uint8, POINTER(c_uint64),
    ]

    # DKG session
    lib.tss_dkg_new.restype = TssStatus
    lib.tss_dkg_new.argtypes = [
        c_uint8, c_uint16, c_uint16, c_uint16,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint64), POINTER(TssBuffer),
    ]

    lib.tss_dkg_next.restype = TssStatus
    lib.tss_dkg_next.argtypes = [
        c_uint64, TssSlice,
        POINTER(c_uint64), POINTER(TssBuffer), POINTER(TssBuffer),
        POINTER(c_bool),
    ]

    # Sign session
    lib.tss_sign_new.restype = TssStatus
    lib.tss_sign_new.argtypes = [
        c_uint64, TssSlice,
        POINTER(c_uint16), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint64), POINTER(TssBuffer),
    ]

    lib.tss_sign_next.restype = TssStatus
    lib.tss_sign_next.argtypes = [
        c_uint64, TssSlice,
        POINTER(TssBuffer), POINTER(TssBuffer),
        POINTER(c_bool),
    ]

    # Refresh session
    lib.tss_refresh_new.restype = TssStatus
    lib.tss_refresh_new.argtypes = [
        c_uint64, POINTER(c_uint16), c_size_t,
        POINTER(c_uint64), POINTER(TssBuffer),
    ]

    lib.tss_refresh_receiver.restype = TssStatus
    lib.tss_refresh_receiver.argtypes = [c_uint64, POINTER(c_uint64)]

    lib.tss_refresh_next.restype = TssStatus
    lib.tss_refresh_next.argtypes = [
        c_uint64, TssSlice,
        POINTER(c_uint64), POINTER(TssBuffer), POINTER(TssBuffer),
        POINTER(c_bool),
    ]

    # FROST operations
    lib.tss_frost_aggregate.restype = TssStatus
    lib.tss_frost_aggregate.argtypes = [
        c_uint8, TssSlice, TssSlice, TssSlice, TssSlice,
        POINTER(TssBuffer),
    ]

    lib.tss_frost_tweak_key_share.restype = TssStatus
    lib.tss_frost_tweak_key_share.argtypes = [
        c_uint64, POINTER(c_uint8), c_size_t, POINTER(c_uint64),
    ]

    lib.tss_frost_tweak_pubkey_package.restype = TssStatus
    lib.tss_frost_tweak_pubkey_package.argtypes = [
        TssSlice, POINTER(c_uint8), c_size_t, POINTER(TssBuffer),
    ]

    lib.tss_frost_generate_dealer.restype = TssStatus
    lib.tss_frost_generate_dealer.argtypes = [
        c_uint8, c_uint16, c_uint16,
        POINTER(c_uint64), POINTER(c_size_t), POINTER(TssBuffer),
    ]

    lib.tss_frost_split_key.restype = TssStatus
    lib.tss_frost_split_key.argtypes = [
        c_uint8, TssSlice, c_uint16, c_uint16,
        POINTER(c_uint64), POINTER(c_size_t), POINTER(TssBuffer),
    ]

    lib.tss_frost_refresh_dealer.restype = TssStatus
    lib.tss_frost_refresh_dealer.argtypes = [
        TssSlice, POINTER(c_uint16), c_size_t,
        POINTER(TssBuffer), POINTER(c_size_t), POINTER(TssBuffer),
    ]

    lib.tss_frost_apply_refresh.restype = TssStatus
    lib.tss_frost_apply_refresh.argtypes = [
        c_uint64, TssSlice, TssSlice, POINTER(c_uint64),
    ]

    lib.tss_frost_repair_part1.restype = TssStatus
    lib.tss_frost_repair_part1.argtypes = [
        c_uint64, POINTER(c_uint16), c_size_t, c_uint16,
        POINTER(TssBuffer), POINTER(c_size_t),
    ]

    lib.tss_frost_repair_part2.restype = TssStatus
    lib.tss_frost_repair_part2.argtypes = [
        c_uint8, POINTER(TssSlice), c_size_t, POINTER(TssBuffer),
    ]

    lib.tss_frost_repair_part3.restype = TssStatus
    lib.tss_frost_repair_part3.argtypes = [
        POINTER(TssSlice), c_size_t, c_uint16, TssSlice,
        POINTER(c_uint64),
    ]

    # Derivation
    lib.tss_derive_child.restype = TssStatus
    lib.tss_derive_child.argtypes = [c_uint64, c_uint32, POINTER(c_uint64)]

    lib.tss_derive_path.restype = TssStatus
    lib.tss_derive_path.argtypes = [c_uint64, c_char_p, POINTER(c_uint64)]


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_slice(data: bytes | bytearray | None) -> TssSlice:
    """Create a TssSlice from Python bytes or bytearray.

    The backing ``ctypes`` array is stored on the returned slice so it is
    automatically zeroed when the slice is garbage-collected (see
    :class:`TssSlice.__del__`).
    """
    s = TssSlice()
    if data:
        backing = (c_uint8 * len(data)).from_buffer_copy(data)
        s.data = backing
        s.len = len(data)
        s._backing = backing
    else:
        s.data = None
        s.len = 0
    return s


def buffer_to_bytes(buf: TssBuffer) -> bytes:
    """Copy a TssBuffer to Python bytes and free the native buffer.

    The native ``tss_buffer_free`` zeroes the Rust-side allocation before
    deallocation, so sensitive data does not persist in native memory.
    """
    lib = get_lib()
    if not buf.data or buf.len == 0:
        lib.tss_buffer_free(ctypes.byref(buf))
        return b""
    result = ctypes.string_at(buf.data, buf.len)
    lib.tss_buffer_free(ctypes.byref(buf))
    return result


def wipe_ctypes_array(arr: ctypes.Array | None) -> None:
    """Zero a ctypes array in-place. Safe to call with None."""
    if arr is not None and ctypes.sizeof(arr) > 0:
        _memset(_addressof(arr), 0, ctypes.sizeof(arr))
