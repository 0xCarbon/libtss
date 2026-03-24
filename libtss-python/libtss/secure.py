"""Memory-hardened types for sensitive cryptographic material.

Provides ``SecureBytes`` for storing secrets outside the CPython GC heap,
``wipe_bytearray`` for best-effort in-place zeroing of mutable buffers,
and ``init()`` for one-time runtime hardening (mlock, core-dump disabling).

Strategy (in order of preference):
  1. **libsodium** — ``sodium_malloc`` provides mlock + guard pages + guaranteed
     zeroing on ``sodium_free``.  Detected at import time via ``ctypes``.
  2. **libc mlock + ctypes.memset** — falls back to ``malloc`` + ``mlock`` if
     libsodium is unavailable.  ``memset`` zeroes on destroy.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import platform
import sys

# ---------------------------------------------------------------------------
# Capture ctypes helpers as class-level references so they survive GC teardown.
# During interpreter shutdown, module globals may be set to ``None`` before
# our ``__del__`` runs — stashing these on the class avoids AttributeError.
# ---------------------------------------------------------------------------
_memset = ctypes.memset
_addressof = ctypes.addressof
_c_uint8 = ctypes.c_uint8
_string_at = ctypes.string_at
_memmove = ctypes.memmove

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_sodium: ctypes.CDLL | None = None
_libc: ctypes.CDLL | None = None


def _load_sodium() -> ctypes.CDLL | None:
    """Try to load libsodium."""
    for name in ("sodium", "libsodium"):
        path = ctypes.util.find_library(name)
        if path:
            try:
                lib = ctypes.CDLL(path)
                # Verify the library has the functions we need
                lib.sodium_init.restype = ctypes.c_int
                lib.sodium_malloc.restype = ctypes.c_void_p
                lib.sodium_malloc.argtypes = [ctypes.c_size_t]
                lib.sodium_free.restype = None
                lib.sodium_free.argtypes = [ctypes.c_void_p]
                lib.sodium_mlock.restype = ctypes.c_int
                lib.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.sodium_munlock.restype = ctypes.c_int
                lib.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.sodium_memzero.restype = None
                lib.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                if lib.sodium_init() < 0:
                    continue  # initialization failed — try next name
                return lib
            except (OSError, AttributeError):
                continue
    return None


def _load_libc() -> ctypes.CDLL | None:
    """Load libc for mlock/munlock fallback."""
    system = platform.system()
    if system in ("Linux", "Darwin"):
        path = ctypes.util.find_library("c")
        if path:
            try:
                lib = ctypes.CDLL(path, use_errno=True)
                lib.mlock.restype = ctypes.c_int
                lib.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.munlock.restype = ctypes.c_int
                lib.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.malloc.restype = ctypes.c_void_p
                lib.malloc.argtypes = [ctypes.c_size_t]
                lib.free.restype = None
                lib.free.argtypes = [ctypes.c_void_p]
                return lib
            except (OSError, AttributeError):
                pass
    return None


def _ensure_backends() -> None:
    """Lazy-initialise backends on first use."""
    global _sodium, _libc
    if _sodium is None and _libc is None:
        _sodium = _load_sodium()
        if _sodium is None:
            _libc = _load_libc()


def has_sodium() -> bool:
    """Return True if libsodium is available."""
    _ensure_backends()
    return _sodium is not None


# ---------------------------------------------------------------------------
# wipe_bytearray
# ---------------------------------------------------------------------------

def wipe_bytearray(b: bytearray | None) -> None:
    """Zero a ``bytearray`` in-place via ``ctypes.memset``.

    This is best-effort: CPython may have copied the data to other heap
    pages before this call.  For guaranteed protection use :class:`SecureBytes`.

    Passing ``None`` or an empty array is a safe no-op.
    """
    if not b:
        return
    arr = (_c_uint8 * len(b)).from_buffer(b)
    _memset(_addressof(arr), 0, len(b))


# ---------------------------------------------------------------------------
# SecureBytes
# ---------------------------------------------------------------------------

class SecureBytes:
    """Stores sensitive data in memory outside the CPython GC heap.

    If libsodium is available, uses ``sodium_malloc`` (mlock + guard pages).
    Otherwise, falls back to ``libc.malloc`` + ``mlock`` + ``memset``.

    Use as a context manager or call :meth:`destroy` explicitly::

        with SecureBytes(exported_key) as sb:
            memview = sb.memoryview()
            # pass memview to crypto libs — no GC-heap copy
        # automatically zeroed and freed

    The constructor is *destructive*: if ``data`` is a ``bytearray`` it will
    be zeroed after copying.  ``bytes`` objects are immutable and cannot be
    wiped — prefer passing ``bytearray`` when possible.
    """

    # Class-level references survive interpreter teardown.
    _memset = staticmethod(_memset)
    _addressof = staticmethod(_addressof)
    _c_uint8 = _c_uint8
    _string_at = staticmethod(_string_at)
    _memmove = staticmethod(_memmove)

    __slots__ = ("_ptr", "_size", "_backend", "_destroyed", "_ctypes_arr",
                 "_free_fn", "_munlock_fn", "_locked", "_view_arr")

    def __init__(self, data: bytes | bytearray) -> None:
        # Set defaults first so __del__ is safe if __init__ raises.
        self._ptr: int | None = None
        self._size = 0
        self._backend = "none"
        self._destroyed = False
        self._ctypes_arr: ctypes.Array | None = None
        self._free_fn = None  # captured at allocation time for shutdown safety
        self._munlock_fn = None
        self._locked = False
        self._view_arr = None  # cached ctypes array for memoryview

        if data is None:
            raise ValueError("data must not be None")
        size = len(data)
        if size == 0:
            return

        _ensure_backends()

        if _sodium is not None:
            ptr = _sodium.sodium_malloc(size)
            if not ptr:
                raise MemoryError("sodium_malloc failed")
            self._ptr = ptr
            self._backend = "sodium"
            self._locked = True  # sodium_malloc always mlocks
            self._free_fn = _sodium.sodium_free
        elif _libc is not None:
            ptr = _libc.malloc(size)
            if not ptr:
                raise MemoryError("malloc failed")
            self._ptr = ptr
            self._locked = _libc.mlock(ptr, size) == 0
            self._backend = "libc"
            self._free_fn = _libc.free
            self._munlock_fn = _libc.munlock
        else:
            # Last resort: ctypes-allocated array (not mlock'd, but we still
            # control zeroing).
            arr = (_c_uint8 * size)()
            self._ptr = _addressof(arr)
            # Store the array to prevent GC while we need it.
            self._backend = "ctypes"
            self._ctypes_arr = arr

        self._size = size

        # Copy data into the secure region.  For bytearray, use from_buffer
        # to get a ctypes pointer without creating an immutable bytes copy.
        if isinstance(data, bytearray):
            src = (_c_uint8 * size).from_buffer(data)
            _memmove(self._ptr, _addressof(src), size)
        else:
            _memmove(self._ptr, data, size)

        # Wipe the source if it is mutable.
        if isinstance(data, bytearray) and len(data) > 0:
            wipe_bytearray(data)

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> SecureBytes:
        return self

    def __exit__(self, *exc: object) -> None:
        self.destroy()

    def __del__(self) -> None:
        self.destroy()

    # -- accessors ---------------------------------------------------------

    @property
    def size(self) -> int:
        """Number of bytes held, or 0 if destroyed."""
        return 0 if self._destroyed else self._size

    @property
    def is_destroyed(self) -> bool:
        return self._destroyed

    @property
    def is_locked(self) -> bool:
        """True if the memory was successfully mlocked (swap-protected)."""
        return self._locked

    def memoryview(self) -> memoryview:
        """Return a zero-copy ``memoryview`` over the secure memory.

        The returned view is valid until :meth:`destroy` is called.  The
        caller **must** keep the ``SecureBytes`` instance alive while the
        view is in use.  Pass the view directly to crypto libraries
        (``cryptography``, ``PyNaCl``, etc.) to avoid copying secrets
        onto the GC heap.

        The view supports item read/write (format ``B``) so callers can
        mutate the contents in-place if needed.

        Raises ``RuntimeError`` if the buffer has been destroyed.
        """
        if self._destroyed:
            raise RuntimeError("SecureBytes has been destroyed")
        if self._size == 0:
            return memoryview(b"")
        # Cache the ctypes array on self so the memoryview's buffer object
        # stays alive as long as this SecureBytes instance exists.
        if self._view_arr is None:
            self._view_arr = (ctypes.c_char * self._size).from_address(self._ptr)
        return memoryview(self._view_arr).cast("B")

    def to_bytes(self) -> bytes:
        """Copy the contents to a ``bytes`` object.

        **Warning:** The returned ``bytes`` object lives on the GC heap and
        cannot be securely wiped.  Prefer :meth:`memoryview` for passing
        data to crypto routines that accept buffer-protocol objects.
        """
        if self._destroyed:
            raise RuntimeError("SecureBytes has been destroyed")
        if self._size == 0:
            return b""
        return self._string_at(self._ptr, self._size)

    # -- lifecycle ---------------------------------------------------------

    def destroy(self) -> None:
        """Zero and release the secure memory. Idempotent."""
        if self._destroyed:
            return
        self._destroyed = True

        ptr = self._ptr
        size = self._size
        self._ptr = None
        self._size = 0
        self._view_arr = None

        if ptr is None or size == 0:
            return

        backend = self._backend

        if backend == "sodium" and self._free_fn is not None:
            # sodium_free zeroes + munlocks + frees.
            self._free_fn(ptr)
        elif backend == "libc" and self._free_fn is not None:
            self._memset(ptr, 0, size)
            if self._munlock_fn is not None:
                self._munlock_fn(ptr, size)  # best-effort
            self._free_fn(ptr)
        elif backend == "ctypes":
            arr = self._ctypes_arr
            self._ctypes_arr = None
            if arr is not None:
                self._memset(self._addressof(arr), 0, size)
        else:
            # Fallback: try to memset whatever pointer we have.
            try:
                self._memset(ptr, 0, size)
            except Exception:
                pass

    def __repr__(self) -> str:
        if self._destroyed:
            return "SecureBytes(destroyed)"
        return f"SecureBytes(size={self._size}, backend={self._backend!r})"

    def __len__(self) -> int:
        return self.size


# ---------------------------------------------------------------------------
# init()
# ---------------------------------------------------------------------------

_TSS_INIT_MLOCK = 1


def init(*, mlock: bool = False) -> None:
    """One-time runtime hardening.

    Args:
        mlock: If True, calls ``tss_init(TSS_INIT_MLOCK)`` on the Rust FFI
            layer to prevent swapping of native secrets, and disables core
            dumps via ``resource.RLIMIT_CORE``.

    Calling without arguments is safe and idempotent.
    """
    if not mlock:
        return

    from libtss._ffi import get_lib
    from libtss.errors import check_status

    flags = _TSS_INIT_MLOCK
    status = get_lib().tss_init(flags)
    check_status(status)

    # Disable core dumps on POSIX systems.
    if sys.platform != "win32":
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, ValueError, OSError):
            pass  # best-effort
