"""Error types for libtss."""

from __future__ import annotations

import ctypes

from libtss._ffi import (
    TSS_ERR_ABORT,
    TSS_ERR_ABORT_BAN,
    TSS_OK,
    get_lib,
)


class TssError(Exception):
    """Error raised by libtss FFI calls."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


class TssAbortError(TssError):
    """Protocol abort with identified culprits."""

    def __init__(
        self,
        code: int,
        message: str,
        culprits: list[int],
        banned_party: int | None = None,
    ) -> None:
        self.culprits = culprits
        self.banned_party = banned_party
        super().__init__(code, message)


def check_status(status: int) -> None:
    """Raise TssError/TssAbortError if status is non-zero."""
    if status == TSS_OK:
        return

    lib = get_lib()

    # Read error message atomically
    needed = lib.tss_last_error_copy(None, 0)
    if needed > 0:
        buf = (ctypes.c_uint8 * needed)()
        lib.tss_last_error_copy(buf, needed)
        # Exclude NUL terminator
        message = bytes(buf[: needed - 1]).decode("utf-8", errors="replace")
    else:
        message = "unknown error"

    if status in (TSS_ERR_ABORT, TSS_ERR_ABORT_BAN):
        count = lib.tss_abort_culprit_count()
        culprits = [lib.tss_abort_culprit(i) for i in range(count)]
        banned = lib.tss_abort_banned_party()
        raise TssAbortError(
            status,
            message,
            culprits=culprits,
            banned_party=banned if banned != 0 else None,
        )

    raise TssError(status, message)
