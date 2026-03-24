namespace Libtss;

/// <summary>
/// Status codes returned by native libtss FFI functions.
/// </summary>
public enum TssStatus : int
{
    /// <summary>Operation completed successfully.</summary>
    Ok = 0,

    /// <summary>Invalid threshold configuration (t, n, suite).</summary>
    InvalidConfig = 1,

    /// <summary>Identifier is zero or out of range.</summary>
    InvalidId = 2,

    /// <summary>Key share validation failed.</summary>
    InvalidShare = 3,

    /// <summary>Commitment verification failed.</summary>
    InvalidCommit = 4,

    /// <summary>Signature verification or format error.</summary>
    InvalidSig = 5,

    /// <summary>Attempted to reuse a consumed nonce or session.</summary>
    NonceReuse = 6,

    /// <summary>Handle does not exist or has been freed.</summary>
    HandleInvalid = 7,

    /// <summary>Wrong protocol for this operation.</summary>
    ProtoMismatch = 8,

    /// <summary>Deserialization of protocol data failed.</summary>
    Deserialize = 9,

    /// <summary>Recoverable protocol abort (safe to retry).</summary>
    Abort = 10,

    /// <summary>
    /// Ban abort: counterparty MUST be permanently excluded from all future sessions.
    /// Call <see cref="TssAbortException.BannedParty"/> to identify the offending party.
    /// </summary>
    AbortBan = 11,

    /// <summary>BIP-341 tweaking error.</summary>
    Tweak = 13,

    /// <summary>Session has already completed.</summary>
    SessionComplete = 14,

    /// <summary>Internal panic in the native library.</summary>
    InternalPanic = 255,
}
