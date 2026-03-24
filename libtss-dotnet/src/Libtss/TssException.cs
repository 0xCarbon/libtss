using System.Runtime.InteropServices;
using System.Text;

namespace Libtss;

/// <summary>
/// Exception thrown when a libtss native function returns a non-zero status code.
/// </summary>
public class TssException : Exception
{
    /// <summary>
    /// The native status code that caused this exception.
    /// </summary>
    public TssStatus Code { get; }

    public TssException(TssStatus code, string message)
        : base(message)
    {
        Code = code;
    }

    public TssException(TssStatus code, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <summary>
    /// Checks a native status code and throws the appropriate exception if it indicates an error.
    /// Must be called immediately after the native call, before any other FFI call on the same thread.
    /// </summary>
    internal static unsafe void ThrowIfError(int status)
    {
        if (status == (int)TssStatus.Ok)
            return;

        var code = (TssStatus)status;
        string message = ReadLastError();

        if (code == TssStatus.Abort || code == TssStatus.AbortBan)
        {
            var culpritCount = (int)Native.tss_abort_culprit_count();
            var culprits = new ushort[culpritCount];
            for (int i = 0; i < culpritCount; i++)
            {
                culprits[i] = Native.tss_abort_culprit((nuint)i);
            }

            ushort? bannedParty = null;
            if (code == TssStatus.AbortBan)
            {
                ushort banned = Native.tss_abort_banned_party();
                if (banned != 0)
                    bannedParty = banned;
            }

            throw new TssAbortException(code, message, culprits, bannedParty);
        }

        throw new TssException(code, message);
    }

    /// <summary>
    /// Reads the last error message from the native thread-local storage.
    /// Uses <c>tss_last_error_copy</c> for safe, atomic access.
    /// </summary>
    private static unsafe string ReadLastError()
    {
        // First call to get the required buffer size (including NUL terminator).
        nuint needed = Native.tss_last_error_copy(null, 0);
        if (needed <= 1)
            return string.Empty;

        // Allocate buffer and copy the error message.
        byte* buf = stackalloc byte[(int)needed];
        Native.tss_last_error_copy(buf, needed);

        // Decode excluding the NUL terminator.
        return Encoding.UTF8.GetString(buf, (int)needed - 1);
    }
}

/// <summary>
/// Exception thrown on protocol abort errors, carrying culprit and ban information.
/// </summary>
/// <remarks>
/// When <see cref="BannedParty"/> is non-null, the identified party MUST be permanently
/// excluded from all future sessions involving the same key group. This is a security-critical
/// requirement for DKLs23 -- continued interaction with a cheating party enables gradual
/// private key extraction via OT correlation leakage.
/// </remarks>
public sealed class TssAbortException : TssException
{
    /// <summary>
    /// Participant identifiers of the parties that caused the abort.
    /// </summary>
    public ushort[] Culprits { get; }

    /// <summary>
    /// The party that must be permanently banned, or null if this is a recoverable abort.
    /// Only set when <see cref="TssException.Code"/> is <see cref="TssStatus.AbortBan"/>.
    /// </summary>
    public ushort? BannedParty { get; }

    internal TssAbortException(TssStatus code, string message, ushort[] culprits, ushort? bannedParty)
        : base(code, message)
    {
        Culprits = culprits;
        BannedParty = bannedParty;
    }
}
