using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Libtss;

[Flags]
public enum InitOptions : uint
{
    None = 0,
    Mlock = 1,
}

/// <summary>
/// Top-level entry points for the libtss threshold signing library.
/// </summary>
public static class Tss
{
    /// <summary>
    /// Initializes the native libtss library and optionally enables memory locking.
    /// When <see cref="InitOptions.Mlock"/> is set, also disables core dumps on Linux
    /// via <c>prctl(PR_SET_DUMPABLE, 0)</c> (best-effort).
    /// </summary>
    public static void Init(InitOptions options = InitOptions.None)
    {
        int status = Native.tss_init((uint)options);
        TssException.ThrowIfError(status);

        if (options.HasFlag(InitOptions.Mlock) &&
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // PR_SET_DUMPABLE = 4, arg = 0 (disable)
            // Best-effort: ignore failures (e.g. unprivileged containers)
            Native.prctl(4, 0, 0, 0, 0);
        }
    }

    /// <summary>
    /// Securely zeros a byte array. Null-safe.
    /// </summary>
    public static void WipeBytes(byte[]? data)
    {
        if (data is not null)
            CryptographicOperations.ZeroMemory(data.AsSpan());
    }

    /// <summary>
    /// Securely zeros a span of bytes.
    /// </summary>
    public static void WipeBytes(Span<byte> data)
    {
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>
    /// Returns the version string of the native libtss library.
    /// </summary>
    public static string Version()
    {
        IntPtr ptr = Native.tss_version();
        return Marshal.PtrToStringAnsi(ptr) ?? string.Empty;
    }

    /// <summary>
    /// Verifies a signature against a message and public key for a given ciphersuite.
    /// </summary>
    /// <remarks>
    /// Works for both FROST (Schnorr) and DKLs23 (ECDSA) signatures.
    /// For FROST suites, <paramref name="message"/> is the original message.
    /// For DKLs23 suites, <paramref name="message"/> is the raw message
    /// (hashing is handled internally by the native library).
    /// </remarks>
    /// <param name="suite">The ciphersuite that was used for signing.</param>
    /// <param name="message">The message that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKey">The public key bytes.</param>
    /// <returns>True if the signature is valid; false otherwise.</returns>
    public static unsafe bool Verify(
        Ciphersuite suite,
        byte[] message,
        byte[] signature,
        byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);

        fixed (byte* pMsg = message)
        fixed (byte* pSig = signature)
        fixed (byte* pPk = publicKey)
        {
            var msgSlice = new TssSlice { Data = pMsg, Len = (nuint)message.Length };
            var sigSlice = new TssSlice { Data = pSig, Len = (nuint)signature.Length };
            var pkSlice = new TssSlice { Data = pPk, Len = (nuint)publicKey.Length };

            return Native.tss_verify((byte)suite, msgSlice, sigSlice, pkSlice);
        }
    }
}
