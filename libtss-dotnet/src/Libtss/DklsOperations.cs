using System.Security.Cryptography;

namespace Libtss;

/// <summary>
/// DKLs23-specific operations that are not part of the unified session API.
/// </summary>
public static class DklsOperations
{
    /// <summary>
    /// Imports an existing ECDSA key as DKLs23 shares (trusted dealer).
    /// </summary>
    /// <remarks>
    /// The group key is the key's own public key. The caller holds every share: hand each
    /// one to its party, erase the key and the shares, and have the parties run
    /// <see cref="RefreshSession.CreateDkls"/> before use.
    /// </remarks>
    /// <param name="suite"><see cref="Ciphersuite.Secp256k1ECDSA"/> or <see cref="Ciphersuite.Secp256r1ECDSA"/>.</param>
    /// <param name="secretKey">32-byte big-endian secret key.
    /// <b>Warning:</b> This array is securely zeroed after the method returns.</param>
    /// <param name="maxSigners">Total number of share holders (n).</param>
    /// <param name="minSigners">Minimum signers required (t).</param>
    /// <param name="chainCode">The key's existing 32-byte BIP-32 chain code, or <c>null</c>
    /// to sample a new one.</param>
    /// <returns>
    /// A tuple of the key share handles and the serialized public key package.
    /// </returns>
    public static unsafe (KeyShareHandle[] Handles, byte[] PublicKeyPackage) SplitKey(
        Ciphersuite suite,
        byte[] secretKey,
        ushort maxSigners,
        ushort minSigners,
        byte[]? chainCode = null)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        chainCode ??= Array.Empty<byte>();

        try
        {
            var handles = new ulong[maxSigners];
            nuint handleCount;
            var outPkg = new NativeTssBuffer();
            int status;

            fixed (byte* pKey = secretKey)
            fixed (byte* pChainCode = chainCode)
            fixed (ulong* pHandles = handles)
            fixed (TssBuffer* pOutPkg = &outPkg.Raw)
            {
                var keySlice = new TssSlice { Data = pKey, Len = (nuint)secretKey.Length };
                var chainCodeSlice = new TssSlice { Data = pChainCode, Len = (nuint)chainCode.Length };

                status = Native.tss_dkls_split_key(
                    (byte)suite, keySlice, chainCodeSlice, maxSigners, minSigners,
                    pHandles, &handleCount, pOutPkg);
            }
            TssException.ThrowIfError(status);

            byte[] pkgBytes = outPkg.ToArray();
            var result = new KeyShareHandle[(int)handleCount];
            for (int i = 0; i < (int)handleCount; i++)
            {
                result[i] = new KeyShareHandle(handles[i]);
            }

            return (result, pkgBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKey);
        }
    }
}
