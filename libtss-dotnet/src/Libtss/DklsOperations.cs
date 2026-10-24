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
            using var outPkg = new NativeTssBuffer();
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

    /// <summary>
    /// BOLT 3 derivation of a DKLs23 secp256k1 key share for a commitment
    /// (<c>basepoint + SHA256(perCommitmentPoint || basepoint)·G</c>).
    /// </summary>
    /// <remarks>
    /// Every party derives with the same 33-byte compressed point. A derived share keeps the
    /// base share's OT state, so a counterparty banned under a derived key is banned for the
    /// base key too.
    /// </remarks>
    public static unsafe KeyShareHandle Bolt3Derive(KeyShareHandle keyShare, byte[] perCommitmentPoint)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(perCommitmentPoint);
        ulong handle;
        int status;
        using var share = keyShare.Lease();
        fixed (byte* pPoint = perCommitmentPoint)
        {
            var point = new TssSlice { Data = pPoint, Len = (nuint)perCommitmentPoint.Length };
            status = Native.tss_bolt3_derive(share.Value, point, &handle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(handle);
    }

    /// <summary>
    /// BOLT 3 revocation derivation for a commitment whose 32-byte per-commitment secret was
    /// revealed; the secret must match the point. <paramref name="perCommitmentSecret"/> is
    /// securely zeroed after the method returns.
    /// </summary>
    public static unsafe KeyShareHandle Bolt3DeriveRevocation(
        KeyShareHandle keyShare,
        byte[] perCommitmentPoint,
        byte[] perCommitmentSecret)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(perCommitmentPoint);
        ArgumentNullException.ThrowIfNull(perCommitmentSecret);
        try
        {
            ulong handle;
            int status;
            using var share = keyShare.Lease();
            fixed (byte* pPoint = perCommitmentPoint)
            fixed (byte* pSecret = perCommitmentSecret)
            {
                var point = new TssSlice { Data = pPoint, Len = (nuint)perCommitmentPoint.Length };
                var secret = new TssSlice { Data = pSecret, Len = (nuint)perCommitmentSecret.Length };
                status = Native.tss_bolt3_derive_revocation(share.Value, point, secret, &handle);
            }
            TssException.ThrowIfError(status);
            return new KeyShareHandle(handle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(perCommitmentSecret);
        }
    }

    /// <summary><see cref="Bolt3Derive"/> on a serialized secp256k1 ECDSA public key package.</summary>
    public static unsafe byte[] Bolt3DerivePublicKeys(byte[] publicKeyPackage, byte[] perCommitmentPoint) =>
        DerivePackage(publicKeyPackage, perCommitmentPoint, revocation: false);

    /// <summary><see cref="Bolt3DeriveRevocation"/> on a public key package (no secret needed).</summary>
    public static unsafe byte[] Bolt3DeriveRevocationPublicKeys(byte[] publicKeyPackage, byte[] perCommitmentPoint) =>
        DerivePackage(publicKeyPackage, perCommitmentPoint, revocation: true);

    private static unsafe byte[] DerivePackage(byte[] publicKeyPackage, byte[] perCommitmentPoint, bool revocation)
    {
        ArgumentNullException.ThrowIfNull(publicKeyPackage);
        ArgumentNullException.ThrowIfNull(perCommitmentPoint);
        using var outPkg = new NativeTssBuffer();
        int status;
        fixed (byte* pPkg = publicKeyPackage)
        fixed (byte* pPoint = perCommitmentPoint)
        fixed (TssBuffer* pOut = &outPkg.Raw)
        {
            var pkg = new TssSlice { Data = pPkg, Len = (nuint)publicKeyPackage.Length };
            var point = new TssSlice { Data = pPoint, Len = (nuint)perCommitmentPoint.Length };
            status = revocation
                ? Native.tss_bolt3_derive_revocation_pubkey_package(pkg, point, pOut)
                : Native.tss_bolt3_derive_pubkey_package(pkg, point, pOut);
        }
        TssException.ThrowIfError(status);
        return outPkg.ToArray();
    }

    /// <summary>
    /// This helper's DKLs23 repair term for <paramref name="target"/>, as messages to send to
    /// the target only, over a confidential, authenticated channel.
    /// </summary>
    /// <remarks>
    /// <paramref name="helpers"/> lists the helper identifiers (no duplicates, at least
    /// min_signers, including this party, not the target); every helper uses the same list and
    /// <paramref name="repairId"/>. The helpers must authenticate the target: repair hands the
    /// target index's share to whoever receives the terms.
    /// </remarks>
    public static unsafe Message[] RepairHelperTerm(
        KeyShareHandle keyShare,
        ushort[] helpers,
        ushort target,
        byte[] repairId)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(helpers);
        ArgumentNullException.ThrowIfNull(repairId);
        using var outMessages = new NativeTssBuffer();
        int status;
        using var share = keyShare.Lease();
        fixed (ushort* pHelpers = helpers)
        fixed (byte* pId = repairId)
        fixed (TssBuffer* pOut = &outMessages.Raw)
        {
            var id = new TssSlice { Data = pId, Len = (nuint)repairId.Length };
            status = Native.tss_repair_helper_term(
                share.Value, pHelpers, (nuint)helpers.Length, target, id, pOut);
        }
        TssException.ThrowIfError(status);
        byte[] raw = outMessages.ToArray();
        try
        {
            return MessageCodec.Decode(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// Assembles the helpers' repair messages into the target's repaired DKLs23 share. Each
    /// message's <c>From</c> must be its authenticated sender. The share cannot sign until all
    /// parties run <see cref="RefreshSession.CreateDkls"/>.
    /// </summary>
    public static unsafe KeyShareHandle RepairAssemble(
        Ciphersuite suite,
        byte[] publicKeyPackage,
        ushort target,
        Message[] messages)
    {
        ArgumentNullException.ThrowIfNull(publicKeyPackage);
        ArgumentNullException.ThrowIfNull(messages);
        byte[] blob = MessageCodec.Encode(messages);
        try
        {
            ulong handle;
            int status;
            fixed (byte* pPkg = publicKeyPackage)
            fixed (byte* pBlob = blob)
            {
                var pkg = new TssSlice { Data = pPkg, Len = (nuint)publicKeyPackage.Length };
                var msgs = new TssSlice { Data = pBlob, Len = (nuint)blob.Length };
                status = Native.tss_repair_assemble((byte)suite, pkg, target, msgs, &handle);
            }
            TssException.ThrowIfError(status);
            return new KeyShareHandle(handle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }
    }
}
