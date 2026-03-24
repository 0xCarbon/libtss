using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Libtss;

/// <summary>
/// FROST-specific operations that are not part of the unified session API.
/// Includes coordinator aggregation, BIP-341 tweaking, trusted dealer key generation,
/// dealer refresh, and share repair.
/// </summary>
public static class FrostOperations
{
    /// <summary>
    /// Aggregates FROST signature shares into a final Schnorr signature.
    /// For coordinator-only deployments where a non-signing coordinator aggregates shares.
    /// </summary>
    /// <param name="suite">Ciphersuite used for signing.</param>
    /// <param name="message">The message that was signed.</param>
    /// <param name="commitments">Concatenated commitment messages from signers (round 1 output).</param>
    /// <param name="shares">Concatenated share messages from signers (round 2 output).</param>
    /// <param name="pubkeyPackage">Serialized public key package.</param>
    /// <returns>The aggregated signature bytes.</returns>
    public static unsafe byte[] Aggregate(
        Ciphersuite suite,
        byte[] message,
        byte[] commitments,
        byte[] shares,
        byte[] pubkeyPackage)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(commitments);
        ArgumentNullException.ThrowIfNull(shares);
        ArgumentNullException.ThrowIfNull(pubkeyPackage);

        var outSig = new NativeTssBuffer();
        int status;

        fixed (byte* pMsg = message)
        fixed (byte* pCommit = commitments)
        fixed (byte* pShares = shares)
        fixed (byte* pPkg = pubkeyPackage)
        fixed (TssBuffer* pOutSig = &outSig.Raw)
        {
            var msgSlice = new TssSlice { Data = pMsg, Len = (nuint)message.Length };
            var commitSlice = new TssSlice { Data = pCommit, Len = (nuint)commitments.Length };
            var sharesSlice = new TssSlice { Data = pShares, Len = (nuint)shares.Length };
            var pkgSlice = new TssSlice { Data = pPkg, Len = (nuint)pubkeyPackage.Length };

            status = Native.tss_frost_aggregate(
                (byte)suite, msgSlice, commitSlice, sharesSlice, pkgSlice, pOutSig);
        }
        TssException.ThrowIfError(status);
        return outSig.ToArray();
    }

    /// <summary>
    /// Applies a BIP-341 Taproot tweak to a key share.
    /// Only valid for <see cref="Ciphersuite.Secp256k1Taproot"/>.
    /// </summary>
    /// <param name="keyShare">The key share to tweak. The original remains valid.</param>
    /// <param name="merkleRoot">
    /// The Taproot merkle root (32 bytes). Pass an empty array for keypath-only.
    /// </param>
    /// <returns>A new tweaked key share handle.</returns>
    public static unsafe KeyShareHandle TweakKeyShare(KeyShareHandle keyShare, byte[] merkleRoot)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(merkleRoot);

        ulong outHandle;
        int status;

        fixed (byte* pMerkle = merkleRoot)
        {
            status = Native.tss_frost_tweak_key_share(
                keyShare.Handle,
                merkleRoot.Length > 0 ? pMerkle : null,
                (nuint)merkleRoot.Length,
                &outHandle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    /// <summary>
    /// Applies a BIP-341 Taproot tweak to a public key package.
    /// Only valid for <see cref="Ciphersuite.Secp256k1Taproot"/>.
    /// </summary>
    /// <param name="pubkeyPackage">Serialized public key package to tweak.</param>
    /// <param name="merkleRoot">
    /// The Taproot merkle root (32 bytes). Pass an empty array for keypath-only.
    /// </param>
    /// <returns>The tweaked serialized public key package.</returns>
    public static unsafe byte[] TweakPublicKeyPackage(byte[] pubkeyPackage, byte[] merkleRoot)
    {
        ArgumentNullException.ThrowIfNull(pubkeyPackage);
        ArgumentNullException.ThrowIfNull(merkleRoot);

        var outPkg = new NativeTssBuffer();
        int status;

        fixed (byte* pPkg = pubkeyPackage)
        fixed (byte* pMerkle = merkleRoot)
        fixed (TssBuffer* pOutPkg = &outPkg.Raw)
        {
            var pkgSlice = new TssSlice { Data = pPkg, Len = (nuint)pubkeyPackage.Length };

            status = Native.tss_frost_tweak_pubkey_package(
                pkgSlice,
                merkleRoot.Length > 0 ? pMerkle : null,
                (nuint)merkleRoot.Length,
                pOutPkg);
        }
        TssException.ThrowIfError(status);
        return outPkg.ToArray();
    }

    /// <summary>
    /// Generates key shares via trusted dealer (for testing or migration).
    /// </summary>
    /// <param name="suite">Ciphersuite for the generated shares.</param>
    /// <param name="maxSigners">Total number of share holders (n).</param>
    /// <param name="minSigners">Minimum signers required (t).</param>
    /// <returns>
    /// A tuple of the generated key share handles and the serialized public key package.
    /// </returns>
    public static unsafe (KeyShareHandle[] Handles, byte[] PublicKeyPackage) GenerateDealer(
        Ciphersuite suite,
        ushort maxSigners,
        ushort minSigners)
    {
        // Pre-allocate handle array sized to maxSigners.
        var handles = new ulong[maxSigners];
        nuint handleCount;
        var outPkg = new NativeTssBuffer();
        int status;

        fixed (ulong* pHandles = handles)
        fixed (TssBuffer* pOutPkg = &outPkg.Raw)
        {
            status = Native.tss_frost_generate_dealer(
                (byte)suite, maxSigners, minSigners,
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

    /// <summary>
    /// Splits an existing secret key into threshold shares via trusted dealer.
    /// </summary>
    /// <param name="suite">Ciphersuite for the generated shares.</param>
    /// <param name="secretKey">The secret key bytes to split.
    /// <b>Warning:</b> This array is securely zeroed after the method returns.
    /// The caller must not rely on its contents after calling this method.</param>
    /// <param name="maxSigners">Total number of share holders (n).</param>
    /// <param name="minSigners">Minimum signers required (t).</param>
    /// <returns>
    /// A tuple of the generated key share handles and the serialized public key package.
    /// </returns>
    public static unsafe (KeyShareHandle[] Handles, byte[] PublicKeyPackage) SplitKey(
        Ciphersuite suite,
        byte[] secretKey,
        ushort maxSigners,
        ushort minSigners)
    {
        ArgumentNullException.ThrowIfNull(secretKey);

        try
        {
            var handles = new ulong[maxSigners];
            nuint handleCount;
            var outPkg = new NativeTssBuffer();
            int status;

            fixed (byte* pKey = secretKey)
            fixed (ulong* pHandles = handles)
            fixed (TssBuffer* pOutPkg = &outPkg.Raw)
            {
                var keySlice = new TssSlice { Data = pKey, Len = (nuint)secretKey.Length };

                status = Native.tss_frost_split_key(
                    (byte)suite, keySlice, maxSigners, minSigners,
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
    /// Trusted dealer refresh: generates refreshing shares without interaction.
    /// The group public key does NOT change.
    /// </summary>
    /// <param name="pubkeyPackage">Serialized public key package.</param>
    /// <param name="participants">Participant identifiers to generate refresh shares for.</param>
    /// <returns>
    /// A tuple of per-participant refresh share blobs keyed by participant ID
    /// and the updated serialized public key package.
    /// </returns>
    public static unsafe (Dictionary<ushort, byte[]> RefreshShares, byte[] PublicKeyPackage) RefreshDealer(
        byte[] pubkeyPackage,
        ushort[] participants)
    {
        ArgumentNullException.ThrowIfNull(pubkeyPackage);
        ArgumentNullException.ThrowIfNull(participants);

        var outShares = new NativeTssBuffer();
        nuint shareCount;
        var outPkg = new NativeTssBuffer();
        int status;

        fixed (byte* pPkg = pubkeyPackage)
        fixed (ushort* pParts = participants)
        fixed (TssBuffer* pOutShares = &outShares.Raw)
        fixed (TssBuffer* pOutPkg = &outPkg.Raw)
        {
            var pkgSlice = new TssSlice { Data = pPkg, Len = (nuint)pubkeyPackage.Length };

            status = Native.tss_frost_refresh_dealer(
                pkgSlice,
                pParts, (nuint)participants.Length,
                pOutShares, &shareCount, pOutPkg);
        }
        TssException.ThrowIfError(status);

        // Parse directly from native memory — no intermediate managed byte[].
        Dictionary<ushort, byte[]> shares;
        byte[] pkgBytes;
        try
        {
            pkgBytes = outPkg.ToArray();
            shares = ParseIdBlobs(
                new ReadOnlySpan<byte>(outShares.Raw.Data, (int)outShares.Raw.Len),
                (int)shareCount);
        }
        finally
        {
            outShares.Dispose();
        }

        return (shares, pkgBytes);
    }

    /// <summary>
    /// Applies a trusted-dealer refreshing share to an existing key share.
    /// </summary>
    /// <param name="keyShare">The existing key share to refresh.</param>
    /// <param name="refreshData">The refresh share data for this participant.</param>
    /// <param name="pubkeyPackage">The updated serialized public key package.</param>
    /// <returns>A new refreshed key share handle.</returns>
    public static unsafe KeyShareHandle ApplyRefresh(
        KeyShareHandle keyShare,
        byte[] refreshData,
        byte[] pubkeyPackage)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(refreshData);
        ArgumentNullException.ThrowIfNull(pubkeyPackage);

        ulong outHandle;
        int status;

        fixed (byte* pRefresh = refreshData)
        fixed (byte* pPkg = pubkeyPackage)
        {
            var refreshSlice = new TssSlice { Data = pRefresh, Len = (nuint)refreshData.Length };
            var pkgSlice = new TssSlice { Data = pPkg, Len = (nuint)pubkeyPackage.Length };

            status = Native.tss_frost_apply_refresh(
                keyShare.Handle, refreshSlice, pkgSlice, &outHandle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    /// <summary>
    /// Share repair part 1: generate repair deltas (called by each helper).
    /// </summary>
    /// <param name="keyShare">Helper's key share.</param>
    /// <param name="helpers">Identifiers of all helpers (including self).</param>
    /// <param name="participant">Identifier of the participant being repaired.</param>
    /// <returns>
    /// Per-helper delta blobs keyed by helper identifier, so each delta can be
    /// routed to the correct helper regardless of serialization order.
    /// </returns>
    public static unsafe Dictionary<ushort, byte[]> RepairPart1(
        KeyShareHandle keyShare,
        ushort[] helpers,
        ushort participant)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(helpers);

        var outDeltas = new NativeTssBuffer();
        nuint deltaCount;
        int status;

        fixed (ushort* pHelpers = helpers)
        fixed (TssBuffer* pOutDeltas = &outDeltas.Raw)
        {
            status = Native.tss_frost_repair_part1(
                keyShare.Handle,
                pHelpers, (nuint)helpers.Length,
                participant,
                pOutDeltas, &deltaCount);
        }
        TssException.ThrowIfError(status);

        // Parse directly from native memory — no intermediate managed byte[].
        Dictionary<ushort, byte[]> deltas;
        try
        {
            deltas = ParseIdBlobs(
                new ReadOnlySpan<byte>(outDeltas.Raw.Data, (int)outDeltas.Raw.Len),
                (int)deltaCount);
        }
        finally
        {
            outDeltas.Dispose();
        }
        return deltas;
    }

    /// <summary>
    /// Share repair part 2: sum received deltas into sigma (called by each helper).
    /// </summary>
    /// <param name="suite">Ciphersuite for the repair operation.</param>
    /// <param name="deltas">Delta blobs received from other helpers.</param>
    /// <returns>The sigma blob to send to the recovering participant.</returns>
    public static unsafe byte[] RepairPart2(Ciphersuite suite, byte[][] deltas)
    {
        ArgumentNullException.ThrowIfNull(deltas);

        var outSigma = new NativeTssBuffer();
        int status;

        // Build an array of TssSlice, one per delta.
        var slices = new TssSlice[deltas.Length];

        // We need to pin all delta arrays simultaneously.
        // Use GCHandle for each to ensure they remain pinned during the native call.
        var gcHandles = new System.Runtime.InteropServices.GCHandle[deltas.Length];
        try
        {
            for (int i = 0; i < deltas.Length; i++)
            {
                gcHandles[i] = System.Runtime.InteropServices.GCHandle.Alloc(
                    deltas[i], System.Runtime.InteropServices.GCHandleType.Pinned);
                slices[i] = new TssSlice
                {
                    Data = (byte*)gcHandles[i].AddrOfPinnedObject(),
                    Len = (nuint)deltas[i].Length
                };
            }

            fixed (TssSlice* pSlices = slices)
            fixed (TssBuffer* pOutSigma = &outSigma.Raw)
            {
                status = Native.tss_frost_repair_part2(
                    (byte)suite, pSlices, (nuint)deltas.Length, pOutSigma);
            }
        }
        finally
        {
            for (int i = 0; i < gcHandles.Length; i++)
            {
                if (gcHandles[i].IsAllocated)
                    gcHandles[i].Free();
            }
        }

        TssException.ThrowIfError(status);
        return outSigma.ToArray();
    }

    /// <summary>
    /// Share repair part 3: reconstruct key share from sigmas
    /// (called by the recovering participant).
    /// </summary>
    /// <param name="sigmas">Sigma blobs received from helpers.</param>
    /// <param name="participant">The identifier of the participant being repaired.</param>
    /// <param name="pubkeyPackage">Serialized public key package.</param>
    /// <returns>The reconstructed key share handle.</returns>
    public static unsafe KeyShareHandle RepairPart3(
        byte[][] sigmas,
        ushort participant,
        byte[] pubkeyPackage)
    {
        ArgumentNullException.ThrowIfNull(sigmas);
        ArgumentNullException.ThrowIfNull(pubkeyPackage);

        ulong outHandle;
        int status;

        var slices = new TssSlice[sigmas.Length];
        var gcHandles = new System.Runtime.InteropServices.GCHandle[sigmas.Length];
        try
        {
            for (int i = 0; i < sigmas.Length; i++)
            {
                gcHandles[i] = System.Runtime.InteropServices.GCHandle.Alloc(
                    sigmas[i], System.Runtime.InteropServices.GCHandleType.Pinned);
                slices[i] = new TssSlice
                {
                    Data = (byte*)gcHandles[i].AddrOfPinnedObject(),
                    Len = (nuint)sigmas[i].Length
                };
            }

            fixed (TssSlice* pSlices = slices)
            fixed (byte* pPkg = pubkeyPackage)
            {
                var pkgSlice = new TssSlice { Data = pPkg, Len = (nuint)pubkeyPackage.Length };

                status = Native.tss_frost_repair_part3(
                    pSlices, (nuint)sigmas.Length,
                    participant, pkgSlice, &outHandle);
            }
        }
        finally
        {
            for (int i = 0; i < gcHandles.Length; i++)
            {
                if (gcHandles[i].IsAllocated)
                    gcHandles[i].Free();
            }
        }

        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    /// <summary>
    /// Parses the native id-blob format: repeated (id:u16 LE, len:u32 LE, data).
    /// Accepts a <see cref="ReadOnlySpan{T}"/> so callers can parse directly from
    /// native memory without allocating an intermediate managed array.
    /// </summary>
    private static unsafe Dictionary<ushort, byte[]> ParseIdBlobs(ReadOnlySpan<byte> raw, int expectedCount)
    {
        var result = new Dictionary<ushort, byte[]>(expectedCount);
        int pos = 0;

        for (int i = 0; i < expectedCount; i++)
        {
            if (pos + 6 > raw.Length)
                throw new InvalidOperationException(
                    $"Truncated id-blob at index {i}: need 6 header bytes, have {raw.Length - pos}");

            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(raw.Slice(pos));
            pos += 2;

            int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(pos));
            pos += 4;

            if (pos + len > raw.Length)
                throw new InvalidOperationException(
                    $"Truncated id-blob data at index {i}: need {len} bytes, have {raw.Length - pos}");

            var blob = new byte[len];
            raw.Slice(pos, len).CopyTo(blob);
            result[id] = blob;
            pos += len;
        }

        return result;
    }
}
