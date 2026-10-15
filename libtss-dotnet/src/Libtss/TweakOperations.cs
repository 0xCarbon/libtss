namespace Libtss;

/// <summary>
/// Scalar tweaks for DKLs23 threshold ECDSA key shares
/// (<see cref="Ciphersuite.Secp256k1ECDSA"/> and <see cref="Ciphersuite.Secp256r1ECDSA"/>).
/// Lightning derives per-commitment keys from caller-supplied scalars rather than BIP-32
/// indices: LND's single tweak is <c>k' = k + t (mod n)</c> and its revocation ("double")
/// tweak composes <c>k' = k * a (mod n)</c> with an additive step.
/// </summary>
/// <remarks>
/// <para>
/// Each operation returns a new key share whose secret share, public key, BIP-32 derivation
/// data and address are moved by the given map, together with a public key package whose
/// group key and every verifying share are moved by the same map. Because Lagrange
/// coefficients sum to one, a threshold set of tweaked shares signs under the tweaked group
/// key; every party must apply the same tweak before a signing session.
/// </para>
/// <para>
/// A tweak is not a BIP-32 edge: the derivation metadata still describes the un-tweaked
/// ancestor and the chain code is unchanged. For BIP-341 Taproot tweaking of FROST shares
/// see <see cref="FrostOperations.TweakKeyShare"/>.
/// </para>
/// </remarks>
public static class TweakOperations
{
    private const int ScalarLength = 32;

    /// <summary>
    /// Returns a new key share whose secret is <c>k + tweak (mod n)</c>.
    /// The original key share remains valid.
    /// </summary>
    /// <param name="keyShare">The key share to tweak.</param>
    /// <param name="tweak">
    /// A 32-byte big-endian scalar, reduced mod n (LND's per-commitment "single tweak"
    /// convention). A zero tweak is a no-op.
    /// </param>
    /// <returns>A new key share handle for the tweaked share.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keyShare"/> or <paramref name="tweak"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="tweak"/> is not 32 bytes.</exception>
    /// <exception cref="TssException">
    /// <see cref="TssStatus.ProtoMismatch"/> when the key share is not a DKLs23 share;
    /// <see cref="TssStatus.Tweak"/> when the tweak produces the identity public key.
    /// </exception>
    public static unsafe KeyShareHandle TweakAdd(KeyShareHandle keyShare, byte[] tweak)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ValidateScalar(tweak, nameof(tweak));

        ulong outHandle;
        int status;
        fixed (byte* p = tweak)
        {
            status = Native.tss_tweak_add(keyShare.Handle, p, (nuint)tweak.Length, &outHandle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    /// <summary>
    /// Returns a new key share whose secret is <c>k * factor (mod n)</c>.
    /// The original key share remains valid.
    /// </summary>
    /// <param name="keyShare">The key share to tweak.</param>
    /// <param name="factor">
    /// A 32-byte big-endian scalar, reduced mod n; the building block of LND's revocation
    /// ("double") tweak. A factor of one is a no-op.
    /// </param>
    /// <returns>A new key share handle for the tweaked share.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keyShare"/> or <paramref name="factor"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="factor"/> is not 32 bytes.</exception>
    /// <exception cref="TssException">
    /// <see cref="TssStatus.ProtoMismatch"/> when the key share is not a DKLs23 share;
    /// <see cref="TssStatus.Tweak"/> when the factor reduces to zero.
    /// </exception>
    public static unsafe KeyShareHandle TweakMul(KeyShareHandle keyShare, byte[] factor)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ValidateScalar(factor, nameof(factor));

        ulong outHandle;
        int status;
        fixed (byte* p = factor)
        {
            status = Native.tss_tweak_mul(keyShare.Handle, p, (nuint)factor.Length, &outHandle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    private static void ValidateScalar(byte[] scalar, string paramName)
    {
        ArgumentNullException.ThrowIfNull(scalar, paramName);
        if (scalar.Length != ScalarLength)
            throw new ArgumentException($"Must be exactly {ScalarLength} bytes.", paramName);
    }
}
