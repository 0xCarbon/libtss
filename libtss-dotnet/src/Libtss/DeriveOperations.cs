namespace Libtss;

/// <summary>
/// BIP-32 key derivation operations for threshold signing key shares.
/// Supports non-hardened derivation for Secp256k1ECDSA (DKLs23),
/// Secp256r1ECDSA (DKLs23), and Secp256k1Taproot (FROST).
/// </summary>
public static class DeriveOperations
{
    /// <summary>
    /// Derives a child key share using non-hardened BIP-32 derivation.
    /// The original key share remains valid; the returned handle is a new key share.
    /// </summary>
    /// <param name="keyShare">The parent key share handle.</param>
    /// <param name="childNumber">Non-hardened child index (must be less than 2^31).</param>
    /// <returns>A new key share handle for the derived child.</returns>
    public static unsafe KeyShareHandle DeriveChild(KeyShareHandle keyShare, uint childNumber)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        if (childNumber >= (1u << 31))
            throw new ArgumentOutOfRangeException(nameof(childNumber), "Must be less than 2^31 (non-hardened).");

        ulong outHandle;
        int status = Native.tss_derive_child(keyShare.Handle, childNumber, &outHandle);
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }

    /// <summary>
    /// Derives a key share along a BIP-32 path (e.g. "m/44/60/0/0").
    /// Hardened segments (e.g. "m/44'/0'") are rejected.
    /// The original key share remains valid.
    /// </summary>
    /// <param name="keyShare">The root key share handle.</param>
    /// <param name="path">BIP-32 derivation path string.</param>
    /// <returns>A new key share handle for the derived key.</returns>
    public static unsafe KeyShareHandle DerivePath(KeyShareHandle keyShare, string path)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(path);
        if (path.Contains('\0'))
            throw new ArgumentException("Path must not contain NUL bytes.", nameof(path));

        ulong outHandle;
        int status = Native.tss_derive_path(keyShare.Handle, path, &outHandle);
        TssException.ThrowIfError(status);
        return new KeyShareHandle(outHandle);
    }
}
