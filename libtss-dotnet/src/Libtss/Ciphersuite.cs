namespace Libtss;

/// <summary>
/// Threshold signing protocol.
/// </summary>
public enum Protocol : byte
{
    /// <summary>RFC 9591 threshold Schnorr signatures.</summary>
    Frost = 0,

    /// <summary>DKLs23 threshold ECDSA.</summary>
    DKLs23 = 1,
}

/// <summary>
/// Ciphersuite identifier (curve + hash combination).
/// </summary>
public enum Ciphersuite : byte
{
    /// <summary>FROST over secp256k1 with BIP-340 x-only keys (Taproot).</summary>
    Secp256k1Taproot = 0,

    /// <summary>FROST over secp256k1 with standard compressed keys.</summary>
    Secp256k1 = 1,

    /// <summary>FROST over Edwards25519 (Ed25519-compatible signatures).</summary>
    Ed25519 = 2,

    /// <summary>FROST over NIST P-256.</summary>
    P256 = 3,

    /// <summary>FROST over ristretto255.</summary>
    Ristretto255 = 4,

    /// <summary>FROST over Edwards448.</summary>
    Ed448 = 5,

    /// <summary>DKLs23 threshold ECDSA over secp256k1.</summary>
    Secp256k1ECDSA = 6,

    /// <summary>DKLs23 threshold ECDSA over secp256r1 (NIST P-256).</summary>
    Secp256r1ECDSA = 7,
}

/// <summary>
/// Extension methods for <see cref="Ciphersuite"/>.
/// </summary>
public static class CiphersuiteExtensions
{
    /// <summary>
    /// Returns the threshold signing protocol used by this ciphersuite.
    /// </summary>
    public static Protocol GetProtocol(this Ciphersuite suite) => suite switch
    {
        Ciphersuite.Secp256k1ECDSA => Protocol.DKLs23,
        Ciphersuite.Secp256r1ECDSA => Protocol.DKLs23,
        _ => Protocol.Frost,
    };
}
