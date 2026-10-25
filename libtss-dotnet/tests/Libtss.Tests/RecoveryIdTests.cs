using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Signing reports the ECDSA recovery id for DKLs23 (checked by recovering the
/// group key) and null for FROST, and checks per-suite signature lengths.
/// </summary>
public class RecoveryIdTests
{
    private sealed record Curve(BigInteger P, BigInteger A, BigInteger B, BigInteger Gx, BigInteger Gy, BigInteger N);

    private static BigInteger Hex(string s) => BigInteger.Parse("0" + s, System.Globalization.NumberStyles.HexNumber);

    private static readonly Dictionary<Ciphersuite, Curve> Curves = new()
    {
        [Ciphersuite.Secp256k1ECDSA] = new(
            Hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
            0,
            7,
            Hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            Hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
            Hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")),
        [Ciphersuite.Secp256r1ECDSA] = new(
            Hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            Hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
            Hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            Hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            Hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            Hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")),
    };

    private static BigInteger Mod(BigInteger x, BigInteger m) => ((x % m) + m) % m;

    private static BigInteger Inv(BigInteger x, BigInteger m) => BigInteger.ModPow(Mod(x, m), m - 2, m);

    private static (BigInteger X, BigInteger Y)? Add(Curve c, (BigInteger X, BigInteger Y)? p1, (BigInteger X, BigInteger Y)? p2)
    {
        if (p1 is null) return p2;
        if (p2 is null) return p1;
        var (x1, y1) = p1.Value;
        var (x2, y2) = p2.Value;
        if (x1 == x2 && Mod(y1 + y2, c.P) == 0) return null;
        BigInteger lam = x1 == x2
            ? Mod((3 * x1 * x1 + c.A) * Inv(2 * y1, c.P), c.P)
            : Mod((y2 - y1) * Inv(x2 - x1, c.P), c.P);
        var x = Mod(lam * lam - x1 - x2, c.P);
        return (x, Mod(lam * (x1 - x) - y1, c.P));
    }

    private static (BigInteger X, BigInteger Y)? Mul(Curve c, BigInteger k, (BigInteger X, BigInteger Y)? p)
    {
        (BigInteger X, BigInteger Y)? result = null;
        while (k > 0)
        {
            if (!k.IsEven) result = Add(c, result, p);
            p = Add(c, p, p);
            k >>= 1;
        }
        return result;
    }

    private static BigInteger FromBigEndian(ReadOnlySpan<byte> bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: true);

    private static byte[] Recover(Ciphersuite suite, byte[] digest, byte[] sig, int recoveryId)
    {
        var c = Curves[suite];
        var r = FromBigEndian(sig.AsSpan(0, 32));
        var s = FromBigEndian(sig.AsSpan(32, 32));
        // Both field primes are 3 mod 4, so the square root is a single power.
        var y = BigInteger.ModPow(Mod(r * r * r + c.A * r + c.B, c.P), (c.P + 1) / 4, c.P);
        if ((int)(y % 2) != recoveryId) y = c.P - y;
        var e = Mod(FromBigEndian(digest), c.N);
        var rInv = Inv(r, c.N);
        var q = Add(c, Mul(c, Mod(s * rInv, c.N), (r, y)), Mul(c, Mod(-e * rInv, c.N), (c.Gx, c.Gy)))!.Value;
        var outBytes = new byte[33];
        outBytes[0] = (byte)(q.Y.IsEven ? 2 : 3);
        int len = q.X.GetByteCount(isUnsigned: true);
        q.X.TryWriteBytes(outBytes.AsSpan(33 - len), out _, isUnsigned: true, isBigEndian: true);
        return outBytes;
    }

    private static SignResult Sign(KeyShareHandle[] shares, byte[] message, byte[]? signId)
    {
        int n = shares.Length;
        var sessions = new SignSession[n];
        var outgoing = new Message[]?[n];
        for (int i = 0; i < n; i++)
        {
            ushort[]? counterparties = signId is null ? null : new[] { (ushort)(n - i) };
            (sessions[i], outgoing[i]) = SignSession.Create(shares[i], message, counterparties, signId);
        }
        try
        {
            for (int round = 0; round < 10; round++)
            {
                var next = new Message[]?[n];
                for (int i = 0; i < n; i++)
                {
                    ushort id = (ushort)(i + 1);
                    var inbound = outgoing
                        .Where((_, sender) => sender != i)
                        .SelectMany(m => m ?? Array.Empty<Message>())
                        .Where(m => m.To is null || m.To == id)
                        .ToArray();
                    var result = sessions[i].Next(inbound);
                    if (result.Complete) return result;
                    next[i] = result.Messages;
                }
                outgoing = next;
            }
        }
        finally
        {
            foreach (var s in sessions) s.Dispose();
        }
        throw new InvalidOperationException("signing did not complete");
    }

    // Each signature shows a given parity with probability 1/2.
    private const int MaxSignatures = 32;

    [Theory]
    [InlineData(Ciphersuite.Secp256k1ECDSA)]
    [InlineData(Ciphersuite.Secp256r1ECDSA)]
    public void DklsSignaturesReportBothRecoveryIds(Ciphersuite suite)
    {
        var secret = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var (shares, _) = DklsOperations.SplitKey(suite, secret, 2, 2, null);
        try
        {
            var groupKey = shares[0].GroupVerifyingKey;
            var seen = new HashSet<int>();
            for (int attempt = 0; attempt < MaxSignatures && seen.Count < 2; attempt++)
            {
                var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"recovery-{attempt}"));
                var result = Sign(shares, digest, Encoding.UTF8.GetBytes($"dotnet-recovery-{suite}-{attempt}"));
                Assert.Equal(64, result.Signature!.Length);
                Assert.NotNull(result.RecoveryId);
                int recoveryId = result.RecoveryId!.Value;
                Assert.InRange(recoveryId, 0, 1);
                Assert.Equal(groupKey, Recover(suite, digest, result.Signature, recoveryId));
                seen.Add(recoveryId);
            }
            Assert.Equal(new[] { 0, 1 }, seen.Order());
        }
        finally
        {
            foreach (var h in shares) h.Dispose();
        }
    }

    [Theory]
    [InlineData(Ciphersuite.Secp256k1Taproot, 64)]
    [InlineData(Ciphersuite.Secp256k1, 65)]
    [InlineData(Ciphersuite.Ed25519, 64)]
    [InlineData(Ciphersuite.P256, 65)]
    [InlineData(Ciphersuite.Ristretto255, 64)]
    [InlineData(Ciphersuite.Ed448, 114)]
    public void FrostSignaturesHaveNoRecoveryId(Ciphersuite suite, int length)
    {
        Assert.Equal(length, suite.SignatureLength());
        var (shares, _) = FrostOperations.GenerateDealer(suite, 2, 2);
        try
        {
            var result = Sign(shares, "frost message"u8.ToArray(), null);
            Assert.Equal(length, result.Signature!.Length);
            Assert.Null(result.RecoveryId);
        }
        finally
        {
            foreach (var h in shares) h.Dispose();
        }
    }

    [Fact]
    public void MalformedMessageBundleThrowsDeserialize()
    {
        var err = Assert.Throws<TssException>(() => MessageCodec.Decode(new byte[] { 1, 0, 2 }));
        Assert.Equal(TssStatus.Deserialize, err.Code);
    }
}
