using System.Security.Cryptography;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>DKLs23 key import and complete refresh through the .NET binding.</summary>
public class DklsTests
{
    private static KeyShareHandle[] Refresh(KeyShareHandle[] shares, byte[] sessionId)
    {
        var sessions = new RefreshSession[shares.Length];
        var outgoing = new Message[shares.Length][];
        for (int i = 0; i < shares.Length; i++)
            (sessions[i], outgoing[i]) = RefreshSession.CreateDkls(shares[i], sessionId);

        var refreshed = new KeyShareHandle[shares.Length];
        try
        {
            for (int round = 0; round < 3; round++)
            {
                var next = new Message[shares.Length][];
                for (int i = 0; i < shares.Length; i++)
                {
                    ushort id = (ushort)(i + 1);
                    var inbound = outgoing
                        .Where((_, sender) => sender != i)
                        .SelectMany(msgs => msgs ?? Array.Empty<Message>())
                        .Where(m => m.To is null || m.To == id)
                        .ToArray();
                    var result = sessions[i].Next(inbound);
                    if (result.Complete)
                        refreshed[i] = result.KeyShare!;
                    else
                        next[i] = result.Messages!;
                }
                outgoing = next;
            }
        }
        finally
        {
            foreach (var s in sessions)
                s.Dispose();
        }
        return refreshed;
    }

    [Theory]
    [InlineData(Ciphersuite.Secp256k1ECDSA)]
    [InlineData(Ciphersuite.Secp256r1ECDSA)]
    public void ImportKeepsKeyAndChainCodeAndRefreshes(Ciphersuite suite)
    {
        var secret = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var chainCode = Enumerable.Repeat((byte)0x17, 32).ToArray();
        var (shares, _) = DklsOperations.SplitKey(suite, secret, 3, 2, chainCode);
        try
        {
            Assert.All(secret, b => Assert.Equal(0, b));
            if (suite == Ciphersuite.Secp256r1ECDSA)
            {
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = Enumerable.Repeat((byte)0x42, 32).ToArray(),
                });
                var q = ecdsa.ExportParameters(false).Q;
                var expected = new byte[33];
                expected[0] = (byte)(0x02 | (q.Y![31] & 1));
                q.X!.CopyTo(expected, 1);
                Assert.Equal(expected, shares[0].GroupVerifyingKey);
            }
            foreach (var share in shares)
                Assert.Equal(chainCode, share.ChainCode);

            var refreshed = Refresh(shares, "dotnet-refresh"u8.ToArray());
            try
            {
                for (int i = 0; i < shares.Length; i++)
                {
                    Assert.Equal(shares[i].GroupVerifyingKey, refreshed[i].GroupVerifyingKey);
                    Assert.NotEqual(shares[i].VerifyingShare, refreshed[i].VerifyingShare);
                }
            }
            finally
            {
                foreach (var h in refreshed)
                    h?.Dispose();
            }
        }
        finally
        {
            foreach (var h in shares)
                h.Dispose();
        }
    }

    private static Message[] Inbound(Message[]?[] outgoing, int self) =>
        outgoing
            .Where((_, sender) => sender != self)
            .SelectMany(msgs => msgs ?? Array.Empty<Message>())
            .Where(m => m.To is null || m.To == self + 1)
            .ToArray();

    /// <summary>DKG and signing advance through Next (native out_complete flag).</summary>
    [Fact]
    public void DkgAndSignAdvanceThroughNext()
    {
        const int n = 2;
        var sessions = new DkgSession[n];
        var outgoing = new Message[]?[n];
        for (int i = 0; i < n; i++)
            (sessions[i], outgoing[i]) = DkgSession.Create(
                Ciphersuite.Secp256k1ECDSA, (ushort)(i + 1), n, 2, "dotnet-dkg"u8.ToArray());

        var shares = new KeyShareHandle[n];
        for (int round = 0; round < 10 && shares.Any(s => s is null); round++)
        {
            var next = new Message[]?[n];
            for (int i = 0; i < n; i++)
            {
                if (shares[i] is not null) continue;
                var result = sessions[i].Next(Inbound(outgoing, i));
                if (result.Complete) shares[i] = result.KeyShare!;
                else next[i] = result.Messages;
            }
            outgoing = next;
        }
        Assert.All(shares, Assert.NotNull);

        var message = SHA256.HashData("dotnet-sign"u8.ToArray());
        var signers = new SignSession[n];
        for (int i = 0; i < n; i++)
            (signers[i], outgoing[i]) = SignSession.Create(
                shares[i], message, new[] { (ushort)(2 - i) }, "dotnet-sign-id"u8.ToArray());

        byte[]? signature = null;
        for (int round = 0; round < 10 && signature is null; round++)
        {
            var next = new Message[]?[n];
            for (int i = 0; i < n; i++)
            {
                var result = signers[i].Next(Inbound(outgoing, i));
                if (result.Complete) signature = result.Signature;
                else next[i] = result.Messages;
            }
            outgoing = next;
        }
        Assert.NotNull(signature);
        Assert.Equal(64, signature!.Length);

        foreach (var s in signers) s.Dispose();
        foreach (var s in sessions) s.Dispose();
        foreach (var h in shares) h.Dispose();
    }

    // BOLT 3, Appendix E: Key Derivation Test Vectors.
    private static readonly byte[] Bolt3BaseSecret = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] Bolt3Secret = Convert.FromHexString("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    private static readonly byte[] Bolt3Point = Convert.FromHexString("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
    private static readonly byte[] Bolt3Local = Convert.FromHexString("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5");
    private static readonly byte[] Bolt3Revocation = Convert.FromHexString("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0");

    // suite (1) + min_signers (2) + verifying key length (4) + verifying key
    private static byte[] PackageKey(byte[] raw) => raw[7..(7 + BitConverter.ToInt32(raw, 3))];

    [Fact]
    public void Bolt3MatchesTheBolt3Vectors()
    {
        var (shares, package) = DklsOperations.SplitKey(
            Ciphersuite.Secp256k1ECDSA, (byte[])Bolt3BaseSecret.Clone(), 3, 2);
        using var local = DklsOperations.Bolt3Derive(shares[0], Bolt3Point);
        using var revocation = DklsOperations.Bolt3DeriveRevocation(shares[0], Bolt3Point, (byte[])Bolt3Secret.Clone());
        Assert.Equal(Bolt3Local, local.GroupVerifyingKey);
        Assert.Equal(Bolt3Revocation, revocation.GroupVerifyingKey);
        Assert.Equal(Bolt3Local, PackageKey(DklsOperations.Bolt3DerivePublicKeys(package, Bolt3Point)));
        Assert.Equal(Bolt3Revocation, PackageKey(DklsOperations.Bolt3DeriveRevocationPublicKeys(package, Bolt3Point)));
        Assert.Throws<TssException>(() =>
            DklsOperations.Bolt3DeriveRevocation(shares[0], Bolt3Point, Enumerable.Repeat((byte)1, 32).ToArray()));
        foreach (var h in shares) h.Dispose();
    }

    [Fact]
    public void ImportRejectsInvalidInput()
    {
        Assert.Throws<TssException>(() =>
            DklsOperations.SplitKey(Ciphersuite.Secp256k1ECDSA, new byte[32], 3, 2));
        Assert.Throws<TssException>(() =>
            DklsOperations.SplitKey(Ciphersuite.Ed25519, Enumerable.Repeat((byte)1, 32).ToArray(), 3, 2));
        Assert.Throws<TssException>(() =>
            DklsOperations.SplitKey(Ciphersuite.Secp256k1ECDSA, Enumerable.Repeat((byte)1, 32).ToArray(), 3, 2, new byte[31]));
    }
}
