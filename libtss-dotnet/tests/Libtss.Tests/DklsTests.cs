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
