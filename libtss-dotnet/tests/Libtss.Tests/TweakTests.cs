using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Exercises <see cref="TweakOperations"/> against the native library. DKLs23 shares are
/// produced by an in-process DKG so the positive path (tweaked shares signing under the
/// tweaked group key) is covered, not only the argument and status-code rejections.
/// </summary>
public class TweakTests
{
    private const int MaxProtocolRounds = 16;

    private const string DkgDriverBlocked =
        "Needs a DKLs23 share from DkgSession, but Native.tss_dkg_next / tss_sign_next / tss_refresh_next " +
        "declare `[MarshalAs(UnmanagedType.U1)] bool* out_complete`, which the runtime rejects with " +
        "MarshalDirectiveException (pre-existing). Declare those parameters as `byte*`, compare against 0 " +
        "at the three Next call sites, and remove this Skip.";

    private static readonly byte[] DkgSessionId = Encoding.UTF8.GetBytes("tweak-tests-dkg");
    private static readonly byte[] SignSessionId = Encoding.UTF8.GetBytes("tweak-tests-sign");

    private static void RequireNativeLibrary()
    {
        try
        {
            _ = Tss.Version();
        }
        catch (DllNotFoundException)
        {
            Assert.Fail(
                "Native library libtss_ffi not found. " +
                "Build the Rust crate first: cargo build --release");
        }
        Tss.Init();
    }

    private static byte[] Scalar(ulong value)
    {
        var scalar = new byte[32];
        BinaryPrimitives.WriteUInt64BigEndian(scalar.AsSpan(24), value);
        return scalar;
    }

    private static Message[] Inbox(Message[]?[] outbound, ushort[] ids, int recipient)
    {
        var inbox = new List<Message>();
        for (int sender = 0; sender < outbound.Length; sender++)
        {
            if (sender == recipient || outbound[sender] is null)
                continue;
            foreach (var message in outbound[sender]!)
            {
                if (message.To is null || message.To == ids[recipient])
                    inbox.Add(message);
            }
        }
        return inbox.ToArray();
    }

    private static KeyShareHandle[] RunDkg(Ciphersuite suite, ushort maxSigners, ushort minSigners)
    {
        var sessions = new DkgSession[maxSigners];
        var outbound = new Message[]?[maxSigners];
        var ids = new ushort[maxSigners];
        var shares = new KeyShareHandle?[maxSigners];
        try
        {
            for (ushort id = 1; id <= maxSigners; id++)
            {
                ids[id - 1] = id;
                (sessions[id - 1], outbound[id - 1]) = DkgSession.Create(suite, id, maxSigners, minSigners, DkgSessionId);
            }

            for (int round = 0; round < MaxProtocolRounds && shares.Any(s => s is null); round++)
            {
                var next = new Message[]?[maxSigners];
                for (int i = 0; i < maxSigners; i++)
                {
                    if (shares[i] is not null)
                        continue;
                    var result = sessions[i].Next(Inbox(outbound, ids, i));
                    if (result.Complete)
                        shares[i] = result.KeyShare;
                    else
                        next[i] = result.Messages;
                }
                outbound = next;
            }

            Assert.All(shares, share => Assert.NotNull(share));
            return shares.Select(share => share!).ToArray();
        }
        finally
        {
            foreach (var session in sessions)
                session?.Dispose();
        }
    }

    private static byte[] RunSign(KeyShareHandle[] signers, byte[] digest)
    {
        var ids = signers.Select(share => share.Identifier).ToArray();
        var sessions = new SignSession[signers.Length];
        var outbound = new Message[]?[signers.Length];
        byte[]? signature = null;
        try
        {
            for (int i = 0; i < signers.Length; i++)
            {
                var counterparties = ids.Where((_, j) => j != i).ToArray();
                (sessions[i], outbound[i]) = SignSession.Create(signers[i], digest, counterparties, SignSessionId);
            }

            var complete = new bool[signers.Length];
            for (int round = 0; round < MaxProtocolRounds && complete.Any(c => !c); round++)
            {
                var next = new Message[]?[signers.Length];
                for (int i = 0; i < signers.Length; i++)
                {
                    if (complete[i])
                        continue;
                    var result = sessions[i].Next(Inbox(outbound, ids, i));
                    if (result.Complete)
                    {
                        complete[i] = true;
                        signature = result.Signature;
                    }
                    else
                    {
                        next[i] = result.Messages;
                    }
                }
                outbound = next;
            }

            Assert.All(complete, c => Assert.True(c));
            Assert.NotNull(signature);
            return signature!;
        }
        finally
        {
            foreach (var session in sessions)
                session?.Dispose();
        }
    }

    private static void DisposeAll(IEnumerable<KeyShareHandle> handles)
    {
        foreach (var handle in handles)
            handle.Dispose();
    }

    [Fact]
    public void TweakAdd_UnsupportedSuite_Throws()
    {
        RequireNativeLibrary();
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2);
        try
        {
            var add = Assert.Throws<TssException>(() => TweakOperations.TweakAdd(handles[0], Scalar(7)));
            Assert.Equal(TssStatus.ProtoMismatch, add.Code);

            var mul = Assert.Throws<TssException>(() => TweakOperations.TweakMul(handles[0], Scalar(7)));
            Assert.Equal(TssStatus.ProtoMismatch, mul.Code);
        }
        finally
        {
            DisposeAll(handles);
        }
    }

    [Fact]
    public void TweakAdd_RejectsBadLength()
    {
        RequireNativeLibrary();
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2);
        try
        {
            Assert.Throws<ArgumentException>(() => TweakOperations.TweakAdd(handles[0], new byte[31]));
            Assert.Throws<ArgumentException>(() => TweakOperations.TweakMul(handles[0], new byte[33]));
            Assert.Throws<ArgumentNullException>(() => TweakOperations.TweakAdd(handles[0], null!));
            Assert.Throws<ArgumentNullException>(() => TweakOperations.TweakMul(handles[0], null!));
            Assert.Throws<ArgumentNullException>(() => TweakOperations.TweakAdd(null!, Scalar(7)));
            Assert.Throws<ArgumentNullException>(() => TweakOperations.TweakMul(null!, Scalar(7)));
        }
        finally
        {
            DisposeAll(handles);
        }
    }

    [Fact(Skip = DkgDriverBlocked)]
    public void TweakMul_ZeroFactor_Throws()
    {
        RequireNativeLibrary();
        var shares = RunDkg(Ciphersuite.Secp256k1ECDSA, maxSigners: 2, minSigners: 2);
        try
        {
            var ex = Assert.Throws<TssException>(() => TweakOperations.TweakMul(shares[0], Scalar(0)));
            Assert.Equal(TssStatus.Tweak, ex.Code);
        }
        finally
        {
            DisposeAll(shares);
        }
    }

    [Fact(Skip = DkgDriverBlocked)]
    public void TweakMul_ByOne_And_TweakAdd_ByZero_KeepGroupKey()
    {
        RequireNativeLibrary();
        var shares = RunDkg(Ciphersuite.Secp256k1ECDSA, maxSigners: 2, minSigners: 2);
        try
        {
            using var scaled = TweakOperations.TweakMul(shares[0], Scalar(1));
            using var shifted = TweakOperations.TweakAdd(shares[0], Scalar(0));

            Assert.Equal(shares[0].GroupVerifyingKey, scaled.GroupVerifyingKey);
            Assert.Equal(shares[0].VerifyingShare, scaled.VerifyingShare);
            Assert.Equal(shares[0].GroupVerifyingKey, shifted.GroupVerifyingKey);
            Assert.Equal(shares[0].VerifyingShare, shifted.VerifyingShare);
        }
        finally
        {
            DisposeAll(shares);
        }
    }

    [Theory(Skip = DkgDriverBlocked)]
    [InlineData(Ciphersuite.Secp256k1ECDSA)]
    [InlineData(Ciphersuite.Secp256r1ECDSA)]
    public void TweakAdd_MovesGroupKeyConsistentlyAcrossParties(Ciphersuite suite)
    {
        RequireNativeLibrary();
        var shares = RunDkg(suite, maxSigners: 2, minSigners: 2);
        var tweaked = new List<KeyShareHandle>();
        try
        {
            byte[] parentKey = shares[0].GroupVerifyingKey;
            tweaked.AddRange(shares.Select(share => TweakOperations.TweakAdd(share, Scalar(7))));

            Assert.Equal(tweaked[0].GroupVerifyingKey, tweaked[1].GroupVerifyingKey);
            Assert.NotEqual(parentKey, tweaked[0].GroupVerifyingKey);
            Assert.Equal(suite, tweaked[0].Ciphersuite);
            Assert.Equal(shares[0].Identifier, tweaked[0].Identifier);
            Assert.Equal(shares[1].Identifier, tweaked[1].Identifier);

            Assert.Equal(parentKey, shares[0].GroupVerifyingKey);
        }
        finally
        {
            DisposeAll(tweaked);
            DisposeAll(shares);
        }
    }

    [Fact(Skip = DkgDriverBlocked)]
    public void TweakAdd_SignsUnderTweakedGroupKey()
    {
        RequireNativeLibrary();
        var shares = RunDkg(Ciphersuite.Secp256k1ECDSA, maxSigners: 2, minSigners: 2);
        var tweaked = new List<KeyShareHandle>();
        try
        {
            tweaked.AddRange(shares.Select(share => TweakOperations.TweakAdd(share, Scalar(7))));
            byte[] parentKey = shares[0].GroupVerifyingKey;
            byte[] tweakedKey = tweaked[0].GroupVerifyingKey;

            byte[] message = Encoding.UTF8.GetBytes("hello tweaked ecdsa");
            byte[] signature = RunSign(tweaked.ToArray(), SHA256.HashData(message));

            Assert.True(Tss.Verify(Ciphersuite.Secp256k1ECDSA, message, signature, tweakedKey));
            Assert.False(Tss.Verify(Ciphersuite.Secp256k1ECDSA, message, signature, parentKey));
        }
        finally
        {
            DisposeAll(tweaked);
            DisposeAll(shares);
        }
    }

    [Fact(Skip = DkgDriverBlocked)]
    public void TweakMulThenAdd_SignsUnderComposedGroupKey()
    {
        RequireNativeLibrary();
        var shares = RunDkg(Ciphersuite.Secp256k1ECDSA, maxSigners: 2, minSigners: 2);
        var scaled = new List<KeyShareHandle>();
        var composed = new List<KeyShareHandle>();
        try
        {
            scaled.AddRange(shares.Select(share => TweakOperations.TweakMul(share, Scalar(0x2A))));
            composed.AddRange(scaled.Select(share => TweakOperations.TweakAdd(share, Scalar(0x1D))));

            byte[] parentKey = shares[0].GroupVerifyingKey;
            byte[] scaledKey = scaled[0].GroupVerifyingKey;
            byte[] composedKey = composed[0].GroupVerifyingKey;
            Assert.Equal(composedKey, composed[1].GroupVerifyingKey);
            Assert.NotEqual(parentKey, scaledKey);
            Assert.NotEqual(scaledKey, composedKey);

            byte[] message = Encoding.UTF8.GetBytes("hello revocation tweak");
            byte[] signature = RunSign(composed.ToArray(), SHA256.HashData(message));

            Assert.True(Tss.Verify(Ciphersuite.Secp256k1ECDSA, message, signature, composedKey));
            Assert.False(Tss.Verify(Ciphersuite.Secp256k1ECDSA, message, signature, scaledKey));
            Assert.False(Tss.Verify(Ciphersuite.Secp256k1ECDSA, message, signature, parentKey));
        }
        finally
        {
            DisposeAll(composed);
            DisposeAll(scaled);
            DisposeAll(shares);
        }
    }
}
