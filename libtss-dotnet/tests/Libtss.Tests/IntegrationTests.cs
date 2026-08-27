using System.Security.Cryptography;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Integration tests that exercise the native libtss_ffi library through the .NET binding.
/// The native library must be built (<c>cargo build --release</c>) and is staged into the
/// test output directory via the csproj. Tests fail explicitly if the native library is missing.
/// </summary>
public class IntegrationTests
{
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
    }

    [Fact]
    public void Init_WithNone_Succeeds()
    {
        RequireNativeLibrary();
        Tss.Init(InitOptions.None);
    }

    [Fact]
    public void Init_WithMlock_SucceedsOrThrowsPermissionError()
    {
        RequireNativeLibrary();
        try
        {
            Tss.Init(InitOptions.Mlock);
        }
        catch (TssException)
        {
            // Expected on systems without CAP_IPC_LOCK / ulimit -l unlimited.
            // The call must not crash — a TssException is the correct failure mode.
        }
    }

    [Fact]
    public void Init_CalledTwice_Succeeds()
    {
        RequireNativeLibrary();
        Tss.Init(InitOptions.None);
        Tss.Init(InitOptions.None);
    }

    [Fact]
    public void ExportImportSecure_RoundTrips()
    {
        RequireNativeLibrary();
        Tss.Init();

        var (handles, _) = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2);
        try
        {
            using var secure = handles[0].ExportKeyShareSecure();
            Assert.True(secure.Length > 0);

            using var imported = KeyShareHandle.ImportKeyShareSecure(secure, Ciphersuite.Ed25519);
            Assert.Equal(handles[0].Identifier, imported.Identifier);

            // Re-export and compare bytes
            using var reExported = imported.ExportKeyShareSecure();
            Assert.Equal(secure.Span.ToArray(), reExported.Span.ToArray());
        }
        finally
        {
            foreach (var h in handles)
                h.Dispose();
        }
    }

    [Fact]
    public void ImportKeyShareSecure_MatchesImport()
    {
        RequireNativeLibrary();
        Tss.Init();

        var (handles, _) = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2);
        try
        {
            byte[] raw = handles[0].Export();
            using var secureData = new SecureBytes((byte[])raw.Clone());
            using var fromSecure = KeyShareHandle.ImportKeyShareSecure(secureData, Ciphersuite.Ed25519);
            using var fromRaw = KeyShareHandle.Import(raw, Ciphersuite.Ed25519);

            Assert.Equal(fromRaw.Identifier, fromSecure.Identifier);
        }
        finally
        {
            foreach (var h in handles)
                h.Dispose();
        }
    }

    [Fact]
    public void SplitKey_ZerosInputSecretKey()
    {
        RequireNativeLibrary();
        Tss.Init();

        var secretKey = new byte[32];
        RandomNumberGenerator.Fill(secretKey);
        secretKey[0] = 0xFF;
        secretKey[31] = 0xAA;

        try
        {
            var (handles, _) = FrostOperations.SplitKey(
                Ciphersuite.Ed25519, secretKey, maxSigners: 3, minSigners: 2);
            foreach (var h in handles)
                h.Dispose();
        }
        catch (TssException)
        {
            // SplitKey may reject an invalid scalar — that's fine,
            // we only care that zeroing happened.
        }

        // The input array must be zeroed regardless of success or failure
        Assert.All(secretKey, b => Assert.Equal(0, b));
    }

    [Fact]
    public void ChainCode_Taproot_IsSha256OfGroupKey()
    {
        RequireNativeLibrary();
        Tss.Init();

        var (handles, _) = FrostOperations.GenerateDealer(
            Ciphersuite.Secp256k1Taproot, maxSigners: 3, minSigners: 2);
        try
        {
            byte[] chainCode = handles[0].ChainCode;
            Assert.Equal(32, chainCode.Length);
            Assert.Equal(SHA256.HashData(handles[0].GroupVerifyingKey), chainCode);
        }
        finally
        {
            foreach (var h in handles)
                h.Dispose();
        }
    }

    [Fact]
    public void ChainCode_ChangesAfterDeriveChild()
    {
        RequireNativeLibrary();
        Tss.Init();

        var (handles, _) = FrostOperations.GenerateDealer(
            Ciphersuite.Secp256k1Taproot, maxSigners: 3, minSigners: 2);
        try
        {
            using var child = DeriveOperations.DeriveChild(handles[0], childNumber: 7);
            byte[] childChainCode = child.ChainCode;
            Assert.Equal(32, childChainCode.Length);
            Assert.NotEqual(handles[0].ChainCode, childChainCode);
        }
        finally
        {
            foreach (var h in handles)
                h.Dispose();
        }
    }

    [Fact]
    public void ChainCode_UnsupportedSuite_Throws()
    {
        RequireNativeLibrary();
        Tss.Init();

        var (handles, _) = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2);
        try
        {
            var ex = Assert.Throws<TssException>(() => handles[0].ChainCode);
            Assert.Equal(TssStatus.ProtoMismatch, ex.Code);
        }
        finally
        {
            foreach (var h in handles)
                h.Dispose();
        }
    }

    [Fact]
    public void WipeBytes_ZerosArray()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        Tss.WipeBytes(data);
        Assert.All(data, b => Assert.Equal(0, b));
    }

    [Fact]
    public void WipeBytes_NullIsSafe()
    {
        Tss.WipeBytes((byte[]?)null);
    }
}
