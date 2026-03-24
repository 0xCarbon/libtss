using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Memory hardening verification tests (Issue #75).
/// Validates that SecureBytes, WipeBytes, and handle lifecycle
/// behave correctly from the .NET binding perspective.
/// </summary>
public class MemoryHardeningTests
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

    // -- SecureBytes lifecycle ------------------------------------------------

    [Fact]
    public void SecureBytes_SourceArrayIsZeroed()
    {
        var source = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        using var secure = new SecureBytes(source);
        Assert.All(source, b => Assert.Equal(0, b));
    }

    [Fact]
    public unsafe void SecureBytes_HoldsCorrectData()
    {
        var expected = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var copy = (byte[])expected.Clone();
        using var secure = new SecureBytes(copy);
        Assert.Equal(expected, secure.Span.ToArray());
        Assert.Equal(expected.Length, secure.Length);
    }

    [Fact]
    public void SecureBytes_DisposeIsIdempotent()
    {
        var secure = new SecureBytes(new byte[] { 1, 2, 3 });
        secure.Dispose();
        secure.Dispose();
        secure.Dispose(); // triple dispose
    }

    [Fact]
    public void SecureBytes_ThrowsAfterDispose()
    {
        var secure = new SecureBytes(new byte[] { 1, 2 });
        secure.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = secure.Length; });
        Assert.Throws<ObjectDisposedException>(() => { _ = secure.Span; });
        Assert.Throws<ObjectDisposedException>(() => secure.CopyTo(new byte[2]));
    }

    [Fact]
    public void SecureBytes_CopyToWorks()
    {
        var expected = new byte[] { 10, 20, 30, 40 };
        using var secure = new SecureBytes((byte[])expected.Clone());
        var dest = new byte[4];
        secure.CopyTo(dest);
        Assert.Equal(expected, dest);
    }

    [Fact]
    public void SecureBytes_CopyToThrowsIfDestinationTooSmall()
    {
        using var secure = new SecureBytes(new byte[] { 1, 2, 3, 4 });
        Assert.Throws<ArgumentException>(() => secure.CopyTo(new byte[2]));
    }

    [Fact]
    public void SecureBytes_EmptyArrayThrows()
    {
        Assert.Throws<ArgumentException>(() => new SecureBytes(Array.Empty<byte>()));
    }

    [Fact]
    public void SecureBytes_NullArrayThrows()
    {
        Assert.Throws<ArgumentNullException>(() => new SecureBytes(null!));
    }

    // -- WipeBytes ------------------------------------------------------------

    [Fact]
    public void WipeBytes_ZeroesAllBytes()
    {
        var sizes = new[] { 1, 16, 32, 64, 256, 1024 };
        foreach (var sz in sizes)
        {
            var data = new byte[sz];
            for (int i = 0; i < sz; i++)
                data[i] = (byte)((i % 255) + 1); // non-zero fill
            Tss.WipeBytes(data);
            Assert.All(data, b => Assert.Equal(0, b));
        }
    }

    [Fact]
    public void WipeBytes_NullIsSafe()
    {
        Tss.WipeBytes((byte[]?)null);
    }

    [Fact]
    public void WipeBytes_EmptyIsSafe()
    {
        Tss.WipeBytes(Array.Empty<byte>());
    }

    [Fact]
    public void WipeBytes_SpanZeroesData()
    {
        var data = new byte[] { 0xFF, 0xFE, 0xFD };
        Tss.WipeBytes(data.AsSpan());
        Assert.All(data, b => Assert.Equal(0, b));
    }

    // -- KeyShareHandle lifecycle (requires native library) -------------------

    [Fact]
    public void KeyShareHandle_DisposeIsIdempotent()
    {
        RequireNativeLibrary();

        var handles = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, 3, 2, out _);
        try
        {
            var handle = handles[0];
            handle.Dispose();
            handle.Dispose(); // must not panic/crash
        }
        finally
        {
            // Dispose all handles to avoid leaking secret-bearing native memory
            foreach (var h in handles)
                h.Dispose(); // idempotent — safe even if already disposed above
        }
    }

    [Fact]
    public void KeyShareHandle_ThrowsAfterDispose()
    {
        RequireNativeLibrary();

        var handles = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, 3, 2, out _);
        var handle = handles[0];
        // Dispose the other handles
        for (int i = 1; i < handles.Length; i++)
            handles[i].Dispose();

        handle.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = handle.Identifier);
        Assert.Throws<ObjectDisposedException>(() => _ = handle.Ciphersuite);
    }

    // -- ExportKeyShareSecure (requires native library) -----------------------

    [Fact]
    public void ExportKeyShareSecure_NoIntermediateManagedCopy()
    {
        RequireNativeLibrary();

        var handles = FrostOperations.GenerateDealer(
            Ciphersuite.Ed25519, 3, 2, out _);
        using var handle = handles[0];
        for (int i = 1; i < handles.Length; i++)
            handles[i].Dispose();

        // ExportKeyShareSecure copies directly from native → unmanaged memory,
        // bypassing the GC heap. We verify it returns valid data that can
        // be used for re-import.
        using var secure = handle.ExportKeyShareSecure();
        Assert.True(secure.Length > 0, "ExportKeyShareSecure returned empty data");

        // Re-import from secure bytes
        using var reimported = KeyShareHandle.ImportKeyShareSecure(secure, Ciphersuite.Ed25519);
        Assert.Equal(handle.Identifier, reimported.Identifier);
    }

    // -- Init -----------------------------------------------------------------

    [Fact]
    public void Init_WithNone_Succeeds()
    {
        RequireNativeLibrary();
        Tss.Init(InitOptions.None);
    }

    [Fact]
    public void Init_MultipleCallsSucceed()
    {
        RequireNativeLibrary();
        Tss.Init(InitOptions.None);
        Tss.Init(InitOptions.None);
        Tss.Init(InitOptions.None);
    }

    [Fact]
    public void Init_Mlock_SucceedsOrThrowsPermissionError()
    {
        RequireNativeLibrary();
        try
        {
            Tss.Init(InitOptions.Mlock);
        }
        catch (TssException)
        {
            // Expected without CAP_IPC_LOCK — must not crash
        }
    }
}
