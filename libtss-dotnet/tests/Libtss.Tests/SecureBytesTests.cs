using Libtss;
using Xunit;

namespace Libtss.Tests;

public class SecureBytesTests
{
    [Fact]
    public void SourceArrayIsZeroed()
    {
        var source = new byte[] { 1, 2, 3, 4, 5 };
        using var secure = new SecureBytes(source);
        Assert.All(source, b => Assert.Equal(0, b));
    }

    [Fact]
    public unsafe void SpanReturnsCorrectData()
    {
        var expected = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var copy = (byte[])expected.Clone();
        using var secure = new SecureBytes(copy);
        Assert.Equal(expected, secure.Span.ToArray());
    }

    [Fact]
    public void CopyToWorks()
    {
        var expected = new byte[] { 10, 20, 30 };
        var copy = (byte[])expected.Clone();
        using var secure = new SecureBytes(copy);

        var dest = new byte[3];
        secure.CopyTo(dest);
        Assert.Equal(expected, dest);
    }

    [Fact]
    public void LengthReturnsCorrectValue()
    {
        var source = new byte[] { 1, 2, 3 };
        using var secure = new SecureBytes(source);
        Assert.Equal(3, secure.Length);
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        var secure = new SecureBytes(new byte[] { 1, 2, 3 });
        secure.Dispose();
        secure.Dispose();
    }

    [Fact]
    public void ThrowsAfterDispose_Length()
    {
        var secure = new SecureBytes(new byte[] { 1 });
        secure.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = secure.Length; });
    }

    [Fact]
    public unsafe void ThrowsAfterDispose_Span()
    {
        var secure = new SecureBytes(new byte[] { 1 });
        secure.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = secure.Span; });
    }

    [Fact]
    public void ThrowsAfterDispose_CopyTo()
    {
        var secure = new SecureBytes(new byte[] { 1 });
        secure.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { secure.CopyTo(new byte[1]); });
    }

    [Fact]
    public void EmptyArrayThrows()
    {
        Assert.Throws<ArgumentException>(() => { _ = new SecureBytes(Array.Empty<byte>()); });
    }

    [Fact]
    public void NullArrayThrows()
    {
        Assert.Throws<ArgumentNullException>(() => { _ = new SecureBytes(null!); });
    }

    [Fact]
    public void CopyToThrowsIfDestinationTooSmall()
    {
        using var secure = new SecureBytes(new byte[] { 1, 2, 3 });
        Assert.Throws<ArgumentException>(() => { secure.CopyTo(new byte[2]); });
    }
}
