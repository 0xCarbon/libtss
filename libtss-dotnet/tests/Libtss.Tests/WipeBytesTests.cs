using Libtss;
using Xunit;

namespace Libtss.Tests;

public class WipeBytesTests
{
    [Fact]
    public void WipeBytes_ZerosArray()
    {
        var data = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC };
        Tss.WipeBytes(data);
        Assert.All(data, b => Assert.Equal(0, b));
    }

    [Fact]
    public void WipeBytes_NullIsSafe()
    {
        Tss.WipeBytes((byte[]?)null);
    }

    [Fact]
    public void WipeBytes_EmptyArrayIsSafe()
    {
        Tss.WipeBytes(Array.Empty<byte>());
    }

    [Fact]
    public void WipeBytes_Span_ZerosData()
    {
        var data = new byte[] { 1, 2, 3 };
        Tss.WipeBytes(data.AsSpan());
        Assert.All(data, b => Assert.Equal(0, b));
    }
}
