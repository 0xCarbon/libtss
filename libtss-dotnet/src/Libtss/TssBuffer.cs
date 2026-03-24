namespace Libtss;

/// <summary>
/// RAII wrapper for a native <see cref="Libtss.TssBuffer"/> allocated by the libtss library.
/// Ensures the buffer is freed exactly once via <c>tss_buffer_free</c>.
/// </summary>
/// <remarks>
/// This is an internal helper. Public API methods copy data to managed byte arrays
/// and free the native buffer before returning.
/// </remarks>
internal sealed class NativeTssBuffer : IDisposable
{
    private TssBuffer _buffer;
    private bool _disposed;

    /// <summary>
    /// Wraps an existing native buffer. Takes ownership; the buffer will be freed on dispose.
    /// </summary>
    internal NativeTssBuffer(TssBuffer buffer)
    {
        _buffer = buffer;
    }

    /// <summary>
    /// Creates an empty (null) buffer wrapper.
    /// </summary>
    internal NativeTssBuffer()
    {
        _buffer = default;
    }

    /// <summary>
    /// Returns a reference to the underlying native buffer struct.
    /// Used to pass the buffer address to native functions that populate it.
    /// </summary>
    internal ref TssBuffer Raw => ref _buffer;

    /// <summary>
    /// Copies the native buffer contents to a managed byte array and frees the native buffer.
    /// After this call, the wrapper is disposed and must not be used again.
    /// </summary>
    internal unsafe byte[] ToArray()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NativeTssBuffer));

        if (_buffer.Data == null || _buffer.Len == 0)
        {
            Dispose();
            return [];
        }

        if (_buffer.Len > int.MaxValue)
            throw new InvalidOperationException(
                $"Native buffer too large for managed array: {_buffer.Len} bytes");

        int len = (int)_buffer.Len;
        var result = new byte[len];
        fixed (byte* dest = result)
        {
            Buffer.MemoryCopy(_buffer.Data, dest, len, len);
        }

        Dispose();
        return result;
    }

    /// <summary>
    /// Copies the native buffer contents to a managed byte array without freeing.
    /// The buffer remains valid for further use.
    /// </summary>
    internal unsafe byte[] CopyToArray()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NativeTssBuffer));

        if (_buffer.Data == null || _buffer.Len == 0)
            return [];

        if (_buffer.Len > int.MaxValue)
            throw new InvalidOperationException(
                $"Native buffer too large for managed array: {_buffer.Len} bytes");

        int len = (int)_buffer.Len;
        var result = new byte[len];
        fixed (byte* dest = result)
        {
            Buffer.MemoryCopy(_buffer.Data, dest, len, len);
        }

        return result;
    }

    public unsafe void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_buffer.Data != null)
        {
            fixed (TssBuffer* p = &_buffer)
            {
                Native.tss_buffer_free(p);
            }
        }

        _buffer = default;
    }
}
