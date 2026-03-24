using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Libtss;

/// <summary>
/// Stores sensitive data in unmanaged, mlock'd memory outside the .NET GC heap.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="SecureBytes(byte[])"/> constructor is a destructive/ownership-transferring
/// operation: the source managed array is securely zeroed after copying. Callers must not
/// rely on the array contents after construction.
/// </para>
/// <para>
/// On dispose (or finalization), the unmanaged memory is securely zeroed via
/// <see cref="NativeMemory.Clear"/>, unlocked, and freed.
/// </para>
/// </remarks>
public sealed class SecureBytes : IDisposable
{
    private IntPtr _ptr;
    private int _length;
    private int _disposed;

    /// <summary>
    /// Creates a <see cref="SecureBytes"/> from a managed array. The source array is
    /// securely zeroed after the data is copied to unmanaged memory.
    /// </summary>
    public SecureBytes(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0)
            throw new ArgumentException("Data must not be empty.", nameof(data));

        _length = data.Length;
        _ptr = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, _ptr, data.Length);
        LockMemory(_ptr, (nuint)_length);
        CryptographicOperations.ZeroMemory(data.AsSpan());
    }

    /// <summary>
    /// Allocates unmanaged memory of the given size. Caller is responsible for
    /// copying data into the buffer via <see cref="DangerousGetPtr"/>.
    /// </summary>
    internal SecureBytes(int length)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        _length = length;
        _ptr = Marshal.AllocHGlobal(length);
        LockMemory(_ptr, (nuint)_length);
    }

    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _length;
        }
    }

    public unsafe ReadOnlySpan<byte> Span
    {
        get
        {
            ThrowIfDisposed();
            return new ReadOnlySpan<byte>((void*)_ptr, _length);
        }
    }

    public unsafe void CopyTo(Span<byte> destination)
    {
        ThrowIfDisposed();
        if (destination.Length < _length)
            throw new ArgumentException("Destination too small.", nameof(destination));

        new ReadOnlySpan<byte>((void*)_ptr, _length).CopyTo(destination);
    }

    internal IntPtr DangerousGetPtr()
    {
        ThrowIfDisposed();
        return _ptr;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }

    public unsafe void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        if (_ptr == IntPtr.Zero)
            return;

        NativeMemory.Clear((void*)_ptr, (nuint)_length);
        UnlockMemory(_ptr, (nuint)_length);
        Marshal.FreeHGlobal(_ptr);
        _ptr = IntPtr.Zero;
        _length = 0;
        GC.SuppressFinalize(this);
    }

    ~SecureBytes()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        if (_ptr == IntPtr.Zero)
            return;

        unsafe { NativeMemory.Clear((void*)_ptr, (nuint)_length); }
        UnlockMemory(_ptr, (nuint)_length);
        Marshal.FreeHGlobal(_ptr);
        _ptr = IntPtr.Zero;
        _length = 0;
    }

    private static void LockMemory(IntPtr ptr, nuint len)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            Native.mlock(ptr, len); // best-effort
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Native.VirtualLock(ptr, len); // best-effort
        }
    }

    private static void UnlockMemory(IntPtr ptr, nuint len)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            Native.munlock(ptr, len); // best-effort
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Native.VirtualUnlock(ptr, len); // best-effort
        }
    }
}
