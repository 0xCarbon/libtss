namespace Libtss;

/// <summary>
/// Opaque handle to a key share stored in the native libtss handle registry.
/// </summary>
/// <remarks>
/// <para>
/// The handle is thread-safe on the Rust side (registry is Mutex-protected).
/// However, the same handle should not be used from multiple threads simultaneously
/// for mutable operations (except <see cref="Dispose"/>, which is idempotent).
/// </para>
/// <para>
/// Secret material is zeroed when the handle is freed.
/// </para>
/// </remarks>
public sealed class KeyShareHandle : IDisposable
{
    private ulong _handle;
    private int _disposed; // int for Interlocked atomics

    internal KeyShareHandle(ulong handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// The raw native handle value. For internal use by session constructors.
    /// </summary>
    internal ulong Handle
    {
        get
        {
            ThrowIfDisposed();
            return _handle;
        }
    }

    /// <summary>
    /// The 1-based participant identifier for this key share.
    /// </summary>
    public unsafe ushort Identifier
    {
        get
        {
            ThrowIfDisposed();
            ushort id;
            int status = Native.tss_handle_identifier(_handle, &id);
            TssException.ThrowIfError(status);
            return id;
        }
    }

    /// <summary>
    /// The ciphersuite this key share belongs to.
    /// </summary>
    public Ciphersuite Ciphersuite
    {
        get
        {
            ThrowIfDisposed();
            byte raw = Native.tss_handle_ciphersuite(_handle);
            return (Ciphersuite)raw;
        }
    }

    /// <summary>
    /// The threshold signing protocol determined by this key share's ciphersuite.
    /// </summary>
    public Protocol Protocol => Ciphersuite.GetProtocol();

    /// <summary>
    /// The group public key (combined verification key) as raw bytes.
    /// </summary>
    public unsafe byte[] GroupVerifyingKey
    {
        get
        {
            ThrowIfDisposed();
            var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_group_key(_handle, p);
            }
            TssException.ThrowIfError(status);
            return buf.ToArray();
        }
    }

    /// <summary>
    /// The public verification key for this specific share as raw bytes.
    /// </summary>
    public unsafe byte[] VerifyingShare
    {
        get
        {
            ThrowIfDisposed();
            var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_verifying_share(_handle, p);
            }
            TssException.ThrowIfError(status);
            return buf.ToArray();
        }
    }

    /// <summary>
    /// The full serialized public key package (group key + all verifying shares).
    /// </summary>
    public unsafe byte[] PublicKeyPackage
    {
        get
        {
            ThrowIfDisposed();
            var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_pubkey_package(_handle, p);
            }
            TssException.ThrowIfError(status);
            return buf.ToArray();
        }
    }

    /// <summary>
    /// Exports the key share as a serialized byte blob.
    /// </summary>
    /// <remarks>
    /// <b>Security:</b> The output contains unencrypted secret key material.
    /// The caller MUST encrypt the bytes before persisting to disk or transmitting
    /// over a network.
    /// </remarks>
    /// <returns>Serialized key share bytes (unencrypted).</returns>
    public unsafe byte[] Export()
    {
        ThrowIfDisposed();
        var buf = new NativeTssBuffer();
        int status;
        fixed (TssBuffer* p = &buf.Raw)
        {
            status = Native.tss_handle_export(_handle, p);
        }
        TssException.ThrowIfError(status);
        return buf.ToArray();
    }

    /// <summary>
    /// Exports the key share into a <see cref="SecureBytes"/> that never touches the GC heap.
    /// Data is copied directly from the native buffer to unmanaged locked memory.
    /// </summary>
    public unsafe SecureBytes ExportKeyShareSecure()
    {
        ThrowIfDisposed();
        TssBuffer buf = default;
        int status = Native.tss_handle_export(_handle, &buf);
        TssException.ThrowIfError(status);

        if (buf.Data == null || buf.Len == 0)
            throw new InvalidOperationException("Export returned empty buffer");

        int len = (int)buf.Len;
        SecureBytes? secure = null;
        try
        {
            secure = new SecureBytes(len);
            Buffer.MemoryCopy(buf.Data, (void*)secure.DangerousGetPtr(), len, len);
        }
        catch
        {
            secure?.Dispose();
            throw;
        }
        finally
        {
            Native.tss_buffer_free(&buf);
        }
        return secure;
    }

    /// <summary>
    /// Imports a key share from a <see cref="SecureBytes"/> without creating intermediate
    /// managed copies. Reads directly from the unmanaged pointer.
    /// </summary>
    public static unsafe KeyShareHandle ImportKeyShareSecure(SecureBytes data, Ciphersuite suite)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0)
            throw new ArgumentException("Data must not be empty.", nameof(data));

        ulong handle;
        int status = Native.tss_handle_import(
            (byte*)data.DangerousGetPtr(), (nuint)data.Length, (byte)suite, &handle);
        TssException.ThrowIfError(status);
        return new KeyShareHandle(handle);
    }

    /// <summary>
    /// Imports a previously exported key share from serialized bytes.
    /// </summary>
    /// <param name="data">Serialized key share bytes (as returned by <see cref="Export"/>).</param>
    /// <param name="suite">The ciphersuite the key share belongs to.</param>
    /// <returns>A new <see cref="KeyShareHandle"/> wrapping the imported share.</returns>
    public static unsafe KeyShareHandle Import(byte[] data, Ciphersuite suite)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0)
            throw new ArgumentException("Data must not be empty.", nameof(data));

        ulong handle;
        int status;
        fixed (byte* p = data)
        {
            status = Native.tss_handle_import(p, (nuint)data.Length, (byte)suite, &handle);
        }
        TssException.ThrowIfError(status);
        return new KeyShareHandle(handle);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }

    /// <summary>
    /// Frees the native handle and zeroes secret material.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        Native.tss_handle_free(_handle);
        _handle = 0;
        GC.SuppressFinalize(this);
    }

    ~KeyShareHandle()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
        {
            Native.tss_handle_free(_handle);
            _handle = 0;
        }
    }
}
