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
    private static readonly Action<ulong> FreeHandle = Native.tss_handle_free;

    private readonly NativeRef _native;

    internal KeyShareHandle(ulong handle)
    {
        _native = new NativeRef(handle, FreeHandle);
    }

    /// <summary>
    /// Takes a reference to the native handle for one native call. Dispose the
    /// lease after the call; the handle is not freed (by <see cref="Dispose"/>
    /// on another thread or by the finalizer) while a lease is held.
    /// </summary>
    internal NativeRef.Lease Lease() => _native.Acquire(nameof(KeyShareHandle));

    /// <summary>
    /// The raw native handle value without a lease. Callers must call
    /// <c>GC.KeepAlive</c> on this object after the native call that uses the
    /// value. Prefer <see cref="Lease"/>.
    /// </summary>
    internal ulong Handle
    {
        get
        {
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            return lease.Value;
        }
    }

    /// <summary>
    /// The 1-based participant identifier for this key share.
    /// </summary>
    public unsafe ushort Identifier
    {
        get
        {
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            ushort id;
            int status = Native.tss_handle_identifier(lease.Value, &id);
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
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            byte raw = Native.tss_handle_ciphersuite(lease.Value);
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
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            using var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_group_key(lease.Value, p);
            }
            TssException.ThrowIfError(status);
            return buf.ToArray();
        }
    }

    /// <summary>
    /// The 32-byte BIP-32 chain code paired with <see cref="GroupVerifyingKey"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the BIP-32-capable ciphersuites carry a chain code:
    /// <see cref="Ciphersuite.Secp256k1ECDSA"/>, <see cref="Ciphersuite.Secp256r1ECDSA"/>
    /// and <see cref="Ciphersuite.Secp256k1Taproot"/>. Every other suite throws a
    /// <see cref="TssException"/> with <see cref="TssStatus.ProtoMismatch"/>.
    /// </para>
    /// <para>
    /// Pair with <see cref="GroupVerifyingKey"/> to build a BIP-32 extended public key (xpub)
    /// whose off-MPC child derivation matches <see cref="DeriveOperations.DeriveChild"/>.
    /// For <see cref="Ciphersuite.Secp256k1Taproot"/> the chain code is SHA-256 of the group
    /// key and is re-derived for each child, so an external CKDpub matches only at depth 1.
    /// </para>
    /// </remarks>
    public unsafe byte[] ChainCode
    {
        get
        {
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            using var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_chain_code(lease.Value, p);
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
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            using var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_verifying_share(lease.Value, p);
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
            using var lease = _native.Acquire(nameof(KeyShareHandle));
            using var buf = new NativeTssBuffer();
            int status;
            fixed (TssBuffer* p = &buf.Raw)
            {
                status = Native.tss_handle_pubkey_package(lease.Value, p);
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
        using var lease = _native.Acquire(nameof(KeyShareHandle));
        using var buf = new NativeTssBuffer();
        int status;
        fixed (TssBuffer* p = &buf.Raw)
        {
            status = Native.tss_handle_export(lease.Value, p);
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
        using var lease = _native.Acquire(nameof(KeyShareHandle));
        TssBuffer buf = default;
        int status = Native.tss_handle_export(lease.Value, &buf);
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
        int length = data.Length;
        byte* ptr = (byte*)data.DangerousGetPtr();
        int status = Native.tss_handle_import(ptr, (nuint)length, (byte)suite, &handle);
        // data's finalizer wipes and frees the pointer; keep it reachable
        // until the native call has returned.
        GC.KeepAlive(data);
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

    /// <summary>
    /// Frees the native handle and zeroes secret material. Idempotent; when
    /// a native call on this handle is in flight on another thread, the handle
    /// is freed as soon as that call returns.
    /// </summary>
    public void Dispose()
    {
        _native.Dispose();
        GC.SuppressFinalize(this);
    }

    ~KeyShareHandle()
    {
        _native.Dispose();
    }
}
