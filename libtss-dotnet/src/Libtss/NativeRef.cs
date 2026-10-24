using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Libtss.Tests")]

namespace Libtss;

/// <summary>
/// Reference-counted owner of a native registry handle (session or key share),
/// in the manner of <c>SafeHandle</c>.
/// </summary>
/// <remarks>
/// The owner holds one reference; every native call holds another through a
/// <see cref="Lease"/>. <see cref="Dispose"/> drops the owner's reference and
/// the native handle is freed only when the last reference is released, so a
/// concurrent <c>Dispose</c> or a finalizer waits for in-flight calls instead
/// of freeing the handle underneath them.
/// </remarks>
internal sealed class NativeRef
{
    private readonly ulong _value;
    private readonly Action<ulong> _free;
    private int _refs = 1;
    private int _disposed;
    private int _consumed;

    internal NativeRef(ulong value, Action<ulong> free)
    {
        _value = value;
        _free = free;
    }

    internal bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>
    /// Takes a reference for one native call. Throws
    /// <see cref="ObjectDisposedException"/> after <see cref="Dispose"/>.
    /// </summary>
    /// <param name="ownerName">Owner type name for the exception message. A
    /// name rather than the owner itself, so the owner is not kept reachable
    /// by this call.</param>
    internal Lease Acquire(string ownerName)
    {
        while (true)
        {
            int refs = Volatile.Read(ref _refs);
            if (refs == 0 || Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(ownerName);
            if (Interlocked.CompareExchange(ref _refs, refs + 1, refs) == refs)
                break;
        }
        TestHooks.RunAfterHandleAcquired();
        return new Lease(this);
    }

    private void Release()
    {
        if (Interlocked.Decrement(ref _refs) == 0 && Volatile.Read(ref _consumed) == 0)
            _free(_value);
    }

    /// <summary>Drops the owner's reference. Idempotent.</summary>
    internal void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            Release();
    }

    /// <summary>
    /// The native side consumed the handle (a completed session): drop the
    /// owner's reference without freeing it.
    /// </summary>
    internal void MarkConsumed()
    {
        Volatile.Write(ref _consumed, 1);
        Dispose();
    }

    /// <summary>A reference held for the duration of one native call.</summary>
    internal readonly struct Lease : IDisposable
    {
        private readonly NativeRef _owner;

        internal Lease(NativeRef owner) => _owner = owner;

        internal ulong Value => _owner._value;

        public void Dispose() => _owner.Release();
    }
}

/// <summary>
/// Test-only hook points. Lifetime tests set <see cref="AfterHandleAcquired"/>
/// to force garbage collection and finalizers between reading a native handle
/// and the native call that uses it.
/// </summary>
internal static class TestHooks
{
    internal static volatile Action? AfterHandleAcquired;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void RunAfterHandleAcquired() => AfterHandleAcquired?.Invoke();
}
