using System.Reflection;
using System.Runtime.CompilerServices;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Native calls must keep their native handles alive. The tests use
/// <see cref="TestHooks.AfterHandleAcquired"/> to run a full collection and
/// the finalizers between reading a native handle and the native call that
/// uses it, on owners that are otherwise unreachable, and to dispose a
/// session while its <c>Next</c> is in flight.
/// </summary>
/// <remarks>
/// Whether the JIT lets an owner become unreachable during its own call
/// depends on the build and the method, so the collection tests are best
/// effort. The finalizer and dispose tests run the finalizer or
/// <c>Dispose</c> at the hook point directly and are deterministic.
/// </remarks>
[Collection("TestHooks")]
public class LifetimeTests : IDisposable
{

    public LifetimeTests()
    {
        TestHooks.AfterHandleAcquired = () =>
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        };
    }

    public void Dispose() => TestHooks.AfterHandleAcquired = null;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static KeyShareHandle[] Dealer() =>
        FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 2, 2).Handles;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private KeyShareHandle Unrooted()
    {
        var handles = Dealer();
        handles[1].Dispose();
        return handles[0];
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private SecureBytes UnrootedExport()
    {
        var handles = Dealer();
        try
        {
            return handles[0].ExportKeyShareSecure();
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
        }
    }

    [Fact]
    public void KeyShareHandle_SurvivesFinalizationDuringCall()
    {
        for (int i = 0; i < 3; i++)
        {
            // Each temporary is unreachable once its handle value is read.
            Assert.Equal(32, Unrooted().GroupVerifyingKey.Length);
            Assert.Equal(Ciphersuite.Ed25519, Unrooted().Ciphersuite);
            Assert.NotEmpty(Unrooted().Export());
            Assert.NotEmpty(Unrooted().VerifyingShare);
        }
    }

    [Fact]
    public void ImportKeyShareSecure_SurvivesFinalizationDuringCall()
    {
        for (int i = 0; i < 3; i++)
        {
            // The SecureBytes is only reachable through the argument; its
            // finalizer must not free the memory before the import returns.
            using var imported = KeyShareHandle.ImportKeyShareSecure(UnrootedExport(), Ciphersuite.Ed25519);
            Assert.Equal(Ciphersuite.Ed25519, imported.Ciphersuite);
        }
    }

    private static void RunFinalizer(object owner) =>
        owner.GetType()
            .GetMethod("Finalize", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(owner, null);

    [Fact]
    public void Finalizer_DuringKeyShareCall_DoesNotFreeTheHandle()
    {
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 2, 2);
        handles[1].Dispose();
        var share = handles[0];
        // Runs the finalizer between reading the handle and the native call,
        // as the GC may when the owner is unreachable during its own call.
        TestHooks.AfterHandleAcquired = () =>
        {
            TestHooks.AfterHandleAcquired = null;
            RunFinalizer(share);
        };
        Assert.Equal(32, share.GroupVerifyingKey.Length);
        GC.SuppressFinalize(share);
    }

    [Fact]
    public void Finalizer_DuringNext_DoesNotFreeTheSession()
    {
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 2, 2);
        try
        {
            var (s1, m1) = SignSession.Create(handles[0], [1, 2, 3]);
            var (s2, _) = SignSession.Create(handles[1], [1, 2, 3]);
            using var keep = s1;
            ulong raw = NativeValue(s2);
            TestHooks.AfterHandleAcquired = () =>
            {
                TestHooks.AfterHandleAcquired = null;
                RunFinalizer(s2);
            };
            var step = s2.Next(m1);
            Assert.False(step.Complete);
            GC.SuppressFinalize(s2);
            // Freed once the in-flight call returned.
            var err = Assert.Throws<TssException>(() => RawSignNext(raw));
            Assert.Equal(TssStatus.HandleInvalid, err.Code);
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
        }
    }

    private static ulong NativeValue(object owner)
    {
        var field = owner.GetType().GetField("_native", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var native = field.GetValue(owner)!;
        return (ulong)native.GetType().GetField("_value", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(native)!;
    }

    [Fact]
    public void Dispose_DuringNext_WaitsAndThenFreesTheSession()
    {
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 2, 2);
        try
        {
            var (s1, m1) = SignSession.Create(handles[0], [1, 2, 3]);
            var (s2, _) = SignSession.Create(handles[1], [1, 2, 3]);
            using var keep = s1;
            ulong raw = NativeValue(s2);

            // Dispose s2 from inside its own Next, after the handle is
            // acquired and before the native call.
            TestHooks.AfterHandleAcquired = () =>
            {
                TestHooks.AfterHandleAcquired = null;
                s2.Dispose();
            };
            var step = s2.Next(m1);
            Assert.False(step.Complete);
            Assert.NotEmpty(step.Messages!);

            Assert.Throws<ObjectDisposedException>(() => s2.Next([]));
            // The native session was freed when the in-flight call returned.
            var err = Assert.Throws<TssException>(() => RawSignNext(raw));
            Assert.Equal(TssStatus.HandleInvalid, err.Code);
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
        }
    }

    [Fact]
    public void Dispose_DuringKeyShareCall_FreesAfterTheCall()
    {
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 2, 2);
        handles[1].Dispose();
        var share = handles[0];
        TestHooks.AfterHandleAcquired = () =>
        {
            TestHooks.AfterHandleAcquired = null;
            share.Dispose();
        };
        Assert.Equal(32, share.GroupVerifyingKey.Length);
        Assert.Throws<ObjectDisposedException>(() => share.Ciphersuite);
    }

    private static unsafe void RawSignNext(ulong session)
    {
        TssBuffer sig = default, msgs = default;
        byte recovery, complete;
        int status = Native.tss_sign_next_recoverable(session, default, &sig, &recovery, &msgs, &complete);
        TssException.ThrowIfError(status);
    }
}

[CollectionDefinition("TestHooks", DisableParallelization = true)]
public class TestHooksCollection
{
}
