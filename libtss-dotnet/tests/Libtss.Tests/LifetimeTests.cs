using System.Runtime.CompilerServices;
using Libtss;
using Xunit;

namespace Libtss.Tests;

/// <summary>
/// Native calls must keep their managed owners alive. These tests force
/// collections while calls are in flight on objects that are otherwise
/// unreachable.
/// </summary>
public class LifetimeTests
{
    private static void WithGcPressure(Action body)
    {
        using var stop = new CancellationTokenSource();
        var collector = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        });
        try
        {
            body();
        }
        finally
        {
            stop.Cancel();
            collector.Wait();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static SecureBytes ExportFresh()
    {
        var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 3, 2);
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
    public void ImportKeyShareSecure_SurvivesConcurrentCollection()
    {
        WithGcPressure(() =>
        {
            for (int i = 0; i < 200; i++)
            {
                // The SecureBytes is only reachable through the argument; its
                // finalizer must not run before the native import returns.
                using var imported = KeyShareHandle.ImportKeyShareSecure(ExportFresh(), Ciphersuite.Ed25519);
                Assert.Equal(Ciphersuite.Ed25519, imported.Ciphersuite);
            }
        });
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static KeyShareHandle Unrooted(KeyShareHandle[] handles, int index)
    {
        var h = handles[index];
        handles[index] = null!;
        return h;
    }

    [Fact]
    public void KeyShareHandle_PropertiesSurviveConcurrentCollection()
    {
        WithGcPressure(() =>
        {
            for (int i = 0; i < 200; i++)
            {
                var (handles, _) = FrostOperations.GenerateDealer(Ciphersuite.Ed25519, 3, 2);
                // Each temporary is unreachable once its handle value is loaded.
                Assert.Equal(32, Unrooted(handles, 0).GroupVerifyingKey.Length);
                Assert.Equal(Ciphersuite.Ed25519, Unrooted(handles, 1).Ciphersuite);
                Assert.NotEmpty(Unrooted(handles, 2).Export());
            }
        });
    }
}
