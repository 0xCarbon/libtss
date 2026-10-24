namespace Libtss;

/// <summary>
/// Result of a signing session round.
/// </summary>
/// <param name="Complete">True when signing has finished and the signature is available.</param>
/// <param name="Messages">Messages to send to other participants (null when complete).</param>
/// <param name="Signature">The final signature bytes (only set when complete).</param>
/// <param name="RecoveryId">ECDSA recovery id (0 or 1) of a completed DKLs23 signature; null otherwise.</param>
public sealed record SignResult(
    bool Complete,
    Message[]? Messages,
    byte[]? Signature,
    byte? RecoveryId = null);

/// <summary>
/// Protocol-agnostic signing session.
/// </summary>
/// <remarks>
/// <para>
/// Wraps either FROST signing (3 rounds: commit, share, aggregate) or
/// DKLs23 signing (4 phases) internally.
/// </para>
/// <para>
/// Both protocols produce a final signature. FROST includes a local aggregation step
/// as round 3 so every participant gets the signature.
/// </para>
/// </remarks>
public sealed class SignSession : IDisposable
{
    private static readonly Action<ulong> FreeSession = Native.tss_session_free;

    private readonly NativeRef _native;
    private readonly Ciphersuite _suite;

    private SignSession(ulong handle, Ciphersuite suite)
    {
        _native = new NativeRef(handle, FreeSession);
        _suite = suite;
    }

    /// <summary>
    /// Creates a signing session and produces first-round messages.
    /// </summary>
    /// <param name="keyShare">Key share handle to sign with.</param>
    /// <param name="message">
    /// The message to sign. For FROST suites, this is the original message.
    /// For DKLs23 suites, this must be a 32-byte hash.
    /// </param>
    /// <param name="counterparties">
    /// Counterparty identifiers. Required for DKLs23; ignored for FROST (pass null).
    /// </param>
    /// <param name="signId">
    /// Signing session identifier for domain separation. Required for DKLs23; ignored for FROST.
    /// </param>
    /// <returns>A tuple of the new session and the first-round messages to send.</returns>
    public static unsafe (SignSession Session, Message[] Messages) Create(
        KeyShareHandle keyShare,
        byte[] message,
        ushort[]? counterparties = null,
        byte[]? signId = null)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(message);

        Ciphersuite suite = keyShare.Ciphersuite;
        ulong sessionHandle;
        using var outMessages = new NativeTssBuffer();
        int status;

        using (var share = keyShare.Lease())
        fixed (byte* pMessage = message)
        fixed (ushort* pCounterparties = counterparties)
        fixed (byte* pSignId = signId)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            var msgSlice = new TssSlice
            {
                Data = pMessage,
                Len = (nuint)message.Length
            };

            status = Native.tss_sign_new(
                share.Value,
                msgSlice,
                pCounterparties,
                counterparties != null ? (nuint)counterparties.Length : 0,
                pSignId,
                signId != null ? (nuint)signId.Length : 0,
                &sessionHandle,
                pOutMessages);
            TssException.ThrowIfError(status);
        }

        var session = new SignSession(sessionHandle, suite);
        try
        {
            return (session, MessageCodec.DecodeAndWipe(outMessages.ToArray()));
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Advances the signing session with received messages from other participants.
    /// </summary>
    /// <param name="received">Messages received from other participants in the current round.</param>
    /// <returns>
    /// A <see cref="SignResult"/> indicating whether signing is complete or has more
    /// messages to exchange. A completed DKLs23 signature carries its ECDSA
    /// recovery id (0 or 1) in <see cref="SignResult.RecoveryId"/>; FROST
    /// signatures carry null.
    /// </returns>
    public unsafe SignResult Next(Message[] received)
    {
        ObjectDisposedException.ThrowIf(_native.IsDisposed, this);
        ArgumentNullException.ThrowIfNull(received);

        byte[] encodedInput = MessageCodec.Encode(received);
        using var outSignature = new NativeTssBuffer();
        using var outMessages = new NativeTssBuffer();
        byte recoveryId = Native.TSS_NO_RECOVERY_ID;
        byte complete;
        int status;

        try
        {
            using var lease = _native.Acquire(nameof(SignSession));
            fixed (byte* pInput = encodedInput)
            fixed (TssBuffer* pOutSignature = &outSignature.Raw)
            fixed (TssBuffer* pOutMessages = &outMessages.Raw)
            {
                var inputSlice = new TssSlice
                {
                    Data = pInput,
                    Len = (nuint)encodedInput.Length
                };
                status = Native.tss_sign_next_recoverable(
                    lease.Value,
                    inputSlice,
                    pOutSignature,
                    &recoveryId,
                    pOutMessages,
                    &complete);
            }
            TssException.ThrowIfError(status);
        }
        finally
        {
            Tss.WipeBytes(encodedInput);
        }

        if (complete != 0)
        {
            // The native session is consumed on completion.
            _native.MarkConsumed();
            GC.SuppressFinalize(this);

            byte[] signature = outSignature.ToArray();
            outMessages.Dispose();

            int expected = _suite.SignatureLength();
            if (signature.Length != expected)
                throw new InvalidOperationException(
                    $"invalid signature length for ciphersuite {_suite}: expected {expected} bytes, got {signature.Length}");

            byte? recovery = null;
            if (_suite.GetProtocol() == Protocol.DKLs23)
            {
                if (recoveryId > 1)
                    throw new InvalidOperationException("DKLs23 signature is missing its recovery id");
                recovery = recoveryId;
            }

            return new SignResult(
                Complete: true,
                Messages: null,
                Signature: signature,
                RecoveryId: recovery);
        }
        else
        {
            outSignature.Dispose();
            var messages = MessageCodec.DecodeAndWipe(outMessages.ToArray());

            return new SignResult(
                Complete: false,
                Messages: messages,
                Signature: null);
        }
    }

    /// <summary>
    /// Frees the native session handle. Idempotent; when <see cref="Next"/> is
    /// in flight on another thread, the session is freed as soon as that call
    /// returns.
    /// </summary>
    public void Dispose()
    {
        _native.Dispose();
        GC.SuppressFinalize(this);
    }

    ~SignSession()
    {
        _native.Dispose();
    }
}
