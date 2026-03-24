namespace Libtss;

/// <summary>
/// Result of a signing session round.
/// </summary>
/// <param name="Complete">True when signing has finished and the signature is available.</param>
/// <param name="Messages">Messages to send to other participants (null when complete).</param>
/// <param name="Signature">The final signature bytes (only set when complete).</param>
public sealed record SignResult(
    bool Complete,
    Message[]? Messages,
    byte[]? Signature);

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
    private ulong _handle;
    private int _disposed;

    private SignSession(ulong handle)
    {
        _handle = handle;
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

        ulong sessionHandle;
        var outMessages = new NativeTssBuffer();
        int status;

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
                keyShare.Handle,
                msgSlice,
                pCounterparties,
                counterparties != null ? (nuint)counterparties.Length : 0,
                pSignId,
                signId != null ? (nuint)signId.Length : 0,
                &sessionHandle,
                pOutMessages);
        }
        TssException.ThrowIfError(status);

        byte[] msgBytes = outMessages.ToArray();
        var messages = MessageCodec.Decode(msgBytes);

        return (new SignSession(sessionHandle), messages);
    }

    /// <summary>
    /// Advances the signing session with received messages from other participants.
    /// </summary>
    /// <param name="received">Messages received from other participants in the current round.</param>
    /// <returns>
    /// A <see cref="SignResult"/> indicating whether signing is complete or has more
    /// messages to exchange.
    /// </returns>
    public unsafe SignResult Next(Message[] received)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(received);

        byte[] encodedInput = MessageCodec.Encode(received);
        var outSignature = new NativeTssBuffer();
        var outMessages = new NativeTssBuffer();
        bool complete;
        int status;

        fixed (byte* pInput = encodedInput)
        fixed (TssBuffer* pOutSignature = &outSignature.Raw)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            var inputSlice = new TssSlice
            {
                Data = pInput,
                Len = (nuint)encodedInput.Length
            };
            status = Native.tss_sign_next(
                _handle,
                inputSlice,
                pOutSignature,
                pOutMessages,
                &complete);
        }
        TssException.ThrowIfError(status);

        if (complete)
        {
            byte[] signature = outSignature.ToArray();
            outMessages.Dispose();

            // Session is consumed on completion; prevent double-free.
            Interlocked.Exchange(ref _disposed, 1);
            _handle = 0;
            GC.SuppressFinalize(this);

            return new SignResult(
                Complete: true,
                Messages: null,
                Signature: signature);
        }
        else
        {
            outSignature.Dispose();
            byte[] msgBytes = outMessages.ToArray();
            var messages = MessageCodec.Decode(msgBytes);

            return new SignResult(
                Complete: false,
                Messages: messages,
                Signature: null);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }

    /// <summary>
    /// Frees the native session handle.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        Native.tss_session_free(_handle);
        _handle = 0;
        GC.SuppressFinalize(this);
    }

    ~SignSession()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
        {
            Native.tss_session_free(_handle);
            _handle = 0;
        }
    }
}
