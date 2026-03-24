namespace Libtss;

/// <summary>
/// Result of a DKG session round.
/// </summary>
/// <param name="Complete">True when DKG has finished and results are available.</param>
/// <param name="Messages">Messages to send to other participants (null when complete).</param>
/// <param name="KeyShare">The generated key share (only set when complete).</param>
/// <param name="PublicKeyPackage">Serialized public key package (only set when complete).</param>
public sealed record DkgResult(
    bool Complete,
    Message[]? Messages,
    KeyShareHandle? KeyShare,
    byte[]? PublicKeyPackage);

/// <summary>
/// Protocol-agnostic distributed key generation session.
/// </summary>
/// <remarks>
/// Wraps either FROST DKG (3 rounds) or DKLs23 DKG (4 phases) internally.
/// The client uses the same <see cref="Create"/> / <see cref="Next"/> loop regardless of protocol.
/// </remarks>
public sealed class DkgSession : IDisposable
{
    private ulong _handle;
    private int _disposed;

    private DkgSession(ulong handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Creates a DKG session and produces first-round messages.
    /// </summary>
    /// <param name="suite">Ciphersuite determining protocol, curve, and hash.</param>
    /// <param name="selfId">1-based identifier for this participant.</param>
    /// <param name="maxSigners">Total number of share holders (n).</param>
    /// <param name="minSigners">Minimum signers required (t). Must be &gt;= 2.</param>
    /// <param name="sessionId">
    /// Session identifier for domain separation. Required for DKLs23; optional for FROST.
    /// Pass null for FROST to use the ciphersuite's built-in binding.
    /// </param>
    /// <returns>A tuple of the new session and the first-round messages to send.</returns>
    public static unsafe (DkgSession Session, Message[] Messages) Create(
        Ciphersuite suite,
        ushort selfId,
        ushort maxSigners,
        ushort minSigners,
        byte[]? sessionId = null)
    {
        ulong sessionHandle;
        var outMessages = new NativeTssBuffer();
        int status;

        fixed (byte* pSessionId = sessionId)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            status = Native.tss_dkg_new(
                (byte)suite,
                selfId,
                maxSigners,
                minSigners,
                pSessionId,
                sessionId != null ? (nuint)sessionId.Length : 0,
                &sessionHandle,
                pOutMessages);
        }
        TssException.ThrowIfError(status);

        byte[] msgBytes = outMessages.ToArray();
        var messages = MessageCodec.Decode(msgBytes);

        return (new DkgSession(sessionHandle), messages);
    }

    /// <summary>
    /// Advances the DKG session with received messages from other participants.
    /// </summary>
    /// <param name="received">Messages received from other participants in the current round.</param>
    /// <returns>
    /// A <see cref="DkgResult"/> indicating whether the protocol is complete or has more
    /// messages to exchange.
    /// </returns>
    public unsafe DkgResult Next(Message[] received)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(received);

        byte[] encodedInput = MessageCodec.Encode(received);
        ulong outKeyShare;
        var outPubKeyPkg = new NativeTssBuffer();
        var outMessages = new NativeTssBuffer();
        bool complete;
        int status;

        fixed (byte* pInput = encodedInput)
        fixed (TssBuffer* pPubKeyPkg = &outPubKeyPkg.Raw)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            var inputSlice = new TssSlice
            {
                Data = pInput,
                Len = (nuint)encodedInput.Length
            };
            status = Native.tss_dkg_next(
                _handle,
                inputSlice,
                &outKeyShare,
                pPubKeyPkg,
                pOutMessages,
                &complete);
        }
        TssException.ThrowIfError(status);

        if (complete)
        {
            byte[] pubKeyPkgBytes = outPubKeyPkg.ToArray();
            outMessages.Dispose();

            // Session is consumed on completion; prevent double-free.
            Interlocked.Exchange(ref _disposed, 1);
            _handle = 0;
            GC.SuppressFinalize(this);

            return new DkgResult(
                Complete: true,
                Messages: null,
                KeyShare: new KeyShareHandle(outKeyShare),
                PublicKeyPackage: pubKeyPkgBytes);
        }
        else
        {
            outPubKeyPkg.Dispose();
            byte[] msgBytes = outMessages.ToArray();
            var messages = MessageCodec.Decode(msgBytes);

            return new DkgResult(
                Complete: false,
                Messages: messages,
                KeyShare: null,
                PublicKeyPackage: null);
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

    ~DkgSession()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
        {
            Native.tss_session_free(_handle);
            _handle = 0;
        }
    }
}
