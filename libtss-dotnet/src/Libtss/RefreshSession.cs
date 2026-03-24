namespace Libtss;

/// <summary>
/// Result of a refresh session round.
/// </summary>
/// <param name="Complete">True when refresh has finished and results are available.</param>
/// <param name="Messages">Messages to send to other participants (null when complete).</param>
/// <param name="KeyShare">The refreshed key share (only set when complete).</param>
/// <param name="PublicKeyPackage">Serialized updated public key package (only set when complete).</param>
public sealed record RefreshResult(
    bool Complete,
    Message[]? Messages,
    KeyShareHandle? KeyShare,
    byte[]? PublicKeyPackage);

/// <summary>
/// Protocol-agnostic share refresh session.
/// </summary>
/// <remarks>
/// Produces new key shares of the same secret key. The group public key does NOT change.
/// </remarks>
public sealed class RefreshSession : IDisposable
{
    private ulong _handle;
    private int _disposed;

    private RefreshSession(ulong handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Creates an interactive share refresh session and produces first-round messages.
    /// </summary>
    /// <param name="keyShare">The existing key share to refresh.</param>
    /// <param name="participants">
    /// Participant identifiers involved in the refresh.
    /// </param>
    /// <returns>A tuple of the new session and the first-round messages to send.</returns>
    public static unsafe (RefreshSession Session, Message[] Messages) Create(
        KeyShareHandle keyShare,
        ushort[] participants)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(participants);

        ulong sessionHandle;
        var outMessages = new NativeTssBuffer();
        int status;

        fixed (ushort* pParticipants = participants)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            status = Native.tss_refresh_new(
                keyShare.Handle,
                pParticipants,
                (nuint)participants.Length,
                &sessionHandle,
                pOutMessages);
        }
        TssException.ThrowIfError(status);

        byte[] msgBytes = outMessages.ToArray();
        var messages = MessageCodec.Decode(msgBytes);

        return (new RefreshSession(sessionHandle), messages);
    }

    /// <summary>
    /// Creates a receiver-only refresh session (does not produce first-round messages).
    /// </summary>
    /// <remarks>
    /// Used by participants who are receiving a refresh initiated by others.
    /// Call <see cref="Next"/> with the received messages to advance the protocol.
    /// </remarks>
    /// <param name="keyShare">The existing key share to refresh.</param>
    /// <returns>A new receiver refresh session.</returns>
    public static unsafe RefreshSession CreateReceiver(KeyShareHandle keyShare)
    {
        ArgumentNullException.ThrowIfNull(keyShare);

        ulong sessionHandle;
        int status = Native.tss_refresh_receiver(keyShare.Handle, &sessionHandle);
        TssException.ThrowIfError(status);

        return new RefreshSession(sessionHandle);
    }

    /// <summary>
    /// Advances the refresh session with received messages from other participants.
    /// </summary>
    /// <param name="received">Messages received from other participants in the current round.</param>
    /// <returns>
    /// A <see cref="RefreshResult"/> indicating whether the protocol is complete or has more
    /// messages to exchange.
    /// </returns>
    public unsafe RefreshResult Next(Message[] received)
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
            status = Native.tss_refresh_next(
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

            return new RefreshResult(
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

            return new RefreshResult(
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

    ~RefreshSession()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) == 0)
        {
            Native.tss_session_free(_handle);
            _handle = 0;
        }
    }
}
