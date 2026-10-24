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
    private static readonly Action<ulong> FreeSession = Native.tss_session_free;

    private readonly NativeRef _native;

    private RefreshSession(ulong handle)
    {
        _native = new NativeRef(handle, FreeSession);
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
        using var outMessages = new NativeTssBuffer();
        int status;

        using (var share = keyShare.Lease())
        fixed (ushort* pParticipants = participants)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            status = Native.tss_refresh_new(
                share.Value,
                pParticipants,
                (nuint)participants.Length,
                &sessionHandle,
                pOutMessages);
        }
        TssException.ThrowIfError(status);

        return WithMessages(new RefreshSession(sessionHandle), outMessages);
    }

    /// <summary>
    /// Creates a DKLs23 complete refresh session (secp256k1 / secp256r1).
    /// </summary>
    /// <remarks>
    /// All parties run it together under the same fresh <paramref name="sessionId"/>;
    /// <see cref="Next"/> is called three times. The group key stays the same and every
    /// share and its OT state are regenerated. Refreshed shares sign only with shares
    /// from the same refresh.
    /// </remarks>
    /// <param name="keyShare">The existing DKLs23 key share to refresh.</param>
    /// <param name="sessionId">Non-empty refresh session identifier shared by all parties.</param>
    /// <returns>A tuple of the new session and the first-round messages to send.</returns>
    public static unsafe (RefreshSession Session, Message[] Messages) CreateDkls(
        KeyShareHandle keyShare,
        byte[] sessionId)
    {
        ArgumentNullException.ThrowIfNull(keyShare);
        ArgumentNullException.ThrowIfNull(sessionId);
        if (sessionId.Length == 0)
            throw new ArgumentException("sessionId must not be empty", nameof(sessionId));

        ulong sessionHandle;
        using var outMessages = new NativeTssBuffer();
        int status;

        using (var share = keyShare.Lease())
        fixed (byte* pSessionId = sessionId)
        fixed (TssBuffer* pOutMessages = &outMessages.Raw)
        {
            status = Native.tss_refresh_new_dkls(
                share.Value,
                pSessionId,
                (nuint)sessionId.Length,
                &sessionHandle,
                pOutMessages);
        }
        TssException.ThrowIfError(status);

        return WithMessages(new RefreshSession(sessionHandle), outMessages);
    }

    private static (RefreshSession Session, Message[] Messages) WithMessages(
        RefreshSession session, NativeTssBuffer outMessages)
    {
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
    /// Creates a FROST receiver-only refresh session (does not produce first-round messages).
    /// </summary>
    /// <remarks>
    /// Used by participants who are receiving a refresh from a trusted dealer.
    /// Call <see cref="Next"/> with the dealer's messages: only the message from
    /// <paramref name="dealer"/> addressed to this party is accepted, and the refreshed
    /// public key package is checked against the current one.
    /// </remarks>
    /// <param name="keyShare">The existing key share to refresh.</param>
    /// <param name="dealer">Identifier of the party that called <see cref="Create"/>.</param>
    /// <returns>A new receiver refresh session.</returns>
    public static unsafe RefreshSession CreateReceiver(KeyShareHandle keyShare, ushort dealer)
    {
        ArgumentNullException.ThrowIfNull(keyShare);

        ulong sessionHandle;
        int status;
        using (var share = keyShare.Lease())
        {
            status = Native.tss_refresh_receiver(share.Value, dealer, &sessionHandle);
        }
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
        ObjectDisposedException.ThrowIf(_native.IsDisposed, this);
        ArgumentNullException.ThrowIfNull(received);

        byte[] encodedInput = MessageCodec.Encode(received);
        ulong outKeyShare;
        using var outPubKeyPkg = new NativeTssBuffer();
        using var outMessages = new NativeTssBuffer();
        byte complete;
        int status;

        try
        {
            using var lease = _native.Acquire(nameof(RefreshSession));
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
                    lease.Value,
                    inputSlice,
                    &outKeyShare,
                    pPubKeyPkg,
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
            byte[] pubKeyPkgBytes = outPubKeyPkg.ToArray();
            outMessages.Dispose();

            // The native session is consumed on completion.
            _native.MarkConsumed();
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
            var messages = MessageCodec.DecodeAndWipe(outMessages.ToArray());

            return new RefreshResult(
                Complete: false,
                Messages: messages,
                KeyShare: null,
                PublicKeyPackage: null);
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

    ~RefreshSession()
    {
        _native.Dispose();
    }
}
