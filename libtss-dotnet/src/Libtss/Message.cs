namespace Libtss;

/// <summary>
/// A protocol message produced or consumed by libtss sessions.
/// </summary>
/// <remarks>
/// <para>
/// Messages are opaque to the client. Route based on the <see cref="To"/> field:
/// <list type="bullet">
///   <item><c>null</c> -- broadcast to all other participants.</item>
///   <item>Non-null -- send to that specific participant via a confidential channel.</item>
/// </list>
/// </para>
/// <para>
/// Do NOT parse or modify <see cref="Data"/>; it is produced and consumed by the library.
/// </para>
/// </remarks>
public sealed class Message
{
    /// <summary>1-based sender identifier.</summary>
    public ushort From { get; }

    /// <summary>
    /// 1-based recipient identifier, or <c>null</c> for broadcast.
    /// </summary>
    public ushort? To { get; }

    /// <summary>Opaque protocol message payload.</summary>
    public byte[] Data { get; }

    public Message(ushort from, ushort? to, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        From = from;
        To = to;
        Data = data;
    }

    public override string ToString() =>
        $"Message(from={From}, to={To?.ToString() ?? "broadcast"}, len={Data.Length})";
}

/// <summary>
/// Encodes and decodes arrays of <see cref="Message"/> using the native TLV wire format
/// (from:u16 LE, to:u16 LE, len:u32 LE, data).
/// </summary>
public static class MessageCodec
{
    /// <summary>
    /// Encodes an array of messages into the native concatenated TLV format.
    /// Uses <c>tss_message_build</c> for each message to build the buffer.
    /// </summary>
    public static unsafe byte[] Encode(Message[] messages)
    {
        ArgumentNullException.ThrowIfNull(messages);

        if (messages.Length == 0)
            return [];

        var buf = new NativeTssBuffer();
        try
        {
            foreach (var msg in messages)
            {
                ushort to = msg.To ?? 0;
                int status;
                fixed (TssBuffer* pbuf = &buf.Raw)
                fixed (byte* pdata = msg.Data)
                {
                    status = Native.tss_message_build(
                        pbuf, msg.From, to, pdata, (nuint)msg.Data.Length);
                }
                TssException.ThrowIfError(status);
            }
            return buf.ToArray();
        }
        catch
        {
            buf.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Decodes a native concatenated TLV buffer into an array of messages.
    /// Uses <c>tss_message_count</c> and <c>tss_message_at</c> for parsing.
    /// </summary>
    public static unsafe Message[] Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
            return [];

        fixed (byte* pdata = data)
        {
            var slice = new TssSlice { Data = pdata, Len = (nuint)data.Length };

            nuint count = Native.tss_message_count(slice);
            if (count == 0)
            {
                // Non-empty input that parses to zero messages indicates malformed TLV data.
                // The FFI count helper returns 0 on parse errors rather than surfacing them.
                throw new InvalidOperationException(
                    "Failed to parse message bundle: malformed TLV data");
            }

            var messages = new Message[(int)count];
            for (nuint i = 0; i < count; i++)
            {
                ushort from, to;
                TssSlice outData;
                int status = Native.tss_message_at(slice, i, &from, &to, &outData);
                TssException.ThrowIfError(status);

                byte[] payload;
                if (outData.Data != null && (int)outData.Len > 0)
                {
                    payload = new byte[(int)outData.Len];
                    fixed (byte* dest = payload)
                    {
                        Buffer.MemoryCopy(outData.Data, dest, payload.Length, payload.Length);
                    }
                }
                else
                {
                    payload = [];
                }

                messages[(int)i] = new Message(from, to == 0 ? null : to, payload);
            }

            return messages;
        }
    }

    /// <summary>
    /// Encodes messages and returns the raw bytes as a TssSlice-compatible span.
    /// Internal helper for session methods that need to pass messages to native code.
    /// </summary>
    internal static byte[] EncodeForNative(Message[] messages)
    {
        return Encode(messages);
    }
}
