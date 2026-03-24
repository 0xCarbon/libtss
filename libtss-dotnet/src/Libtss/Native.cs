using System.Runtime.InteropServices;

namespace Libtss;

/// <summary>
/// Native interop structures matching the C ABI layout.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct TssSlice
{
    public unsafe byte* Data;
    public nuint Len;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TssBuffer
{
    public unsafe byte* Data;
    public nuint Len;
}

/// <summary>
/// P/Invoke declarations for all libtss_ffi C functions.
/// </summary>
internal static unsafe class Native
{
    private const string LibName = "libtss_ffi";

    // --- Version ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr tss_version();

    // --- Verification ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool tss_verify(
        byte suite,
        TssSlice message,
        TssSlice signature,
        TssSlice public_key);

    // --- Error Handling ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr tss_last_error();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern nuint tss_last_error_len();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern nuint tss_last_error_copy(byte* buf, nuint buf_len);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern nuint tss_abort_culprit_count();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort tss_abort_culprit(nuint index);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort tss_abort_banned_party();

    // --- Memory ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void tss_buffer_free(TssBuffer* buf);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void tss_handle_free(ulong handle);

    // --- DKG Session ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_dkg_new(
        byte suite,
        ushort self_id,
        ushort max_signers,
        ushort min_signers,
        byte* session_id,
        nuint session_id_len,
        ulong* out_session,
        TssBuffer* out_messages);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_dkg_next(
        ulong session,
        TssSlice messages,
        ulong* out_key_share,
        TssBuffer* out_pubkey_package,
        TssBuffer* out_messages,
        [MarshalAs(UnmanagedType.U1)] bool* out_complete);

    // --- Sign Session ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_sign_new(
        ulong key_share,
        TssSlice message,
        ushort* counterparties,
        nuint counterparties_len,
        byte* sign_id,
        nuint sign_id_len,
        ulong* out_session,
        TssBuffer* out_messages);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_sign_next(
        ulong session,
        TssSlice messages,
        TssBuffer* out_signature,
        TssBuffer* out_messages,
        [MarshalAs(UnmanagedType.U1)] bool* out_complete);

    // --- Refresh Session ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_refresh_new(
        ulong key_share,
        ushort* participants,
        nuint participants_len,
        ulong* out_session,
        TssBuffer* out_messages);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_refresh_receiver(
        ulong key_share,
        ulong* out_session);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_refresh_next(
        ulong session,
        TssSlice messages,
        ulong* out_key_share,
        TssBuffer* out_pubkey_package,
        TssBuffer* out_messages,
        [MarshalAs(UnmanagedType.U1)] bool* out_complete);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void tss_session_free(ulong session);

    // --- Handle Queries ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_identifier(ulong handle, ushort* out_id);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_verifying_share(ulong handle, TssBuffer* @out);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_group_key(ulong handle, TssBuffer* @out);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_pubkey_package(ulong handle, TssBuffer* @out);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern byte tss_handle_ciphersuite(ulong handle);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_export(ulong handle, TssBuffer* @out);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_handle_import(
        byte* data,
        nuint data_len,
        byte suite,
        ulong* out_handle);

    // --- Message Helpers ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern nuint tss_message_count(TssSlice messages);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_message_at(
        TssSlice messages,
        nuint index,
        ushort* out_from,
        ushort* out_to,
        TssSlice* out_data);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_message_build(
        TssBuffer* buf,
        ushort from,
        ushort to,
        byte* data,
        nuint data_len);

    // --- FROST Operations ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_aggregate(
        byte suite,
        TssSlice message,
        TssSlice commitments,
        TssSlice shares,
        TssSlice pubkey_package,
        TssBuffer* out_signature);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_tweak_key_share(
        ulong key_share,
        byte* merkle_root,
        nuint merkle_root_len,
        ulong* out_tweaked_share);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_tweak_pubkey_package(
        TssSlice pubkey_package,
        byte* merkle_root,
        nuint merkle_root_len,
        TssBuffer* out_tweaked_package);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_generate_dealer(
        byte suite,
        ushort max_signers,
        ushort min_signers,
        ulong* out_handles,
        nuint* out_handle_count,
        TssBuffer* out_pubkey_package);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_split_key(
        byte suite,
        TssSlice secret_key,
        ushort max_signers,
        ushort min_signers,
        ulong* out_handles,
        nuint* out_handle_count,
        TssBuffer* out_pubkey_package);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_refresh_dealer(
        TssSlice pubkey_package,
        ushort* participants,
        nuint participant_count,
        TssBuffer* out_refresh_shares,
        nuint* out_share_count,
        TssBuffer* out_pubkey_package);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_apply_refresh(
        ulong key_share,
        TssSlice refresh_data,
        TssSlice pubkey_package,
        ulong* out_key_share);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_repair_part1(
        ulong key_share,
        ushort* helpers,
        nuint helper_count,
        ushort participant,
        TssBuffer* out_deltas,
        nuint* out_delta_count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_repair_part2(
        byte suite,
        TssSlice* deltas,
        nuint delta_count,
        TssBuffer* out_sigma);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_frost_repair_part3(
        TssSlice* sigmas,
        nuint sigma_count,
        ushort participant,
        TssSlice pubkey_package,
        ulong* out_key);

    // --- Derivation ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_derive_child(
        ulong key_share,
        uint child_number,
        ulong* out_handle);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_derive_path(
        ulong key_share,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        ulong* out_handle);

    // --- Init ---

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int tss_init(uint flags);

    // --- Platform: Linux / macOS (libc) ---

    [DllImport("libc", SetLastError = true)]
    public static extern int mlock(IntPtr addr, nuint len);

    [DllImport("libc", SetLastError = true)]
    public static extern int munlock(IntPtr addr, nuint len);

    [DllImport("libc", SetLastError = true)]
    public static extern int prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);

    // --- Platform: Windows ---

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualLock(IntPtr lpAddress, nuint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualUnlock(IntPtr lpAddress, nuint dwSize);
}
