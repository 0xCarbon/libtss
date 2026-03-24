/**
 * Low-level FFI bindings to liblibtss_ffi via koffi.
 *
 * Works in Node.js, Bun, and any runtime that supports native addons.
 * koffi loads the shared library at runtime via dlopen — no compilation
 * step needed for consumers.
 *
 * Library search order:
 *   1. LIBTSS_LIB environment variable (explicit path)
 *   2. target/release/ relative to cwd
 *   3. target/debug/   relative to cwd
 *   4. System library paths (LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, etc.)
 */

import koffi from "koffi";
import { Buffer } from "node:buffer";
import { existsSync } from "node:fs";
import { join } from "node:path";

// ── Library loading ────────────────────────────────────────────────────────

function findLib(): string {
	const env = process.env.LIBTSS_LIB;
	if (env && existsSync(env)) {
		return env;
	}

	const isWindows = process.platform === "win32";
	const ext =
		process.platform === "darwin" ? "dylib" : isWindows ? "dll" : "so";
	// Cargo omits the `lib` prefix on Windows DLLs
	const libName = isWindows
		? `libtss_ffi.${ext}`
		: `liblibtss_ffi.${ext}`;

	const searchDirs = [
		join(process.cwd(), "target", "release"),
		join(process.cwd(), "target", "debug"),
	];

	for (const dir of searchDirs) {
		const path = join(dir, libName);
		if (existsSync(path)) {
			return path;
		}
	}

	// Fall back to system library search
	return libName;
}

const native = koffi.load(findLib());

// ── Struct types ───────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const TssSlice = koffi.struct("TssSlice", {
	data: "uint8_t *",
	len: "size_t",
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const TssBuffer = koffi.struct("TssBuffer", {
	data: "uint8_t *",
	len: "size_t",
});

// ── Function declarations ──────────────────────────────────────────────────

export const TSS_INIT_MLOCK = 1;

/* eslint-disable @typescript-eslint/no-explicit-any */
export const lib: Record<string, (...args: any[]) => any> = {
	// Init
	tss_init: native.func("int32_t tss_init(uint32_t flags)"),

	// Version
	tss_version: native.func("const char *tss_version()"),

	// Verify
	tss_verify: native.func(
		"bool tss_verify(uint8_t suite, TssSlice message, TssSlice signature, TssSlice public_key)",
	),

	// Error handling
	tss_last_error: native.func("const char *tss_last_error()"),
	tss_last_error_len: native.func("size_t tss_last_error_len()"),
	tss_abort_culprit_count: native.func("size_t tss_abort_culprit_count()"),
	tss_abort_culprit: native.func("uint16_t tss_abort_culprit(size_t index)"),
	tss_abort_banned_party: native.func("uint16_t tss_abort_banned_party()"),

	// Memory
	tss_buffer_free: native.func("void tss_buffer_free(TssBuffer *buf)"),
	tss_handle_free: native.func("void tss_handle_free(uint64_t handle)"),
	tss_session_free: native.func("void tss_session_free(uint64_t handle)"),

	// Handle operations
	tss_handle_identifier: native.func(
		"int32_t tss_handle_identifier(uint64_t handle, _Out_ uint16_t *out_id)",
	),
	tss_handle_ciphersuite: native.func(
		"uint8_t tss_handle_ciphersuite(uint64_t handle)",
	),
	tss_handle_verifying_share: native.func(
		"int32_t tss_handle_verifying_share(uint64_t handle, _Out_ TssBuffer *out)",
	),
	tss_handle_group_key: native.func(
		"int32_t tss_handle_group_key(uint64_t handle, _Out_ TssBuffer *out)",
	),
	tss_handle_pubkey_package: native.func(
		"int32_t tss_handle_pubkey_package(uint64_t handle, _Out_ TssBuffer *out)",
	),
	tss_handle_export: native.func(
		"int32_t tss_handle_export(uint64_t handle, _Out_ TssBuffer *out)",
	),
	tss_handle_import: native.func(
		"int32_t tss_handle_import(const uint8_t *data, size_t data_len, uint8_t suite, _Out_ uint64_t *out_handle)",
	),

	// DKG session
	tss_dkg_new: native.func(
		"int32_t tss_dkg_new(uint8_t suite, uint16_t self_id, uint16_t max_signers, uint16_t min_signers, const uint8_t *session_id, size_t session_id_len, _Out_ uint64_t *out_session, _Out_ TssBuffer *out_messages)",
	),
	tss_dkg_next: native.func(
		"int32_t tss_dkg_next(uint64_t session, TssSlice messages, _Out_ uint64_t *out_key_share, _Out_ TssBuffer *out_pubkey_package, _Out_ TssBuffer *out_messages, _Out_ bool *out_complete)",
	),

	// Sign session
	tss_sign_new: native.func(
		"int32_t tss_sign_new(uint64_t key_share, TssSlice message, const uint16_t *counterparties, size_t counterparties_len, const uint8_t *sign_id, size_t sign_id_len, _Out_ uint64_t *out_session, _Out_ TssBuffer *out_messages)",
	),
	tss_sign_next: native.func(
		"int32_t tss_sign_next(uint64_t session, TssSlice messages, _Out_ TssBuffer *out_signature, _Out_ TssBuffer *out_messages, _Out_ bool *out_complete)",
	),

	// Refresh session
	tss_refresh_new: native.func(
		"int32_t tss_refresh_new(uint64_t key_share, const uint16_t *participants, size_t participants_len, _Out_ uint64_t *out_session, _Out_ TssBuffer *out_messages)",
	),
	tss_refresh_receiver: native.func(
		"int32_t tss_refresh_receiver(uint64_t key_share, _Out_ uint64_t *out_session)",
	),
	tss_refresh_next: native.func(
		"int32_t tss_refresh_next(uint64_t session, TssSlice messages, _Out_ uint64_t *out_key_share, _Out_ TssBuffer *out_pubkey_package, _Out_ TssBuffer *out_messages, _Out_ bool *out_complete)",
	),

	// FROST operations
	tss_frost_aggregate: native.func(
		"int32_t tss_frost_aggregate(uint8_t suite, TssSlice message, TssSlice commitments, TssSlice shares, TssSlice pubkey_package, _Out_ TssBuffer *out_signature)",
	),
	tss_frost_tweak_key_share: native.func(
		"int32_t tss_frost_tweak_key_share(uint64_t key_share, const uint8_t *merkle_root, size_t merkle_root_len, _Out_ uint64_t *out_tweaked_share)",
	),
	tss_frost_tweak_pubkey_package: native.func(
		"int32_t tss_frost_tweak_pubkey_package(TssSlice pubkey_package, const uint8_t *merkle_root, size_t merkle_root_len, _Out_ TssBuffer *out_tweaked_package)",
	),
	tss_frost_split_key: native.func(
		"int32_t tss_frost_split_key(uint8_t suite, TssSlice secret_key, uint16_t max_signers, uint16_t min_signers, uint64_t *out_handles, _Out_ size_t *out_handle_count, _Out_ TssBuffer *out_pubkey_package)",
	),

	// Derivation
	tss_derive_child: native.func(
		"int32_t tss_derive_child(uint64_t key_share, uint32_t child_number, _Out_ uint64_t *out_handle)",
	),
	tss_derive_path: native.func(
		"int32_t tss_derive_path(uint64_t key_share, const char *path, _Out_ uint64_t *out_handle)",
	),
};
/* eslint-enable @typescript-eslint/no-explicit-any */

// ── Helpers ────────────────────────────────────────────────────────────────

export interface TssBufferOut {
	data: unknown;
	len: number | bigint;
}

export function makeSlice(data: Uint8Array): { data: Uint8Array; len: number } {
	return { data, len: data.length };
}

export function allocBuffer(): TssBufferOut {
	return { data: null, len: 0 };
}

export function readBuffer(buf: TssBufferOut): Uint8Array {
	const len = Number(buf.len);
	if (!buf.data || len === 0) {
		lib.tss_buffer_free(buf);
		return new Uint8Array(0);
	}
	try {
		return new Uint8Array(koffi.view(buf.data, len)).slice();
	} finally {
		lib.tss_buffer_free(buf);
	}
}

/**
 * Like readBuffer but copies FFI data directly into a Buffer.allocUnsafeSlow()
 * allocation (outside V8's pooled slab) so the plaintext never lands on the
 * regular V8 heap where GC could copy it.
 */
export function readBufferSecure(buf: TssBufferOut): Buffer {
	const len = Number(buf.len);
	if (!buf.data || len === 0) {
		lib.tss_buffer_free(buf);
		return Buffer.allocUnsafeSlow(0);
	}
	try {
		const result = Buffer.allocUnsafeSlow(len);
		result.set(new Uint8Array(koffi.view(buf.data, len)));
		return result;
	} finally {
		lib.tss_buffer_free(buf);
	}
}

export function readLastError(): string {
	return lib.tss_last_error() ?? "";
}

export function readAbortInfo(): {
	culprits: number[];
	bannedParty: number | undefined;
} {
	const count = Number(lib.tss_abort_culprit_count());
	const culprits: number[] = [];
	for (let i = 0; i < count; i++) {
		culprits.push(lib.tss_abort_culprit(i));
	}
	const banned = lib.tss_abort_banned_party();
	return {
		culprits,
		bannedParty: banned === 0 ? undefined : banned,
	};
}
