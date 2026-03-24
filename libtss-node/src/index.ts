import { checkStatus } from "./error";
import { TSS_INIT_MLOCK, allocBuffer, lib, makeSlice, readBuffer } from "./ffi";
import { KeyShareHandle } from "./handle";
import { SecureBuffer, wipeBytes } from "./secure";
import { DkgSession, RefreshSession, SignSession } from "./session";
import type { Ciphersuite } from "./types";

export * from "./error";
export * from "./handle";
export * from "./message";
export { SecureBuffer, wipeBytes } from "./secure";
export * from "./session";
export * from "./types";

export function init(options?: { mlock?: boolean }): void {
	let flags = 0;
	if (options?.mlock) {
		flags |= TSS_INIT_MLOCK;
	}
	checkStatus(lib.tss_init(flags));
}

export function version(): string {
	return lib.tss_version() ?? "";
}

export function verify(
	suite: Ciphersuite,
	message: Uint8Array,
	signature: Uint8Array,
	publicKey: Uint8Array,
): boolean {
	return lib.tss_verify(
		suite,
		makeSlice(message),
		makeSlice(signature),
		makeSlice(publicKey),
	);
}

export function importKeyShare(
	suite: Ciphersuite,
	data: Uint8Array,
): KeyShareHandle {
	const outHandle: [bigint] = [0n];
	checkStatus(
		lib.tss_handle_import(data, data.length, suite, outHandle),
	);
	return new KeyShareHandle(outHandle[0]);
}

export function importKeyShareSecure(
	suite: Ciphersuite,
	secure: SecureBuffer,
): KeyShareHandle {
	return importKeyShare(suite, secure.bytes());
}

export function frostSplitKey(
	suite: Ciphersuite,
	secretKey: Uint8Array,
	maxSigners: number,
	minSigners: number,
): { keyShares: KeyShareHandle[]; publicKeys: Uint8Array } {
	try {
		const outHandles = new BigUint64Array(maxSigners);
		const outCount: [number | bigint] = [0n];
		const outPkg = allocBuffer();
		checkStatus(
			lib.tss_frost_split_key(
				suite,
				makeSlice(secretKey),
				maxSigners,
				minSigners,
				outHandles,
				outCount,
				outPkg,
			),
		);
		const count = Number(outCount[0]);
		const shares: KeyShareHandle[] = [];
		for (let i = 0; i < count; i++) {
			shares.push(new KeyShareHandle(outHandles[i]));
		}
		return { keyShares: shares, publicKeys: readBuffer(outPkg) };
	} finally {
		wipeBytes(secretKey);
	}
}

export function frostAggregate(
	suite: Ciphersuite,
	message: Uint8Array,
	commitments: Uint8Array,
	shares: Uint8Array,
	pubkeyPackage: Uint8Array,
): Uint8Array {
	const outSig = allocBuffer();
	checkStatus(
		lib.tss_frost_aggregate(
			suite,
			makeSlice(message),
			makeSlice(commitments),
			makeSlice(shares),
			makeSlice(pubkeyPackage),
			outSig,
		),
	);
	return readBuffer(outSig);
}

// ── BIP-32 Derivation ──────────────────────────────────────────────────────

export function deriveChild(
	keyShare: KeyShareHandle,
	childNumber: number,
): KeyShareHandle {
	if (!Number.isInteger(childNumber) || childNumber < 0 || childNumber >= 2 ** 31) {
		throw new Error("childNumber must be an integer in range [0, 2^31)");
	}
	const outHandle: [bigint] = [0n];
	checkStatus(
		lib.tss_derive_child(keyShare.handle, childNumber, outHandle),
	);
	return new KeyShareHandle(outHandle[0]);
}

export function derivePath(
	keyShare: KeyShareHandle,
	path: string,
): KeyShareHandle {
	if (path.includes("\0")) {
		throw new Error("path must not contain NUL bytes");
	}
	const outHandle: [bigint] = [0n];
	checkStatus(lib.tss_derive_path(keyShare.handle, path, outHandle));
	return new KeyShareHandle(outHandle[0]);
}

// ── FROST Operations ───────────────────────────────────────────────────────

export function frostTweakKeyShare(
	keyShare: KeyShareHandle,
	merkleRoot?: Uint8Array,
): KeyShareHandle {
	const outHandle: [bigint] = [0n];
	checkStatus(
		lib.tss_frost_tweak_key_share(
			keyShare.handle,
			merkleRoot ?? null,
			merkleRoot?.length ?? 0,
			outHandle,
		),
	);
	return new KeyShareHandle(outHandle[0]);
}

export function frostTweakPubkeyPackage(
	pubkeyPackage: Uint8Array,
	merkleRoot?: Uint8Array,
): Uint8Array {
	const outPkg = allocBuffer();
	checkStatus(
		lib.tss_frost_tweak_pubkey_package(
			makeSlice(pubkeyPackage),
			merkleRoot ?? null,
			merkleRoot?.length ?? 0,
			outPkg,
		),
	);
	return readBuffer(outPkg);
}

export function newDkgSession(
	...args: Parameters<typeof DkgSession.create>
): ReturnType<typeof DkgSession.create> {
	return DkgSession.create(...args);
}

export function newSignSession(
	...args: Parameters<typeof SignSession.create>
): ReturnType<typeof SignSession.create> {
	return SignSession.create(...args);
}

export function newRefreshSession(
	...args: Parameters<typeof RefreshSession.create>
): ReturnType<typeof RefreshSession.create> {
	return RefreshSession.create(...args);
}

export function newRefreshReceiver(
	...args: Parameters<typeof RefreshSession.createReceiver>
): ReturnType<typeof RefreshSession.createReceiver> {
	return RefreshSession.createReceiver(...args);
}
