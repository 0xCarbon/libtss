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

/**
 * Import an existing ECDSA key as DKLs23 shares (trusted dealer).
 *
 * `suite` is `Secp256k1ECDSA` or `Secp256r1ECDSA`; `secretKey` is a 32-byte
 * big-endian scalar; `chainCode` is the key's existing 32-byte BIP-32 chain
 * code, or omitted to sample a new one. The group key is the key's own public
 * key. The caller holds every share: hand each one to its party, erase the
 * key and the shares, and have the parties run `RefreshSession.createDkls`
 * before use. `secretKey` is wiped after the call.
 */
export function dklsSplitKey(
	suite: Ciphersuite,
	secretKey: Uint8Array,
	maxSigners: number,
	minSigners: number,
	chainCode?: Uint8Array,
): { keyShares: KeyShareHandle[]; publicKeys: Uint8Array } {
	try {
		const outHandles = new BigUint64Array(maxSigners);
		const outCount: [number | bigint] = [0n];
		const outPkg = allocBuffer();
		checkStatus(
			lib.tss_dkls_split_key(
				suite,
				makeSlice(secretKey),
				makeSlice(chainCode ?? new Uint8Array(0)),
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

/**
 * BOLT 3 derivation of a DKLs23 secp256k1 key share for a commitment
 * (`basepoint + SHA256(perCommitmentPoint || basepoint)·G`). Every party
 * derives with the same 33-byte compressed point. A derived share keeps the
 * base share's OT state, so a counterparty banned under a derived key is
 * banned for the base key too.
 */
export function bolt3Derive(
	keyShare: KeyShareHandle,
	perCommitmentPoint: Uint8Array,
): KeyShareHandle {
	const outHandle: [bigint] = [0n];
	checkStatus(
		lib.tss_bolt3_derive(
			keyShare.handle,
			makeSlice(perCommitmentPoint),
			outHandle,
		),
	);
	return new KeyShareHandle(outHandle[0]);
}

/**
 * BOLT 3 revocation derivation for a commitment whose 32-byte
 * `perCommitmentSecret` was revealed; the secret must match the point.
 */
export function bolt3DeriveRevocation(
	keyShare: KeyShareHandle,
	perCommitmentPoint: Uint8Array,
	perCommitmentSecret: Uint8Array,
): KeyShareHandle {
	const outHandle: [bigint] = [0n];
	checkStatus(
		lib.tss_bolt3_derive_revocation(
			keyShare.handle,
			makeSlice(perCommitmentPoint),
			makeSlice(perCommitmentSecret),
			outHandle,
		),
	);
	return new KeyShareHandle(outHandle[0]);
}

/** `bolt3Derive` on a serialized secp256k1 ECDSA public key package. */
export function bolt3DerivePublicKeys(
	publicKeys: Uint8Array,
	perCommitmentPoint: Uint8Array,
): Uint8Array {
	const out = allocBuffer();
	checkStatus(
		lib.tss_bolt3_derive_pubkey_package(
			makeSlice(publicKeys),
			makeSlice(perCommitmentPoint),
			out,
		),
	);
	return readBuffer(out);
}

/** `bolt3DeriveRevocation` on a public key package (no secret needed). */
export function bolt3DeriveRevocationPublicKeys(
	publicKeys: Uint8Array,
	perCommitmentPoint: Uint8Array,
): Uint8Array {
	const out = allocBuffer();
	checkStatus(
		lib.tss_bolt3_derive_revocation_pubkey_package(
			makeSlice(publicKeys),
			makeSlice(perCommitmentPoint),
			out,
		),
	);
	return readBuffer(out);
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
