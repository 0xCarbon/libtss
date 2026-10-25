import { fromByteArray, toByteArray } from "base64-js";
import { identifier, identifiers, u8 } from "./checks";
import { TssError } from "./error";
import { KeyShareHandle } from "./handle";
import { decodeMessages, encodeMessages } from "./message";
import NativeLibtss from "./NativeLibtss";
import { DkgSession, RefreshSession, SignSession } from "./session";
import type { Ciphersuite, Message } from "./types";

export * from "./error";
export * from "./handle";
export * from "./message";
export * from "./session";
export * from "./types";

function encodeBase64(value: Uint8Array): string {
	return fromByteArray(value);
}

export async function importKeyShare(
	suite: Ciphersuite,
	data: Uint8Array,
): Promise<KeyShareHandle> {
	const suiteId = u8(suite, "suite");
	try {
		return new KeyShareHandle(
			await NativeLibtss.importKeyShare(suiteId, encodeBase64(data)),
		);
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

export async function version(): Promise<string> {
	try {
		return await NativeLibtss.version();
	} catch (error) {
		throw TssError.fromNative(error);
	}
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

export async function init(options?: { mlock?: boolean }): Promise<void> {
	try {
		await NativeLibtss.initialize({ mlock: options?.mlock ?? false });
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

export async function exportKeyShareToKeychain(
	handle: KeyShareHandle,
): Promise<string> {
	try {
		return await NativeLibtss.exportKeyShareSecure(handle.handle);
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

export async function importKeyShareFromKeychain(
	suite: Ciphersuite,
	keychainId: string,
): Promise<KeyShareHandle> {
	const suiteId = u8(suite, "suite");
	try {
		return new KeyShareHandle(
			await NativeLibtss.importKeyShareSecure(suiteId, keychainId),
		);
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

export async function verify(
	suite: Ciphersuite,
	message: Uint8Array,
	signature: Uint8Array,
	publicKey: Uint8Array,
): Promise<boolean> {
	const suiteId = u8(suite, "suite");
	try {
		return await NativeLibtss.verify(
			suiteId,
			encodeBase64(message),
			encodeBase64(signature),
			encodeBase64(publicKey),
		);
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

async function native<T>(fn: () => Promise<T>): Promise<T> {
	try {
		return await fn();
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

/**
 * This helper's DKLs23 repair term for `target`, as messages to send to the
 * target only, over a confidential, authenticated channel. `helpers` lists the
 * helper identifiers (no duplicates, at least `minSigners`, including this
 * party, not the target); every helper uses the same list and `repairId`. The
 * helpers must authenticate the target: repair hands index `target`'s share
 * to whoever receives the terms.
 */
export async function dklsRepairHelperTerm(
	keyShare: KeyShareHandle,
	helpers: number[],
	target: number,
	repairId: Uint8Array,
): Promise<Message[]> {
	const helperIds = identifiers(helpers, "helper");
	const targetId = identifier(target, "target");
	const encoded = await native(() =>
		NativeLibtss.repairHelperTerm(
			keyShare.handle,
			helperIds,
			targetId,
			encodeBase64(repairId),
		),
	);
	return decodeMessages(toByteArray(encoded));
}

/**
 * Assembles the helpers' repair messages into the target's repaired DKLs23
 * share. Each message's `from` must be its authenticated sender. The share
 * cannot sign until all parties run `RefreshSession.createDkls`.
 */
export async function dklsRepairAssemble(
	suite: Ciphersuite,
	publicKeys: Uint8Array,
	target: number,
	messages: Message[],
): Promise<KeyShareHandle> {
	const suiteId = u8(suite, "suite");
	const targetId = identifier(target, "target");
	const blob = encodeMessages(messages);
	const encoded = encodeBase64(blob);
	blob.fill(0);
	return new KeyShareHandle(
		await native(() =>
			NativeLibtss.repairAssemble(
				suiteId,
				encodeBase64(publicKeys),
				targetId,
				encoded,
			),
		),
	);
}

/**
 * BOLT 3 derivation of a DKLs23 secp256k1 key share for a commitment
 * (`basepoint + SHA256(perCommitmentPoint || basepoint)·G`). A derived share
 * keeps the base share's OT state, so a counterparty banned under a derived
 * key is banned for the base key too.
 */
export async function bolt3Derive(
	keyShare: KeyShareHandle,
	perCommitmentPoint: Uint8Array,
): Promise<KeyShareHandle> {
	return new KeyShareHandle(
		await native(() =>
			NativeLibtss.bolt3Derive(
				keyShare.handle,
				encodeBase64(perCommitmentPoint),
			),
		),
	);
}

/**
 * BOLT 3 revocation derivation for a commitment whose 32-byte
 * `perCommitmentSecret` was revealed; the secret must match the point. The
 * `perCommitmentSecret` array is zeroed after the call (the base64 copy sent
 * across the bridge cannot be).
 */
export async function bolt3DeriveRevocation(
	keyShare: KeyShareHandle,
	perCommitmentPoint: Uint8Array,
	perCommitmentSecret: Uint8Array,
): Promise<KeyShareHandle> {
	const secret = encodeBase64(perCommitmentSecret);
	perCommitmentSecret.fill(0);
	return new KeyShareHandle(
		await native(() =>
			NativeLibtss.bolt3DeriveRevocation(
				keyShare.handle,
				encodeBase64(perCommitmentPoint),
				secret,
			),
		),
	);
}

/** `bolt3Derive` on a serialized secp256k1 ECDSA public key package. */
export async function bolt3DerivePublicKeys(
	publicKeys: Uint8Array,
	perCommitmentPoint: Uint8Array,
): Promise<Uint8Array> {
	return toByteArray(
		await native(() =>
			NativeLibtss.bolt3DerivePubkeyPackage(
				encodeBase64(publicKeys),
				encodeBase64(perCommitmentPoint),
			),
		),
	);
}

/** `bolt3DeriveRevocation` on a public key package (no secret needed). */
export async function bolt3DeriveRevocationPublicKeys(
	publicKeys: Uint8Array,
	perCommitmentPoint: Uint8Array,
): Promise<Uint8Array> {
	return toByteArray(
		await native(() =>
			NativeLibtss.bolt3DeriveRevocationPubkeyPackage(
				encodeBase64(publicKeys),
				encodeBase64(perCommitmentPoint),
			),
		),
	);
}
