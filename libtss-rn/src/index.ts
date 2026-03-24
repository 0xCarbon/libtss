import { fromByteArray } from "base64-js";
import { TssError } from "./error";
import { KeyShareHandle } from "./handle";
import NativeLibtss from "./NativeLibtss";
import { DkgSession, RefreshSession, SignSession } from "./session";
import type { Ciphersuite } from "./types";

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
	try {
		return new KeyShareHandle(
			await NativeLibtss.importKeyShare(suite, encodeBase64(data)),
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

export async function init(
	options?: { mlock?: boolean },
): Promise<void> {
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
	try {
		return new KeyShareHandle(
			await NativeLibtss.importKeyShareSecure(suite, keychainId),
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
	try {
		return await NativeLibtss.verify(
			suite,
			encodeBase64(message),
			encodeBase64(signature),
			encodeBase64(publicKey),
		);
	} catch (error) {
		throw TssError.fromNative(error);
	}
}
