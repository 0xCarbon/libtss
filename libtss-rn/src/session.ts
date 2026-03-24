import { fromByteArray, toByteArray } from "base64-js";
import { TssError } from "./error";
import { KeyShareHandle } from "./handle";
import { decodeMessages, encodeMessages } from "./message";
import NativeLibtss from "./NativeLibtss";
import type {
	DkgOutput,
	Message,
	RefreshOutput,
	SignOutput,
	ThresholdConfig,
} from "./types";
import { Protocol } from "./types";

const FROST_SIGNATURE_BYTES = 64;
const DKLS23_SIGNATURE_BYTES = 65;

const sessionRegistry =
	typeof FinalizationRegistry === "undefined"
		? null
		: new FinalizationRegistry<string>((handle) => {
				void NativeLibtss.handleFree(handle).catch(() => {});
			});

function encodeBase64(data: Uint8Array): string {
	return fromByteArray(data);
}

function decodeBase64(data: string): Uint8Array {
	return Uint8Array.from(toByteArray(data));
}

function encodeMessageBuffer(messages: Message[]): string {
	return encodeBase64(encodeMessages(messages));
}

function decodeMessageBuffer(messages?: string): Message[] {
	if (!messages) {
		return [];
	}
	return decodeMessages(decodeBase64(messages));
}

async function callNative<T>(fn: () => Promise<T>): Promise<T> {
	try {
		return await fn();
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

abstract class SessionHandle {
	protected readonly handle: string;
	private _freed = false;

	protected constructor(handle: string) {
		this.handle = handle;
		sessionRegistry?.register(this, handle, this);
	}

	free(): void {
		if (this._freed) {
			return;
		}

		this._freed = true;
		sessionRegistry?.unregister(this);
		void NativeLibtss.handleFree(this.handle).catch(() => {});
	}
}

export class DkgSession extends SessionHandle {
	static async create(
		config: ThresholdConfig,
		selfId: number,
		sessionId?: Uint8Array,
	): Promise<[DkgSession, Message[]]> {
		const result = await callNative(() =>
			NativeLibtss.dkgNew(
				config.suite,
				selfId,
				config.maxSigners,
				config.minSigners,
				sessionId ? encodeBase64(sessionId) : null,
			),
		);

		return [
			new DkgSession(result.handle),
			decodeMessageBuffer(result.messages),
		];
	}

	async next(received: Message[]): Promise<DkgOutput> {
		const result = await callNative(() =>
			NativeLibtss.dkgNext(this.handle, encodeMessageBuffer(received)),
		);
		if (!result.complete) {
			return {
				complete: false,
				messages: decodeMessageBuffer(result.messages),
			};
		}

		if (!result.keyShareHandle || !result.pubkeyPackage) {
			throw new Error("missing DKG completion payload");
		}

		return {
			complete: true,
			keyShare: new KeyShareHandle(result.keyShareHandle),
			publicKeys: decodeBase64(result.pubkeyPackage),
		};
	}
}

export class SignSession extends SessionHandle {
	private readonly keyShare: KeyShareHandle;

	private constructor(handle: string, keyShare: KeyShareHandle) {
		super(handle);
		this.keyShare = keyShare;
	}

	static async create(
		keyShare: KeyShareHandle,
		message: Uint8Array,
		counterparties?: number[],
		signId?: Uint8Array,
	): Promise<[SignSession, Message[]]> {
		const result = await callNative(() =>
			NativeLibtss.signNew(
				keyShare.handle,
				encodeBase64(message),
				counterparties ?? null,
				signId ? encodeBase64(signId) : null,
			),
		);
		return [
			new SignSession(result.handle, keyShare),
			decodeMessageBuffer(result.messages),
		];
	}

	async next(received: Message[]): Promise<SignOutput> {
		const result = await callNative(() =>
			NativeLibtss.signNext(this.handle, encodeMessageBuffer(received)),
		);
		if (!result.complete) {
			return {
				complete: false,
				messages: decodeMessageBuffer(result.messages),
			};
		}

		if (!result.signature) {
			throw new Error("missing signature payload");
		}

		const protocol = await this.keyShare.protocol();
		const signature = decodeBase64(result.signature);

		if (protocol === Protocol.DKLs23) {
			if (signature.length !== DKLS23_SIGNATURE_BYTES) {
				throw new Error(
					`invalid DKLs23 signature length: expected ${DKLS23_SIGNATURE_BYTES} bytes, got ${signature.length}`,
				);
			}

			return {
				complete: true,
				signature: {
					data: signature.slice(0, FROST_SIGNATURE_BYTES),
					recoveryId: signature[FROST_SIGNATURE_BYTES],
					protocol,
				},
			};
		}

		if (signature.length !== FROST_SIGNATURE_BYTES) {
			throw new Error(
				`invalid FROST signature length: expected ${FROST_SIGNATURE_BYTES} bytes, got ${signature.length}`,
			);
		}

		return {
			complete: true,
			signature: {
				data: signature,
				recoveryId: null,
				protocol,
			},
		};
	}
}

export class RefreshSession extends SessionHandle {
	static async create(
		keyShare: KeyShareHandle,
		participants?: number[],
	): Promise<[RefreshSession, Message[]]> {
		const result = await callNative(() =>
			NativeLibtss.refreshNew(keyShare.handle, participants ?? null),
		);
		return [
			new RefreshSession(result.handle),
			decodeMessageBuffer(result.messages),
		];
	}

	static async createReceiver(
		keyShare: KeyShareHandle,
	): Promise<RefreshSession> {
		const handle = await callNative(() =>
			NativeLibtss.refreshReceiver(keyShare.handle),
		);
		return new RefreshSession(handle);
	}

	async next(received: Message[]): Promise<RefreshOutput> {
		const result = await callNative(() =>
			NativeLibtss.refreshNext(this.handle, encodeMessageBuffer(received)),
		);
		if (!result.complete) {
			return {
				complete: false,
				messages: decodeMessageBuffer(result.messages),
			};
		}

		if (!result.keyShareHandle || !result.pubkeyPackage) {
			throw new Error("missing refresh completion payload");
		}

		return {
			complete: true,
			keyShare: new KeyShareHandle(result.keyShareHandle),
			publicKeys: decodeBase64(result.pubkeyPackage),
		};
	}
}
