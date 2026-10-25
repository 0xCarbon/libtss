import { fromByteArray, toByteArray } from "base64-js";
import { identifier, identifiers, signerCount, u8 } from "./checks";
import { TssError } from "./error";
import { KeyShareHandle } from "./handle";
import { decodeMessages, encodeMessages } from "./message";
import NativeLibtss from "./NativeLibtss";
import type {
	Ciphersuite,
	DkgOutput,
	Message,
	RefreshOutput,
	SignOutput,
	ThresholdConfig,
} from "./types";
import { Protocol, protocolForCiphersuite, signatureLength } from "./types";

const sessionRegistry =
	typeof FinalizationRegistry === "undefined"
		? null
		: new FinalizationRegistry<string>((handle) => {
				void NativeLibtss.sessionFree(handle).catch(() => {});
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
		void NativeLibtss.sessionFree(this.handle).catch(() => {});
	}
}

export class DkgSession extends SessionHandle {
	static async create(
		config: ThresholdConfig,
		selfId: number,
		sessionId?: Uint8Array,
	): Promise<[DkgSession, Message[]]> {
		const suite = u8(config.suite, "suite");
		const self = identifier(selfId, "selfId");
		const maxSigners = signerCount(config.maxSigners, "maxSigners");
		const minSigners = signerCount(config.minSigners, "minSigners");
		const result = await callNative(() =>
			NativeLibtss.dkgNew(
				suite,
				self,
				maxSigners,
				minSigners,
				sessionId ? encodeBase64(sessionId) : null,
			),
		);

		return [
			new DkgSession(result.handle),
			decodeMessageBuffer(result.messages),
		];
	}

	async next(received: Message[]): Promise<DkgOutput> {
		// Encode first so envelope validation errors surface as RangeError.
		const encoded = encodeMessageBuffer(received);
		const result = await callNative(() =>
			NativeLibtss.dkgNext(this.handle, encoded),
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
	private readonly suite: Ciphersuite;

	private constructor(handle: string, suite: Ciphersuite) {
		super(handle);
		this.suite = suite;
	}

	static async create(
		keyShare: KeyShareHandle,
		message: Uint8Array,
		counterparties?: number[],
		signId?: Uint8Array,
	): Promise<[SignSession, Message[]]> {
		const counterpartyIds = counterparties
			? identifiers(counterparties, "counterparty")
			: null;
		const suite = await keyShare.ciphersuite();
		const result = await callNative(() =>
			NativeLibtss.signNew(
				keyShare.handle,
				encodeBase64(message),
				counterpartyIds,
				signId ? encodeBase64(signId) : null,
			),
		);
		return [
			new SignSession(result.handle, suite),
			decodeMessageBuffer(result.messages),
		];
	}

	async next(received: Message[]): Promise<SignOutput> {
		// Encode first so envelope validation errors surface as RangeError.
		const encoded = encodeMessageBuffer(received);
		const result = await callNative(() =>
			NativeLibtss.signNext(this.handle, encoded),
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

		const protocol = protocolForCiphersuite(this.suite);
		const signature = decodeBase64(result.signature);
		const expected = signatureLength(this.suite);
		if (signature.length !== expected) {
			throw new Error(
				`invalid signature length for ciphersuite ${this.suite}: expected ${expected} bytes, got ${signature.length}`,
			);
		}

		let recoveryId: number | null = null;
		if (protocol === Protocol.DKLs23) {
			if (result.recoveryId !== 0 && result.recoveryId !== 1) {
				throw new Error("DKLs23 signature is missing its recovery id");
			}
			recoveryId = result.recoveryId;
		}

		return {
			complete: true,
			signature: { data: signature, recoveryId, protocol },
		};
	}
}

export class RefreshSession extends SessionHandle {
	static async create(
		keyShare: KeyShareHandle,
		participants?: number[],
	): Promise<[RefreshSession, Message[]]> {
		const participantIds = participants
			? identifiers(participants, "participant")
			: null;
		const result = await callNative(() =>
			NativeLibtss.refreshNew(keyShare.handle, participantIds),
		);
		return [
			new RefreshSession(result.handle),
			decodeMessageBuffer(result.messages),
		];
	}

	/**
	 * DKLs23 complete refresh (secp256k1 / secp256r1). All parties run it
	 * together under the same fresh `sessionId`; `next()` is called three
	 * times. The group key stays the same and every share and its OT state
	 * are regenerated. Refreshed shares sign only with shares from the same
	 * refresh.
	 */
	static async createDkls(
		keyShare: KeyShareHandle,
		sessionId: Uint8Array,
	): Promise<[RefreshSession, Message[]]> {
		if (sessionId.length === 0) {
			throw new Error("sessionId must not be empty");
		}
		const result = await callNative(() =>
			NativeLibtss.refreshNewDkls(keyShare.handle, encodeBase64(sessionId)),
		);
		return [
			new RefreshSession(result.handle),
			decodeMessageBuffer(result.messages),
		];
	}

	/**
	 * Create a FROST refresh session for a non-dealer participant. `dealer` is
	 * the identifier of the trusted party that called `create`; `next` accepts
	 * only the dealer's message addressed to this party and checks the
	 * refreshed public key package against the current one.
	 */
	static async createReceiver(
		keyShare: KeyShareHandle,
		dealer: number,
	): Promise<RefreshSession> {
		const dealerId = identifier(dealer, "dealer");
		const handle = await callNative(() =>
			NativeLibtss.refreshReceiver(keyShare.handle, dealerId),
		);
		return new RefreshSession(handle);
	}

	async next(received: Message[]): Promise<RefreshOutput> {
		// Encode first so envelope validation errors surface as RangeError.
		const encoded = encodeMessageBuffer(received);
		const result = await callNative(() =>
			NativeLibtss.refreshNext(this.handle, encoded),
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
