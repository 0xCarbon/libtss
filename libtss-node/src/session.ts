import { checkStatus } from "./error";
import { allocBuffer, lib, makeSlice, readBuffer } from "./ffi";
import { KeyShareHandle } from "./handle";
import { decodeMessages, encodeMessages } from "./message";
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

const sessionRegistry = new FinalizationRegistry<bigint>((handle) => {
	lib.tss_session_free(handle);
});

abstract class SessionHandle {
	protected readonly handle: bigint;
	private _freed = false;

	protected constructor(handle: bigint) {
		this.handle = handle;
		sessionRegistry.register(this, handle, this);
	}

	free(): void {
		if (this._freed) {
			return;
		}
		this._freed = true;
		sessionRegistry.unregister(this);
		lib.tss_session_free(this.handle);
	}
}

export class DkgSession extends SessionHandle {
	static create(
		config: ThresholdConfig,
		selfId: number,
		sessionId?: Uint8Array,
	): [DkgSession, Message[]] {
		const outSession: [bigint] = [0n];
		const outMessages = allocBuffer();

		checkStatus(
			lib.tss_dkg_new(
				config.suite,
				selfId,
				config.maxSigners,
				config.minSigners,
				sessionId ?? null,
				sessionId?.length ?? 0,
				outSession,
				outMessages,
			),
		);

		const session = new DkgSession(outSession[0]);
		const messages = decodeMessages(readBuffer(outMessages));
		return [session, messages];
	}

	next(received: Message[]): DkgOutput {
		const incoming = encodeMessages(received);
		const outKeyShare: [bigint] = [0n];
		const outPubkey = allocBuffer();
		const outMessages = allocBuffer();
		const outComplete: [boolean] = [false];

		checkStatus(
			lib.tss_dkg_next(
				this.handle,
				makeSlice(incoming),
				outKeyShare,
				outPubkey,
				outMessages,
				outComplete,
			),
		);

		if (!outComplete[0]) {
			return {
				complete: false,
				messages: decodeMessages(readBuffer(outMessages)),
			};
		}

		return {
			complete: true,
			keyShare: new KeyShareHandle(outKeyShare[0]),
			publicKeys: readBuffer(outPubkey),
		};
	}
}

export class SignSession extends SessionHandle {
	private readonly keyShare: KeyShareHandle;

	private constructor(handle: bigint, keyShare: KeyShareHandle) {
		super(handle);
		this.keyShare = keyShare;
	}

	static create(
		keyShare: KeyShareHandle,
		message: Uint8Array,
		counterparties?: number[],
		signId?: Uint8Array,
	): [SignSession, Message[]] {
		const outSession: [bigint] = [0n];
		const outMessages = allocBuffer();

		const cpBuf =
			counterparties && counterparties.length > 0
				? new Uint16Array(counterparties)
				: null;

		checkStatus(
			lib.tss_sign_new(
				keyShare.handle,
				makeSlice(message),
				cpBuf,
				cpBuf?.length ?? 0,
				signId ?? null,
				signId?.length ?? 0,
				outSession,
				outMessages,
			),
		);

		const session = new SignSession(outSession[0], keyShare);
		const messages = decodeMessages(readBuffer(outMessages));
		return [session, messages];
	}

	next(received: Message[]): SignOutput {
		const incoming = encodeMessages(received);
		const outSignature = allocBuffer();
		const outMessages = allocBuffer();
		const outComplete: [boolean] = [false];

		checkStatus(
			lib.tss_sign_next(
				this.handle,
				makeSlice(incoming),
				outSignature,
				outMessages,
				outComplete,
			),
		);

		if (!outComplete[0]) {
			return {
				complete: false,
				messages: decodeMessages(readBuffer(outMessages)),
			};
		}

		const protocol = this.keyShare.protocol();
		const signature = readBuffer(outSignature);

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
	static create(
		keyShare: KeyShareHandle,
		participants?: number[],
	): [RefreshSession, Message[]] {
		const outSession: [bigint] = [0n];
		const outMessages = allocBuffer();

		const pBuf =
			participants && participants.length > 0
				? new Uint16Array(participants)
				: null;

		checkStatus(
			lib.tss_refresh_new(
				keyShare.handle,
				pBuf,
				pBuf?.length ?? 0,
				outSession,
				outMessages,
			),
		);

		const session = new RefreshSession(outSession[0]);
		const messages = decodeMessages(readBuffer(outMessages));
		return [session, messages];
	}

	static createReceiver(keyShare: KeyShareHandle): RefreshSession {
		const outSession: [bigint] = [0n];
		checkStatus(
			lib.tss_refresh_receiver(keyShare.handle, outSession),
		);
		return new RefreshSession(outSession[0]);
	}

	next(received: Message[]): RefreshOutput {
		const incoming = encodeMessages(received);
		const outKeyShare: [bigint] = [0n];
		const outPubkey = allocBuffer();
		const outMessages = allocBuffer();
		const outComplete: [boolean] = [false];

		checkStatus(
			lib.tss_refresh_next(
				this.handle,
				makeSlice(incoming),
				outKeyShare,
				outPubkey,
				outMessages,
				outComplete,
			),
		);

		if (!outComplete[0]) {
			return {
				complete: false,
				messages: decodeMessages(readBuffer(outMessages)),
			};
		}

		return {
			complete: true,
			keyShare: new KeyShareHandle(outKeyShare[0]),
			publicKeys: readBuffer(outPubkey),
		};
	}
}
