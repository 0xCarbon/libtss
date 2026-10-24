import { u8, u16, u16Array } from "./checks";
import { checkStatus } from "./error";
import { allocBuffer, lib, makeSlice, readBuffer } from "./ffi";
import { KeyShareHandle } from "./handle";
import { decodeMessages, encodeMessages } from "./message";
import type {
	Ciphersuite,
	DkgOutput,
	Message,
	RefreshOutput,
	SignOutput,
	ThresholdConfig,
} from "./types";
import { Protocol, protocolForCiphersuite, signatureLength } from "./types";

const NO_RECOVERY_ID = 255;

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
				u8(config.suite, "suite"),
				u16(selfId, "selfId"),
				u16(config.maxSigners, "maxSigners"),
				u16(config.minSigners, "minSigners"),
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
	private readonly suite: Ciphersuite;

	private constructor(handle: bigint, suite: Ciphersuite) {
		super(handle);
		this.suite = suite;
	}

	static create(
		keyShare: KeyShareHandle,
		message: Uint8Array,
		counterparties?: number[],
		signId?: Uint8Array,
	): [SignSession, Message[]] {
		const suite = keyShare.ciphersuite();
		const outSession: [bigint] = [0n];
		const outMessages = allocBuffer();

		const cpBuf =
			counterparties && counterparties.length > 0
				? u16Array(counterparties, "counterparty")
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

		const session = new SignSession(outSession[0], suite);
		const messages = decodeMessages(readBuffer(outMessages));
		return [session, messages];
	}

	next(received: Message[]): SignOutput {
		const incoming = encodeMessages(received);
		const outSignature = allocBuffer();
		const outRecoveryId: [number] = [NO_RECOVERY_ID];
		const outMessages = allocBuffer();
		const outComplete: [boolean] = [false];

		checkStatus(
			lib.tss_sign_next_recoverable(
				this.handle,
				makeSlice(incoming),
				outSignature,
				outRecoveryId,
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

		const protocol = protocolForCiphersuite(this.suite);
		const signature = readBuffer(outSignature);
		const expected = signatureLength(this.suite);
		if (signature.length !== expected) {
			throw new Error(
				`invalid signature length for ciphersuite ${this.suite}: expected ${expected} bytes, got ${signature.length}`,
			);
		}

		let recoveryId: number | null = null;
		if (protocol === Protocol.DKLs23) {
			if (outRecoveryId[0] > 1) {
				throw new Error("DKLs23 signature is missing its recovery id");
			}
			recoveryId = outRecoveryId[0];
		}

		return {
			complete: true,
			signature: { data: signature, recoveryId, protocol },
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
				? u16Array(participants, "participant")
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

	/**
	 * DKLs23 complete refresh (secp256k1 / secp256r1). All parties run it
	 * together under the same fresh `sessionId`; `next()` is called three
	 * times. The group key stays the same and every share and its OT state
	 * are regenerated. Refreshed shares sign only with shares from the same
	 * refresh.
	 */
	static createDkls(
		keyShare: KeyShareHandle,
		sessionId: Uint8Array,
	): [RefreshSession, Message[]] {
		if (sessionId.length === 0) {
			throw new Error("sessionId must not be empty");
		}
		const outSession: [bigint] = [0n];
		const outMessages = allocBuffer();
		checkStatus(
			lib.tss_refresh_new_dkls(
				keyShare.handle,
				sessionId,
				sessionId.length,
				outSession,
				outMessages,
			),
		);
		const session = new RefreshSession(outSession[0]);
		const messages = decodeMessages(readBuffer(outMessages));
		return [session, messages];
	}

	/**
	 * Create a FROST refresh session for a non-dealer participant. `dealer` is
	 * the identifier of the trusted party that called `create`; `next` accepts
	 * only the dealer's message addressed to this party and checks the
	 * refreshed public key package against the current one.
	 */
	static createReceiver(
		keyShare: KeyShareHandle,
		dealer: number,
	): RefreshSession {
		const dealerId = u16(dealer, "dealer");
		const outSession: [bigint] = [0n];
		checkStatus(
			lib.tss_refresh_receiver(keyShare.handle, dealerId, outSession),
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
