import type { KeyShareHandle } from "../handle";
import { DkgSession } from "../session";
import type { Message, ThresholdConfig } from "../types";

const MAX_DKG_ROUNDS = 10;

export interface DkgResult {
	keyShares: KeyShareHandle[];
	publicKeys: Uint8Array;
}

function collectFor(
	participantId: number,
	outgoing: Map<number, Message[]>,
): Message[] {
	const inbound: Message[] = [];
	for (const [senderId, messages] of outgoing) {
		if (senderId === participantId) {
			continue;
		}
		for (const message of messages) {
			if (message.to === null || message.to === participantId) {
				inbound.push(message);
			}
		}
	}
	return inbound;
}

/**
 * Drives a complete DKG for every party in-process, routing each round's
 * broadcast and point-to-point messages between the sessions the way a host
 * application would. Key shares are returned sorted by party identifier.
 */
export function runDkg(
	config: ThresholdConfig,
	sessionId?: Uint8Array,
): DkgResult {
	const sessions = new Map<number, DkgSession>();
	let outgoing = new Map<number, Message[]>();
	for (let partyId = 1; partyId <= config.maxSigners; partyId++) {
		const [session, messages] = DkgSession.create(config, partyId, sessionId);
		sessions.set(partyId, session);
		outgoing.set(partyId, messages);
	}

	const keyShares = new Map<number, KeyShareHandle>();
	let publicKeys: Uint8Array = new Uint8Array(0);
	for (let round = 0; round < MAX_DKG_ROUNDS && sessions.size > 0; round++) {
		const nextOutgoing = new Map<number, Message[]>();
		for (const [partyId, session] of [...sessions]) {
			const output = session.next(collectFor(partyId, outgoing));
			if (output.complete) {
				keyShares.set(partyId, output.keyShare);
				publicKeys = output.publicKeys;
				session.free();
				sessions.delete(partyId);
			} else {
				nextOutgoing.set(partyId, output.messages);
			}
		}
		outgoing = nextOutgoing;
	}

	if (keyShares.size !== config.maxSigners) {
		throw new Error(
			`DKG incomplete: ${keyShares.size}/${config.maxSigners} shares`,
		);
	}

	return {
		keyShares: [...keyShares.entries()]
			.sort(([a], [b]) => a - b)
			.map(([, share]) => share),
		publicKeys,
	};
}

export function freeAll(handles: KeyShareHandle[]): void {
	for (const handle of handles) {
		handle.free();
	}
}
