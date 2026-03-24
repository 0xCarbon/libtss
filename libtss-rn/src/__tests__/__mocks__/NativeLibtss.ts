const MOCK_BYTE_11 = 11;
const MOCK_BYTE_12 = 12;

import { fromByteArray } from "base64-js";

import type { Ciphersuite } from "../../types";

type MockMessage = {
	from: number;
	to: number | null;
	data: Uint8Array | number[];
};

type SessionResult = {
	complete: boolean;
	messages?: string;
	keyShareHandle?: string;
	pubkeyPackage?: string;
	signature?: string;
	round?: number;
};

type HandleState = {
	identifier: number;
	suite: Ciphersuite;
	verifyingShare: Uint8Array;
	groupKey: Uint8Array;
	pubkeyPackage: Uint8Array;
	exported: Uint8Array;
};

const handles = new Map<string, HandleState>();
const freed: string[] = [];
const dkgNewQueue: Array<{
	handle: string;
	messages: string;
}> = [];
const dkgNextQueue: SessionResult[] = [];
const signNewQueue: Array<{
	handle: string;
	messages: string;
}> = [];
const signNextQueue: SessionResult[] = [];
const refreshNewQueue: Array<{
	handle: string;
	messages: string;
}> = [];
const refreshReceiverQueue: string[] = [];
const refreshNextQueue: SessionResult[] = [];
let versionValue = "0.0.0-test";

function bytes(data: Uint8Array | number[]): Uint8Array {
	return data instanceof Uint8Array ? data : Uint8Array.from(data);
}

function base64(data: Uint8Array | number[]): string {
	return fromByteArray(bytes(data));
}

function encodeMessagesBase64(messages: MockMessage[]): string {
	let len = 0;
	for (const message of messages) {
		len += 8 + bytes(message.data).length;
	}

	const out = new Uint8Array(len);
	const view = new DataView(out.buffer);
	let offset = 0;

	for (const message of messages) {
		const payload = bytes(message.data);
		view.setUint16(offset, message.from, true);
		view.setUint16(offset + 2, message.to ?? 0, true);
		view.setUint32(offset + 4, payload.length, true);
		out.set(payload, offset + 8);
		offset += 8 + payload.length;
	}

	return fromByteArray(out);
}

function nextQueued<T>(queue: T[], name: string): T {
	const value = queue.shift();
	if (!value) {
		throw new Error(`missing mock result for ${name}`);
	}
	return value;
}

const NativeLibtss = {
	dkgNew: jest.fn(async () => {
		const entry = nextQueued(dkgNewQueue, "dkgNew");
		return { handle: entry.handle, messages: entry.messages };
	}),
	dkgNext: jest.fn(async (_handle: string) => {
		return nextQueued(dkgNextQueue, "dkgNext");
	}),
	signNew: jest.fn(async () => {
		const entry = nextQueued(signNewQueue, "signNew");
		return { handle: entry.handle, messages: entry.messages };
	}),
	signNext: jest.fn(async (_handle: string) => {
		return nextQueued(signNextQueue, "signNext");
	}),
	refreshNew: jest.fn(async () => {
		const entry = nextQueued(refreshNewQueue, "refreshNew");
		return { handle: entry.handle, messages: entry.messages };
	}),
	refreshReceiver: jest.fn(async () => {
		return nextQueued(refreshReceiverQueue, "refreshReceiver");
	}),
	refreshNext: jest.fn(async (_handle: string) => {
		return nextQueued(refreshNextQueue, "refreshNext");
	}),
	handleFree: jest.fn(async (handle: string) => {
		freed.push(handle);
	}),
	handleIdentifier: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return state.identifier;
	}),
	handleVerifyingShare: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return base64(state.verifyingShare);
	}),
	handleGroupKey: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return base64(state.groupKey);
	}),
	handlePubkeyPackage: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return base64(state.pubkeyPackage);
	}),
	handleCiphersuite: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return state.suite;
	}),
	exportKeyShare: jest.fn(async (handle: string) => {
		const state = handles.get(handle);
		if (!state) {
			throw new Error(`unknown handle ${handle}`);
		}
		return base64(state.exported);
	}),
	importKeyShare: jest.fn(async (suite: number, data: string) => {
		const handle = `${suite}:${data}`;
		if (!handles.has(handle)) {
			handles.set(handle, {
				identifier: 1,
				suite: suite as Ciphersuite,
				verifyingShare: Uint8Array.of(1),
				groupKey: Uint8Array.of(2),
				pubkeyPackage: Uint8Array.of(3),
				exported: Uint8Array.of(4),
			});
		}
		return handle;
	}),
	version: jest.fn(async () => versionValue),
	verify: jest.fn(
		async (
			suite: number,
			message: string,
			signature: string,
			publicKey: string,
		) => true,
	),
	initialize: jest.fn(async (_options: { mlock: boolean }) => {}),
	exportKeyShareSecure: jest.fn(
		async (handle: string) => "mock-keychain-id-" + handle,
	),
	importKeyShareSecure: jest.fn(
		async (suite: number, _keychainId: string) => {
			const handle = `secure:${suite}:${_keychainId}`;
			if (!handles.has(handle)) {
				handles.set(handle, {
					identifier: 1,
					suite: suite as Ciphersuite,
					verifyingShare: Uint8Array.of(1),
					groupKey: Uint8Array.of(2),
					pubkeyPackage: Uint8Array.of(3),
					exported: Uint8Array.of(4),
				});
			}
			return handle;
		},
	),
};

export const __mock = {
	base64,
	encodeMessagesBase64,
	freedHandles(): string[] {
		return [...freed];
	},
	pushDkgNew(entry: { handle: string; messages: string }): void {
		dkgNewQueue.push(entry);
	},
	pushDkgNext(entry: SessionResult): void {
		dkgNextQueue.push(entry);
	},
	pushSignNew(entry: { handle: string; messages: string }): void {
		signNewQueue.push(entry);
	},
	pushSignNext(entry: SessionResult): void {
		signNextQueue.push(entry);
	},
	pushRefreshNew(entry: { handle: string; messages: string }): void {
		refreshNewQueue.push(entry);
	},
	pushRefreshReceiver(handle: string): void {
		refreshReceiverQueue.push(handle);
	},
	pushRefreshNext(entry: SessionResult): void {
		refreshNextQueue.push(entry);
	},
	registerHandle(
		handle: string,
		state: Partial<HandleState> & Pick<HandleState, "suite">,
	): void {
		handles.set(handle, {
			identifier: state.identifier ?? 1,
			suite: state.suite,
			verifyingShare: state.verifyingShare ?? Uint8Array.of(1, 2, 3),
			groupKey: state.groupKey ?? Uint8Array.of(4, 5, 6),
			pubkeyPackage: state.pubkeyPackage ?? Uint8Array.of(7, 8, 9),
			exported: state.exported ?? Uint8Array.of(10, MOCK_BYTE_11, MOCK_BYTE_12),
		});
	},
	reset(): void {
		handles.clear();
		freed.length = 0;
		dkgNewQueue.length = 0;
		dkgNextQueue.length = 0;
		signNewQueue.length = 0;
		signNextQueue.length = 0;
		refreshNewQueue.length = 0;
		refreshReceiverQueue.length = 0;
		refreshNextQueue.length = 0;
		versionValue = "0.0.0-test";

		for (const fn of Object.values(NativeLibtss)) {
			fn.mockClear();
		}
	},
	setVersion(value: string): void {
		versionValue = value;
	},
};

export default NativeLibtss;
