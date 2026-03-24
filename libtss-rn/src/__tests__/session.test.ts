const FROST_SIG_LEN = 64;
const DKL_SIG_LEN = 65;

import {
	Ciphersuite,
	DkgSession,
	importKeyShare,
	KeyShareHandle,
	Protocol,
	RefreshSession,
	SignSession,
	version,
} from "../index";
import { __mock } from "./__mocks__/NativeLibtss";

describe("session wrappers", () => {
	beforeEach(() => {
		__mock.reset();
	});

	it("runs a DKG session through completion", async () => {
		__mock.pushDkgNew({
			handle: "11",
			messages: __mock.encodeMessagesBase64([
				{ from: 1, to: null, data: [1, 2] },
			]),
		});
		__mock.pushDkgNext({
			complete: false,
			messages: __mock.encodeMessagesBase64([
				{ from: 1, to: 2, data: [3, 4, 5] },
			]),
			round: 2,
		});
		__mock.registerHandle("21", {
			suite: Ciphersuite.Secp256k1Taproot,
			identifier: 1,
			pubkeyPackage: Uint8Array.of(8, 9, 10),
		});
		__mock.pushDkgNext({
			complete: true,
			keyShareHandle: "21",
			pubkeyPackage: __mock.base64(Uint8Array.of(8, 9, 10)),
			round: 4,
		});

		const [session, initial] = await DkgSession.create(
			{ minSigners: 2, maxSigners: 3, suite: Ciphersuite.Secp256k1Taproot },
			1,
		);

		expect(initial).toEqual([{ from: 1, to: null, data: Uint8Array.of(1, 2) }]);

		const mid = await session.next([
			{ from: 2, to: null, data: Uint8Array.of(9) },
		]);
		expect(mid).toEqual({
			complete: false,
			messages: [{ from: 1, to: 2, data: Uint8Array.of(3, 4, 5) }],
		});

		const done = await session.next([]);
		expect(done.complete).toBe(true);
		if (done.complete) {
			expect(done.publicKeys).toEqual(Uint8Array.of(8, 9, 10));
			expect(done.keyShare).toBeInstanceOf(KeyShareHandle);
			expect(await done.keyShare.ciphersuite()).toBe(
				Ciphersuite.Secp256k1Taproot,
			);
		}
	});

	it("maps DKLs23 signatures to data plus recovery id", async () => {
		__mock.registerHandle("31", {
			suite: Ciphersuite.Secp256k1ECDSA,
			identifier: 2,
		});
		__mock.pushSignNew({
			handle: "41",
			messages: __mock.encodeMessagesBase64([{ from: 2, to: null, data: [7] }]),
		});
		__mock.pushSignNext({
			complete: true,
			signature: __mock.base64(
				Uint8Array.from([
					...Array.from({ length: FROST_SIG_LEN }, (_, i) => i),
					1,
				]),
			),
			round: 4,
		});

		const keyShare = new KeyShareHandle("31");
		const [session, initial] = await SignSession.create(
			keyShare,
			Uint8Array.of(9, 9, 9),
		);

		expect(initial).toEqual([{ from: 2, to: null, data: Uint8Array.of(7) }]);

		const done = await session.next([]);
		expect(done).toEqual({
			complete: true,
			signature: {
				data: Uint8Array.from(
					Array.from({ length: FROST_SIG_LEN }, (_, i) => i),
				),
				recoveryId: 1,
				protocol: Protocol.DKLs23,
			},
		});
	});

	it("keeps FROST signatures intact and recovery-less", async () => {
		__mock.registerHandle("51", { suite: Ciphersuite.Ed25519, identifier: 1 });
		__mock.pushSignNew({
			handle: "61",
			messages: __mock.encodeMessagesBase64([
				{ from: 1, to: null, data: [5, 5] },
			]),
		});
		__mock.pushSignNext({
			complete: true,
			signature: __mock.base64(
				Uint8Array.from(
					Array.from({ length: FROST_SIG_LEN }, (_, i) => FROST_SIG_LEN - i),
				),
			),
			round: 3,
		});

		const [session] = await SignSession.create(
			new KeyShareHandle("51"),
			Uint8Array.of(1),
		);
		const done = await session.next([]);

		expect(done).toEqual({
			complete: true,
			signature: {
				data: Uint8Array.from(
					Array.from({ length: FROST_SIG_LEN }, (_, i) => FROST_SIG_LEN - i),
				),
				recoveryId: null,
				protocol: Protocol.Frost,
			},
		});
	});

	it("rejects malformed DKLs23 signatures", async () => {
		__mock.registerHandle("111", {
			suite: Ciphersuite.Secp256k1ECDSA,
			identifier: 2,
		});
		__mock.pushSignNew({
			handle: "121",
			messages: __mock.encodeMessagesBase64([{ from: 2, to: null, data: [7] }]),
		});
		__mock.pushSignNext({
			complete: true,
			signature: __mock.base64(
				Uint8Array.from(Array.from({ length: FROST_SIG_LEN }, (_, i) => i)),
			),
			round: 4,
		});

		const [session] = await SignSession.create(
			new KeyShareHandle("111"),
			Uint8Array.of(9, 9, 9),
		);
		await expect(session.next([])).rejects.toThrow(
			"invalid DKLs23 signature length",
		);
	});

	it("rejects malformed FROST signatures", async () => {
		__mock.registerHandle("131", { suite: Ciphersuite.Ed25519, identifier: 1 });
		__mock.pushSignNew({
			handle: "141",
			messages: __mock.encodeMessagesBase64([
				{ from: 1, to: null, data: [5, 5] },
			]),
		});
		__mock.pushSignNext({
			complete: true,
			signature: __mock.base64(
				Uint8Array.from(Array.from({ length: DKL_SIG_LEN }, (_, i) => i)),
			),
			round: 3,
		});

		const [session] = await SignSession.create(
			new KeyShareHandle("131"),
			Uint8Array.of(1),
		);
		await expect(session.next([])).rejects.toThrow(
			"invalid FROST signature length",
		);
	});

	it("supports refresh receiver, key import, and version", async () => {
		__mock.registerHandle("71", {
			suite: Ciphersuite.Secp256k1ECDSA,
			identifier: 4,
		});
		__mock.pushRefreshReceiver("81");
		__mock.registerHandle("91", {
			suite: Ciphersuite.Secp256k1ECDSA,
			identifier: 4,
			pubkeyPackage: Uint8Array.of(4, 4, 4),
		});
		__mock.pushRefreshNext({
			complete: true,
			keyShareHandle: "91",
			pubkeyPackage: __mock.base64(Uint8Array.of(4, 4, 4)),
			round: 4,
		});
		__mock.setVersion("1.2.3");

		const session = await RefreshSession.createReceiver(
			new KeyShareHandle("71"),
		);

		const refreshed = await session.next([]);
		expect(refreshed.complete).toBe(true);
		if (refreshed.complete) {
			expect(await refreshed.keyShare.protocol()).toBe(Protocol.DKLs23);
		}

		const imported = await importKeyShare(
			Ciphersuite.P256,
			Uint8Array.of(8, 8),
		);
		expect(imported).toBeInstanceOf(KeyShareHandle);
		expect(await imported.ciphersuite()).toBe(Ciphersuite.P256);

		expect(await version()).toBe("1.2.3");
	});

	it("supports refresh dealer with participants", async () => {
		__mock.registerHandle("201", {
			suite: Ciphersuite.Ed25519,
			identifier: 1,
		});
		__mock.pushRefreshNew({
			handle: "211",
			messages: __mock.encodeMessagesBase64([
				{ from: 1, to: 2, data: [10, 20] },
			]),
		});
		__mock.registerHandle("221", {
			suite: Ciphersuite.Ed25519,
			identifier: 1,
			pubkeyPackage: Uint8Array.of(5, 5, 5),
		});
		__mock.pushRefreshNext({
			complete: true,
			keyShareHandle: "221",
			pubkeyPackage: __mock.base64(Uint8Array.of(5, 5, 5)),
		});

		const [session, initial] = await RefreshSession.create(
			new KeyShareHandle("201"),
			[1, 2, 3],
		);
		expect(initial).toEqual([{ from: 1, to: 2, data: Uint8Array.of(10, 20) }]);

		const done = await session.next([]);
		expect(done.complete).toBe(true);
		if (done.complete) {
			expect(done.publicKeys).toEqual(Uint8Array.of(5, 5, 5));
		}
	});
});
