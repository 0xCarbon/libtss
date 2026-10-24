const DKLS_SIG_LEN = 64;

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
import NativeLibtss, { __mock } from "./__mocks__/NativeLibtss";

const FROST_SUITES: [string, number, Ciphersuite][] = [
	["Secp256k1Taproot", 64, Ciphersuite.Secp256k1Taproot],
	["Secp256k1", 65, Ciphersuite.Secp256k1],
	["Ed25519", 64, Ciphersuite.Ed25519],
	["P256", 65, Ciphersuite.P256],
	["Ristretto255", 64, Ciphersuite.Ristretto255],
	["Ed448", 114, Ciphersuite.Ed448],
];

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

	function bytesOfLength(length: number): Uint8Array {
		return Uint8Array.from(Array.from({ length }, (_, i) => i));
	}

	async function signOnce(
		suite: Ciphersuite,
		result: { signature: string; recoveryId?: number },
	) {
		__mock.registerHandle("31", { suite, identifier: 2 });
		__mock.pushSignNew({
			handle: "41",
			messages: __mock.encodeMessagesBase64([{ from: 2, to: null, data: [7] }]),
		});
		__mock.pushSignNext({ complete: true, ...result, round: 4 });
		const [session, initial] = await SignSession.create(
			new KeyShareHandle("31"),
			Uint8Array.of(9, 9, 9),
			[1],
		);
		expect(initial).toEqual([{ from: 2, to: null, data: Uint8Array.of(7) }]);
		return session.next([]);
	}

	it.each([
		["Secp256k1ECDSA", Ciphersuite.Secp256k1ECDSA],
		["Secp256r1ECDSA", Ciphersuite.Secp256r1ECDSA],
	])(
		"returns 64-byte %s signatures with the native recovery id",
		async (_name, suite) => {
			const done = await signOnce(suite, {
				signature: __mock.base64(bytesOfLength(DKLS_SIG_LEN)),
				recoveryId: 1,
			});
			expect(done).toEqual({
				complete: true,
				signature: {
					data: bytesOfLength(DKLS_SIG_LEN),
					recoveryId: 1,
					protocol: Protocol.DKLs23,
				},
			});
		},
	);

	it("rejects DKLs23 signatures without a recovery id", async () => {
		await expect(
			signOnce(Ciphersuite.Secp256k1ECDSA, {
				signature: __mock.base64(bytesOfLength(DKLS_SIG_LEN)),
			}),
		).rejects.toThrow("missing its recovery id");
	});

	it("rejects 65-byte DKLs23 signatures", async () => {
		await expect(
			signOnce(Ciphersuite.Secp256k1ECDSA, {
				signature: __mock.base64(bytesOfLength(65)),
				recoveryId: 0,
			}),
		).rejects.toThrow("invalid signature length");
	});

	it.each(FROST_SUITES)(
		"returns %s signatures of %p bytes without a recovery id",
		async (_name, length, suite) => {
			const done = await signOnce(suite, {
				signature: __mock.base64(bytesOfLength(length)),
			});
			expect(done).toEqual({
				complete: true,
				signature: {
					data: bytesOfLength(length),
					recoveryId: null,
					protocol: Protocol.Frost,
				},
			});
		},
	);

	it.each(FROST_SUITES)(
		"rejects %s signatures of the wrong length",
		async (_name, length, suite) => {
			await expect(
				signOnce(suite, {
					signature: __mock.base64(bytesOfLength(length + 1)),
				}),
			).rejects.toThrow("invalid signature length");
		},
	);

	it("frees sessions through sessionFree, not handleFree", async () => {
		__mock.registerHandle("51", { suite: Ciphersuite.Ed25519, identifier: 1 });
		__mock.pushSignNew({ handle: "61", messages: "" });
		const [session] = await SignSession.create(
			new KeyShareHandle("51"),
			Uint8Array.of(1),
		);
		session.free();
		session.free();
		await Promise.resolve();
		expect(__mock.freedSessions()).toEqual(["61"]);
		expect(__mock.freedHandles()).toEqual([]);
	});

	it.each([65539, -1, 1.5])(
		"rejects identifier %p before calling native",
		async (bad) => {
			__mock.registerHandle("51", { suite: Ciphersuite.Ed25519 });
			const share = new KeyShareHandle("51");
			await expect(
				DkgSession.create(
					{ minSigners: 2, maxSigners: 3, suite: Ciphersuite.Ed25519 },
					bad,
				),
			).rejects.toThrow(RangeError);
			await expect(
				DkgSession.create(
					{ minSigners: bad, maxSigners: 3, suite: Ciphersuite.Ed25519 },
					1,
				),
			).rejects.toThrow(RangeError);
			await expect(
				DkgSession.create(
					{ minSigners: 2, maxSigners: bad, suite: Ciphersuite.Ed25519 },
					1,
				),
			).rejects.toThrow(RangeError);
			await expect(
				SignSession.create(share, Uint8Array.of(1), [bad]),
			).rejects.toThrow(RangeError);
			await expect(RefreshSession.create(share, [1, bad])).rejects.toThrow(
				RangeError,
			);
			await expect(
				importKeyShare(bad as Ciphersuite, Uint8Array.of(1)),
			).rejects.toThrow(RangeError);
		},
	);

	it.each([0, -1])("rejects signer count %p before calling native", async (bad) => {
		for (const config of [
			{ minSigners: bad, maxSigners: 3, suite: Ciphersuite.Ed25519 },
			{ minSigners: 2, maxSigners: bad, suite: Ciphersuite.Ed25519 },
		]) {
			await expect(DkgSession.create(config, 1)).rejects.toThrow(RangeError);
		}
		expect(NativeLibtss.dkgNew).not.toHaveBeenCalled();
	});

	it("surfaces envelope validation in next() as RangeError", async () => {
		__mock.pushDkgNew({ handle: "301", messages: "" });
		__mock.registerHandle("311", { suite: Ciphersuite.Ed25519 });
		__mock.pushSignNew({ handle: "321", messages: "" });
		__mock.pushRefreshNew({ handle: "331", messages: "" });
		const [dkg] = await DkgSession.create(
			{ minSigners: 2, maxSigners: 3, suite: Ciphersuite.Ed25519 },
			1,
		);
		const share = new KeyShareHandle("311");
		const [sign] = await SignSession.create(share, Uint8Array.of(1));
		const [refresh] = await RefreshSession.create(share);
		const bad = [{ from: 65536, to: null, data: Uint8Array.of(1) }];
		await expect(dkg.next(bad)).rejects.toThrow(RangeError);
		await expect(sign.next(bad)).rejects.toThrow(RangeError);
		await expect(refresh.next(bad)).rejects.toThrow(RangeError);
		expect(NativeLibtss.dkgNext).not.toHaveBeenCalled();
		expect(NativeLibtss.signNext).not.toHaveBeenCalled();
		expect(NativeLibtss.refreshNext).not.toHaveBeenCalled();
	});

	it("rejects a fractional ciphersuite in DKG", async () => {
		await expect(
			DkgSession.create(
				{ minSigners: 2, maxSigners: 3, suite: 6.5 as Ciphersuite },
				1,
			),
		).rejects.toThrow(RangeError);
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
			1,
		);
		expect(NativeLibtss.refreshReceiver).toHaveBeenLastCalledWith("71", 1);
		await expect(
			RefreshSession.createReceiver(new KeyShareHandle("71"), 0),
		).rejects.toThrow(RangeError);

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
