import { fromByteArray } from "base64-js";
import { KeyShareHandle } from "../handle";
import {
	bolt3Derive,
	bolt3DerivePublicKeys,
	bolt3DeriveRevocation,
	dklsRepairAssemble,
	dklsRepairHelperTerm,
} from "../index";
import { encodeMessages } from "../message";
import { RefreshSession } from "../session";
import { Ciphersuite } from "../types";
import NativeLibtss, { __mock } from "./__mocks__/NativeLibtss";

describe("DKLs23 bindings", () => {
	beforeEach(() => {
		__mock.reset();
	});

	it("RefreshSession.createDkls passes the session id as base64", async () => {
		__mock.pushRefreshNew({ handle: "71", messages: "" });
		const sessionId = Uint8Array.of(1, 2, 3);
		const [session, messages] = await RefreshSession.createDkls(
			new KeyShareHandle("70"),
			sessionId,
		);
		expect(NativeLibtss.refreshNewDkls).toHaveBeenCalledWith(
			"70",
			fromByteArray(sessionId),
		);
		expect(session).toBeInstanceOf(RefreshSession);
		expect(messages).toEqual([]);
		await expect(
			RefreshSession.createDkls(new KeyShareHandle("70"), new Uint8Array(0)),
		).rejects.toThrow();
	});

	it("repair round-trips messages through the bridge", async () => {
		const term = { from: 1, to: 2, data: Uint8Array.of(9, 9) };
		__mock.pushString(fromByteArray(encodeMessages([term])));
		const messages = await dklsRepairHelperTerm(
			new KeyShareHandle("80"),
			[1, 3],
			2,
			Uint8Array.of(7),
		);
		expect(NativeLibtss.repairHelperTerm).toHaveBeenCalledWith(
			"80",
			[1, 3],
			2,
			fromByteArray(Uint8Array.of(7)),
		);
		expect(messages).toEqual([term]);

		__mock.pushString("81");
		const repaired = await dklsRepairAssemble(
			Ciphersuite.Secp256k1ECDSA,
			Uint8Array.of(5),
			2,
			messages,
		);
		expect(repaired.handle).toBe("81");
		expect(NativeLibtss.repairAssemble).toHaveBeenCalledWith(
			Ciphersuite.Secp256k1ECDSA,
			fromByteArray(Uint8Array.of(5)),
			2,
			fromByteArray(encodeMessages(messages)),
		);
	});

	it("BOLT 3 derivations wipe the per-commitment secret", async () => {
		__mock.pushString("90");
		__mock.pushString("91");
		__mock.pushString(fromByteArray(Uint8Array.of(4, 4)));
		const point = new Uint8Array(33).fill(2);
		const secret = new Uint8Array(32).fill(7);
		expect((await bolt3Derive(new KeyShareHandle("1"), point)).handle).toBe(
			"90",
		);
		expect(
			(await bolt3DeriveRevocation(new KeyShareHandle("1"), point, secret))
				.handle,
		).toBe("91");
		expect(secret.every((b) => b === 0)).toBe(true);
		expect(await bolt3DerivePublicKeys(Uint8Array.of(1), point)).toEqual(
			Uint8Array.of(4, 4),
		);
	});
});
