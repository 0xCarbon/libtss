import { verify } from "../index";
import { Ciphersuite } from "../types";
import NativeLibtss from "./__mocks__/NativeLibtss";

describe("verify", () => {
	beforeEach(() => {
		jest.clearAllMocks();
	});

	it("calls the native verify method with base64 encoded strings", async () => {
		const message = new Uint8Array([1, 2, 3]);
		const signature = new Uint8Array([4, 5, 6]);
		const publicKey = new Uint8Array([7, 8, 9]);

		const result = await verify(
			Ciphersuite.Ed25519,
			message,
			signature,
			publicKey,
		);

		expect(NativeLibtss.verify).toHaveBeenCalledWith(
			Ciphersuite.Ed25519,
			"AQID", // Base64 for [1, 2, 3]
			"BAUG", // Base64 for [4, 5, 6]
			"BwgJ", // Base64 for [7, 8, 9]
		);
		expect(result).toBe(true);
	});
});
