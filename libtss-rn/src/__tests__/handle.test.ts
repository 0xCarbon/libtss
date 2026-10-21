const CHAIN_CODE_LEN = 32;

import { TssError } from "../error";
import { KeyShareHandle } from "../handle";
import { Ciphersuite, TssStatusCode } from "../types";
import NativeLibtss, { __mock } from "./__mocks__/NativeLibtss";

describe("KeyShareHandle", () => {
	beforeEach(() => {
		__mock.reset();
	});

	it("chainCode() decodes the native base64 value", async () => {
		const chainCode = Uint8Array.from(
			{ length: CHAIN_CODE_LEN },
			(_, index) => index,
		);
		__mock.registerHandle("51", {
			suite: Ciphersuite.Secp256k1ECDSA,
			chainCode,
		});
		const handle = new KeyShareHandle("51");

		const result = await handle.chainCode();

		expect(NativeLibtss.handleChainCode).toHaveBeenCalledWith("51");
		expect(result).toBeInstanceOf(Uint8Array);
		expect(result).toHaveLength(CHAIN_CODE_LEN);
		expect(result).toEqual(chainCode);
	});

	it("chainCode() maps a native rejection to TssError", async () => {
		NativeLibtss.handleChainCode.mockRejectedValueOnce({
			code: TssStatusCode.PROTO_MISMATCH,
			message: "chain code is not available for this ciphersuite",
		});
		const handle = new KeyShareHandle("61");

		const rejection = handle.chainCode();

		await expect(rejection).rejects.toThrow(TssError);
		await expect(rejection).rejects.toMatchObject({
			code: TssStatusCode.PROTO_MISMATCH,
		});
		expect(NativeLibtss.handleChainCode).toHaveBeenCalledWith("61");
	});
});
