import { TssError } from "../error";
import { KeyShareHandle } from "../handle";
import { tweakAdd, tweakMul } from "../index";
import { Ciphersuite, TssStatusCode } from "../types";
import NativeLibtss, { __mock } from "./__mocks__/NativeLibtss";

const SCALAR_LENGTH = 32;
const SHORT_SCALAR_LENGTH = 31;
const LONG_SCALAR_LENGTH = 33;
const TWEAK_FILL = 7;
const FACTOR_FILL = 9;
const PARENT_HANDLE = "700";
const ADDED_HANDLE = "701";
const MULTIPLIED_HANDLE = "702";

function scalar(fill: number, length = SCALAR_LENGTH): Uint8Array {
	return new Uint8Array(length).fill(fill);
}

function parent(): KeyShareHandle {
	return new KeyShareHandle(PARENT_HANDLE);
}

beforeEach(() => {
	__mock.reset();
	__mock.registerHandle(PARENT_HANDLE, {
		suite: Ciphersuite.Secp256k1ECDSA,
	});
});

describe("tweakAdd", () => {
	it("passes the base64 scalar and wraps the returned handle", async () => {
		__mock.pushTweakAdd(ADDED_HANDLE);
		const tweak = scalar(TWEAK_FILL);

		const result = await tweakAdd(parent(), tweak);

		expect(NativeLibtss.tweakAdd).toHaveBeenCalledWith(
			PARENT_HANDLE,
			__mock.base64(tweak),
		);
		expect(result).toBeInstanceOf(KeyShareHandle);
		expect(result.handle).toBe(ADDED_HANDLE);
		await expect(result.ciphersuite()).resolves.toBe(
			Ciphersuite.Secp256k1ECDSA,
		);
	});

	it("rejects non-32-byte input before calling native", async () => {
		for (const length of [SHORT_SCALAR_LENGTH, LONG_SCALAR_LENGTH, 0]) {
			const error: unknown = await tweakAdd(
				parent(),
				scalar(TWEAK_FILL, length),
			).catch((caught) => caught);

			expect(error).toBeInstanceOf(Error);
			expect(error).not.toBeInstanceOf(TssError);
			expect((error as Error).message).toContain(`${SCALAR_LENGTH}`);
		}

		expect(NativeLibtss.tweakAdd).not.toHaveBeenCalled();
	});

	it("maps a native rejection to TssError", async () => {
		NativeLibtss.tweakAdd.mockRejectedValueOnce({
			code: TssStatusCode.PROTO_MISMATCH,
			message: "tweaks require a DKLs23 ECDSA suite",
		});

		const error: unknown = await tweakAdd(parent(), scalar(TWEAK_FILL)).catch(
			(caught) => caught,
		);

		expect(error).toBeInstanceOf(TssError);
		expect((error as TssError).code).toBe(TssStatusCode.PROTO_MISMATCH);
		expect((error as TssError).message).toBe(
			"tweaks require a DKLs23 ECDSA suite",
		);
	});
});

describe("tweakMul", () => {
	it("passes the base64 scalar and wraps the returned handle", async () => {
		__mock.pushTweakMul(MULTIPLIED_HANDLE);
		const factor = scalar(FACTOR_FILL);

		const result = await tweakMul(parent(), factor);

		expect(NativeLibtss.tweakMul).toHaveBeenCalledWith(
			PARENT_HANDLE,
			__mock.base64(factor),
		);
		expect(result).toBeInstanceOf(KeyShareHandle);
		expect(result.handle).toBe(MULTIPLIED_HANDLE);
		await expect(result.ciphersuite()).resolves.toBe(
			Ciphersuite.Secp256k1ECDSA,
		);
	});

	it("rejects non-32-byte input before calling native", async () => {
		for (const length of [SHORT_SCALAR_LENGTH, LONG_SCALAR_LENGTH, 0]) {
			const error: unknown = await tweakMul(
				parent(),
				scalar(FACTOR_FILL, length),
			).catch((caught) => caught);

			expect(error).toBeInstanceOf(Error);
			expect(error).not.toBeInstanceOf(TssError);
			expect((error as Error).message).toContain(`${SCALAR_LENGTH}`);
		}

		expect(NativeLibtss.tweakMul).not.toHaveBeenCalled();
	});

	it("maps a native rejection to TssError", async () => {
		NativeLibtss.tweakMul.mockRejectedValueOnce({
			code: TssStatusCode.TWEAK,
			message: "factor reduces to zero",
		});

		const error: unknown = await tweakMul(
			parent(),
			scalar(FACTOR_FILL),
		).catch((caught) => caught);

		expect(error).toBeInstanceOf(TssError);
		expect((error as TssError).code).toBe(TssStatusCode.TWEAK);
		expect((error as TssError).message).toBe("factor reduces to zero");
	});
});
