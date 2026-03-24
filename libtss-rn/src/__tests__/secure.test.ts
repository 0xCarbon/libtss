import {
	init,
	exportKeyShareToKeychain,
	importKeyShareFromKeychain,
} from "../index";
import { KeyShareHandle } from "../handle";
import { TssError } from "../error";
import { Ciphersuite, TssStatusCode } from "../types";
import NativeLibtss, { __mock } from "./__mocks__/NativeLibtss";

beforeEach(() => {
	__mock.reset();
});

describe("init", () => {
	it("calls native initialize with default mlock value", async () => {
		await init();
		expect(NativeLibtss.initialize).toHaveBeenCalledWith({ mlock: false });
	});

	it("calls native initialize with mlock enabled", async () => {
		await init({ mlock: true });
		expect(NativeLibtss.initialize).toHaveBeenCalledWith({ mlock: true });
	});

	it("propagates native errors as TssError", async () => {
		NativeLibtss.initialize.mockRejectedValueOnce({
			code: TssStatusCode.INTERNAL_PANIC,
			message: "init failed",
		});
		await expect(init()).rejects.toThrow(TssError);
	});
});

describe("exportKeyShareToKeychain", () => {
	it("calls native and returns opaque ID", async () => {
		__mock.registerHandle("test-handle", {
			suite: Ciphersuite.Secp256k1,
		});
		const handle = new KeyShareHandle("test-handle");
		const result = await exportKeyShareToKeychain(handle);
		expect(NativeLibtss.exportKeyShareSecure).toHaveBeenCalledWith(
			"test-handle",
		);
		expect(typeof result).toBe("string");
	});

	it("propagates native errors as TssError", async () => {
		NativeLibtss.exportKeyShareSecure.mockRejectedValueOnce({
			code: TssStatusCode.HANDLE_INVALID,
			message: "bad handle",
		});
		const handle = new KeyShareHandle("bad-handle");
		await expect(exportKeyShareToKeychain(handle)).rejects.toThrow(TssError);
	});
});

describe("importKeyShareFromKeychain", () => {
	it("calls native and returns KeyShareHandle", async () => {
		const result = await importKeyShareFromKeychain(
			Ciphersuite.Secp256k1,
			"some-keychain-id",
		);
		expect(NativeLibtss.importKeyShareSecure).toHaveBeenCalledWith(
			Ciphersuite.Secp256k1,
			"some-keychain-id",
		);
		expect(result).toBeInstanceOf(KeyShareHandle);
	});

	it("propagates native errors as TssError", async () => {
		NativeLibtss.importKeyShareSecure.mockRejectedValueOnce({
			code: TssStatusCode.DESERIALIZE,
			message: "corrupt data",
		});
		await expect(
			importKeyShareFromKeychain(Ciphersuite.Secp256k1, "bad-id"),
		).rejects.toThrow(TssError);
	});
});
