import { TssError } from "../error";
import { TssStatusCode } from "../types";

describe("TssError", () => {
	it("maps native abort errors with culprits", () => {
		const error = TssError.fromNative({
			code: TssStatusCode.ABORT,
			message: "invalid signature share",
			culprits: [2, 4],
		});

		expect(error).toBeInstanceOf(TssError);
		expect(error.code).toBe(TssStatusCode.ABORT);
		expect(error.culprits).toEqual([2, 4]);
		expect(error.bannedParty).toBeUndefined();
		expect(error.isAbort()).toBe(true);
		expect(error.isBanAbort()).toBe(false);
	});

	it("maps ban aborts and preserves the banned party", () => {
		const error = TssError.fromNative({
			code: TssStatusCode.ABORT_BAN,
			message: "cheating counterparty",
			culprits: [3],
			bannedParty: 3,
		});

		expect(error.code).toBe(TssStatusCode.ABORT_BAN);
		expect(error.bannedParty).toBe(3);
		expect(error.isAbort()).toBe(true);
		expect(error.isBanAbort()).toBe(true);
	});

	it("falls back to a generic error message", () => {
		const error = TssError.fromNative({ code: TssStatusCode.HANDLE_INVALID });

		expect(error.message).toBe("libtss native call failed");
		expect(error.isAbort()).toBe(false);
	});

	it("reads bridge metadata from nested userInfo and string status codes", () => {
		const error = TssError.fromNative({
			code: "E_LIBTSS",
			message: "native bridge failed",
			userInfo: {
				code: String(TssStatusCode.ABORT_BAN),
				culprits: [5],
				bannedParty: 5,
			},
		});

		expect(error.code).toBe(TssStatusCode.ABORT_BAN);
		expect(error.message).toBe("native bridge failed");
		expect(error.culprits).toEqual([5]);
		expect(error.bannedParty).toBe(5);
	});
});
