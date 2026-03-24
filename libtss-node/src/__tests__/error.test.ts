jest.mock("../ffi", () => ({
	readLastError: () => "",
	readAbortInfo: () => ({ culprits: [], bannedParty: undefined }),
}));

import { TssError } from "../error";
import { TssStatusCode } from "../types";

describe("TssError", () => {
	it("stores code and message", () => {
		const error = new TssError(
			TssStatusCode.INVALID_CONFIG,
			"bad config",
		);

		expect(error).toBeInstanceOf(TssError);
		expect(error.code).toBe(TssStatusCode.INVALID_CONFIG);
		expect(error.message).toBe("bad config");
		expect(error.isAbort()).toBe(false);
		expect(error.isBanAbort()).toBe(false);
	});

	it("tracks abort with culprits", () => {
		const error = new TssError(TssStatusCode.ABORT, "invalid share", {
			culprits: [2, 4],
		});

		expect(error.isAbort()).toBe(true);
		expect(error.isBanAbort()).toBe(false);
		expect(error.culprits).toEqual([2, 4]);
		expect(error.bannedParty).toBeUndefined();
	});

	it("tracks ban abort with banned party", () => {
		const error = new TssError(TssStatusCode.ABORT_BAN, "cheater", {
			culprits: [3],
			bannedParty: 3,
		});

		expect(error.isAbort()).toBe(true);
		expect(error.isBanAbort()).toBe(true);
		expect(error.bannedParty).toBe(3);
	});
});
