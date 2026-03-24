import { decodeMessages, encodeMessages, messageCount } from "../message";

describe("message codec", () => {
	it("round-trips broadcast and point-to-point messages", () => {
		const messages = [
			{ from: 1, to: null, data: Uint8Array.of(1, 2, 3) },
			{ from: 2, to: 3, data: Uint8Array.of(9, 8) },
		];

		const encoded = encodeMessages(messages);

		expect(messageCount(encoded)).toBe(2);
		expect(decodeMessages(encoded)).toEqual(messages);
	});

	it("returns zero for an empty message buffer", () => {
		expect(messageCount(new Uint8Array())).toBe(0);
		expect(decodeMessages(new Uint8Array())).toEqual([]);
	});

	it("rejects a truncated header", () => {
		expect(() => decodeMessages(Uint8Array.of(1, 2, 3))).toThrow(
			"truncated message header",
		);
		expect(() => messageCount(Uint8Array.of(1, 2, 3))).toThrow(
			"truncated message header",
		);
	});

	it("rejects a truncated payload", () => {
		const encoded = encodeMessages([
			{ from: 7, to: null, data: Uint8Array.of(1, 2, 3, 4) },
		]);

		expect(() =>
			decodeMessages(encoded.subarray(0, encoded.length - 1)),
		).toThrow("truncated message payload");
		expect(() =>
			messageCount(encoded.subarray(0, encoded.length - 1)),
		).toThrow("truncated message payload");
	});
});
