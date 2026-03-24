import { SecureBuffer, wipeBytes } from "../secure";

describe("wipeBytes", () => {
	it("zeroes a buffer in-place", () => {
		const buf = Uint8Array.of(1, 2, 3, 4);
		wipeBytes(buf);
		expect(buf.every((b) => b === 0)).toBe(true);
	});

	it("handles empty arrays", () => {
		expect(() => wipeBytes(new Uint8Array(0))).not.toThrow();
	});

	it("handles null/undefined gracefully", () => {
		expect(() => wipeBytes(null as unknown as Uint8Array)).not.toThrow();
		expect(() =>
			wipeBytes(undefined as unknown as Uint8Array),
		).not.toThrow();
	});
});

describe("SecureBuffer", () => {
	it("copies data and wipes source", () => {
		const src = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
		const sb = new SecureBuffer(src);

		expect(new Uint8Array(sb.bytes())).toEqual(
			Uint8Array.of(0xde, 0xad, 0xbe, 0xef),
		);
		expect(src.every((b) => b === 0)).toBe(true);

		sb.destroy();
	});

	it("destroy zeroes the buffer", () => {
		const sb = new SecureBuffer(Uint8Array.of(0xca, 0xfe));
		const ref = sb.bytes();
		sb.destroy();

		expect(ref.every((b) => b === 0)).toBe(true);
		expect(sb.isDestroyed).toBe(true);
	});

	it("double-destroy does not throw", () => {
		const sb = new SecureBuffer(Uint8Array.of(1, 2, 3));
		sb.destroy();
		expect(() => sb.destroy()).not.toThrow();
	});

	it("bytes() throws after destroy", () => {
		const sb = new SecureBuffer(Uint8Array.of(1));
		sb.destroy();
		expect(() => sb.bytes()).toThrow();
	});

	it("Symbol.dispose zeroes the buffer", () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const disposeSymbol = (Symbol as any).dispose as symbol | undefined;
		if (typeof disposeSymbol !== "symbol") {
			// Node < 20.4 — skip gracefully
			return;
		}
		const sb = new SecureBuffer(Uint8Array.of(0xaa, 0xbb));
		const ref = sb.bytes();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(sb as any)[disposeSymbol]();

		expect(ref.every((b) => b === 0)).toBe(true);
		expect(sb.isDestroyed).toBe(true);
	});

	it("handles empty data", () => {
		const sb = new SecureBuffer(new Uint8Array(0));
		expect(sb.length).toBe(0);
		expect(() => sb.destroy()).not.toThrow();
	});

	it("reports correct length", () => {
		const sb = new SecureBuffer(Uint8Array.of(1, 2, 3, 4, 5));
		expect(sb.length).toBe(5);
		sb.destroy();
		expect(sb.length).toBe(0);
	});
});
