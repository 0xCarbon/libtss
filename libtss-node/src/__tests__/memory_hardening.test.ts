/**
 * Memory hardening verification tests (Issue #75).
 *
 * Validates that SecureBuffer, wipeBytes, and handle lifecycle
 * behave correctly from the Node.js binding perspective.
 */

import { SecureBuffer, wipeBytes } from "../secure";

// ---------------------------------------------------------------------------
// wipeBytes
// ---------------------------------------------------------------------------

describe("wipeBytes - memory hardening", () => {
	it("zeroes all bytes for various sizes", () => {
		for (const sz of [1, 16, 32, 64, 256, 1024]) {
			const buf = new Uint8Array(sz);
			for (let i = 0; i < sz; i++) buf[i] = (i % 255) + 1;
			wipeBytes(buf);
			expect(buf.every((b) => b === 0)).toBe(true);
		}
	});

	it("handles null and undefined without throwing", () => {
		expect(() => wipeBytes(null as unknown as Uint8Array)).not.toThrow();
		expect(() =>
			wipeBytes(undefined as unknown as Uint8Array),
		).not.toThrow();
	});

	it("handles empty array without throwing", () => {
		expect(() => wipeBytes(new Uint8Array(0))).not.toThrow();
	});
});

// ---------------------------------------------------------------------------
// SecureBuffer lifecycle
// ---------------------------------------------------------------------------

describe("SecureBuffer - memory hardening", () => {
	it("copies data and wipes the source slice", () => {
		const src = Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe);
		const expected = new Uint8Array(src);
		const sb = new SecureBuffer(src);

		// Source should be zeroed
		expect(src.every((b) => b === 0)).toBe(true);
		// SecureBuffer holds the original data
		expect(new Uint8Array(sb.bytes())).toEqual(expected);
		expect(sb.length).toBe(expected.length);

		sb.destroy();
	});

	it("destroy zeroes the backing buffer", () => {
		const sb = new SecureBuffer(Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd));
		const ref = sb.bytes();
		sb.destroy();

		// The underlying Buffer should be zeroed
		expect(ref.every((b) => b === 0)).toBe(true);
		expect(sb.isDestroyed).toBe(true);
		expect(sb.length).toBe(0);
	});

	it("double-destroy does not throw", () => {
		const sb = new SecureBuffer(Uint8Array.of(1, 2, 3));
		sb.destroy();
		expect(() => sb.destroy()).not.toThrow();
		expect(() => sb.destroy()).not.toThrow(); // triple
	});

	it("bytes() throws after destroy", () => {
		const sb = new SecureBuffer(Uint8Array.of(1));
		sb.destroy();
		expect(() => sb.bytes()).toThrow("SecureBuffer has been destroyed");
	});

	it("handles empty data", () => {
		const sb = new SecureBuffer(new Uint8Array(0));
		expect(sb.length).toBe(0);
		expect(() => sb.destroy()).not.toThrow();
	});

	it("wrap takes ownership of a Buffer", () => {
		const buf = Buffer.allocUnsafeSlow(4);
		buf[0] = 0xde;
		buf[1] = 0xad;
		buf[2] = 0xbe;
		buf[3] = 0xef;

		const sb = SecureBuffer.wrap(buf);
		expect(new Uint8Array(sb.bytes())).toEqual(
			Uint8Array.of(0xde, 0xad, 0xbe, 0xef),
		);

		sb.destroy();
		// Underlying Buffer should be zeroed
		expect(buf.every((b) => b === 0)).toBe(true);
	});

	// Symbol.dispose support
	it("Symbol.dispose zeroes the buffer if available", () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const disposeSymbol = (Symbol as any).dispose as symbol | undefined;
		if (typeof disposeSymbol !== "symbol") {
			// Node < 20.4 — skip gracefully
			return;
		}
		const sb = new SecureBuffer(Uint8Array.of(0xca, 0xfe));
		const ref = sb.bytes();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(sb as any)[disposeSymbol]();

		expect(ref.every((b) => b === 0)).toBe(true);
		expect(sb.isDestroyed).toBe(true);
	});

	// Large buffer test
	it("handles large buffers correctly", () => {
		const size = 64 * 1024; // 64 KiB
		const data = new Uint8Array(size);
		for (let i = 0; i < size; i++) data[i] = (i % 255) + 1;

		const sb = new SecureBuffer(data);
		expect(data.every((b) => b === 0)).toBe(true); // source wiped
		expect(sb.length).toBe(size);

		sb.destroy();
		expect(sb.isDestroyed).toBe(true);
	});
});
