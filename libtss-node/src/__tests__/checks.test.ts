import { KeyShareHandle } from "../handle";
import { dklsRepairAssemble, dklsRepairHelperTerm } from "../index";
import { encodeMessages } from "../message";
import { DkgSession, RefreshSession, SignSession } from "../session";
import { Ciphersuite } from "../types";

const BAD = [65539, -1, 1.5];
// Party identifiers also reject 0.
const BAD_ID = [...BAD, 0];
const encoder = new TextEncoder();

describe("integer range checks", () => {
	// Range checks run before any native call, so an unused handle suffices.
	const share = new KeyShareHandle(0n);
	afterAll(() => share.free());

	it.each(BAD_ID)("dklsRepairHelperTerm rejects helper %p", (bad) => {
		expect(() =>
			dklsRepairHelperTerm(share, [1, bad], 3, encoder.encode("r")),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("dklsRepairHelperTerm rejects target %p", (bad) => {
		expect(() =>
			dklsRepairHelperTerm(share, [1, 2], bad, encoder.encode("r")),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("dklsRepairAssemble rejects target %p", (bad) => {
		expect(() =>
			dklsRepairAssemble(Ciphersuite.Secp256k1ECDSA, new Uint8Array(1), bad, []),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("dklsRepairAssemble rejects message sender %p", (bad) => {
		expect(() =>
			dklsRepairAssemble(Ciphersuite.Secp256k1ECDSA, new Uint8Array(1), 3, [
				{ from: bad, to: 3, data: new Uint8Array(1) },
			]),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("encodeMessages rejects from %p", (bad) => {
		expect(() =>
			encodeMessages([{ from: bad, to: 1, data: new Uint8Array(1) }]),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("encodeMessages rejects to %p", (bad) => {
		expect(() =>
			encodeMessages([{ from: 1, to: bad, data: new Uint8Array(1) }]),
		).toThrow(RangeError);
	});

	it.each(BAD)("DkgSession.create rejects maxSigners %p", (bad) => {
		expect(() =>
			DkgSession.create(
				{ suite: Ciphersuite.Ed25519, maxSigners: bad, minSigners: 2 },
				1,
			),
		).toThrow(RangeError);
	});

	it.each(BAD)("DkgSession.create rejects minSigners %p", (bad) => {
		expect(() =>
			DkgSession.create(
				{ suite: Ciphersuite.Ed25519, maxSigners: 3, minSigners: bad },
				1,
			),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("DkgSession.create rejects selfId %p", (bad) => {
		expect(() =>
			DkgSession.create(
				{ suite: Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2 },
				bad,
			),
		).toThrow(RangeError);
	});

	it.each([256, -1, 1.5])("DkgSession.create rejects suite %p", (bad) => {
		expect(() =>
			DkgSession.create({ suite: bad, maxSigners: 3, minSigners: 2 }, 1),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("SignSession.create rejects counterparty %p", (bad) => {
		expect(() =>
			SignSession.create(share, new Uint8Array(32), [2, bad]),
		).toThrow(RangeError);
	});

	it.each(BAD_ID)("RefreshSession.create rejects participant %p", (bad) => {
		expect(() => RefreshSession.create(share, [1, bad])).toThrow(RangeError);
	});

	it("encodeMessages accepts a null or undefined recipient as broadcast", () => {
		const data = new Uint8Array(1);
		expect(encodeMessages([{ from: 1, to: null, data }])).toEqual(
			encodeMessages([{ from: 1, data } as never]),
		);
	});
});
