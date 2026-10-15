import { TssError } from "../error";
import { frostSplitKey, tweakAdd, tweakMul } from "../index";
import { Ciphersuite, TssStatusCode } from "../types";
import { freeAll, runDkg } from "./helpers";

const TWEAK_SCALAR_BYTES = 32;
const ED25519_SCALAR_BYTES = 32;
// A little-endian scalar whose top byte is below 0x10 is < 2^252 and therefore
// a canonical, non-zero Ed25519 secret. frostSplitKey rejects non-canonical
// scalars, which a random 32-byte string is roughly 15 times out of 16.
const CANONICAL_SCALAR_BYTE = 0x07;

const TWO_OF_TWO_ECDSA = {
	suite: Ciphersuite.Secp256k1ECDSA,
	maxSigners: 2,
	minSigners: 2,
};
const TWO_OF_THREE_ED25519 = {
	suite: Ciphersuite.Ed25519,
	maxSigners: 3,
	minSigners: 2,
};
const SESSION_ID = new TextEncoder().encode("tweak-session");

function scalar(value: number): Uint8Array {
	const bytes = new Uint8Array(TWEAK_SCALAR_BYTES);
	new DataView(bytes.buffer).setUint32(TWEAK_SCALAR_BYTES - 4, value, false);
	return bytes;
}

function thrownBy(fn: () => unknown): unknown {
	try {
		fn();
	} catch (error) {
		return error;
	}
	return undefined;
}

function ed25519Shares() {
	const secretKey = new Uint8Array(ED25519_SCALAR_BYTES).fill(
		CANONICAL_SCALAR_BYTE,
	);
	return frostSplitKey(
		TWO_OF_THREE_ED25519.suite,
		secretKey,
		TWO_OF_THREE_ED25519.maxSigners,
		TWO_OF_THREE_ED25519.minSigners,
	).keyShares;
}

describe("tweakAdd", () => {
	it("moves every party to the same tweaked group key and leaves the parent intact", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		const parentKey = keyShares[0].groupVerifyingKey();
		const tweaked = keyShares.map((share) => tweakAdd(share, scalar(7)));
		try {
			const [first, second] = tweaked.map((share) =>
				share.groupVerifyingKey(),
			);

			expect(second).toEqual(first);
			expect(first).not.toEqual(parentKey);
			expect(tweaked[0].verifyingShare()).not.toEqual(
				keyShares[0].verifyingShare(),
			);
			expect(tweaked.map((share) => share.identifier())).toEqual(
				keyShares.map((share) => share.identifier()),
			);
			expect(keyShares[0].groupVerifyingKey()).toEqual(parentKey);
			expect(keyShares[1].groupVerifyingKey()).toEqual(parentKey);
		} finally {
			freeAll([...tweaked, ...keyShares]);
		}
	});

	it("rejects a wrong-length tweak before reaching the native library", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		try {
			const error = thrownBy(() =>
				tweakAdd(keyShares[0], new Uint8Array(TWEAK_SCALAR_BYTES - 1)),
			);

			expect(error).toBeInstanceOf(Error);
			expect(error).not.toBeInstanceOf(TssError);
			expect((error as Error).message).toBe("tweak must be 32 bytes");
		} finally {
			freeAll(keyShares);
		}
	});

	it("rejects ciphersuites without scalar tweaks", () => {
		const keyShares = ed25519Shares();
		try {
			const error = thrownBy(() => tweakAdd(keyShares[0], scalar(7)));

			expect(error).toBeInstanceOf(TssError);
			expect((error as TssError).code).toBe(TssStatusCode.PROTO_MISMATCH);
		} finally {
			freeAll(keyShares);
		}
	});
});

describe("tweakMul", () => {
	it("leaves the group key unchanged when multiplying by one", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		const scaled = tweakMul(keyShares[0], scalar(1));
		try {
			expect(scaled.groupVerifyingKey()).toEqual(
				keyShares[0].groupVerifyingKey(),
			);
			expect(scaled.verifyingShare()).toEqual(keyShares[0].verifyingShare());
		} finally {
			freeAll([scaled, ...keyShares]);
		}
	});

	it("rejects a zero factor with the TWEAK status", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		try {
			const error = thrownBy(() => tweakMul(keyShares[0], scalar(0)));

			expect(error).toBeInstanceOf(TssError);
			expect((error as TssError).code).toBe(TssStatusCode.TWEAK);
		} finally {
			freeAll(keyShares);
		}
	});

	it("rejects a wrong-length factor before reaching the native library", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		try {
			const error = thrownBy(() =>
				tweakMul(keyShares[0], new Uint8Array(TWEAK_SCALAR_BYTES + 1)),
			);

			expect(error).toBeInstanceOf(Error);
			expect(error).not.toBeInstanceOf(TssError);
			expect((error as Error).message).toBe("tweak must be 32 bytes");
		} finally {
			freeAll(keyShares);
		}
	});

	it("rejects ciphersuites without scalar tweaks", () => {
		const keyShares = ed25519Shares();
		try {
			const error = thrownBy(() => tweakMul(keyShares[0], scalar(7)));

			expect(error).toBeInstanceOf(TssError);
			expect((error as TssError).code).toBe(TssStatusCode.PROTO_MISMATCH);
		} finally {
			freeAll(keyShares);
		}
	});
});
