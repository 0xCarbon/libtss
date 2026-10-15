import { createHmac } from "node:crypto";
import { TssError } from "../error";
import { deriveChild, frostSplitKey } from "../index";
import { Ciphersuite, TssStatusCode } from "../types";
import { freeAll, runDkg } from "./helpers";

const CHAIN_CODE_BYTES = 32;
const CHILD_NUMBER = 7;
const CHILD_NUMBER_BYTES = 4;
const HMAC_SHA512_HALF_BYTES = 32;
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
const SESSION_ID = new TextEncoder().encode("chain-code-session");

function bip32ChildChainCode(
	parentKey: Uint8Array,
	parentChainCode: Uint8Array,
	childNumber: number,
): Uint8Array {
	const index = new Uint8Array(CHILD_NUMBER_BYTES);
	new DataView(index.buffer).setUint32(0, childNumber, false);
	const digest = createHmac("sha512", parentChainCode)
		.update(parentKey)
		.update(index)
		.digest();
	return new Uint8Array(digest.subarray(HMAC_SHA512_HALF_BYTES));
}

function thrownBy(fn: () => unknown): unknown {
	try {
		fn();
	} catch (error) {
		return error;
	}
	return undefined;
}

describe("KeyShareHandle.chainCode", () => {
	it("returns the same 32-byte chain code to every DKLs23 party", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		try {
			const [first, second] = keyShares.map((share) => share.chainCode());

			expect(first).toHaveLength(CHAIN_CODE_BYTES);
			expect(second).toEqual(first);
		} finally {
			freeAll(keyShares);
		}
	});

	it("re-derives the chain code of a child share per BIP-32", () => {
		const { keyShares } = runDkg(TWO_OF_TWO_ECDSA, SESSION_ID);
		const parent = keyShares[0];
		const child = deriveChild(parent, CHILD_NUMBER);
		try {
			const parentChainCode = parent.chainCode();
			const childChainCode = child.chainCode();

			expect(childChainCode).toHaveLength(CHAIN_CODE_BYTES);
			expect(childChainCode).not.toEqual(parentChainCode);
			expect(childChainCode).toEqual(
				bip32ChildChainCode(
					parent.groupVerifyingKey(),
					parentChainCode,
					CHILD_NUMBER,
				),
			);
		} finally {
			freeAll([child, ...keyShares]);
		}
	});

	it("rejects ciphersuites without BIP-32 derivation", () => {
		const secretKey = new Uint8Array(ED25519_SCALAR_BYTES).fill(
			CANONICAL_SCALAR_BYTE,
		);
		const { keyShares } = frostSplitKey(
			TWO_OF_THREE_ED25519.suite,
			secretKey,
			TWO_OF_THREE_ED25519.maxSigners,
			TWO_OF_THREE_ED25519.minSigners,
		);
		try {
			const error = thrownBy(() => keyShares[0].chainCode());

			expect(error).toBeInstanceOf(TssError);
			expect((error as TssError).code).toBe(TssStatusCode.PROTO_MISMATCH);
		} finally {
			freeAll(keyShares);
		}
	});
});
