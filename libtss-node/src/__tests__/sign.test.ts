import { createHash } from "node:crypto";
import { verify } from "../index";
import { Ciphersuite, Protocol, signatureLength } from "../types";
import { freeAll, runDkg, runSign } from "./helpers";

const SUITES: [string, Ciphersuite, number][] = [
	["Secp256k1Taproot", Ciphersuite.Secp256k1Taproot, 64],
	["Secp256k1", Ciphersuite.Secp256k1, 65],
	["Ed25519", Ciphersuite.Ed25519, 64],
	["P256", Ciphersuite.P256, 65],
	["Ristretto255", Ciphersuite.Ristretto255, 64],
	["Ed448", Ciphersuite.Ed448, 114],
	["Secp256k1ECDSA", Ciphersuite.Secp256k1ECDSA, 64],
	["Secp256r1ECDSA", Ciphersuite.Secp256r1ECDSA, 64],
];

describe("native signing", () => {
	test.each(SUITES)(
		"%s signs, reports its length and verifies",
		(_name, suite, length) => {
			expect(signatureLength(suite)).toBe(length);
			const { keyShares } = runDkg(
				{ suite, maxSigners: 3, minSigners: 2 },
				new TextEncoder().encode(`node-sign-dkg-${suite}`),
			);
			try {
				const isDkls =
					suite === Ciphersuite.Secp256k1ECDSA ||
					suite === Ciphersuite.Secp256r1ECDSA;
				const message = new TextEncoder().encode("libtss node signing");
				// DKLs23 signs a 32-byte digest and verifies the original message.
				const signed = isDkls
					? new Uint8Array(createHash("sha256").update(message).digest())
					: message;
				const signatures = runSign(
					[keyShares[0], keyShares[2]],
					signed,
					new TextEncoder().encode(`node-sign-${suite}`),
				);
				const groupKey = keyShares[0].groupVerifyingKey();
				for (const signature of signatures) {
					expect(signature.data).toHaveLength(length);
					expect(signature.data).toEqual(signatures[0].data);
					if (isDkls) {
						expect(signature.protocol).toBe(Protocol.DKLs23);
						expect([0, 1]).toContain(signature.recoveryId);
					} else {
						expect(signature.protocol).toBe(Protocol.Frost);
						expect(signature.recoveryId).toBeNull();
					}
					expect(verify(suite, message, signature.data, groupKey)).toBe(true);
				}
			} finally {
				freeAll(keyShares);
			}
		},
		120_000,
	);
});
