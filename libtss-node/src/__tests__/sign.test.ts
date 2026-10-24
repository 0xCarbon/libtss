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

// Public key recovery over the two DKLs23 curves, used to check that the
// reported recovery id matches the signature.
type Curve = { p: bigint; a: bigint; b: bigint; g: [bigint, bigint]; n: bigint };
type Point = [bigint, bigint] | null;

const CURVES: Record<number, Curve> = {
	[Ciphersuite.Secp256k1ECDSA]: {
		p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
		a: 0n,
		b: 7n,
		g: [
			0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
			0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
		],
		n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
	},
	[Ciphersuite.Secp256r1ECDSA]: {
		p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
		a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
		b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
		g: [
			0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
			0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
		],
		n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
	},
};

const mod = (x: bigint, m: bigint) => ((x % m) + m) % m;

function powMod(base: bigint, exp: bigint, m: bigint): bigint {
	let result = 1n;
	let b = mod(base, m);
	let e = exp;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % m;
		b = (b * b) % m;
		e >>= 1n;
	}
	return result;
}

const inv = (x: bigint, m: bigint) => powMod(x, m - 2n, m);

function add(c: Curve, p1: Point, p2: Point): Point {
	if (!p1) return p2;
	if (!p2) return p1;
	if (p1[0] === p2[0] && mod(p1[1] + p2[1], c.p) === 0n) return null;
	const lam =
		p1[0] === p2[0]
			? mod((3n * p1[0] * p1[0] + c.a) * inv(2n * p1[1], c.p), c.p)
			: mod((p2[1] - p1[1]) * inv(p2[0] - p1[0], c.p), c.p);
	const x = mod(lam * lam - p1[0] - p2[0], c.p);
	return [x, mod(lam * (p1[0] - x) - p1[1], c.p)];
}

function mul(c: Curve, k: bigint, point: Point): Point {
	let result: Point = null;
	let p = point;
	let e = k;
	while (e > 0n) {
		if (e & 1n) result = add(c, result, p);
		p = add(c, p, p);
		e >>= 1n;
	}
	return result;
}

const toBigInt = (bytes: Uint8Array) =>
	BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);

function recover(
	suite: Ciphersuite,
	digest: Uint8Array,
	signature: Uint8Array,
	recoveryId: number,
): Uint8Array {
	const c = CURVES[suite];
	const r = toBigInt(signature.subarray(0, 32));
	const s = toBigInt(signature.subarray(32));
	// Both field primes are 3 mod 4, so the square root is a single power.
	let y = powMod(r * r * r + c.a * r + c.b, (c.p + 1n) / 4n, c.p);
	if (Number(y & 1n) !== recoveryId) y = c.p - y;
	const e = mod(toBigInt(digest), c.n);
	const rInv = inv(r, c.n);
	const q = add(
		c,
		mul(c, mod(s * rInv, c.n), [r, y]),
		mul(c, mod(-e * rInv, c.n), c.g),
	);
	if (!q) throw new Error("recovered the point at infinity");
	const out = new Uint8Array(33);
	out[0] = 2 + Number(q[1] & 1n);
	out.set(Buffer.from(q[0].toString(16).padStart(64, "0"), "hex"), 1);
	return out;
}

// Signing attempts while waiting to observe both recovery ids; each attempt
// shows a given parity with probability 1/2.
const MAX_SIGNATURES = 32;

describe("DKLs23 recovery id", () => {
	test.each([
		["Secp256k1ECDSA", Ciphersuite.Secp256k1ECDSA],
		["Secp256r1ECDSA", Ciphersuite.Secp256r1ECDSA],
	])(
		"%s reports both recovery ids and each recovers the group key",
		(_name, suite) => {
			const { keyShares } = runDkg(
				{ suite, maxSigners: 2, minSigners: 2 },
				new TextEncoder().encode(`node-recovery-dkg-${suite}`),
			);
			try {
				const groupKey = keyShares[0].groupVerifyingKey();
				const seen = new Set<number>();
				for (let attempt = 0; attempt < MAX_SIGNATURES; attempt++) {
					const digest = new Uint8Array(
						createHash("sha256").update(`recovery-${attempt}`).digest(),
					);
					const [signature] = runSign(
						keyShares,
						digest,
						new TextEncoder().encode(`node-recovery-${suite}-${attempt}`),
					);
					const recoveryId = signature.recoveryId;
					if (recoveryId !== 0 && recoveryId !== 1) {
						throw new Error(`unexpected recovery id ${recoveryId}`);
					}
					expect(recover(suite, digest, signature.data, recoveryId)).toEqual(
						groupKey,
					);
					seen.add(recoveryId);
					if (seen.size === 2) break;
				}
				expect([...seen].sort()).toEqual([0, 1]);
			} finally {
				freeAll(keyShares);
			}
		},
		300_000,
	);
});
