import { createECDH } from "node:crypto";
import type { KeyShareHandle } from "../handle";
import {
	bolt3Derive,
	bolt3DerivePublicKeys,
	bolt3DeriveRevocation,
	bolt3DeriveRevocationPublicKeys,
	dklsSplitKey,
} from "../index";
import { RefreshSession } from "../session";
import { Ciphersuite, type Message } from "../types";
import { freeAll } from "./helpers";

const SUITES: [Ciphersuite, string][] = [
	[Ciphersuite.Secp256k1ECDSA, "secp256k1"],
	[Ciphersuite.Secp256r1ECDSA, "prime256v1"],
];

function refreshAll(
	shares: KeyShareHandle[],
	sessionId: Uint8Array,
): KeyShareHandle[] {
	const sessions = new Map<number, RefreshSession>();
	let outgoing = new Map<number, Message[]>();
	shares.forEach((share, i) => {
		const [session, messages] = RefreshSession.createDkls(share, sessionId);
		sessions.set(i + 1, session);
		outgoing.set(i + 1, messages);
	});
	const refreshed = new Map<number, KeyShareHandle>();
	for (let round = 0; round < 3; round++) {
		const next = new Map<number, Message[]>();
		for (const [id, session] of sessions) {
			const inbound: Message[] = [];
			for (const [sender, messages] of outgoing) {
				if (sender === id) continue;
				for (const m of messages) {
					if (m.to === null || m.to === id) inbound.push(m);
				}
			}
			const output = session.next(inbound);
			if (output.complete) {
				refreshed.set(id, output.keyShare);
			} else {
				next.set(id, output.messages);
			}
		}
		outgoing = next;
	}
	for (const session of sessions.values()) session.free();
	return [...refreshed.entries()].sort(([a], [b]) => a - b).map(([, s]) => s);
}

describe("DKLs23 key import and refresh", () => {
	it.each(SUITES)(
		"imports, keeps the key and refreshes (suite %i)",
		(suite, curve) => {
			const secret = new Uint8Array(32).fill(0x42);
			const expected = createECDH(curve);
			expected.setPrivateKey(Buffer.from(secret));
			const chainCode = new Uint8Array(32).fill(0x17);

			const { keyShares } = dklsSplitKey(suite, secret, 3, 2, chainCode);
			expect(secret.every((b) => b === 0)).toBe(true);
			try {
				for (const share of keyShares) {
					expect(Buffer.from(share.groupVerifyingKey())).toEqual(
						expected.getPublicKey(null, "compressed"),
					);
					expect(Buffer.from(share.chainCode())).toEqual(
						Buffer.from(chainCode),
					);
				}
				const refreshed = refreshAll(
					keyShares,
					new TextEncoder().encode("node-refresh"),
				);
				try {
					expect(refreshed).toHaveLength(3);
					refreshed.forEach((share, i) => {
						expect(share.groupVerifyingKey()).toEqual(
							keyShares[i].groupVerifyingKey(),
						);
						expect(share.verifyingShare()).not.toEqual(
							keyShares[i].verifyingShare(),
						);
					});
				} finally {
					freeAll(refreshed);
				}
			} finally {
				freeAll(keyShares);
			}
		},
	);

	it("rejects a zero secret key and an empty refresh session id", () => {
		expect(() =>
			dklsSplitKey(Ciphersuite.Secp256k1ECDSA, new Uint8Array(32), 3, 2),
		).toThrow();
		const { keyShares } = dklsSplitKey(
			Ciphersuite.Secp256k1ECDSA,
			new Uint8Array(32).fill(1),
			2,
			2,
		);
		try {
			expect(() =>
				RefreshSession.createDkls(keyShares[0], new Uint8Array(0)),
			).toThrow();
		} finally {
			freeAll(keyShares);
		}
	});
});

// BOLT 3, Appendix E: Key Derivation Test Vectors.
const hex = (value: string) => new Uint8Array(Buffer.from(value, "hex"));
const BOLT3_BASE_SECRET =
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BOLT3_SECRET =
	"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const BOLT3_POINT =
	"025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486";
const BOLT3_LOCAL =
	"0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5";
const BOLT3_REVOCATION =
	"02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0";

// suite (1) + min_signers (2) + verifying key length (4) + verifying key
const packageKey = (raw: Uint8Array) =>
	Buffer.from(raw.subarray(7, 7 + Buffer.from(raw).readUInt32LE(3))).toString(
		"hex",
	);

describe("BOLT 3 derivation", () => {
	it("matches the BOLT 3 vectors", () => {
		const { keyShares, publicKeys } = dklsSplitKey(
			Ciphersuite.Secp256k1ECDSA,
			hex(BOLT3_BASE_SECRET),
			3,
			2,
		);
		const local = bolt3Derive(keyShares[0], hex(BOLT3_POINT));
		const revocation = bolt3DeriveRevocation(
			keyShares[0],
			hex(BOLT3_POINT),
			hex(BOLT3_SECRET),
		);
		try {
			expect(Buffer.from(local.groupVerifyingKey()).toString("hex")).toBe(
				BOLT3_LOCAL,
			);
			expect(Buffer.from(revocation.groupVerifyingKey()).toString("hex")).toBe(
				BOLT3_REVOCATION,
			);
			expect(
				packageKey(bolt3DerivePublicKeys(publicKeys, hex(BOLT3_POINT))),
			).toBe(BOLT3_LOCAL);
			expect(
				packageKey(
					bolt3DeriveRevocationPublicKeys(publicKeys, hex(BOLT3_POINT)),
				),
			).toBe(BOLT3_REVOCATION);
			expect(() =>
				bolt3DeriveRevocation(
					keyShares[0],
					hex(BOLT3_POINT),
					new Uint8Array(32).fill(1),
				),
			).toThrow();
		} finally {
			freeAll([...keyShares, local, revocation]);
		}
	});
});
