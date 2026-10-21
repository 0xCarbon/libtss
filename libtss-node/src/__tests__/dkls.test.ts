import { createECDH } from "node:crypto";
import type { KeyShareHandle } from "../handle";
import { dklsSplitKey } from "../index";
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
