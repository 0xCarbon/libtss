import type { KeyShareHandle } from "../handle";
import { TssError } from "../error";
import { RefreshSession } from "../session";
import { Ciphersuite, TssStatusCode } from "../types";
import { freeAll, runDkg, runSign } from "./helpers";

describe("FROST refresh receiver", () => {
	test("refreshes from the named dealer and signs", () => {
		const { keyShares } = runDkg({
			suite: Ciphersuite.Ed25519,
			maxSigners: 3,
			minSigners: 2,
		});
		const refreshed: KeyShareHandle[] = [];
		try {
			const [dealer, messages] = RefreshSession.create(keyShares[0], [1, 2, 3]);
			dealer.free();
			for (const share of keyShares) {
				const id = share.identifier();
				const receiver = RefreshSession.createReceiver(share, 1);
				const output = receiver.next(messages.filter((m) => m.to === id));
				receiver.free();
				if (!output.complete) {
					throw new Error("expected refresh to complete");
				}
				refreshed.push(output.keyShare);
			}
			const signatures = runSign(
				[refreshed[0], refreshed[2]],
				new TextEncoder().encode("refreshed"),
				new TextEncoder().encode("node-refresh-sign"),
			);
			expect(signatures).toHaveLength(2);
		} finally {
			freeAll(keyShares);
			freeAll(refreshed);
		}
	});

	test("rejects a message that is not from the dealer", () => {
		const { keyShares } = runDkg({
			suite: Ciphersuite.Ed25519,
			maxSigners: 3,
			minSigners: 2,
		});
		try {
			const [dealer, messages] = RefreshSession.create(keyShares[0], [1, 2, 3]);
			dealer.free();
			expect(() => RefreshSession.createReceiver(keyShares[1], 9)).toThrow(
				expect.objectContaining({ code: TssStatusCode.INVALID_ID }),
			);
			expect(() => RefreshSession.createReceiver(keyShares[1], 65536)).toThrow(
				RangeError,
			);
			const receiver = RefreshSession.createReceiver(keyShares[1], 3);
			try {
				receiver.next(messages.filter((m) => m.to === 2));
				throw new Error("expected abort");
			} catch (error) {
				expect(error).toBeInstanceOf(TssError);
				expect((error as TssError).code).toBe(TssStatusCode.ABORT);
				expect((error as TssError).culprits).toEqual([1]);
			} finally {
				receiver.free();
			}
		} finally {
			freeAll(keyShares);
		}
	});
});
