// Smoke test for the libtss-rn iOS bridge, run by .github/workflows/rn-ios.yml
// in a throwaway React Native app. It runs a 2-of-2 DKG and signature for one
// FROST and one DKLs23 suite through the native module and logs
// LIBTSS_SMOKE_OK or LIBTSS_SMOKE_FAIL (console.error reaches the device log
// in release builds).
import React, { useEffect, useState } from "react";
import { SafeAreaView, Text } from "react-native";
import {
	Ciphersuite,
	DkgSession,
	type KeyShareHandle,
	type Message,
	SignSession,
	verify,
	version,
} from "@alore/libtss-rn";

const MAX_ROUNDS = 10;
// DKLs23 requires every party to use the same session id (DKG) and sign id.
const ascii = (text: string) =>
	Uint8Array.from(text, (char) => char.charCodeAt(0));
const DKG_SESSION_ID = ascii("libtss-smoke-dkg");
const SIGN_ID = ascii("libtss-smoke-sign");

function inbound(self: number, outgoing: Map<number, Message[]>): Message[] {
	const messages: Message[] = [];
	for (const [sender, sent] of outgoing) {
		if (sender === self) continue;
		for (const message of sent) {
			if (message.to === null || message.to === self) messages.push(message);
		}
	}
	return messages;
}

async function dkg(suite: Ciphersuite): Promise<KeyShareHandle[]> {
	const config = { suite, maxSigners: 2, minSigners: 2 };
	const sessions = new Map<number, DkgSession>();
	let outgoing = new Map<number, Message[]>();
	for (const id of [1, 2]) {
		const [session, messages] = await DkgSession.create(
			config,
			id,
			DKG_SESSION_ID,
		);
		sessions.set(id, session);
		outgoing.set(id, messages);
	}
	const shares = new Map<number, KeyShareHandle>();
	for (let round = 0; round < MAX_ROUNDS && sessions.size > 0; round++) {
		const next = new Map<number, Message[]>();
		for (const [id, session] of [...sessions]) {
			const output = await session.next(inbound(id, outgoing));
			if (output.complete) {
				shares.set(id, output.keyShare);
				session.free();
				sessions.delete(id);
			} else {
				next.set(id, output.messages);
			}
		}
		outgoing = next;
	}
	if (shares.size !== 2) throw new Error(`DKG incomplete for suite ${suite}`);
	return [shares.get(1) as KeyShareHandle, shares.get(2) as KeyShareHandle];
}

async function sign(
	shares: KeyShareHandle[],
	message: Uint8Array,
): Promise<Uint8Array> {
	const sessions = new Map<number, SignSession>();
	let outgoing = new Map<number, Message[]>();
	for (const [index, share] of shares.entries()) {
		const id = index + 1;
		const [session, messages] = await SignSession.create(
			share,
			message,
			[3 - id],
			SIGN_ID,
		);
		sessions.set(id, session);
		outgoing.set(id, messages);
	}
	let signature: Uint8Array | undefined;
	for (let round = 0; round < MAX_ROUNDS && sessions.size > 0; round++) {
		const next = new Map<number, Message[]>();
		for (const [id, session] of [...sessions]) {
			const output = await session.next(inbound(id, outgoing));
			if (output.complete) {
				signature = output.signature.data;
				session.free();
				sessions.delete(id);
			} else {
				next.set(id, output.messages);
			}
		}
		outgoing = next;
	}
	if (signature === undefined || sessions.size > 0) {
		throw new Error("signing did not complete");
	}
	return signature;
}

async function smoke(): Promise<string> {
	const libtssVersion = await version();
	const digest = new Uint8Array(32).fill(7);
	for (const suite of [Ciphersuite.Ed25519, Ciphersuite.Secp256k1ECDSA]) {
		const shares = await dkg(suite);
		try {
			const signature = await sign(shares, digest);
			const key = await shares[0].groupVerifyingKey();
			if (!(await verify(suite, digest, signature, key))) {
				throw new Error(`signature does not verify for suite ${suite}`);
			}
		} finally {
			for (const share of shares) share.free();
		}
	}
	return libtssVersion;
}

export default function App(): React.JSX.Element {
	const [status, setStatus] = useState("running");
	useEffect(() => {
		smoke().then(
			(libtssVersion) => {
				console.error(`LIBTSS_SMOKE_OK ${libtssVersion}`);
				setStatus(`ok ${libtssVersion}`);
			},
			(error: unknown) => {
				console.error(`LIBTSS_SMOKE_FAIL ${String(error)}`);
				setStatus(`failed: ${String(error)}`);
			},
		);
	}, []);
	return (
		<SafeAreaView>
			<Text>libtss smoke: {status}</Text>
		</SafeAreaView>
	);
}
