import type { KeyShareHandle } from "./handle";

export enum Protocol {
	Frost = 0,
	DKLs23 = 1,
}

export enum Ciphersuite {
	Secp256k1Taproot = 0,
	Secp256k1 = 1,
	Ed25519 = 2,
	P256 = 3,
	Ristretto255 = 4,
	Ed448 = 5,
	Secp256k1ECDSA = 6,
}

export interface ThresholdConfig {
	minSigners: number;
	maxSigners: number;
	suite: Ciphersuite;
}

export interface Message {
	from: number;
	to: number | null;
	data: Uint8Array;
}

export interface Signature {
	data: Uint8Array;
	recoveryId: number | null;
	protocol: Protocol;
}

export enum TssStatusCode {
	OK = 0,
	INVALID_CONFIG = 1,
	INVALID_ID = 2,
	INVALID_SHARE = 3,
	INVALID_COMMIT = 4,
	INVALID_SIG = 5,
	NONCE_REUSE = 6,
	HANDLE_INVALID = 7,
	PROTO_MISMATCH = 8,
	DESERIALIZE = 9,
	ABORT = 10,
	ABORT_BAN = 11,
	TWEAK = 13,
	SESSION_COMPLETE = 14,
	INTERNAL_PANIC = 255,
}

export type DkgOutput =
	| { complete: false; messages: Message[] }
	| { complete: true; keyShare: KeyShareHandle; publicKeys: Uint8Array };

export type SignOutput =
	| { complete: false; messages: Message[] }
	| { complete: true; signature: Signature };

export type RefreshOutput =
	| { complete: false; messages: Message[] }
	| { complete: true; keyShare: KeyShareHandle; publicKeys: Uint8Array };

export function protocolForCiphersuite(suite: Ciphersuite): Protocol {
	return suite === Ciphersuite.Secp256k1ECDSA
		? Protocol.DKLs23
		: Protocol.Frost;
}
