export interface NativeLibtssModule {
	dkgNew(
		suite: number,
		selfId: number,
		maxSigners: number,
		minSigners: number,
		sessionId: string | null,
	): Promise<{ handle: string; messages: string }>;
	dkgNext(
		handle: string,
		messages: string,
	): Promise<{
		complete: boolean;
		messages?: string;
		keyShareHandle?: string;
		pubkeyPackage?: string;
	}>;
	signNew(
		keyShareHandle: string,
		message: string,
		counterparties: number[] | null,
		signId: string | null,
	): Promise<{ handle: string; messages: string }>;
	signNext(
		handle: string,
		messages: string,
	): Promise<{
		complete: boolean;
		messages?: string;
		signature?: string;
		recoveryId?: number;
	}>;
	refreshNew(
		keyShareHandle: string,
		participants: number[] | null,
	): Promise<{ handle: string; messages: string }>;
	refreshNewDkls(
		keyShareHandle: string,
		sessionId: string,
	): Promise<{ handle: string; messages: string }>;
	refreshReceiver(keyShareHandle: string): Promise<string>;
	refreshNext(
		handle: string,
		messages: string,
	): Promise<{
		complete: boolean;
		messages?: string;
		keyShareHandle?: string;
		pubkeyPackage?: string;
	}>;
	repairHelperTerm(
		keyShareHandle: string,
		helpers: number[],
		target: number,
		repairId: string,
	): Promise<string>;
	repairAssemble(
		suite: number,
		pubkeyPackage: string,
		target: number,
		messages: string,
	): Promise<string>;
	bolt3Derive(keyShareHandle: string, perCommitmentPoint: string): Promise<string>;
	bolt3DeriveRevocation(
		keyShareHandle: string,
		perCommitmentPoint: string,
		perCommitmentSecret: string,
	): Promise<string>;
	bolt3DerivePubkeyPackage(
		pubkeyPackage: string,
		perCommitmentPoint: string,
	): Promise<string>;
	bolt3DeriveRevocationPubkeyPackage(
		pubkeyPackage: string,
		perCommitmentPoint: string,
	): Promise<string>;
	handleFree(handle: string): Promise<void>;
	sessionFree(handle: string): Promise<void>;
	handleIdentifier(handle: string): Promise<number>;
	handleVerifyingShare(handle: string): Promise<string>;
	handleGroupKey(handle: string): Promise<string>;
	handleChainCode(handle: string): Promise<string>;
	handlePubkeyPackage(handle: string): Promise<string>;
	handleCiphersuite(handle: string): Promise<number>;
	exportKeyShare(handle: string): Promise<string>;
	importKeyShare(suite: number, data: string): Promise<string>;
	version(): Promise<string>;
	verify(
		suite: number,
		message: string,
		signature: string,
		publicKey: string,
	): Promise<boolean>;
	initialize(options: { mlock: boolean }): Promise<void>;
	exportKeyShareSecure(handle: string): Promise<string>;
	importKeyShareSecure(suite: number, keychainId: string): Promise<string>;
}

type ReactNativeModule = {
	NativeModules?: {
		Libtss?: NativeLibtssModule;
	};
};

const reactNative =
	typeof require === "function"
		? ((() => {
				try {
					return require("react-native") as ReactNativeModule;
				} catch {
					return undefined;
				}
			})() ?? undefined)
		: undefined;

const moduleInstance = reactNative?.NativeModules?.Libtss;

if (!moduleInstance) {
	throw new Error("Native module Libtss is not available");
}

export default moduleInstance as NativeLibtssModule;
