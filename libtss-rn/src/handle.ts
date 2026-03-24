import { toByteArray } from "base64-js";
import { TssError } from "./error";
import NativeLibtss from "./NativeLibtss";
import {
	type Ciphersuite,
	type Protocol,
	protocolForCiphersuite,
} from "./types";

const handleRegistry =
	typeof FinalizationRegistry === "undefined"
		? null
		: new FinalizationRegistry<string>((handle) => {
				void NativeLibtss.handleFree(handle).catch(() => {});
			});

function decodeBase64(value: string): Uint8Array {
	return Uint8Array.from(toByteArray(value));
}

async function callNative<T>(fn: () => Promise<T>): Promise<T> {
	try {
		return await fn();
	} catch (error) {
		throw TssError.fromNative(error);
	}
}

export class KeyShareHandle {
	private readonly _handle: string;
	private _freed = false;

	constructor(handle: string) {
		this._handle = handle;
		handleRegistry?.register(this, handle, this);
	}

	get handle(): string {
		return this._handle;
	}

	free(): void {
		if (this._freed) {
			return;
		}

		this._freed = true;
		handleRegistry?.unregister(this);
		void NativeLibtss.handleFree(this._handle).catch(() => {});
	}

	async identifier(): Promise<number> {
		return callNative(() => NativeLibtss.handleIdentifier(this._handle));
	}

	async verifyingShare(): Promise<Uint8Array> {
		return decodeBase64(
			await callNative(() => NativeLibtss.handleVerifyingShare(this._handle)),
		);
	}

	async groupVerifyingKey(): Promise<Uint8Array> {
		return decodeBase64(
			await callNative(() => NativeLibtss.handleGroupKey(this._handle)),
		);
	}

	async publicKeyPackage(): Promise<Uint8Array> {
		return decodeBase64(
			await callNative(() => NativeLibtss.handlePubkeyPackage(this._handle)),
		);
	}

	async ciphersuite(): Promise<Ciphersuite> {
		return (await callNative(() =>
			NativeLibtss.handleCiphersuite(this._handle),
		)) as Ciphersuite;
	}

	async protocol(): Promise<Protocol> {
		return protocolForCiphersuite(await this.ciphersuite());
	}

	async export(): Promise<Uint8Array> {
		return decodeBase64(
			await callNative(() => NativeLibtss.exportKeyShare(this._handle)),
		);
	}
}
