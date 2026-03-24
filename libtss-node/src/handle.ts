import { TssError, checkStatus } from "./error";
import { allocBuffer, lib, readBuffer, readBufferSecure } from "./ffi";
import { SecureBuffer } from "./secure";
import {
	type Ciphersuite,
	type Protocol,
	TssStatusCode,
	protocolForCiphersuite,
} from "./types";

const handleRegistry = new FinalizationRegistry<bigint>((handle) => {
	lib.tss_handle_free(handle);
});

export class KeyShareHandle {
	private readonly _handle: bigint;
	private _freed = false;

	constructor(handle: bigint) {
		this._handle = handle;
		handleRegistry.register(this, handle, this);
	}

	get handle(): bigint {
		return this._handle;
	}

	free(): void {
		if (this._freed) {
			return;
		}
		this._freed = true;
		handleRegistry.unregister(this);
		lib.tss_handle_free(this._handle);
	}

	identifier(): number {
		const out: [number] = [0];
		checkStatus(lib.tss_handle_identifier(this._handle, out));
		return out[0];
	}

	verifyingShare(): Uint8Array {
		const buf = allocBuffer();
		checkStatus(lib.tss_handle_verifying_share(this._handle, buf));
		return readBuffer(buf);
	}

	groupVerifyingKey(): Uint8Array {
		const buf = allocBuffer();
		checkStatus(lib.tss_handle_group_key(this._handle, buf));
		return readBuffer(buf);
	}

	publicKeyPackage(): Uint8Array {
		const buf = allocBuffer();
		checkStatus(lib.tss_handle_pubkey_package(this._handle, buf));
		return readBuffer(buf);
	}

	ciphersuite(): Ciphersuite {
		const raw: number = lib.tss_handle_ciphersuite(this._handle);
		if (raw === 0xff) {
			throw new TssError(
				TssStatusCode.HANDLE_INVALID,
				"invalid or freed key share handle",
			);
		}
		return raw as Ciphersuite;
	}

	protocol(): Protocol {
		return protocolForCiphersuite(this.ciphersuite());
	}

	export(): Uint8Array {
		const buf = allocBuffer();
		checkStatus(lib.tss_handle_export(this._handle, buf));
		return readBuffer(buf);
	}

	exportSecure(): SecureBuffer {
		const buf = allocBuffer();
		checkStatus(lib.tss_handle_export(this._handle, buf));
		return SecureBuffer.wrap(readBufferSecure(buf));
	}
}
