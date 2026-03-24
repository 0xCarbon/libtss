import { Buffer } from "node:buffer";

export function wipeBytes(buf: Uint8Array): void {
	if (!buf || buf.length === 0) {
		return;
	}
	buf.fill(0);
}

export class SecureBuffer {
	private _buf: Buffer | null;

	constructor(data: Uint8Array) {
		this._buf = Buffer.allocUnsafeSlow(data.length);
		this._buf.set(data);
		wipeBytes(data);
	}

	bytes(): Uint8Array {
		if (this._buf === null) {
			throw new Error("SecureBuffer has been destroyed");
		}
		return this._buf;
	}

	get length(): number {
		return this._buf?.length ?? 0;
	}

	get isDestroyed(): boolean {
		return this._buf === null;
	}

	destroy(): void {
		if (this._buf === null) {
			return;
		}
		this._buf.fill(0);
		this._buf = null;
	}

	/**
	 * Take ownership of a pre-allocated Buffer without copying. The caller
	 * must not reference `buf` after calling this — SecureBuffer owns it.
	 */
	static wrap(buf: Buffer): SecureBuffer {
		const sb = Object.create(SecureBuffer.prototype) as SecureBuffer;
		sb._buf = buf;
		return sb;
	}
}

// Attach Symbol.dispose at runtime so the emitted .d.ts does not require
// ESNext.Disposable — avoids breaking consumers on TS < 5.2 / lib: ES2021.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const disposeSymbol = (Symbol as any).dispose as symbol | undefined;
if (typeof disposeSymbol === "symbol") {
	Object.defineProperty(SecureBuffer.prototype, disposeSymbol, {
		value: SecureBuffer.prototype.destroy,
		writable: true,
		configurable: true,
	});
}
