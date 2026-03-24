/**
 * Supplementary type declarations for consumers with ESNext.Disposable.
 * Import this module to get typed `using` support for SecureBuffer:
 *
 *   import "@alore/libtss-node/disposable";
 *   using sb = new SecureBuffer(data);
 *
 * Without this import, SecureBuffer still supports Symbol.dispose at runtime
 * on Node 20.4+, but TypeScript won't type-check it.
 */
import { SecureBuffer } from "./lib/secure";

declare module "./lib/secure" {
	interface SecureBuffer {
		[Symbol.dispose](): void;
	}
}
