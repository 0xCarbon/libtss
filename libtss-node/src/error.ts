import { readAbortInfo, readLastError } from "./ffi";
import { TssStatusCode } from "./types";

export class TssError extends Error {
	readonly code: TssStatusCode;
	readonly culprits?: number[];
	readonly bannedParty?: number;

	constructor(
		code: TssStatusCode,
		message: string,
		options: { culprits?: number[]; bannedParty?: number } = {},
	) {
		super(message);
		this.name = "TssError";
		this.code = code;
		this.culprits = options.culprits;
		this.bannedParty = options.bannedParty;
	}

	static fromStatus(status: number): TssError {
		const message = readLastError() || "libtss FFI call failed";
		const code = status as TssStatusCode;

		if (
			code === TssStatusCode.ABORT ||
			code === TssStatusCode.ABORT_BAN
		) {
			const info = readAbortInfo();
			return new TssError(code, message, info);
		}

		return new TssError(code, message);
	}

	isAbort(): boolean {
		return (
			this.code === TssStatusCode.ABORT ||
			this.code === TssStatusCode.ABORT_BAN
		);
	}

	isBanAbort(): boolean {
		return this.code === TssStatusCode.ABORT_BAN;
	}
}

export function checkStatus(status: number): void {
	if (status !== TssStatusCode.OK) {
		throw TssError.fromStatus(status);
	}
}
