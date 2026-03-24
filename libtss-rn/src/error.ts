import { TssStatusCode } from "./types";

type NativeErrorShape = {
	code?: number | string;
	message?: string;
	culprits?: number[];
	bannedParty?: number;
	userInfo?: {
		code?: number | string;
		message?: string;
		culprits?: number[];
		bannedParty?: number;
	};
};

function asStatusCode(
	value: number | string | undefined,
): TssStatusCode | undefined {
	if (typeof value === "number") {
		return value as TssStatusCode;
	}

	if (typeof value === "string") {
		const parsed = Number.parseInt(value, 10);
		if (!Number.isNaN(parsed)) {
			return parsed as TssStatusCode;
		}
	}

	return undefined;
}

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

	static fromNative(native: unknown): TssError {
		if (native instanceof TssError) {
			return native;
		}

		const value = (native ?? {}) as NativeErrorShape;
		const metadata = value.userInfo ?? value;

		return new TssError(
			asStatusCode(metadata.code) ??
				asStatusCode(value.code) ??
				TssStatusCode.INTERNAL_PANIC,
			value.message ?? metadata.message ?? "libtss native call failed",
			{
				culprits: Array.isArray(metadata.culprits)
					? metadata.culprits
					: Array.isArray(value.culprits)
						? value.culprits
						: undefined,
				bannedParty:
					typeof metadata.bannedParty === "number"
						? metadata.bannedParty
						: typeof value.bannedParty === "number"
							? value.bannedParty
							: undefined,
			},
		);
	}

	isAbort(): boolean {
		return (
			this.code === TssStatusCode.ABORT || this.code === TssStatusCode.ABORT_BAN
		);
	}

	isBanAbort(): boolean {
		return this.code === TssStatusCode.ABORT_BAN;
	}
}
