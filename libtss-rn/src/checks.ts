// Range checks for integers passed to the native bridge. The Android and iOS
// bridges and DataView would otherwise truncate fractional or oversized values.

function checkInteger(value: number, name: string, max: number): number {
	if (!Number.isInteger(value) || value < 0 || value > max) {
		throw new RangeError(`${name} must be an integer in [0, ${max}]`);
	}
	return value;
}

export function u8(value: number, name: string): number {
	return checkInteger(value, name, 0xff);
}

export function u16(value: number, name: string): number {
	return checkInteger(value, name, 0xffff);
}

/** Signer count (maxSigners / minSigners): integer in [1, 65535], as the native bridges require. */
export function signerCount(value: number, name: string): number {
	if (!Number.isInteger(value) || value < 1 || value > 0xffff) {
		throw new RangeError(`${name} must be an integer in [1, 65535]`);
	}
	return value;
}

/** Party identifier: integer in [1, 65535]. */
export function identifier(value: number, name: string): number {
	if (!Number.isInteger(value) || value < 1 || value > 0xffff) {
		throw new RangeError(`${name} must be an integer in [1, 65535]`);
	}
	return value;
}

export function identifiers(
	values: readonly number[],
	name: string,
): number[] {
	return values.map((value) => identifier(value, name));
}
