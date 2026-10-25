// Range checks for integers passed to the native library. koffi, typed
// arrays and DataView wrap or truncate out-of-range values silently.

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

/** Party identifier: integer in [1, 65535]. */
export function identifier(value: number, name: string): number {
	if (!Number.isInteger(value) || value < 1 || value > 0xffff) {
		throw new RangeError(`${name} must be an integer in [1, 65535]`);
	}
	return value;
}

/** Party identifiers, each an integer in [1, 65535]. */
export function identifierArray(
	values: readonly number[],
	name: string,
): Uint16Array {
	return Uint16Array.from(values, (value) => identifier(value, name));
}
