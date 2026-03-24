import type { Message } from "./types";

function walkMessages(
	buffer: Uint8Array,
	visit?: (message: Message) => void,
): number {
	const view = new DataView(
		buffer.buffer,
		buffer.byteOffset,
		buffer.byteLength,
	);
	let offset = 0;
	let count = 0;

	while (offset < buffer.byteLength) {
		if (buffer.byteLength - offset < 8) {
			throw new Error("truncated message header");
		}

		const from = view.getUint16(offset, true);
		const rawTo = view.getUint16(offset + 2, true);
		const len = view.getUint32(offset + 4, true);
		const end = offset + 8 + len;

		if (end > buffer.byteLength) {
			throw new Error("truncated message payload");
		}

		visit?.({
			from,
			to: rawTo === 0 ? null : rawTo,
			data: buffer.slice(offset + 8, end),
		});

		offset = end;
		count += 1;
	}

	return count;
}

export function encodeMessages(messages: Message[]): Uint8Array {
	let len = 0;
	for (const message of messages) {
		len += 8 + message.data.length;
	}

	const out = new Uint8Array(len);
	const view = new DataView(out.buffer);
	let offset = 0;

	for (const message of messages) {
		view.setUint16(offset, message.from, true);
		view.setUint16(offset + 2, message.to ?? 0, true);
		view.setUint32(offset + 4, message.data.length, true);
		out.set(message.data, offset + 8);
		offset += 8 + message.data.length;
	}

	return out;
}

export function decodeMessages(buffer: Uint8Array): Message[] {
	const messages: Message[] = [];
	walkMessages(buffer, (message) => {
		messages.push(message);
	});
	return messages;
}

export function messageCount(buffer: Uint8Array): number {
	return walkMessages(buffer);
}
