package tss

/*
#include "tss_ffi.h"
*/
import "C"

import "unsafe"

type Message struct {
	From Identifier
	To   Identifier
	Data []byte
}

func ParseMessages(blob []byte) ([]Message, error) {
	slice := bytesToSlice(blob)
	count := int(C.tss_message_count(slice))
	out := make([]Message, 0, count)
	for i := 0; i < count; i++ {
		var from C.uint16_t
		var to C.uint16_t
		var data C.struct_TssSlice
		if err := callStatus(func() C.TssStatus {
			return C.tss_message_at(slice, C.uintptr_t(i), &from, &to, &data)
		}); err != nil {
			return nil, err
		}
		out = append(out, Message{
			From: Identifier(from),
			To:   Identifier(to),
			Data: append([]byte(nil), sliceToBytes(data)...),
		})
	}
	return out, nil
}

func BuildMessages(messages []Message) ([]byte, error) {
	var buf C.struct_TssBuffer
	for _, msg := range messages {
		payload := msg.Data
		var ptr *C.uint8_t
		if len(payload) > 0 {
			ptr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
		}
		if err := callStatus(func() C.TssStatus {
			return C.tss_message_build(
				&buf,
				C.uint16_t(msg.From),
				C.uint16_t(msg.To),
				ptr,
				C.uintptr_t(len(payload)),
			)
		}); err != nil {
			if buf.data != nil {
				C.tss_buffer_free(&buf)
			}
			return nil, err
		}
	}
	return bufferToBytes(&buf), nil
}
