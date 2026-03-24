package tss

/*
#include "tss_ffi.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type TssError struct {
	Code    int32
	Message string
}

func (e *TssError) Error() string {
	return e.Message
}

type AbortError struct {
	*TssError
	Culprits []Identifier
	Banned   Identifier
}

func statusErr(code C.TssStatus) error {
	if int32(code) == int32(C.TSS_OK) {
		return nil
	}

	messageLen := C.tss_last_error_len()
	message := C.GoStringN(C.tss_last_error(), C.int(messageLen))
	base := &TssError{
		Code:    int32(code),
		Message: message,
	}

	if base.Code == int32(C.TSS_ERR_ABORT) || base.Code == int32(C.TSS_ERR_ABORT_BAN) {
		count := int(C.tss_abort_culprit_count())
		culprits := make([]Identifier, 0, count)
		for i := 0; i < count; i++ {
			culprits = append(culprits, Identifier(C.tss_abort_culprit(C.uintptr_t(i))))
		}
		return &AbortError{
			TssError: base,
			Culprits: culprits,
			Banned:   Identifier(C.tss_abort_banned_party()),
		}
	}

	return base
}

func callStatus(fn func() C.TssStatus) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return statusErr(fn())
}

func invalidLocalHandle() error {
	return &TssError{
		Code:    int32(C.TSS_ERR_HANDLE_INVALID),
		Message: "handle already freed",
	}
}

func bufferToBytes(buf *C.struct_TssBuffer) []byte {
	if buf.data == nil || buf.len == 0 {
		return nil
	}
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	C.tss_buffer_free(buf)
	return data
}

func sliceToBytes(buf C.struct_TssSlice) []byte {
	if buf.data == nil || buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
}

func bytesToSlice(data []byte) C.struct_TssSlice {
	if len(data) == 0 {
		return C.struct_TssSlice{}
	}
	return C.struct_TssSlice{
		data: (*C.uint8_t)(unsafe.Pointer(&data[0])),
		len:  C.uintptr_t(len(data)),
	}
}

func checkNonNil(name string, ptr any) error {
	if ptr == nil {
		return fmt.Errorf("%s is nil", name)
	}
	return nil
}
