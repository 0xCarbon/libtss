package tss

/*
#include "tss_ffi.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type DKGSession struct{ native *nativeHandle }
type SignSession struct {
	native *nativeHandle
	suite  Ciphersuite
}
type RefreshSession struct{ native *nativeHandle }

type DKGStep struct {
	Messages         []Message
	Complete         bool
	KeyShare         *KeyShareHandle
	PublicKeyPackage PublicKeyPackage
}

type SignStep struct {
	Messages  []Message
	Complete  bool
	Signature Signature
}

type RefreshStep struct {
	Messages         []Message
	Complete         bool
	KeyShare         *KeyShareHandle
	PublicKeyPackage PublicKeyPackage
}

func newDKGSession(handle C.TssHandle) *DKGSession {
	out := &DKGSession{native: newSessionNativeHandle(handle)}
	runtime.SetFinalizer(out, func(s *DKGSession) { s.Free() })
	return out
}

func newSignSession(handle C.TssHandle, suite Ciphersuite) *SignSession {
	out := &SignSession{native: newSessionNativeHandle(handle), suite: suite}
	runtime.SetFinalizer(out, func(s *SignSession) { s.Free() })
	return out
}

func newRefreshSession(handle C.TssHandle) *RefreshSession {
	out := &RefreshSession{native: newSessionNativeHandle(handle)}
	runtime.SetFinalizer(out, func(s *RefreshSession) { s.Free() })
	return out
}

func (s *DKGSession) Free() {
	if s == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	s.native.free()
}

func (s *SignSession) Free() {
	if s == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	s.native.free()
}

func (s *RefreshSession) Free() {
	if s == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	s.native.free()
}

func NewDKGSession(config ThresholdConfig, self Identifier, sessionID []byte) (*DKGSession, []Message, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	var native C.TssHandle
	var out C.struct_TssBuffer
	var sidPtr *C.uint8_t
	if len(sessionID) > 0 {
		sidPtr = (*C.uint8_t)(unsafe.Pointer(&sessionID[0]))
	}
	if err := callStatus(func() C.TssStatus {
		return C.tss_dkg_new(
			C.uint8_t(config.Suite),
			C.uint16_t(self),
			C.uint16_t(config.MaxSigners),
			C.uint16_t(config.MinSigners),
			sidPtr,
			C.uintptr_t(len(sessionID)),
			&native,
			&out,
		)
	}); err != nil {
		return nil, nil, err
	}
	msgs, err := ParseMessages(bufferToBytes(&out))
	if err != nil {
		C.tss_session_free(native)
		return nil, nil, err
	}
	return newDKGSession(native), msgs, nil
}

func (s *DKGSession) Next(messages []Message) (DKGStep, error) {
	handle, err := s.native.value()
	if err != nil {
		return DKGStep{}, err
	}
	blob, err := BuildMessages(messages)
	if err != nil {
		return DKGStep{}, err
	}
	var outKey C.TssHandle
	var outPkg C.struct_TssBuffer
	var outMsgs C.struct_TssBuffer
	var complete C.bool
	if err := callStatus(func() C.TssStatus {
		return C.tss_dkg_next(
			handle,
			bytesToSlice(blob),
			&outKey,
			&outPkg,
			&outMsgs,
			&complete,
		)
	}); err != nil {
		return DKGStep{}, err
	}
	step := DKGStep{Complete: bool(complete)}
	if step.Complete {
		step.KeyShare = newKeyShareHandle(outKey)
		pkgBytes := bufferToBytes(&outPkg)
		step.PublicKeyPackage, err = decodePublicKeyPackage(pkgBytes)
		return step, err
	}
	step.Messages, err = ParseMessages(bufferToBytes(&outMsgs))
	return step, err
}

func NewSignSession(keyShare *KeyShareHandle, message []byte, counterparties []Identifier, signID []byte) (*SignSession, []Message, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, nil, err
	}
	suite, err := keyShare.Ciphersuite()
	if err != nil {
		return nil, nil, err
	}
	var native C.TssHandle
	var out C.struct_TssBuffer
	var cpPtr *C.uint16_t
	if len(counterparties) > 0 {
		cpPtr = (*C.uint16_t)(unsafe.Pointer(&counterparties[0]))
	}
	var sidPtr *C.uint8_t
	if len(signID) > 0 {
		sidPtr = (*C.uint8_t)(unsafe.Pointer(&signID[0]))
	}
	if err := callStatus(func() C.TssStatus {
		return C.tss_sign_new(
			handle,
			bytesToSlice(message),
			cpPtr,
			C.uintptr_t(len(counterparties)),
			sidPtr,
			C.uintptr_t(len(signID)),
			&native,
			&out,
		)
	}); err != nil {
		return nil, nil, err
	}
	msgs, err := ParseMessages(bufferToBytes(&out))
	if err != nil {
		C.tss_session_free(native)
		return nil, nil, err
	}
	return newSignSession(native, suite), msgs, nil
}

func (s *SignSession) Next(messages []Message) (SignStep, error) {
	handle, err := s.native.value()
	if err != nil {
		return SignStep{}, err
	}
	blob, err := BuildMessages(messages)
	if err != nil {
		return SignStep{}, err
	}
	var outSig C.struct_TssBuffer
	var outMsgs C.struct_TssBuffer
	var complete C.bool
	if err := callStatus(func() C.TssStatus {
		return C.tss_sign_next(
			handle,
			bytesToSlice(blob),
			&outSig,
			&outMsgs,
			&complete,
		)
	}); err != nil {
		return SignStep{}, err
	}
	step := SignStep{Complete: bool(complete)}
	if step.Complete {
		step.Signature = Signature{
			Protocol: s.suite.Protocol(),
			Data:     bufferToBytes(&outSig),
		}
		return step, nil
	}
	step.Messages, err = ParseMessages(bufferToBytes(&outMsgs))
	return step, err
}

func NewRefreshSession(keyShare *KeyShareHandle, participants []Identifier) (*RefreshSession, []Message, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, nil, err
	}
	var native C.TssHandle
	var out C.struct_TssBuffer
	var pPtr *C.uint16_t
	if len(participants) > 0 {
		pPtr = (*C.uint16_t)(unsafe.Pointer(&participants[0]))
	}
	if err := callStatus(func() C.TssStatus {
		return C.tss_refresh_new(
			handle,
			pPtr,
			C.uintptr_t(len(participants)),
			&native,
			&out,
		)
	}); err != nil {
		return nil, nil, err
	}
	msgs, err := ParseMessages(bufferToBytes(&out))
	if err != nil {
		C.tss_session_free(native)
		return nil, nil, err
	}
	return newRefreshSession(native), msgs, nil
}

func NewRefreshReceiver(keyShare *KeyShareHandle) (*RefreshSession, error) {
	if err := checkNonNil("keyShare", keyShare); err != nil {
		return nil, err
	}
	handle, err := keyShare.native.value()
	if err != nil {
		return nil, err
	}
	var native C.TssHandle
	if err := callStatus(func() C.TssStatus {
		return C.tss_refresh_receiver(handle, &native)
	}); err != nil {
		return nil, err
	}
	return newRefreshSession(native), nil
}

func (s *RefreshSession) Next(messages []Message) (RefreshStep, error) {
	handle, err := s.native.value()
	if err != nil {
		return RefreshStep{}, err
	}
	blob, err := BuildMessages(messages)
	if err != nil {
		return RefreshStep{}, err
	}
	var outKey C.TssHandle
	var outPkg C.struct_TssBuffer
	var outMsgs C.struct_TssBuffer
	var complete C.bool
	if err := callStatus(func() C.TssStatus {
		return C.tss_refresh_next(
			handle,
			bytesToSlice(blob),
			&outKey,
			&outPkg,
			&outMsgs,
			&complete,
		)
	}); err != nil {
		return RefreshStep{}, err
	}
	step := RefreshStep{Complete: bool(complete)}
	if step.Complete {
		step.KeyShare = newKeyShareHandle(outKey)
		step.PublicKeyPackage, err = decodePublicKeyPackage(bufferToBytes(&outPkg))
		return step, err
	}
	step.Messages, err = ParseMessages(bufferToBytes(&outMsgs))
	return step, err
}
