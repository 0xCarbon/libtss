package ext

import "github.com/0xCarbon/libtss-go/tss"

type Step[Result any] interface {
	IsComplete() bool
	GetMessages() []tss.Message
	GetResult() *Result
}
type DKGStep struct {
	tss.DKGStep
}

func (s DKGStep) IsComplete() bool {
	return s.DKGStep.Complete
}

func (s DKGStep) GetMessages() []tss.Message {
	return s.DKGStep.Messages
}
func (s DKGStep) GetResult() *DKGResult {
	if !s.IsComplete() {
		return nil
	}
	return &DKGResult{
		KeyShare:         s.KeyShare,
		PublicKeyPackage: s.PublicKeyPackage,
	}
}

type SignStep struct {
	tss.SignStep
}

func (s SignStep) IsComplete() bool {
	return s.SignStep.Complete
}

func (s SignStep) GetMessages() []tss.Message {
	return s.SignStep.Messages
}

func (s SignStep) GetResult() *SignResult {
	if !s.IsComplete() {
		return nil
	}
	sig := SignResult(s.Signature)
	return &sig
}

type RefreshStep struct {
	tss.RefreshStep
}

func (s RefreshStep) IsComplete() bool {
	return s.RefreshStep.Complete
}

func (s RefreshStep) GetMessages() []tss.Message {
	return s.RefreshStep.Messages
}

func (s RefreshStep) GetResult() *RefreshResult {
	if !s.IsComplete() {
		return nil
	}
	return &RefreshResult{
		KeyShare:         s.KeyShare,
		PublicKeyPackage: s.PublicKeyPackage,
	}
}
