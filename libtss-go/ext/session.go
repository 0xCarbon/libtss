package ext

import "github.com/0xCarbon/libtss-go/tss"

type Session[Result any] interface {
	Next([]tss.Message) (Step[Result], error)
	Free()
	SessionID() []byte
}

type DKGSession struct {
	*tss.DKGSession
	sessionID []byte
}

func NewDKGSession(config tss.ThresholdConfig, self tss.Identifier, sessionID []byte) (*DKGSession, []tss.Message, error) {
	sess, first, err := tss.NewDKGSession(config, self, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return &DKGSession{sess, sessionID}, first, err
}

func (s *DKGSession) Next(msgs []tss.Message) (Step[DKGResult], error) {
	step, err := s.DKGSession.Next(msgs)
	return DKGStep{step}, err
}

func (s *DKGSession) SessionID() []byte {
	return s.sessionID
}

type SignSession struct {
	*tss.SignSession
	sessionID []byte
}

func NewSignSession(keyShare *tss.KeyShareHandle, message []byte, counterparties []tss.Identifier, sessionID []byte) (*SignSession, []tss.Message, error) {
	sess, first, err := tss.NewSignSession(keyShare, message, counterparties, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return &SignSession{sess, sessionID}, first, err
}

func (s *SignSession) Next(msgs []tss.Message) (Step[SignResult], error) {
	step, err := s.SignSession.Next(msgs)
	return SignStep{step}, err
}

func (s *SignSession) SessionID() []byte {
	return s.sessionID
}

type RefreshSession struct {
	*tss.RefreshSession
	sessionID []byte
}

func NewRefreshSessionFROST(keyShare *tss.KeyShareHandle, ids []tss.Identifier, sessionID []byte) (*RefreshSession, []tss.Message, error) {
	sess, first, err := tss.NewRefreshSession(keyShare, ids)
	if err != nil {
		return nil, nil, err
	}
	return &RefreshSession{sess, sessionID}, first, err
}

func NewRefreshSessionDKLs(keyShare *tss.KeyShareHandle, sessionID []byte) (*RefreshSession, []tss.Message, error) {
	sess, first, err := tss.NewRefreshSessionDKLs(keyShare, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return &RefreshSession{sess, sessionID}, first, err
}

func NewRefreshReceiverFROST(keyShare *tss.KeyShareHandle, dealerID tss.Identifier, sessionID []byte) (*RefreshSession, error) {
	sess, err := tss.NewRefreshReceiver(keyShare, dealerID)
	if err != nil {
		return nil, err
	}
	return &RefreshSession{sess, sessionID}, err
}

func (s *RefreshSession) Next(msgs []tss.Message) (Step[RefreshResult], error) {
	step, err := s.RefreshSession.Next(msgs)
	return RefreshStep{step}, err
}

func (s *RefreshSession) SessionID() []byte {
	return s.sessionID
}
