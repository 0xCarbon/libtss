package ext

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/0xCarbon/libtss-go/tss"
)

type Party[Result any] interface {
	ID() tss.Identifier
	Free()
	InitialResult() *Result
	Start() ([]MessagePacket, error)
	Next(in MessagePacket) ([]MessagePacket, *Result, error)
}
type BaseParty[Result any] struct {
	sync.Mutex

	// ===== must be initialized =====
	session  Session[Result]
	id       tss.Identifier
	otherIDs []tss.Identifier
	firstMsg []tss.Message
	// pendingMsg buffers received messages by round and sender. It only ever holds the current round and the next one.
	// {
	//   round-0:{
	//      id-1: [msg1, msg2],
	//      id-2: [msg1, msg2],
	//   }
	// }
	pendingMsg map[int]map[tss.Identifier][]tss.Message
	// ===== must be initialized =====

	// initialResult is non-nil when the result is already known once the firstMsg messages are sent (the FROST dealer).
	initialResult *Result

	round               int
	expectedSenderCount int // represents the number of expected senders in the current round of the protocol.
}

func NewParty[Result any](session Session[Result], id tss.Identifier, otherIDs []tss.Identifier, firstMsg []tss.Message, expectedSenderCount int) *BaseParty[Result] {
	return &BaseParty[Result]{
		session:             session,
		id:                  id,
		otherIDs:            otherIDs,
		firstMsg:            firstMsg,
		pendingMsg:          make(map[int]map[tss.Identifier][]tss.Message),
		expectedSenderCount: expectedSenderCount,
	}
}

func (p *BaseParty[Result]) Name() string {
	return fmt.Sprintf("[party-%d, round-%d]", p.id, p.round)
}
func (p *BaseParty[Result]) WrapErr(err error) error {
	return fmt.Errorf("%s: %w", p.Name(), err)
}

func (p *BaseParty[Result]) ID() tss.Identifier {
	return p.id
}

func (p *BaseParty[Result]) Free() {
	p.session.Free()
}

// InitialResult returns the result if it is available without receiving any message, or nil otherwise.
func (p *BaseParty[Result]) InitialResult() *Result {
	return p.initialResult
}

// PackMessages groups msgs by recipient, returning one MessagePacket per party.
// Broadcasts (To == 0) go to every other party; messages addressed to self are dropped.
// It returns an error if a message is addressed to an unknown party.
func (p *BaseParty[Result]) PackMessages(msgs []tss.Message) ([]MessagePacket, error) {
	packetMap := make(map[tss.Identifier]*MessagePacket)

	for _, id := range p.otherIDs {
		packetMap[id] = &MessagePacket{
			From:      p.id,
			To:        id,
			Round:     p.round,
			SessionID: p.session.SessionID(),
		}
	}
	for _, m := range msgs {
		if m.To == 0 {
			// broadcast to every other party
			for id := range packetMap {
				packetMap[id].Msgs = append(packetMap[id].Msgs, m)
			}
			continue
		}
		if m.To != p.id {
			dst, ok := packetMap[m.To]
			if !ok {
				return nil, fmt.Errorf("message addressed to unknown party %d", m.To)
			}
			dst.Msgs = append(dst.Msgs, m)
		}
	}
	var ret []MessagePacket
	for _, packet := range packetMap {
		if len(packet.Msgs) > 0 {
			ret = append(ret, *packet)
		}
	}
	return ret, nil
}

func (p *BaseParty[Result]) Start() ([]MessagePacket, error) {
	m := p.firstMsg
	p.firstMsg = nil
	return p.PackMessages(m)
}

// validate checks the session ID, sender and receiver of in. It does not check the round.
func (p *BaseParty[Result]) validate(in MessagePacket) error {
	if !bytes.Equal(in.SessionID, p.session.SessionID()) {
		return errors.New("session ID mismatch")
	}
	if !slices.Contains(p.otherIDs, in.From) {
		return fmt.Errorf("unknown sender %d", in.From)
	}
	if in.To != p.id {
		return fmt.Errorf("message addressed to %d, not %d", in.To, p.id)
	}
	for _, m := range in.Msgs {
		if m.From != in.From {
			return fmt.Errorf("inner sender %d does not match sender %d", m.From, in.From)
		}
		if m.To != 0 && m.To != p.id {
			return fmt.Errorf("inner message addressed to %d, not %d", m.To, p.id)
		}
	}
	return nil
}

func (p *BaseParty[Result]) roundMsgs(round int) []tss.Message {
	var msgs []tss.Message
	for _, m := range p.pendingMsg[round] {
		msgs = append(msgs, m...)
	}
	return msgs
}

// Next handles one incoming message.
// Messages from different senders may arrive out of order, so a message for the next round is
// buffered until this party reaches that round. A message can never be more than one round ahead:
// a peer cannot leave round r+1 until it has received this party's round r+1 messages, which are
// only sent after this party finishes round r.
// One call may advance several rounds; the returned messages are ordered by round.
func (p *BaseParty[Result]) Next(in MessagePacket) ([]MessagePacket, *Result, error) {
	if len(in.Msgs) == 0 {
		return nil, nil, nil
	}
	p.Lock()
	defer p.Unlock()
	if err := p.validate(in); err != nil {
		return nil, nil, p.WrapErr(err)
	}

	// Only accept the current round and the next one (arrived early); anything else is invalid.
	if in.Round != p.round && in.Round != p.round+1 {
		return nil, nil, p.WrapErr(fmt.Errorf("unexpected round %d, current round %d", in.Round, p.round))
	}
	msgCache := p.pendingMsg[in.Round]
	if msgCache == nil {
		msgCache = make(map[tss.Identifier][]tss.Message)
		p.pendingMsg[in.Round] = msgCache
	}
	// already received this round's message from in.From
	if _, ok := msgCache[in.From]; ok {
		return nil, nil, p.WrapErr(fmt.Errorf("duplicate round %d message from %d", in.Round, in.From))
	}
	msgCache[in.From] = in.Msgs

	var out []MessagePacket
	var r *Result
	// advance while every message of the current round has arrived
	for len(p.pendingMsg[p.round]) == p.expectedSenderCount {
		step, err := p.session.Next(p.roundMsgs(p.round))
		delete(p.pendingMsg, p.round)

		if err != nil {
			return nil, nil, p.WrapErr(err)
		}
		p.round++

		if msgs := step.GetMessages(); len(msgs) > 0 {
			split, err := p.PackMessages(msgs)
			if err != nil {
				return nil, nil, p.WrapErr(err)
			}
			out = append(out, split...)
		}
		if step.IsComplete() {
			r = step.GetResult()
			break
		}
	}
	return out, r, nil
}

type DKGParty = BaseParty[DKGResult]

func NewDKGParty(config tss.ThresholdConfig, self tss.Identifier, sessionID []byte) (*DKGParty, error) {
	sess, first, err := NewDKGSession(config, self, sessionID)
	if err != nil {
		return nil, err
	}
	var otherIDs []tss.Identifier
	for i := range tss.Identifier(config.MaxSigners) {
		if i+1 != self {
			otherIDs = append(otherIDs, i+1)
		}
	}

	p := NewParty[DKGResult](sess, self, otherIDs, first, int(config.MaxSigners-1))
	return p, nil
}

type SignParty = BaseParty[SignResult]

func NewSignParty(keyShare *tss.KeyShareHandle, message []byte, ids []tss.Identifier, sessionID []byte) (*SignParty, error) {
	if len(ids) < 2 {
		return nil, fmt.Errorf("need at least 2 ids, got %d", len(ids))
	}
	selfID, err := keyShare.Identifier()
	if err != nil {
		return nil, err
	}

	seen := make(map[tss.Identifier]bool)
	var otherIDs []tss.Identifier
	for _, id := range ids {
		if seen[id] {
			return nil, fmt.Errorf("duplicate id %v", id)
		}
		seen[id] = true
		if id != selfID {
			otherIDs = append(otherIDs, id)
		}
	}

	sess, first, err := NewSignSession(keyShare, message, otherIDs, sessionID)
	if err != nil {
		return nil, err
	}

	p := NewParty[SignResult](sess, selfID, otherIDs, first, len(ids)-1)
	return p, nil
}

type RefreshParty = BaseParty[RefreshResult]

// NewRefreshParty creates a refresh party. The protocol is chosen by the key share's ciphersuite.
//   - frostDealerID is the ID of the dealer; it is only used by FROST and ignored by DKLs23.
func NewRefreshParty(keyShare *tss.KeyShareHandle, ids []tss.Identifier, sessionID []byte, frostDealerID tss.Identifier) (*RefreshParty, error) {
	if len(ids) < 2 {
		return nil, fmt.Errorf("need at least 2 ids, got %d", len(ids))
	}
	selfID, err := keyShare.Identifier()
	if err != nil {
		return nil, err
	}
	suite, err := keyShare.Ciphersuite()
	if err != nil {
		return nil, err
	}
	seen := make(map[tss.Identifier]bool)
	otherIDs := make([]tss.Identifier, 0, len(ids)-1)
	for _, id := range ids {
		if seen[id] {
			return nil, fmt.Errorf("duplicate id %v", id)
		}
		seen[id] = true
		if id != selfID {
			otherIDs = append(otherIDs, id)
		}
	}
	{
		if suite.Protocol() == tss.ProtocolDKLs23 {
			sess, first, err := NewRefreshSessionDKLs(keyShare, sessionID)
			if err != nil {
				return nil, err
			}
			return NewParty[RefreshResult](sess, selfID, otherIDs, first, len(ids)-1), nil
		}
	}

	{
		//  ======= FROST =======

		if selfID == frostDealerID {
			return newFrostDealerParty(keyShare, ids, otherIDs, sessionID, frostDealerID)
		}
		recv, err := NewRefreshReceiverFROST(keyShare, frostDealerID, sessionID)
		if err != nil {
			return nil, err
		}
		return NewParty[RefreshResult](recv, selfID, otherIDs, nil, 1), nil
	}
}

func newFrostDealerParty(keyShare *tss.KeyShareHandle, ids []tss.Identifier, otherIDs []tss.Identifier, sessionID []byte, frostDealerID tss.Identifier) (*RefreshParty, error) {
	selfID := frostDealerID
	dealerSess, msgs, err := NewRefreshSessionFROST(keyShare, ids, sessionID)
	if err != nil {
		return nil, err
	}
	dealerSess.Free()

	var own, firstMsg []tss.Message
	for _, m := range msgs {
		if m.To == selfID {
			own = append(own, m)
		} else {
			firstMsg = append(firstMsg, m)
		}
	}
	// The dealer applies its own share the same way a receiver does.
	sess, err := NewRefreshReceiverFROST(keyShare, selfID, sessionID)
	if err != nil {
		return nil, err
	}
	step, err := sess.Next(own)
	if err != nil {
		sess.Free()
		return nil, err
	}
	if !step.IsComplete() {
		sess.Free()
		return nil, errors.New("FROST refresh dealer: applying its own share did not complete")
	}
	p := NewParty[RefreshResult](sess, selfID, otherIDs, firstMsg, 0)
	p.initialResult = step.GetResult()
	return p, nil
}
