package ext

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xCarbon/libtss-go/tss"
)

type link struct{ from, to tss.Identifier }

// delayTransport delays every message on the given links while keeping their order within a link.
// It simulates messages from different senders arriving out of order.
type delayTransport struct {
	*LocalTransport
	slow map[tss.Identifier]chan MessagePacket
}

func newDelayTransport(ctx context.Context, tr *LocalTransport, delayed []link, d time.Duration) *delayTransport {
	dt := &delayTransport{LocalTransport: tr, slow: make(map[tss.Identifier]chan MessagePacket)}
	for _, l := range delayed {
		if l.from != tr.id {
			continue
		}
		q := make(chan MessagePacket, 64)
		dst := tr.idToCh[l.to]
		dt.slow[l.to] = q
		go func() {
			for m := range q {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return
				}
				select {
				case dst <- m:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return dt
}

func (dt *delayTransport) Send(ctx context.Context, msgs []MessagePacket) error {
	for _, m := range msgs {
		if q, ok := dt.slow[m.To]; ok {
			q <- m
			continue
		}
		if err := dt.LocalTransport.Send(ctx, []MessagePacket{m}); err != nil {
			return err
		}
	}
	return nil
}

// runDelayed runs all parties like RunLocal, but delays messages on the delayed links.
func runDelayed[Result any](ctx context.Context, parties []Party[Result], delayed []link) ([]*Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	trs := make([]*LocalTransport, len(parties))
	for i, p := range parties {
		trs[i] = NewLocalTransport(64, p.ID())
	}
	for i := range trs {
		for j := range trs {
			if i != j {
				trs[i].idToCh[trs[j].id] = trs[j].ch
			}
		}
	}

	results := make([]*Result, len(parties))
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for i, p := range parties {
		tr := newDelayTransport(ctx, trs[i], delayed, 300*time.Millisecond)
		wg.Go(func() {
			r, err := Run[Result](ctx, p, tr)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
					cancel()
				})
				return
			}
			results[i] = r
		})
	}
	wg.Wait()
	return results, firstErr
}

// Tests the case where a next-round message arrives before the current round is complete.
func TestDKGWithReorderedSenders(t *testing.T) {
	suites := map[string]tss.Ciphersuite{
		"ed25519":   tss.CiphersuiteEd25519,
		"secp256k1": tss.CiphersuiteSecp256k1ECDSA,
	}
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			config := tss.ThresholdConfig{MinSigners: 2, MaxSigners: 3, Suite: suite}
			parties := make([]Party[DKGResult], 3)
			for i := range parties {
				p, err := NewDKGParty(config, tss.Identifier(i+1), []byte("reorder-dkg"))
				if err != nil {
					t.Fatalf("NewDKGParty(%d): %v", i+1, err)
				}
				t.Cleanup(p.Free)
				parties[i] = p
			}
			// Messages from 1 to 2 always arrive late, so 2 receives 3's next-round message first.
			results, err := runDelayed(ctx, parties, []link{{1, 2}})
			if err != nil {
				t.Fatalf("DKG: %v", err)
			}
			for _, r := range results {
				t.Cleanup(r.KeyShare.Free)
			}
		})
	}
}

func newTestDKGParty(t *testing.T) *DKGParty {
	t.Helper()
	config := tss.ThresholdConfig{MinSigners: 2, MaxSigners: 3, Suite: tss.CiphersuiteEd25519}
	p, err := NewDKGParty(config, 1, []byte("sid"))
	if err != nil {
		t.Fatalf("NewDKGParty: %v", err)
	}
	t.Cleanup(p.Free)
	return p
}

func TestNextRejectsInvalidMessages(t *testing.T) {
	sid := []byte("sid")
	msg := func(round int, from tss.Identifier, inner ...tss.Message) MessagePacket {
		if len(inner) == 0 {
			inner = []tss.Message{{From: from, Data: []byte{1}}}
		}
		return MessagePacket{Round: round, SessionID: sid, From: from, To: 1, Msgs: inner}
	}
	cases := []struct {
		name string
		in   []MessagePacket
		want string
	}{
		{"session id", []MessagePacket{{SessionID: []byte("other"), From: 2, To: 1, Msgs: []tss.Message{{From: 2}}}}, "session ID mismatch"},
		{"unknown sender", []MessagePacket{msg(0, 9)}, "unknown sender"},
		{"self as sender", []MessagePacket{msg(0, 1)}, "unknown sender"},
		{"wrong receiver", []MessagePacket{{SessionID: sid, From: 2, To: 3, Msgs: []tss.Message{{From: 2}}}}, "message addressed to 3"},
		{"inner sender", []MessagePacket{msg(0, 2, tss.Message{From: 3})}, "does not match"},
		{"inner receiver", []MessagePacket{msg(0, 2, tss.Message{From: 2, To: 3})}, "inner message addressed to 3"},
		{"duplicate sender", []MessagePacket{msg(0, 2), msg(0, 2)}, "duplicate"},
		{"two rounds ahead", []MessagePacket{msg(2, 2)}, "unexpected round"},
		{"stale round", []MessagePacket{msg(-1, 2)}, "unexpected round"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newTestDKGParty(t)
			var err error
			for _, in := range c.in {
				if _, _, err = p.Next(in); err != nil {
					break
				}
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want error containing %q", err, c.want)
			}
		})
	}
}

func TestNextBuffersNextRound(t *testing.T) {
	p := newTestDKGParty(t)
	in := MessagePacket{Round: 1, SessionID: []byte("sid"), From: 2, To: 1, Msgs: []tss.Message{{From: 2, Data: []byte{1}}}}
	out, r, err := p.Next(in)
	if err != nil || out != nil || r != nil {
		t.Fatalf("got (%v, %v, %v), want the message buffered", out, r, err)
	}
	if p.round != 0 || len(p.pendingMsg[1]) != 1 {
		t.Fatalf("round %d, pending %v", p.round, p.pendingMsg)
	}
}

func TestNewRefreshPartyEmptyIDs(t *testing.T) {
	shares, _, err := tss.FrostGenerateDealer(tss.CiphersuiteEd25519, 3, 2)
	if err != nil {
		t.Fatalf("FrostGenerateDealer: %v", err)
	}
	for _, s := range shares {
		t.Cleanup(s.Free)
	}
	if _, err := NewRefreshParty(shares[0], nil, []byte("sid"), 1); err == nil {
		t.Fatal("want an error for empty ids")
	}
}
