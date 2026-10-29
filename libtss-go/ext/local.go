package ext

import (
	"context"
	"sync"

	"github.com/0xCarbon/libtss-go/tss"
)

type LocalTransport struct {
	id     tss.Identifier
	ch     chan MessagePacket
	idToCh map[tss.Identifier]chan MessagePacket
}

func NewLocalTransport(n int, id tss.Identifier) *LocalTransport {
	return &LocalTransport{
		id:     id,
		ch:     make(chan MessagePacket, n),
		idToCh: make(map[tss.Identifier]chan MessagePacket),
	}
}

func (tr *LocalTransport) Send(ctx context.Context, msgs []MessagePacket) error {

	for _, m := range msgs {
		if len(m.Msgs) == 0 {
			continue
		}
		select {
		case tr.idToCh[m.To] <- m:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (tr *LocalTransport) Recv(ctx context.Context) (*MessagePacket, error) {
	select {
	case m := <-tr.ch:
		return &m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RunLocal runs all parties in-process over channels. Intended for local testing and debugging.
func RunLocal[Result any](ctx context.Context, parties []Party[Result]) ([]*Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	trs := make([]*LocalTransport, len(parties))
	for i, p := range parties {
		trs[i] = NewLocalTransport(len(parties), p.ID())
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
		wg.Go(func() {
			r, err := Run[Result](ctx, p, trs[i])
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

	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func RunLocalDKG(ctx context.Context, parties []*DKGParty) ([]*DKGResult, error) {
	ps := make([]Party[DKGResult], len(parties))
	for i, p := range parties {
		ps[i] = p
	}
	return RunLocal[DKGResult](ctx, ps)
}

func RunLocalSign(ctx context.Context, parties []*SignParty) ([]*SignResult, error) {
	ps := make([]Party[SignResult], len(parties))
	for i, p := range parties {
		ps[i] = p
	}
	return RunLocal[SignResult](ctx, ps)
}

func RunLocalRefresh(ctx context.Context, parties []*RefreshParty) ([]*RefreshResult, error) {
	ps := make([]Party[RefreshResult], len(parties))
	for i, p := range parties {
		ps[i] = p
	}
	return RunLocal[RefreshResult](ctx, ps)
}
