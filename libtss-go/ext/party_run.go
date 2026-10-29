package ext

import (
	"context"
)

func Run[Result any](ctx context.Context, party Party[Result], tr Transport) (*Result, error) {
	msgs, err := party.Start()
	if err != nil {
		return nil, err
	}
	var r *Result
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if msgs != nil {
			err = tr.Send(ctx, msgs)
			if err != nil {
				return nil, err
			}
		}
		if r = party.InitialResult(); r != nil {
			return r, nil
		}

		msg, err := tr.Recv(ctx)
		if err != nil {
			return nil, err
		}
		msgs, r, err = party.Next(*msg)
		if err != nil {
			return nil, err
		}
		if r != nil {
			// The final step may still produce messages that other parties need.
			if msgs != nil {
				err = tr.Send(ctx, msgs)
				if err != nil {
					return nil, err
				}
			}
			return r, nil
		}
	}
}

func RunDKG(ctx context.Context, party *DKGParty, tr Transport) (*DKGResult, error) {
	return Run[DKGResult](ctx, party, tr)
}

func RunSign(ctx context.Context, party *SignParty, tr Transport) (*SignResult, error) {
	return Run[SignResult](ctx, party, tr)
}

func RunRefresh(ctx context.Context, party *RefreshParty, tr Transport) (*RefreshResult, error) {
	return Run[RefreshResult](ctx, party, tr)
}
