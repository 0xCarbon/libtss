package ext

import "context"

// Transport only sends and receives Messages.
// A real network only needs to implement these two methods, honoring ctx cancellation and deadlines.
// Implementations must deliver every message exactly once: no drops, no duplicates.
type Transport interface {
	// Send delivers each message in msg to the party named by its To field. It must not block forever.
	Send(ctx context.Context, msgs []MessagePacket) error
	// Recv blocks until a message arrives or ctx is done.
	Recv(ctx context.Context) (*MessagePacket, error)
}
