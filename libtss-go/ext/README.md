# ext

`ext` is an extension package for `tss`. It builds higher-level, idiomatic Go APIs on top of the low-level `tss` APIs, without modifying `tss` itself: it only depends on `tss`'s public API.

It takes over the protocol plumbing that every `tss` user would otherwise write by hand: round tracking, out-of-order message buffering, message routing, and the send/receive loop. You provide the network; `ext` runs DKG, Sign and Refresh over it, with generics for typed results and `context.Context` for cancellation and deadlines. The pieces are small interfaces (`Party`, `Session`, `Transport`), so you can plug in your own transport, or add new protocols whose rounds all involve the same set of senders.

## Design

```
tss (low-level bindings)
 └─ Session[Result] / Step[Result]   typed wrappers around tss sessions
     └─ Party[Result]                round tracking, out-of-order buffering, message packing
         └─ Run(ctx, party, Transport)   the driver loop
```

- **Session / Step**: adapt each `tss` session (DKG, Sign, Refresh) to one generic interface.
- **Party**: owns a session and handles everything around it. It validates incoming packets, buffers messages that arrive one round early, advances rounds once every expected sender has delivered, and groups outgoing messages per recipient (broadcasts are expanded, so each `MessagePacket` has one concrete recipient).
- **Run**: the loop that connects a `Party` to a `Transport`.

Extension points:

- **Networking**: implement `Transport` (`Send` / `Recv`). Nothing else is needed to run over a real network.
- **New protocols**: implement `Session[Result]` and `Step[Result]`, then build the party with `NewParty`. `expectedSenderCount` is the number of distinct peers that send a message in every round. It is fixed for the whole session, so a protocol whose number of senders changes between rounds does not fit `BaseParty` as is.

## Usage

See `party_test.go` for complete DKG, Sign and Refresh examples for each supported ciphersuite, using `RunLocalDKG` / `RunLocalSign` / `RunLocalRefresh`. `party_reorder_test.go` shows out-of-order delivery.

In a real deployment, each node creates only its own party (`NewDKGParty`, `NewSignParty`, `NewRefreshParty`), implements `Transport` for its network, and calls `ext.Run` (or `RunDKG` / `RunSign` / `RunRefresh`). Refresh takes a `frostDealerID`, which FROST uses and DKLs23 ignores.

## Transport contract

- **Exactly-once delivery.** Every packet must be delivered once, with no drops and no duplicates. `Party.Next` returns an error on a second packet for the same round and sender, and the run fails; it does not ignore it. An at-least-once network must deduplicate before handing packets to the party.
- **Round window.** Only the current round and the next one are accepted; any other round is an error.
- **Session ID.** All parties in a run must use the same `sessionID`, and it must be unique per run. Packets with a different one are rejected.
- **Addressing.** `MessagePacket.To` is the real recipient; the transport only does point-to-point delivery.
- **Context.** `Send` and `Recv` must honor `ctx` cancellation and deadlines, and `Send` must not block forever.
- **Security is out of scope.** `From` is self-reported. The transport must authenticate peers and encrypt the channel; `ext` does not.

## Resource management

- Call `Party.Free()` when you are done with a party. It releases the underlying `tss` session.
- A `KeyShareHandle` in a `DKGResult` / `RefreshResult` must be freed with `KeyShare.Free()` when no longer needed.
- A party runs once and cannot be reused. Create a new one for each run.

## Concurrency and errors

- `BaseParty.Next` is guarded by a mutex. `Run` is a single loop per party; run each party in its own goroutine.
- Any error ends the run. There is no retry or recovery, and a failed session must be started again from scratch.
- `Run` returns `ctx.Err()` when the context is cancelled.
- The final step may still produce messages other parties need. `Run` sends them before returning.
- `RunLocal` runs all parties in-process over channels, for tests and debugging only, not for production. The first error cancels all other parties.
