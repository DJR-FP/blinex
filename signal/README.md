# signal

Signal server — a stateless ICE candidate relay. Peers connect via a bidirectional gRPC stream and exchange OFFER / ANSWER / CANDIDATE messages needed for NAT traversal.

## How it works

1. Each agent opens a bidi gRPC stream (`SignalService.Send`)
2. The first message from each agent registers it by WireGuard public key
3. Subsequent messages are routed to the `remote_key` peer, if connected
4. If the target peer isn't connected yet, the message is dropped — the sender will retry

The server holds no state beyond in-flight stream registrations. It's a pure message router.

## Environment variables

| Var | Default | Description |
|---|---|---|
| `SIGNAL_ADDR` | `:10000` | gRPC listen address |

## Message types (proto)

| Type | Direction | Payload |
|---|---|---|
| `MODE` | Client → server | Registration only; no routing |
| `OFFER` | Controller → controlled | `{"ufrag":"…","pwd":"…"}` |
| `ANSWER` | Controlled → controller | `{"ufrag":"…","pwd":"…"}` |
| `CANDIDATE` | Both directions | `{"candidate":"…"}` (pion marshal format) |

## Package layout

```
signal/
├── cmd/server/main.go
└── internal/server/server.go    SignalService impl; in-memory stream map
```
