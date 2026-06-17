# Meshnet — Claude Code Context

## What this is

A WireGuard mesh VPN product (Tailscale/NetBird-like), built from scratch in Go + Next.js. Open-core, targeting SMB/developer teams.

## Repo layout

```
meshnet/
├── proto/          Source .proto files — edit here, then run `buf generate`
├── gen/            Auto-generated Go stubs — NEVER edit by hand
├── management/     Management server (Go, gin, gRPC, GORM)
├── signal/         ICE signal relay (Go, gRPC bidi stream)
├── relay/          STUN/TURN relay (Go, pion/turn)
├── client/         Agent binary (Go, wireguard-go, pion/ice)
├── dashboard/      Web UI (Next.js 14, TypeScript, Tailwind)
├── go.work         Go workspace — links all 5 Go modules
├── buf.yaml        buf config for proto codegen
└── docker-compose.yml
```

## Go toolchain

```bash
export GOROOT=/home/clouduser/go/go
export GOPATH=/home/clouduser/gopath
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
```

Node.js: `/home/clouduser/node/bin/node` (v20)

## Build commands

```bash
# All Go binaries
go build -o bin/management ./management/cmd/server
go build -o bin/signal     ./signal/cmd/server
go build -o bin/relay      ./relay/cmd/server
go build -o bin/agent      ./client/cmd/agent

# Regenerate protobuf stubs
buf generate

# Dashboard
cd dashboard && npm run build
cd dashboard && npx tsc --noEmit   # type check only
```

## Module dependency graph

```
client  →  gen  (replace ../gen)
management →  gen  (replace ../gen)
signal  →  gen  (replace ../gen)
relay   (standalone)
gen     (standalone, generated)
```

All linked via `go.work`. When adding a new module, add it to `go.work`.

## Key architectural constraint: WireGuard + ICE

**Do not** use `wgctrl` (kernel WireGuard) in the agent. The agent uses `wireguard-go` (userspace) with a custom `IceBind` (`conn.Bind` interface in `client/internal/wgmgr/bind.go`).

Why: kernel WireGuard opens its own UDP socket. STUN-discovered external ports won't match that socket, so hole-punching fails. With `IceBind`, WireGuard traffic flows through `net.Conn` objects that `pion/ice` establishes — the ICE path IS the WireGuard path.

## Proto changes

After editing any `.proto` file:
1. Run `buf generate` from the repo root
2. The generated files go to `gen/` automatically
3. All modules pick up the changes via the `replace ../gen` directive

## Store interface

`management/internal/store/store.go` defines the `Store` interface.  
`management/internal/store/memory/` — in-memory impl (dev/test)  
`management/internal/store/postgres/` — GORM PostgreSQL impl (production)

When `DATABASE_URL` env var is set, main.go uses the postgres store. Otherwise uses memory.

Adding new persistence operations: update the interface, then implement in both stores.

## Authentication

- Agent enrolls with a setup key → gets a JWT (`auth.IssueToken`)
- JWT is returned in `LoginResponse.token` (proto field 3)
- JWT contains `PeerID`, `WGPubKey`, `AccountID`
- REST API requires `Authorization: Bearer <jwt>`
- gRPC Sync uses `WGPubKey` directly (no JWT — the pubkey proves identity)

## ICE signaling flow

1. Agent A and Agent B both open a bidi gRPC stream to the signal server
2. First message (MODE type, empty remote_key) registers the agent by pubkey
3. Whichever agent has the lexicographically smaller pubkey becomes controller
4. Controller sends OFFER (ufrag, pwd) → signal server routes to peer
5. Peer sends ANSWER → controller calls `agent.Dial()`; peer calls `agent.Accept()`
6. Both trickle ICE CANDIDATE messages throughout
7. Once connected: `ice.Manager.OnConnected` callback fires → `wg.UpdateEndpoint(peerKey, endpoint, conn)`

## DNS

The agent runs a UDP DNS server on `127.0.0.1:53535`. Queries for `*.mesh` domains resolve to peer IPs. All other queries are forwarded to `8.8.8.8:53`.

To use Magic DNS, configure the device's DNS to `127.0.0.1:53535` or port-forward from :53.

## Default setup key

`MESHNET-DEFAULT-KEY` is seeded at startup (both memory and postgres stores). It's valid for 1 year. Create real keys via the Setup Keys page before going to production.

## Common pitfalls

- **go mod tidy removes pion/ice**: Only happens if no .go file imports it yet. Write the source files that import the packages BEFORE running tidy.
- **conn.Endpoint.DstToBytes()**: wireguard-go requires this method on any `conn.Endpoint` implementation. It's defined on `IceEndpoint` in `bind.go`.
- **`privKey.PublicKey()[:]`**: `wgtypes.Key.PublicKey()` returns a value (not addressable). Store it in a variable first: `pub := privKey.PublicKey(); slice := pub[:]`
- **signal server min() conflict**: `signal/internal/server/server.go` defines a local `min()` function. In Go 1.21+ this conflicts with the builtin. If upgrading Go, remove the local definition.
- **gin-contrib/cors requires Go 1.25**: The management module was upgraded to `go 1.25` when cors was added. Go auto-downloads the 1.25 toolchain.

## Testing locally (no Docker)

```bash
# Terminal 1
MGMT_JWT_SECRET=dev go run ./management/cmd/server

# Terminal 2
go run ./signal/cmd/server

# Terminal 3 (optional)
RELAY_PUBLIC_IP=127.0.0.1 go run ./relay/cmd/server

# Terminal 4 (needs root — creates TUN device)
sudo MESHNET_SETUP_KEY=MESHNET-DEFAULT-KEY go run ./client/cmd/agent

# Terminal 5
cd dashboard && npm run dev
```

Dashboard at http://localhost:3000 — sign in with the JWT printed by the agent.
