# client (meshnet-agent)

The agent binary that runs on every enrolled device. It creates a WireGuard TUN interface, connects to peers via ICE NAT traversal, and serves a Magic DNS resolver.

## What it does

1. Loads or generates a stable WireGuard private key (persisted to `state.json`)
2. Enrolls with the management server using a setup key → receives a CGNAT IP and JWT
3. Configures the `meshnet0` TUN interface with the assigned IP
4. Opens a streaming connection to the management server to receive live peer updates
5. For each new peer, negotiates a direct P2P connection via ICE (STUN hole-punching, TURN relay fallback)
6. Routes WireGuard traffic through the ICE-established connections
7. Serves a Magic DNS resolver on `127.0.0.1:53535` (`hostname.mesh` → peer IP)

## Package layout

```
client/
├── cmd/agent/main.go               Entry point + signal handling (SIGINT/SIGTERM)
└── internal/
    ├── config/config.go            JSON config + env var overrides
    ├── engine/engine.go            Top-level orchestrator — wires everything together
    ├── state/state.go              Persists WireGuard private key to state.json
    ├── wgmgr/
    │   ├── wireguard.go           wireguard-go userspace device management
    │   └── bind.go               IceBind — routes WireGuard I/O through ICE conns
    ├── ice/
    │   ├── manager.go             Per-peer pion/ice agents; offer/answer/candidate exchange
    │   └── protocol.go           ICE signaling message types (JSON)
    ├── signalclient/client.go      gRPC bidi stream to signal server
    ├── mgmclient/client.go         gRPC streaming sync from management
    ├── peer/manager.go             Diff tracker (added / updated / removed)
    └── dns/resolver.go            Magic DNS UDP server
```

## Configuration

Config file: `/etc/meshnet/agent.json` (JSON). All fields can be overridden by env vars.

| Field / Env var | Default | Description |
|---|---|---|
| `management_url` / `MESHNET_MANAGEMENT_URL` | `localhost:50051` | Management gRPC address |
| `signal_url` / `MESHNET_SIGNAL_URL` | `localhost:10000` | Signal gRPC address |
| `setup_key` / `MESHNET_SETUP_KEY` | _(required)_ | Enrollment key |
| `wg_interface` / `MESHNET_WG_IFACE` | `meshnet0` | TUN interface name |
| `state_dir` / `MESHNET_STATE_DIR` | `/var/lib/meshnet` | Directory for state.json |
| `stun_urls` / `MESHNET_STUN_URLS` | `stun:stun.l.google.com:19302` | Comma-separated STUN/TURN URIs |
| `log_level` / `LOG_LEVEL` | `info` | debug / info / warn / error |

## ICE / NAT traversal design

The agent uses **wireguard-go** (userspace) instead of kernel WireGuard, with a custom `IceBind` that implements `conn.Bind`:

```
WireGuard device
      │
      ▼
  IceBind  ←──── registers net.Conn per peer
      │
      ▼
  pion/ice  ←──── exchanges candidates via signal server
      │
      ▼
  UDP socket (ICE-selected candidate pair)
```

**Role assignment:** The peer with the lexicographically smaller WireGuard public key is the ICE controller. This is deterministic — no coordination needed.

**Connection flow:**
1. Management server pushes a new peer via Sync
2. Engine calls `ice.StartConnect(ctx, peerKey)`
3. ICE manager creates a `pion/ice` agent, gathers candidates
4. Sends OFFER (controller) or waits for OFFER (controlled) via signal server
5. Exchanges ICE candidates (trickle ICE)
6. ICE selects a working candidate pair → `net.Conn` is returned
7. `OnConnected` callback fires → `IceBind.AddConn(endpoint, conn)` + `WireGuard.UpsertPeer(endpoint)`

## Requires root

The agent needs root (or `CAP_NET_ADMIN`) to create a TUN device.

```bash
sudo ./bin/agent
# or
sudo -E MESHNET_SETUP_KEY=... ./bin/agent
```
