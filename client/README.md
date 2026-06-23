# client (blinex-agent)

The agent binary that runs on every enrolled device. It creates a WireGuard TUN interface, connects to peers via ICE NAT traversal, and serves a Magic DNS resolver.

## What it does

1. Loads or generates a stable WireGuard private key (persisted to `state.json`)
2. Enrolls with the management server using a setup key → receives a CGNAT IP and JWT
3. Configures the `blinex0` TUN interface with the assigned IP
4. Opens a streaming connection to the management server to receive live peer updates
5. For each new peer, negotiates a direct P2P connection via ICE (STUN hole-punching, TURN relay fallback)
6. Routes WireGuard traffic through the ICE-established connections
7. Serves a Magic DNS resolver on `127.0.0.1:53535` (`hostname.blinex` → peer IP)

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

Config file: `/etc/blinex/agent.json` (JSON). All fields can be overridden by env vars.

| Field / Env var | Default | Description |
|---|---|---|
| `management_url` / `BLINEX_MANAGEMENT_URL` | `localhost:50051` | Management gRPC address |
| `signal_url` / `BLINEX_SIGNAL_URL` | `localhost:10000` | Signal gRPC address |
| `setup_key` / `BLINEX_SETUP_KEY` | _(required)_ | Enrollment key |
| `wg_interface` / `BLINEX_WG_IFACE` | `blinex0` | TUN interface name |
| `state_dir` / `BLINEX_STATE_DIR` | `/var/lib/blinex` | Directory for state.json |
| `stun_urls` / `BLINEX_STUN_URLS` | `stun:stun.l.google.com:19302` | Comma-separated STUN/TURN URIs |
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
sudo -E BLINEX_SETUP_KEY=... ./bin/agent
```

## Uninstalling

Pre-built uninstall binaries are included in each [release](https://github.com/DJR-FP/blinex-agent/releases). The uninstaller removes the agent binary, service, config, state, and platform-specific resources.

### Linux

```bash
# Using the uninstall binary from the release
curl -fsSL https://github.com/DJR-FP/blinex-agent/releases/latest/download/blinex-uninstall-linux-amd64 -o blinex-uninstall
chmod +x blinex-uninstall
sudo ./blinex-uninstall

# Or using the shell script
curl -fsSL https://raw.githubusercontent.com/DJR-FP/blinex-agent/main/uninstall.sh | sudo bash
```

Removes: systemd service, `/usr/local/bin/blinex-agent`, `/etc/blinex/`, `/var/lib/blinex/`, `BLINEX-ACL` iptables chain, and the `blinex0` interface.

### macOS

```bash
curl -fsSL https://github.com/DJR-FP/blinex-agent/releases/latest/download/blinex-uninstall-darwin-arm64 -o blinex-uninstall
chmod +x blinex-uninstall
sudo ./blinex-uninstall
```

Removes: `io.blinex.agent` launchd service, binary, config, state, and log file.

### Windows

Download `blinex-uninstall-windows-amd64.exe` from the [latest release](https://github.com/DJR-FP/blinex-agent/releases) and run it as Administrator.

Removes: `BlinexAgent` Windows service, `%ProgramFiles%\Bline-X\`, `%ProgramData%\Bline-X\`, Bline-X firewall rules, and PATH entry.

## Troubleshooting

### Agent crashes immediately (exit code 2, protobuf panic)

```
panic: runtime error: slice bounds out of range [-2:]
github.com/blinex/gen/common/v1.file_common_v1_types_proto_init()
```

**Cause:** Agent binary version doesn't match the server's protobuf schema. Usually happens after an upgrade.

**Fix:** Make sure the agent and server are running the same version. Re-download the latest agent binary:

```bash
curl -fsSL https://raw.githubusercontent.com/DJR-FP/blinex-agent/main/install.sh | \
  BLINEX_SETUP_KEY=YOUR_KEY \
  BLINEX_MANAGEMENT_URL=your-server:50051 \
  BLINEX_SIGNAL_URL=your-server:10000 \
  sudo -E bash
```

### TOFU: server certificate changed

```
TOFU: server certificate changed for mesh.example.com:50051 (pinned=2aaff671...)
```

**Cause:** The server's TLS certificate was regenerated (e.g. after rebuilding containers), but the agent still has the old certificate pinned in its state file.

**Fix:** Delete the state file and restart:

```bash
sudo rm /var/lib/blinex/state.json
sudo systemctl restart blinex-agent
```

### Authentication handshake failed

```
transport: authentication handshake failed
```

**Cause:** The agent can't verify the server's TLS certificate. Common with self-signed certs.

**Fix:** Set `tls_skip_verify` to `true` in `/etc/blinex/agent.json`:

```json
{
  "management_url": "your-server:50051",
  "signal_url": "your-server:10000",
  "setup_key": "YOUR_KEY",
  "tls_skip_verify": true
}
```

Then `sudo systemctl restart blinex-agent`.

### No known endpoint for peer

```
peer(zIVl…np3g) - Failed to send handshake initiation: no known endpoint for peer
```

**Cause:** ICE negotiation hasn't completed. The WireGuard layer is trying to reach a peer before the ICE connection is established.

**Fix:** Check that:
1. The other peer is actually online and running the agent
2. The signal server is reachable: `nc -zv your-server 10000`
3. The STUN/TURN relay is reachable: `nc -zuv your-server 3478`
4. Firewalls allow UDP traffic between peers for hole-punching

### Stale peer won't delete from dashboard

A peer may get stuck in the database and can't be removed from the UI.

**Fix:** Delete it directly from PostgreSQL:

```bash
# List all peers
docker compose exec postgres psql -U blinex -d blinex -c "SELECT id, hostname, wg_pub_key FROM peers;"

# Delete a specific peer
docker compose exec postgres psql -U blinex -d blinex -c "DELETE FROM peers WHERE wg_pub_key = 'THE_KEY_HERE';"

# Or clear all peers
docker compose exec postgres psql -U blinex -d blinex -c "DELETE FROM peers;"

# Restart management to push updated peer list
docker compose restart management
```

### TUN device unavailable — using netstack mode

```
/dev/net/tun not available, attempting to create it
TUN device unavailable — using userspace netstack mode
```

**Cause:** The kernel TUN device isn't available. Common in LXC/LXD containers and on Windows/macOS.

**What this means:** The agent falls back to userspace networking (netstack), which works without kernel TUN. **However, netstack mode is one-directional for host traffic:**

- **Inbound works** — other peers can reach services on this device, and pings *to* it succeed (the userspace stack auto-replies).
- **Outbound from host apps does NOT work transparently** — running `ping` or other commands *on* this device uses the host's kernel network stack, which has no knowledge of the userspace tunnel. This is the same limitation as Tailscale's `userspace-networking` mode.

**Fix (recommended): enable kernel TUN.** On Linux VMs, load the module: `sudo modprobe tun`.

**For LXC/LXD containers (e.g. Proxmox):** pass `/dev/net/tun` into the container so the agent uses kernel mode and gets full bidirectional connectivity.

On the **host**, edit the container config (`/etc/pve/lxc/<CTID>.conf` on Proxmox) and add:

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

Then restart the container and the agent:

```bash
pct restart <CTID>             # on the Proxmox host
# inside the container:
sudo rm -f /var/lib/blinex/state.json
sudo systemctl restart blinex-agent
```

After restarting, the log should show `WireGuard device ready` (kernel mode) instead of `using userspace netstack mode`.

### Can ping a peer but it can't ping back (kernel TUN)

**Cause:** The mesh route is missing. The agent assigns a `/32` address to `blinex0`, which creates no route for the rest of the mesh range, so replies leave via the default gateway.

**Fix:** v0.9.5+ adds the `100.64.0.0/10` route automatically. If running an older build, add it manually:

```bash
sudo ip route add 100.64.0.0/10 dev blinex0
```

Make it permanent by upgrading to the latest agent.
