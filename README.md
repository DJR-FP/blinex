# Meshnet

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20BSL--1.1-blue)](#license)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#quick-start)

A zero-trust WireGuard mesh VPN — open-source core, built for SMB and developer teams. Think Tailscale/NetBird, but simpler to self-host and extend.

---

## Features

- **Automatic NAT traversal** — ICE hole-punching (STUN) with TURN relay fallback; works across most NATs without port forwarding
- **Stable IPs** — every device gets a permanent CGNAT IP (`100.64.x.x`) and a Magic DNS hostname (`device.mesh`)
- **Simple onboarding** — one `curl | bash` to enroll a device; token appears in the dashboard
- **Web dashboard** — manage devices, setup keys, and access rules from a browser
- **Self-hosted** — `docker compose up` and you own your data; no phone-home
- **PostgreSQL or in-memory** — swap the store with one env var

---

## Architecture

```
┌──────────────────────── Control Plane ──────────────────────────┐
│                                                                   │
│   Management Server          Signal Server       Relay Server    │
│   gRPC :50051                ICE candidate       STUN/TURN       │
│   HTTP :8080                 relay (bidi gRPC)   UDP :3478       │
│   JWT auth · REST API        :10000              pion/turn       │
│   PostgreSQL / in-memory                                          │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
              ▲                        ▲
              │ gRPC                   │ gRPC (signal)
              ▼                        ▼
┌──────────── Device (meshnet-agent) ─────────────────────────────┐
│                                                                   │
│  wireguard-go userspace TUN (meshnet0)                            │
│  └── IceBind  routes WireGuard packets through ICE net.Conn      │
│  pion/ice  per-peer NAT traversal agents                          │
│  Magic DNS  127.0.0.1:53535  →  hostname.mesh                    │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Docker Images

Pre-built images are published to GitHub Container Registry:

| Image | Pull command |
|---|---|
| Management | `docker pull ghcr.io/djr-fp/overlay/management:latest` |
| Signal | `docker pull ghcr.io/djr-fp/overlay/signal:latest` |
| Relay | `docker pull ghcr.io/djr-fp/overlay/relay:latest` |
| Dashboard | `docker pull ghcr.io/djr-fp/overlay/dashboard:latest` |

Image sizes: management 38MB · signal 19MB · relay 13MB · dashboard 155MB

## Quick Start

### Docker Compose (pre-built images)

```bash
git clone https://github.com/DJR-FP/overlay.git
cd overlay

cp .env.example .env
# Edit .env — set JWT_SECRET, POSTGRES_PASSWORD, RELAY_PUBLIC_IP

docker compose up -d
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| Management API | http://localhost:8080 |
| Management gRPC | localhost:50051 |
| Signal | localhost:10000 |
| TURN relay | UDP 3478 |

### Enroll a device

```bash
curl -fsSL https://raw.githubusercontent.com/DJR-FP/overlay/main/install.sh | \
  MESHNET_SETUP_KEY=MESHNET-DEFAULT-KEY \
  MESHNET_MANAGEMENT_URL=your-server:50051 \
  bash
```

The agent prints a JWT on first enrollment — paste it into the dashboard to sign in.

### Development (no Docker)

> Requires Go 1.23+, Node.js 20+, and root/sudo to create a TUN device.

```bash
# Build all binaries
go build -o bin/management ./management/cmd/server
go build -o bin/signal     ./signal/cmd/server
go build -o bin/relay      ./relay/cmd/server
go build -o bin/agent      ./client/cmd/agent

# Start services
MGMT_JWT_SECRET=dev ./bin/management   &   # terminal 1
./bin/signal                            &   # terminal 2
sudo MESHNET_SETUP_KEY=MESHNET-DEFAULT-KEY ./bin/agent  # terminal 3

# Dashboard
cd dashboard && npm install && npm run dev   # http://localhost:3000
```

---

## Project Structure

```
overlay/
├── management/     Management server — device registry, IPAM, REST + gRPC
├── signal/         ICE candidate relay — stateless gRPC message router
├── relay/          STUN/TURN relay — pion/turn, fallback for symmetric NAT
├── client/         Agent binary — WireGuard, ICE NAT traversal, Magic DNS
├── dashboard/      Web UI — Next.js 14, TypeScript, Tailwind CSS
├── proto/          Protobuf definitions (source of truth)
├── gen/            Generated Go stubs — do not edit
├── install.sh      One-line device enrollment script
└── docker-compose.yml
```

---

## Configuration

### Management Server

| Env var | Default | Description |
|---|---|---|
| `MGMT_GRPC_ADDR` | `:50051` | gRPC listen address |
| `MGMT_HTTP_ADDR` | `:8080` | REST API listen address |
| `MGMT_JWT_SECRET` | `change-me` | JWT signing secret |
| `MGMT_NETWORK_CIDR` | `100.64.0.0/10` | CGNAT IP pool |
| `MGMT_DNS_SUFFIX` | `mesh` | Magic DNS suffix |
| `DATABASE_URL` | _(empty = memory)_ | PostgreSQL DSN |
| `MESHNET_DEFAULT_KEY` | `MESHNET-DEFAULT-KEY` | Seed setup key |

### Agent

| Env var | Default | Description |
|---|---|---|
| `MESHNET_SETUP_KEY` | _(required)_ | Enrollment key |
| `MESHNET_MANAGEMENT_URL` | `localhost:50051` | Management gRPC address |
| `MESHNET_SIGNAL_URL` | `localhost:10000` | Signal gRPC address |
| `MESHNET_WG_IFACE` | `meshnet0` | TUN interface name |
| `MESHNET_STATE_DIR` | `/var/lib/meshnet` | Key + token persistence dir |
| `MESHNET_STUN_URLS` | `stun:stun.l.google.com:19302` | STUN/TURN URLs (comma-separated) |

### Relay

| Env var | Default | Description |
|---|---|---|
| `RELAY_PUBLIC_IP` | _(required)_ | Public IP of the relay host |
| `RELAY_UDP_PORT` | `3478` | STUN/TURN port |
| `RELAY_AUTH_USER` | `meshnet` | TURN long-term credential user |
| `RELAY_AUTH_PASS` | `change-me` | TURN password |

---

## How NAT Traversal Works

Standard WireGuard uses a fixed UDP socket. STUN would discover the external address of that socket, but the port mapping often doesn't survive NAT — hole-punching fails.

Meshnet solves this by using **wireguard-go** (userspace) with a custom `IceBind` (`conn.Bind` interface):

```
WireGuard device (wireguard-go)
    │
    ▼
IceBind  ──── per-peer net.Conn (from pion/ice)
    │
    ▼
ICE agent ──── STUN candidate → hole-punch → direct P2P
              (or TURN relay if hole-punch fails)
```

The ICE-established connection *is* the WireGuard transport — no port mismatch. Both peers arrive at the same UDP path and WireGuard handles encryption on top.

**Role assignment:** The peer with the lexicographically smaller WireGuard public key becomes the ICE controller. Deterministic, no coordination needed.

---

## Regenerating Protobuf Stubs

```bash
# Install once
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go install github.com/bufbuild/buf/cmd/buf@latest

# Regenerate after editing .proto files
buf generate
```

---

## Roadmap

### Next up
- [ ] **Subnet routing & exit node** — advertise a LAN subnet (`192.168.x.x/24`) or full exit node (`0.0.0.0/0`) through a mesh peer. Requires: route advertisement at enrollment, distributing routes via `SyncResponse.routes` (proto field already exists), applying `AllowedIPs` on peers, IP forwarding + NAT masquerade on the advertising device, and a dashboard toggle per device.

### Planned
- [ ] OIDC / SSO login (Google, GitHub)
- [ ] Access control rule editor in dashboard
- [ ] ICE restart on connection drop
- [ ] iOS + Android clients (wireguard-go + pion/ice)
- [ ] Kubernetes Helm chart

### Done ✅
- [x] WireGuard mesh with ICE NAT traversal (STUN hole-punching + TURN relay fallback)
- [x] CGNAT IP allocation (100.64.0.0/10) + Magic DNS (`hostname.mesh`)
- [x] Management server — gRPC + REST API, JWT auth, CORS
- [x] PostgreSQL store (GORM) with in-memory fallback
- [x] Setup keys — create, list, revoke via dashboard
- [x] Web dashboard — devices, setup keys, settings (Next.js 14)
- [x] Docker images published to GHCR
- [x] GitHub Actions CI — auto-build & push on every commit

---

## License

| Component | License |
|---|---|
| `client/`, `signal/`, `relay/`, `gen/`, `proto/` | MIT |
| `management/`, `dashboard/` | BSL 1.1 (converts to MIT after 4 years) |
