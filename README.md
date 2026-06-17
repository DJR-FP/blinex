# Meshnet

[![Version](https://img.shields.io/badge/version-v0.2.0-blue)](#roadmap)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20BSL--1.1-blue)](#license)
[![Build](https://github.com/DJR-FP/overlay/actions/workflows/docker.yml/badge.svg)](https://github.com/DJR-FP/overlay/actions/workflows/docker.yml)

A zero-trust WireGuard mesh VPN — open-source core, built for SMB and developer teams. Think Tailscale/NetBird, but simpler to self-host and extend.

---

## Features

- **Automatic NAT traversal** — ICE hole-punching (STUN) with TURN relay fallback; works across most NATs without port forwarding
- **Stable IPs** — every device gets a permanent CGNAT IP (`100.64.x.x`) and a Magic DNS hostname (`device.mesh`)
- **TLS encrypted control plane** — management and signal servers are TLS by default; self-signed cert generated automatically if none is provided
- **Exit node / subnet routing** — advertise a LAN subnet or full exit node through any mesh device; toggle per device in the dashboard
- **Simple onboarding** — one `curl | bash` to enroll a device; JWT token appears in the dashboard
- **Web dashboard** — manage devices, routes, setup keys from a browser
- **Self-hosted** — `docker compose up` and you own your data; no phone-home
- **PostgreSQL or in-memory** — swap the store with one env var

---

## Architecture

```
┌──────────────────────── Control Plane (TLS) ────────────────────────┐
│                                                                       │
│   Management Server           Signal Server        Relay Server      │
│   gRPC/TLS :50051             ICE candidate        STUN/TURN         │
│   HTTPS    :8080              relay (bidi gRPC/TLS) UDP :3478        │
│   JWT auth · REST API         :10000               pion/turn         │
│   PostgreSQL / in-memory                                              │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
              ▲                         ▲
              │ gRPC/TLS                │ gRPC/TLS
              ▼                         ▼
┌──────────── Device (meshnet-agent) ──────────────────────────────────┐
│                                                                       │
│  wireguard-go userspace TUN (meshnet0)                                │
│  └── IceBind  routes WireGuard packets through ICE net.Conn          │
│  pion/ice  per-peer NAT traversal agents                              │
│  Magic DNS  127.0.0.1:53535  →  hostname.mesh                        │
│  Subnet / exit node routing  (netlink + iptables MASQUERADE)         │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Docker Images

Pre-built images are published to GitHub Container Registry. Every push to `main` publishes `:latest`; version tags (e.g. `v0.2.0`) are published on release.

| Image | Pull command |
|---|---|
| Management | `docker pull ghcr.io/djr-fp/overlay/management:latest` |
| Signal | `docker pull ghcr.io/djr-fp/overlay/signal:latest` |
| Relay | `docker pull ghcr.io/djr-fp/overlay/relay:latest` |
| Dashboard | `docker pull ghcr.io/djr-fp/overlay/dashboard:latest` |

Pin a specific release: replace `:latest` with `:v0.2.0`.

---

## Quick Start

### Docker Compose (pre-built images)

```bash
git clone https://github.com/DJR-FP/overlay.git
cd overlay

cp .env.example .env
# Edit .env — set JWT_SECRET, POSTGRES_PASSWORD, RELAY_PUBLIC_IP

docker compose up -d
```

| Service | URL | Protocol |
|---|---|---|
| Dashboard | https://localhost:3000 | HTTPS |
| Management API | https://localhost:8080 | HTTPS |
| Management gRPC | localhost:50051 | gRPC/TLS |
| Signal | localhost:10000 | gRPC/TLS |
| TURN relay | localhost:3478 | UDP |

> **TLS note:** By default the management and signal servers generate a self-signed certificate on startup. Agents connect with `InsecureSkipVerify` enabled so everything works out of the box. See [TLS configuration](#tls) to provide real certificates.

### Enroll a device

```bash
curl -fsSL https://raw.githubusercontent.com/DJR-FP/overlay/main/install.sh | \
  MESHNET_SETUP_KEY=MESHNET-DEFAULT-KEY \
  MESHNET_MANAGEMENT_URL=your-server:50051 \
  bash
```

The agent prints a JWT on first enrollment — paste it into the dashboard to sign in.

### Development (no Docker)

> Requires Go 1.25+, Node.js 20+, and root/sudo to create a TUN device.

```bash
# Build all binaries (version injected from VERSION file)
make build

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
├── VERSION             Single source of truth for the release version
├── management/         Management server — device registry, IPAM, REST + gRPC
├── signal/             ICE candidate relay — stateless gRPC/TLS message router
├── relay/              STUN/TURN relay — pion/turn, fallback for symmetric NAT
├── client/             Agent binary — WireGuard, ICE, routing, Magic DNS
├── dashboard/          Web UI — Next.js 14, TypeScript, Tailwind CSS
├── proto/              Protobuf definitions (source of truth)
├── gen/                Generated Go stubs — do not edit
├── install.sh          One-line device enrollment script
└── docker-compose.yml
```

---

## Configuration

### Management Server

| Env var | Default | Description |
|---|---|---|
| `MGMT_GRPC_ADDR` | `:50051` | gRPC/TLS listen address |
| `MGMT_HTTP_ADDR` | `:8080` | HTTPS REST API listen address |
| `MGMT_JWT_SECRET` | `change-me` | JWT signing secret — **change in production** |
| `MGMT_NETWORK_CIDR` | `100.64.0.0/10` | CGNAT IP pool |
| `MGMT_DNS_SUFFIX` | `mesh` | Magic DNS suffix |
| `DATABASE_URL` | _(empty = memory)_ | PostgreSQL DSN |
| `MESHNET_DEFAULT_KEY` | `MESHNET-DEFAULT-KEY` | Seed setup key |
| `TLS_CERT_FILE` | _(empty = self-signed)_ | Path to TLS certificate PEM |
| `TLS_KEY_FILE` | _(empty = self-signed)_ | Path to TLS private key PEM |

### Signal Server

| Env var | Default | Description |
|---|---|---|
| `SIGNAL_ADDR` | `:10000` | gRPC/TLS listen address |
| `TLS_CERT_FILE` | _(empty = self-signed)_ | Path to TLS certificate PEM |
| `TLS_KEY_FILE` | _(empty = self-signed)_ | Path to TLS private key PEM |

### Agent

| Env var | Default | Description |
|---|---|---|
| `MESHNET_SETUP_KEY` | _(required)_ | Enrollment key |
| `MESHNET_MANAGEMENT_URL` | `localhost:50051` | Management gRPC address |
| `MESHNET_SIGNAL_URL` | `localhost:10000` | Signal gRPC address |
| `MESHNET_WG_IFACE` | `meshnet0` | TUN interface name |
| `MESHNET_STATE_DIR` | `/var/lib/meshnet` | Key + token persistence dir |
| `MESHNET_STUN_URLS` | `stun:stun.l.google.com:19302` | STUN/TURN URLs (comma-separated) |
| `MESHNET_TLS_SKIP_VERIFY` | `true` | Skip server cert verification (safe for self-signed) |
| `MESHNET_TLS_CA_CERT` | _(empty)_ | Path to CA cert PEM — pins a specific CA, disables skip-verify |

### Relay

| Env var | Default | Description |
|---|---|---|
| `RELAY_PUBLIC_IP` | _(required)_ | Public IP of the relay host |
| `RELAY_UDP_PORT` | `3478` | STUN/TURN port |
| `RELAY_AUTH_USER` | `meshnet` | TURN long-term credential user |
| `RELAY_AUTH_PASS` | `change-me` | TURN password |

---

## TLS

All control-plane connections (agent ↔ management, agent ↔ signal) are TLS encrypted.

### Default: self-signed certificate

No configuration needed. Both servers generate an in-memory ECDSA P-256 self-signed certificate on startup and log a warning:

```
WARN using self-signed TLS certificate — set TLS_CERT_FILE + TLS_KEY_FILE for production
```

Agents connect with `MESHNET_TLS_SKIP_VERIFY=true` (the default) so they accept self-signed certs. This prevents passive eavesdropping but does not defend against active MITM. Suitable for trusted private networks and home labs.

### Production: real certificates

Set on both management and signal servers:

```bash
TLS_CERT_FILE=/etc/meshnet/server.crt
TLS_KEY_FILE=/etc/meshnet/server.key
```

Set on agents:

```bash
# Option A — disable skip-verify (requires a CA trusted by the OS)
MESHNET_TLS_SKIP_VERIFY=false

# Option B — pin your own CA cert (recommended for self-hosted CA)
MESHNET_TLS_SKIP_VERIFY=false
MESHNET_TLS_CA_CERT=/etc/meshnet/ca.crt
```

Certificates can be obtained from Let's Encrypt (via Certbot or Caddy) or an internal CA.

---

## Subnet Routing & Exit Nodes

Any mesh device can advertise subnets or act as a full exit node. Configuration is done from the dashboard — no agent restart required.

### How it works

1. Admin opens a device in the dashboard → **Routes** → toggles **Exit node** or enters a subnet CIDR (e.g. `192.168.1.0/24`)
2. Management stores the routes and immediately pushes an updated `SyncResponse` to all connected agents
3. Each agent updates WireGuard `AllowedIPs` for the advertising peer
4. For subnet routes, the agent also adds an OS route via netlink
5. The advertising device automatically enables IP forwarding and adds an iptables `MASQUERADE` rule

### Exit node vs subnet routing

| | Exit node | Subnet routing |
|---|---|---|
| Advertised CIDR | `0.0.0.0/0` | e.g. `192.168.1.0/24` |
| Effect on other peers | All internet traffic routed through this device | Only traffic for that subnet routed through this device |
| Gateway setup | IP forwarding + masquerade | IP forwarding + masquerade |
| OS route on consumers | Manual (policy routing required) | Added automatically via netlink |

> **Exit node note:** WireGuard `AllowedIPs = 0.0.0.0/0` is set correctly on consuming peers, but OS default-route changes require policy routing to avoid breaking the management connection. This is left to the operator for now and is on the roadmap to automate.

---

## How NAT Traversal Works

Standard WireGuard uses a fixed UDP socket. STUN discovers the external address of that socket, but the port mapping often doesn't survive NAT — hole-punching fails.

Meshnet solves this with **wireguard-go** (userspace) and a custom `IceBind` (`conn.Bind` interface):

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

The ICE-established connection *is* the WireGuard transport — no port mismatch.

**Role assignment:** The peer with the lexicographically smaller WireGuard public key becomes the ICE controller. Deterministic, no coordination needed.

---

## Versioning

The current version is stored in the [`VERSION`](VERSION) file. It is injected into every binary at build time and exposed at runtime via:

- Startup log: `INFO meshnet management starting version=v0.2.0`
- Health endpoint: `GET /api/v1/health` → `{"status":"ok","version":"v0.2.0"}`

To release a new version:

```bash
# 1. Edit VERSION
echo "0.3.0" > VERSION

# 2. Commit
git add VERSION && git commit -m "chore: bump to v0.3.0"

# 3. Tag and push (triggers Docker image builds in CI)
make tag
```

Docker images are tagged with both `:latest` and `:vX.Y.Z` on every push to `main` and on version tags.

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
- [ ] **Exit node OS routing** — automate policy routing on consuming peers so `0.0.0.0/0` routes work without manual setup
- [ ] **OIDC / SSO login** — Google, GitHub OAuth2 as an alternative to setup key login
- [ ] **Access control rules** — source/destination/protocol policy editor in the dashboard

### Planned
- [ ] ICE restart on connection drop
- [ ] iOS + Android clients (wireguard-go + pion/ice)
- [ ] Kubernetes Helm chart

### Done ✅
- [x] TLS encryption on all control-plane connections (self-signed cert fallback)
- [x] Exit node / subnet routing — dashboard toggle, WG AllowedIPs, OS routes, IP forwarding + masquerade
- [x] Semantic versioning — `VERSION` file, ldflags injection, Docker image tags
- [x] WireGuard mesh with ICE NAT traversal (STUN hole-punching + TURN relay fallback)
- [x] CGNAT IP allocation (100.64.0.0/10) + Magic DNS (`hostname.mesh`)
- [x] Management server — gRPC + REST API, JWT auth, CORS
- [x] PostgreSQL store (GORM) with in-memory fallback
- [x] Setup keys — create, list, revoke via dashboard
- [x] Web dashboard — devices, routes, setup keys (Next.js 14)
- [x] Docker images published to GHCR (`:latest` + `:vX.Y.Z`)
- [x] GitHub Actions CI — auto-build & push on every commit

---

## License

| Component | License |
|---|---|
| `client/`, `signal/`, `relay/`, `gen/`, `proto/` | MIT |
| `management/`, `dashboard/` | BSL 1.1 (converts to MIT after 4 years) |
