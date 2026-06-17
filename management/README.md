# management

Management server — the control plane for Meshnet. Handles device enrollment, IP allocation, peer list distribution, and the REST API consumed by the dashboard.

## Responsibilities

- **Device enrollment** — validates setup keys, allocates CGNAT IPs, issues JWT tokens
- **Peer sync** — server-streaming gRPC that pushes peer list updates to all connected agents
- **IPAM** — thread-safe allocator over `100.64.0.0/10`
- **REST API** — peers CRUD, setup key CRUD, protected by JWT
- **Storage** — in-memory (dev) or PostgreSQL via GORM (production)

## Endpoints

### gRPC (`:50051`)

| RPC | Description |
|---|---|
| `GetServerKey` | Returns the server's WireGuard public key |
| `Login` | Enroll a device with a setup key; returns IP + JWT |
| `Sync` | Server-streaming; pushes peer list on every network change |
| `UpdatePeerMeta` | Agent reports updated hostname/OS/kernel |

### HTTP REST (`:8080`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/health` | None | Health check |
| GET | `/api/v1/peers` | JWT | List peers in your account |
| DELETE | `/api/v1/peers/:key` | JWT | Remove a peer |
| GET | `/api/v1/setup-keys` | JWT | List setup keys |
| POST | `/api/v1/setup-keys` | JWT | Create a setup key |
| DELETE | `/api/v1/setup-keys/:id` | JWT | Revoke a setup key |

## Package layout

```
management/
├── cmd/server/main.go              Entry point; picks store based on DATABASE_URL
├── internal/
│   ├── config/config.go            Env-based config (MGMT_* vars)
│   ├── domain/
│   │   ├── peer.go                 Peer struct
│   │   └── account.go             Account + SetupKey structs
│   ├── store/
│   │   ├── store.go               Store interface
│   │   ├── memory/store.go        Thread-safe in-memory impl
│   │   └── postgres/store.go      GORM PostgreSQL impl
│   ├── grpcserver/
│   │   ├── server.go              ManagementService impl
│   │   └── ipam.go               CGNAT IP allocator
│   ├── httpserver/server.go       Gin REST API + CORS middleware
│   └── auth/auth.go               JWT issue + validate (HS256, 30-day expiry)
```

## Environment variables

| Var | Default | Description |
|---|---|---|
| `MGMT_GRPC_ADDR` | `:50051` | gRPC listen address |
| `MGMT_HTTP_ADDR` | `:8080` | HTTP listen address |
| `MGMT_JWT_SECRET` | `change-me-in-production` | JWT HMAC secret |
| `MGMT_NETWORK_CIDR` | `100.64.0.0/10` | IP pool for peer allocation |
| `MGMT_DNS_SUFFIX` | `mesh` | Magic DNS suffix |
| `DATABASE_URL` | _(empty)_ | PostgreSQL DSN; empty = in-memory |
| `MESHNET_DEFAULT_KEY` | `MESHNET-DEFAULT-KEY` | Setup key seeded at startup |
