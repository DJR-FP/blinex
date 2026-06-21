# relay

STUN and TURN relay server for NAT traversal fallback. Built on `pion/turn`. Used when direct ICE hole-punching fails (e.g. symmetric NAT on both sides).

## When it's used

ICE tries candidates in priority order:
1. Host candidates (direct LAN)
2. Server-reflexive candidates (STUN — discovers external IP:port)
3. Relay candidates (TURN — traffic relayed through this server)

The relay is only used for peer pairs where neither STUN nor direct connection succeeds.

## Environment variables

| Var | Default | Description |
|---|---|---|
| `RELAY_PUBLIC_IP` | _(required)_ | Public IP of this server |
| `RELAY_UDP_PORT` | `3478` | STUN/TURN UDP port |
| `RELAY_REALM` | `blinex.co.uk` | TURN realm string |
| `RELAY_AUTH_USER` | `blinex` | Long-term credential username |
| `RELAY_AUTH_PASS` | `change-me-in-production` | Long-term credential password |

## Agent configuration

To use this relay, set `BLINEX_STUN_URLS` on the agent:

```bash
BLINEX_STUN_URLS="stun:stun.l.google.com:19302,turn:relay.example.com:3478" \
  ./bin/agent
```

TURN credentials are currently hardcoded to the values in `RELAY_AUTH_USER` / `RELAY_AUTH_PASS`. TURN URI with embedded credentials support is planned.

## Package layout

```
relay/
├── cmd/server/main.go
└── internal/server/server.go    pion/turn server setup + long-term auth handler
```
