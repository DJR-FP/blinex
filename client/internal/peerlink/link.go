// Package peerlink manages the data path to a single peer, switching between
// the always-available signal relay and a direct ICE connection when one is
// healthy. Modeled on Tailscale/Netbird: relay is the reliable default, ICE is
// an optimization that is only used after a probe confirms it passes traffic,
// and is abandoned the moment the probe stops responding.
package peerlink

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Probe packet types. WireGuard message types are 1–4; these high bytes are
// never valid WireGuard packets, so a peer running an older (relay-only) build
// simply drops them.
const (
	probePing = 0xFE
	probePong = 0xFD
)

const (
	probeInterval = 3 * time.Second
	probeTimeout  = 10 * time.Second
)

// Injector hands a received packet to WireGuard, tagged with the virtual
// endpoint so WireGuard attributes it to the right peer.
type Injector func(data []byte, src netip.AddrPort)

// Link is the net.Conn the WireGuard bind writes to for one peer. Writes go out
// over ICE when the direct path is healthy, otherwise over the relay.
type Link struct {
	ep        netip.AddrPort
	peerKey   string
	relayConn net.Conn
	inject    Injector

	mu       sync.RWMutex
	iceConn  net.Conn
	useICE   atomic.Bool
	lastPong atomic.Int64 // UnixNano of last probe-pong over ICE
	closed   chan struct{}
	once     sync.Once
}

// New creates a Link with the relay path active. ep is the virtual endpoint
// (e.g. 127.127.0.5:1) WireGuard uses to address this peer.
func New(ep netip.AddrPort, peerKey string, relayConn net.Conn, inject Injector) *Link {
	return &Link{
		ep:        ep,
		peerKey:   peerKey,
		relayConn: relayConn,
		inject:    inject,
		closed:    make(chan struct{}),
	}
}

// Write implements net.Conn — called by the WireGuard bind. Sends over the
// active path (ICE if healthy, else relay).
func (l *Link) Write(b []byte) (int, error) {
	if l.useICE.Load() {
		l.mu.RLock()
		ice := l.iceConn
		l.mu.RUnlock()
		if ice != nil {
			if n, err := ice.Write(b); err == nil {
				return n, nil
			}
			// ICE write failed — fall through to relay.
		}
	}
	return l.relayConn.Write(b)
}

// SetICEConn is called when ICE establishes a direct connection. It starts the
// receive and probe loops; the link only switches to ICE once probes succeed.
func (l *Link) SetICEConn(conn net.Conn) {
	l.mu.Lock()
	old := l.iceConn
	l.iceConn = conn
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	go l.iceReadLoop(conn)
	go l.probeLoop(conn)
	log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: ICE connected, probing direct path")
}

func (l *Link) iceReadLoop(conn net.Conn) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			// ICE path gone — revert to relay.
			if l.useICE.CompareAndSwap(true, false) {
				log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: ICE read error, reverted to relay")
			}
			l.mu.Lock()
			if l.iceConn == conn {
				l.iceConn = nil
			}
			l.mu.Unlock()
			return
		}
		if n == 1 {
			switch buf[0] {
			case probePing:
				_, _ = conn.Write([]byte{probePong})
				continue
			case probePong:
				l.lastPong.Store(time.Now().UnixNano())
				continue
			}
		}
		// Real WireGuard packet — inject into the bind for this peer.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		l.inject(pkt, l.ep)
	}
}

func (l *Link) probeLoop(conn net.Conn) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.closed:
			return
		case <-ticker.C:
			l.mu.RLock()
			cur := l.iceConn
			l.mu.RUnlock()
			if cur != conn {
				return // superseded by a newer ICE conn
			}
			if _, err := conn.Write([]byte{probePing}); err != nil {
				if l.useICE.CompareAndSwap(true, false) {
					log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: probe write failed, reverted to relay")
				}
				return
			}
			last := l.lastPong.Load()
			healthy := last > 0 && time.Since(time.Unix(0, last)) < probeTimeout
			if healthy && l.useICE.CompareAndSwap(false, true) {
				log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: direct ICE path healthy, upgraded from relay")
			} else if !healthy && l.useICE.CompareAndSwap(true, false) {
				log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: direct path stalled, reverted to relay")
			}
		}
	}
}

// UsingICE reports whether the direct path is currently active (for status/UX).
func (l *Link) UsingICE() bool { return l.useICE.Load() }

// Close stops the probe loop and releases the ICE conn. The relay conn is owned
// by the caller and closed separately.
func (l *Link) Close() {
	l.once.Do(func() { close(l.closed) })
	l.mu.Lock()
	if l.iceConn != nil {
		_ = l.iceConn.Close()
		l.iceConn = nil
	}
	l.mu.Unlock()
	l.useICE.Store(false)
}

func short(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
