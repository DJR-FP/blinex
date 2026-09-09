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

// Probe packet types, carried in the first byte. WireGuard message types are
// 1–4, so these high bytes are never a valid WireGuard packet: a peer running
// an older (relay-only) build simply drops them.
const (
	probePing = 0xFE
	probePong = 0xFD
)

const (
	probeInterval = 3 * time.Second
	probeTimeout  = 10 * time.Second

	// A direct path must answer this many consecutive probes before any traffic
	// is moved onto it. At probeInterval that is ~9s of uninterrupted
	// round-trips, so a single stray pong can no longer promote a path that
	// cannot actually carry traffic.
	upgradeThreshold = 3

	// After a promoted path stalls, wait before considering it again, doubling
	// on each successive stall. Without this a marginal path flaps forever:
	// revert to relay, re-promote on the next stray pong, black-hole traffic
	// until the probe times out, repeat.
	minUpgradeBackoff = 15 * time.Second
	maxUpgradeBackoff = 5 * time.Minute

	// A path that stays promoted this long has proven itself; its accumulated
	// backoff is forgiven so one bad patch doesn't penalize it permanently.
	backoffResetAfter = 2 * time.Minute

	// Probes are padded to this size so a completed round-trip proves the path
	// can carry full-size WireGuard packets rather than just a 1-byte datagram.
	// A marginal NAT binding or an MTU-limited path that passes tiny probes but
	// drops real traffic is precisely the failure a 1-byte probe cannot see.
	probePayloadSize = 1200
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
		// Probes are matched on the first byte at any length: peers on older
		// builds send unpadded 1-byte probes, and 0xFE/0xFD can never begin a
		// real WireGuard packet.
		if n >= 1 && (buf[0] == probePing || buf[0] == probePong) {
			if buf[0] == probePing {
				// Answer at the size we were probed with, so the reverse
				// direction is proven at full size too.
				pong := make([]byte, n)
				pong[0] = probePong
				_, _ = conn.Write(pong)
			} else {
				l.lastPong.Store(time.Now().UnixNano())
			}
			continue
		}
		// Real WireGuard packet — inject into the bind for this peer.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		l.inject(pkt, l.ep)
	}
}

// probeState folds each probe tick into a promote/demote decision. It is kept
// free of timers, sockets and locks so the promotion and backoff policy can be
// unit tested directly rather than only observed through a live link.
type probeState struct {
	consecutiveGood int
	seenPong        int64 // lastPong value observed on the previous tick
	backoff         time.Duration
	nextUpgrade     time.Time // not eligible to promote before this
	promotedAt      time.Time
	direct          bool
}

func newProbeState() *probeState { return &probeState{backoff: minUpgradeBackoff} }

// observe records one probe tick, where pong is the latest pong timestamp seen
// by the read loop (UnixNano, 0 if none yet), and reports whether the path
// should now be promoted to direct or demoted back to relay. retryIn is the
// backoff applied on a demotion, for logging.
func (p *probeState) observe(pong int64, now time.Time) (promote, demote bool, retryIn time.Duration) {
	// A tick counts as answered only if a *new* pong landed since the previous
	// tick. Testing the timestamp's age alone would let one pong satisfy every
	// tick inside probeTimeout — which is how a dead path used to keep looking
	// healthy for a full timeout window at a time.
	answered := pong != 0 && pong != p.seenPong &&
		now.Sub(time.Unix(0, pong)) < probeTimeout
	p.seenPong = pong
	if answered {
		p.consecutiveGood++
	} else {
		p.consecutiveGood = 0
	}

	if p.direct {
		if answered {
			return false, false, 0 // still good, stay direct
		}
		p.direct = false
		// Forgive accumulated backoff if the path had been stable a long while
		// before stalling, so one bad patch doesn't penalize it permanently.
		if !p.promotedAt.IsZero() && now.Sub(p.promotedAt) >= backoffResetAfter {
			p.backoff = minUpgradeBackoff
		}
		retryIn = p.backoff
		p.nextUpgrade = now.Add(p.backoff)
		if p.backoff *= 2; p.backoff > maxUpgradeBackoff {
			p.backoff = maxUpgradeBackoff
		}
		return false, true, retryIn
	}

	// On relay: promote only after sustained success, and only once the backoff
	// from any previous stall has elapsed.
	if p.consecutiveGood >= upgradeThreshold && now.After(p.nextUpgrade) {
		p.direct = true
		p.promotedAt = now
		return true, false, 0
	}
	return false, false, 0
}

func (l *Link) probeLoop(conn net.Conn) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	ping := make([]byte, probePayloadSize)
	ping[0] = probePing
	st := newProbeState()

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
			if _, err := conn.Write(ping); err != nil {
				if l.useICE.CompareAndSwap(true, false) {
					log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: probe write failed, reverted to relay")
				}
				return
			}

			promote, demote, retryIn := st.observe(l.lastPong.Load(), time.Now())
			switch {
			case promote:
				if l.useICE.CompareAndSwap(false, true) {
					log.Info().Str("peer", short(l.peerKey)).Msg("peerlink: direct ICE path healthy, upgraded from relay")
				}
			case demote:
				if l.useICE.CompareAndSwap(true, false) {
					log.Info().
						Str("peer", short(l.peerKey)).
						Dur("retry_in", retryIn).
						Msg("peerlink: direct path stalled, reverted to relay")
				}
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
