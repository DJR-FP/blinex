package peerlink

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn that records writes and can feed reads.
type fakeConn struct {
	mu       sync.Mutex
	written  [][]byte
	readCh   chan []byte
	closed   bool
	writeErr error
}

func newFakeConn() *fakeConn { return &fakeConn{readCh: make(chan []byte, 16)} }

func (c *fakeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	c.written = append(c.written, cp)
	return len(b), nil
}

func (c *fakeConn) Read(b []byte) (int, error) {
	data, ok := <-c.readCh
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, data), nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.readCh)
	}
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeConn) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.written)
}

func newTestLink(relay net.Conn, inject Injector) *Link {
	ep := netip.MustParseAddrPort("127.127.0.1:1")
	return New(ep, "peerkey", relay, inject)
}

func TestWriteUsesRelayByDefault(t *testing.T) {
	relay := newFakeConn()
	l := newTestLink(relay, func([]byte, netip.AddrPort) {})
	if _, err := l.Write([]byte("wireguard-packet")); err != nil {
		t.Fatal(err)
	}
	if relay.writes() != 1 {
		t.Fatalf("expected write to go via relay, got %d relay writes", relay.writes())
	}
	if l.UsingICE() {
		t.Fatal("should not be using ICE before probe succeeds")
	}
}

func TestWriteFallsBackToRelayOnICEError(t *testing.T) {
	relay := newFakeConn()
	l := newTestLink(relay, func([]byte, netip.AddrPort) {})
	ice := newFakeConn()
	ice.writeErr = net.ErrClosed
	l.mu.Lock()
	l.iceConn = ice
	l.mu.Unlock()
	l.useICE.Store(true)

	if _, err := l.Write([]byte("pkt")); err != nil {
		t.Fatalf("write should succeed via relay fallback: %v", err)
	}
	if relay.writes() != 1 {
		t.Fatalf("expected relay fallback write, got %d", relay.writes())
	}
}

func TestProbePingGetsPong(t *testing.T) {
	relay := newFakeConn()
	l := newTestLink(relay, func([]byte, netip.AddrPort) {})
	ice := newFakeConn()
	// Start only the read loop (probeLoop would need timing); feed a ping.
	go l.iceReadLoop(ice)
	ice.readCh <- []byte{probePing}
	// The read loop should answer with a pong written back to the ice conn.
	deadline := time.After(time.Second)
	for {
		if ice.writes() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected a pong to be written in response to ping")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	l.Close()
}

func TestInjectDeliversRealPacket(t *testing.T) {
	relay := newFakeConn()
	var got []byte
	var mu sync.Mutex
	l := newTestLink(relay, func(data []byte, _ netip.AddrPort) {
		mu.Lock()
		got = data
		mu.Unlock()
	})
	ice := newFakeConn()
	go l.iceReadLoop(ice)
	ice.readCh <- []byte("real-wireguard-payload")

	deadline := time.After(time.Second)
	for {
		mu.Lock()
		done := got != nil
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected injected packet")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if string(got) != "real-wireguard-payload" {
		t.Fatalf("wrong injected payload: %q", got)
	}
	l.Close()
}

func TestCloseIsIdempotent(t *testing.T) {
	l := newTestLink(newFakeConn(), func([]byte, netip.AddrPort) {})
	l.Close()
	l.Close() // must not panic on double close
}

// --- direct-path promotion policy (probeState) ---
//
// These cover the flapping regression seen live against a peer behind a home
// NAT: the direct path answered the occasional probe but could not carry
// traffic, and the link oscillated relay→direct→relay every ~12s, black-holing
// packets for ~9s at a time.

// pongAt returns a pong timestamp fresh enough to count at now.
func pongAt(now time.Time) int64 { return now.Add(-50 * time.Millisecond).UnixNano() }

func TestStrayPongNeverPromotes(t *testing.T) {
	st := newProbeState()
	now := time.Now()
	// One pong arrives, then nothing more — exactly the marginal-path case.
	// The stale timestamp must not satisfy tick after tick.
	stray := pongAt(now)
	for i := 0; i < 10; i++ {
		now = now.Add(probeInterval)
		promote, _, _ := st.observe(stray, now)
		if promote {
			t.Fatalf("tick %d: promoted on a single stray pong", i)
		}
	}
	if st.direct {
		t.Fatal("path went direct without sustained round-trips")
	}
}

func TestPromotesOnlyAfterConsecutiveGoodProbes(t *testing.T) {
	st := newProbeState()
	now := time.Now()
	for i := 1; i < upgradeThreshold; i++ {
		now = now.Add(probeInterval)
		if promote, _, _ := st.observe(pongAt(now), now); promote {
			t.Fatalf("promoted after only %d good probes, want %d", i, upgradeThreshold)
		}
	}
	now = now.Add(probeInterval)
	promote, _, _ := st.observe(pongAt(now), now)
	if !promote {
		t.Fatalf("expected promotion after %d consecutive good probes", upgradeThreshold)
	}
}

// promote drives st to the direct state and returns the advanced clock.
func promote(t *testing.T, st *probeState, now time.Time) time.Time {
	t.Helper()
	for i := 0; i < upgradeThreshold; i++ {
		now = now.Add(probeInterval)
		st.observe(pongAt(now), now)
	}
	if !st.direct {
		t.Fatal("setup: expected the path to be promoted")
	}
	return now
}

func TestStallDemotesAndBlocksImmediateRepromotion(t *testing.T) {
	st := newProbeState()
	now := promote(t, st, time.Now())

	// Path stalls: no new pong on this tick.
	now = now.Add(probeInterval)
	_, demote, retryIn := st.observe(st.seenPong, now)
	if !demote {
		t.Fatal("expected a demotion when the path stopped answering")
	}
	if retryIn != minUpgradeBackoff {
		t.Fatalf("retryIn = %v, want %v", retryIn, minUpgradeBackoff)
	}

	// Even with perfect probes, it must not go straight back to direct — that
	// immediate re-promotion is what produced the 12-second oscillation.
	for i := 0; i < upgradeThreshold+2; i++ {
		now = now.Add(probeInterval)
		if p, _, _ := st.observe(pongAt(now), now); p {
			t.Fatalf("re-promoted %v after a stall, inside the %v backoff",
				time.Duration(i+1)*probeInterval, minUpgradeBackoff)
		}
	}

	// Once the backoff has elapsed, a healthy path is allowed back.
	now = now.Add(minUpgradeBackoff)
	var promoted bool
	for i := 0; i < upgradeThreshold; i++ {
		now = now.Add(probeInterval)
		if p, _, _ := st.observe(pongAt(now), now); p {
			promoted = true
		}
	}
	if !promoted {
		t.Fatal("expected re-promotion once the backoff elapsed")
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	st := newProbeState()
	now := time.Now()
	want := minUpgradeBackoff
	for i := 0; i < 8; i++ {
		now = promote(t, st, now)
		now = now.Add(probeInterval)
		_, demote, retryIn := st.observe(st.seenPong, now)
		if !demote {
			t.Fatalf("round %d: expected demotion", i)
		}
		if retryIn != want {
			t.Fatalf("round %d: retryIn = %v, want %v", i, retryIn, want)
		}
		if want *= 2; want > maxUpgradeBackoff {
			want = maxUpgradeBackoff
		}
		now = now.Add(retryIn) // serve the backoff before the next round
	}
	if want != maxUpgradeBackoff {
		t.Fatalf("backoff settled at %v, want the %v cap", want, maxUpgradeBackoff)
	}
}

func TestStablePathForgivesEarlierBackoff(t *testing.T) {
	st := newProbeState()
	now := time.Now()

	// One stall, so backoff has grown past the minimum.
	now = promote(t, st, now)
	now = now.Add(probeInterval)
	st.observe(st.seenPong, now)
	now = now.Add(minUpgradeBackoff)
	now = promote(t, st, now)

	// Now hold the path healthy well past backoffResetAfter before stalling.
	for now.Sub(st.promotedAt) < backoffResetAfter+probeInterval {
		now = now.Add(probeInterval)
		st.observe(pongAt(now), now)
	}
	now = now.Add(probeInterval)
	_, demote, retryIn := st.observe(st.seenPong, now)
	if !demote {
		t.Fatal("expected demotion after the long-stable path stalled")
	}
	if retryIn != minUpgradeBackoff {
		t.Fatalf("retryIn = %v, want the backoff forgiven back to %v", retryIn, minUpgradeBackoff)
	}
}

func TestPaddedPingIsAnsweredAtSameSize(t *testing.T) {
	relay := newFakeConn()
	l := newTestLink(relay, func([]byte, netip.AddrPort) {})
	ice := newFakeConn()
	go l.iceReadLoop(ice)

	ping := make([]byte, probePayloadSize)
	ping[0] = probePing
	ice.readCh <- ping

	deadline := time.After(time.Second)
	for ice.writes() == 0 {
		select {
		case <-deadline:
			t.Fatal("no pong written in response to a padded ping")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	ice.mu.Lock()
	got := ice.written[0]
	ice.mu.Unlock()
	if len(got) != probePayloadSize {
		t.Fatalf("pong was %d bytes, want %d — the reverse path must be proven at full size too",
			len(got), probePayloadSize)
	}
	if got[0] != probePong {
		t.Fatalf("first byte = %#x, want probePong %#x", got[0], probePong)
	}
	l.Close()
}
