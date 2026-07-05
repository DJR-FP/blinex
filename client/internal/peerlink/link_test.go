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
