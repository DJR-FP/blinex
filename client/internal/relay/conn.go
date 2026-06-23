package relay

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	signalv1 "github.com/blinex/gen/signal/v1"
)

var relayCounter atomic.Uint32

// Sender sends a signal message to a remote peer.
type Sender interface {
	Send(remoteKey string, body *signalv1.Body) error
}

// Conn implements net.Conn over the signal server's gRPC stream.
// WireGuard packets are relayed through the signal server as RELAY messages.
type Conn struct {
	selfKey   string
	peerKey   string
	signal    Sender
	closed    chan struct{}
	closeOnce sync.Once
	addr      *relayAddr
}

// New creates a relay connection to a specific peer via the signal server.
func New(selfKey, peerKey string, signal Sender) *Conn {
	n := relayCounter.Add(1)
	return &Conn{
		selfKey: selfKey,
		peerKey: peerKey,
		signal:  signal,
		closed:  make(chan struct{}),
		addr:    &relayAddr{ip: net.IPv4(127, 127, byte(n>>8), byte(n)), port: 1},
	}
}

// Read blocks until the conn is closed. Receiving is handled directly by the
// bind layer via ReceiveFromRelay, so this is never used for data.
func (c *Conn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

// Write sends a WireGuard packet to the peer through the signal server.
func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	if err := c.signal.Send(c.peerKey, &signalv1.Body{
		Type: signalv1.Body_RELAY,
		Data: cp,
	}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return &relayAddr{ip: net.IPv4(127, 127, 0, 0), port: 0}
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error   { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error  { return nil }

// Endpoint returns a parseable ip:port string for WireGuard.
// Uses 127.127.0.x:1 as a virtual address space for relay peers.
func (c *Conn) Endpoint() string {
	return c.addr.String()
}

type relayAddr struct {
	ip   net.IP
	port int
}

func (a *relayAddr) Network() string { return "udp" }
func (a *relayAddr) String() string {
	return fmt.Sprintf("%s:%d", a.ip, a.port)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
