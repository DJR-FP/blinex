package relay

import (
	"net"
	"sync"
	"time"

	signalv1 "github.com/blinex/gen/signal/v1"
	"github.com/rs/zerolog/log"
)

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
	recvCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

// New creates a relay connection to a specific peer via the signal server.
func New(selfKey, peerKey string, signal Sender) *Conn {
	return &Conn{
		selfKey: selfKey,
		peerKey: peerKey,
		signal:  signal,
		recvCh:  make(chan []byte, 256),
		closed:  make(chan struct{}),
	}
}

// Deliver enqueues an incoming packet from the signal server.
func (c *Conn) Deliver(data []byte) {
	select {
	case c.recvCh <- data:
	default:
		log.Warn().Str("peer", c.peerKey[:min(8, len(c.peerKey))]).Msg("relay: recv buffer full, dropping packet")
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case pkt := <-c.recvCh:
		n := copy(b, pkt)
		return n, nil
	}
}

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
	return &relayAddr{key: c.selfKey}
}

func (c *Conn) RemoteAddr() net.Addr {
	return &relayAddr{key: c.peerKey}
}

func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error   { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error  { return nil }

type relayAddr struct{ key string }

func (a *relayAddr) Network() string { return "relay" }
func (a *relayAddr) String() string {
	if len(a.key) > 8 {
		return "relay:" + a.key[:8]
	}
	return "relay:" + a.key
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
