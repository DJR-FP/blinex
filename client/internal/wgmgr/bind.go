package wgmgr

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// RelayBind implements conn.Bind with relay support, following Netbird's pattern.
// It uses a dedicated channel for relay packets and returns a separate ReceiveFunc
// for relay data, which wireguard-go runs in its own goroutine.
type RelayBind struct {
	mu        sync.RWMutex
	endpoints map[netip.AddrPort]net.Conn // fake endpoint → relay conn (for sending)
	relayCh   chan relayPacket            // relay receive channel
	doneCh    chan struct{}
	once      sync.Once
}

type relayPacket struct {
	data []byte
	src  netip.AddrPort
}

func NewRelayBind() *RelayBind {
	return &RelayBind{
		endpoints: make(map[netip.AddrPort]net.Conn),
		relayCh:   make(chan relayPacket, 512),
		doneCh:    make(chan struct{}),
	}
}

// SetEndpoint registers a relay conn for a fake endpoint address (for sending).
func (b *RelayBind) SetEndpoint(endpointStr string, c net.Conn) error {
	ap, err := netip.ParseAddrPort(endpointStr)
	if err != nil {
		return fmt.Errorf("parsing endpoint %q: %w", endpointStr, err)
	}
	b.mu.Lock()
	b.endpoints[ap] = c
	b.mu.Unlock()
	return nil
}

// ReceiveFromRelay injects a received packet into WireGuard via the relay channel.
func (b *RelayBind) ReceiveFromRelay(data []byte, src netip.AddrPort) {
	pkt := make([]byte, len(data))
	copy(pkt, data)
	select {
	case b.relayCh <- relayPacket{data: pkt, src: src}:
	case <-b.doneCh:
	}
}

// receiveRelayed is the ReceiveFunc that wireguard-go calls in its own goroutine.
func (b *RelayBind) receiveRelayed(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-b.doneCh:
		return 0, net.ErrClosed
	case pkt := <-b.relayCh:
		n := copy(bufs[0], pkt.data)
		sizes[0] = n
		eps[0] = &RelayEndpoint{addrPort: pkt.src}
		return 1, nil
	}
}

// ── conn.Bind interface ───────────────────────────────────────────────────────

func (b *RelayBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Reset doneCh so receiveRelayed works after a Close/Open cycle
	// (wireguard-go calls Close during init, then Open on device.Up).
	b.doneCh = make(chan struct{})
	b.once = sync.Once{}
	return []conn.ReceiveFunc{b.receiveRelayed}, 0, nil
}

func (b *RelayBind) Close() error {
	b.once.Do(func() {
		close(b.doneCh)
	})
	return nil
}

func (b *RelayBind) SetMark(_ uint32) error { return nil }

func (b *RelayBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	rEp, ok := ep.(*RelayEndpoint)
	if !ok {
		return fmt.Errorf("unexpected endpoint type %T", ep)
	}
	b.mu.RLock()
	c, found := b.endpoints[rEp.addrPort]
	b.mu.RUnlock()
	if !found {
		return fmt.Errorf("no relay conn for %s", rEp.addrPort)
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *RelayBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &RelayEndpoint{addrPort: ap}, nil
}

func (b *RelayBind) BatchSize() int { return 1 }

// ── RelayEndpoint ─────────────────────────────────────────────────────────────

type RelayEndpoint struct {
	addrPort netip.AddrPort
}

func (e *RelayEndpoint) ClearSrc()           {}
func (e *RelayEndpoint) SrcToString() string { return "" }
func (e *RelayEndpoint) DstToString() string { return e.addrPort.String() }
func (e *RelayEndpoint) DstToBytes() []byte {
	b, _ := e.addrPort.MarshalBinary()
	return b
}
func (e *RelayEndpoint) DstIP() netip.Addr { return e.addrPort.Addr() }
func (e *RelayEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
