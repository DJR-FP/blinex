package wgmgr

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"github.com/rs/zerolog/log"
)

// IceBind implements conn.Bind. Each peer gets its own net.Conn (ICE connection);
// WireGuard traffic for that peer is routed through its ICE conn rather than raw UDP.
type IceBind struct {
	mu     sync.RWMutex
	conns  map[netip.AddrPort]net.Conn // endpoint addr → ICE conn
	recvCh chan recvPacket
	doneCh chan struct{}
	once   sync.Once
}

type recvPacket struct {
	data []byte
	src  netip.AddrPort
}

func NewIceBind() *IceBind {
	return &IceBind{
		conns:  make(map[netip.AddrPort]net.Conn),
		recvCh: make(chan recvPacket, 512),
		doneCh: make(chan struct{}),
	}
}

// AddConn registers an ICE-established net.Conn for the given remote endpoint
// and starts a receive loop that feeds packets into WireGuard.
func (b *IceBind) AddConn(endpointStr string, c net.Conn) error {
	ap, err := netip.ParseAddrPort(endpointStr)
	if err != nil {
		return fmt.Errorf("parsing endpoint %q: %w", endpointStr, err)
	}
	b.mu.Lock()
	b.conns[ap] = c
	b.mu.Unlock()

	go b.receiveLoop(ap, c)
	return nil
}

// RemoveConn removes and closes the ICE conn for an endpoint.
func (b *IceBind) RemoveConn(endpointStr string) {
	ap, err := netip.ParseAddrPort(endpointStr)
	if err != nil {
		return
	}
	b.mu.Lock()
	c, ok := b.conns[ap]
	delete(b.conns, ap)
	b.mu.Unlock()
	if ok {
		c.Close()
	}
}

func (b *IceBind) receiveLoop(src netip.AddrPort, c net.Conn) {
	log.Debug().Str("src", src.String()).Msg("bind: receiveLoop started")
	buf := make([]byte, 1<<16)
	for {
		n, err := c.Read(buf)
		if err != nil {
			log.Warn().Err(err).Str("src", src.String()).Msg("bind: receiveLoop exiting")
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case b.recvCh <- recvPacket{data: pkt, src: src}:
		case <-b.doneCh:
			return
		}
	}
}

// ── conn.Bind interface ───────────────────────────────────────────────────────

func (b *IceBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.doneCh:
			return 0, net.ErrClosed
		case pkt := <-b.recvCh:
			n := copy(bufs[0], pkt.data)
			sizes[0] = n
			eps[0] = &IceEndpoint{addrPort: pkt.src}
			log.Debug().Int("bytes", n).Str("from", pkt.src.String()).Int("type", int(bufs[0][0])).Msg("bind: recv → WireGuard")
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

func (b *IceBind) Close() error {
	b.once.Do(func() { close(b.doneCh) })
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		c.Close()
	}
	return nil
}

func (b *IceBind) SetMark(_ uint32) error { return nil }

func (b *IceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ice, ok := ep.(*IceEndpoint)
	if !ok {
		return fmt.Errorf("unexpected endpoint type %T", ep)
	}
	b.mu.RLock()
	c, found := b.conns[ice.addrPort]
	b.mu.RUnlock()
	if !found {
		log.Warn().Str("endpoint", ice.addrPort.String()).Int("conns", len(b.conns)).Msg("bind: Send failed — no conn")
		return fmt.Errorf("no conn for endpoint %s (have %d conns)", ice.addrPort, len(b.conns))
	}
	for _, buf := range bufs {
		log.Debug().Int("bytes", len(buf)).Str("to", ice.addrPort.String()).Int("type", int(buf[0])).Msg("bind: Send from WireGuard")
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *IceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &IceEndpoint{addrPort: ap}, nil
}

func (b *IceBind) BatchSize() int { return 1 }

// ── IceEndpoint ───────────────────────────────────────────────────────────────

type IceEndpoint struct {
	addrPort netip.AddrPort
}

func (e *IceEndpoint) ClearSrc()           {}
func (e *IceEndpoint) SrcToString() string { return "" }
func (e *IceEndpoint) DstToString() string { return e.addrPort.String() }
func (e *IceEndpoint) DstToBytes() []byte {
	b, _ := e.addrPort.MarshalBinary()
	return b
}
func (e *IceEndpoint) DstIP() netip.Addr { return e.addrPort.Addr() }
func (e *IceEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
