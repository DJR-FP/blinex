// Package wgmgr — routing-capable userspace netstack.
//
// This is an adaptation of wireguard-go's tun/netstack (SPDX MIT, Copyright
// WireGuard LLC) that additionally lets a netstack-mode peer act as a SUBNET
// ROUTER, the same way NetBird/Tailscale do it in userspace: the gVisor stack
// runs in promiscuous+spoofing mode and installs tcp/udp Forwarders. When a
// mesh peer sends traffic to an advertised LAN subnet, WireGuard decrypts it,
// the forwarder intercepts the connection, dials the real LAN target through
// the HOST's network stack, and relays bytes. Because the outbound dial uses
// the host's own socket, the LAN sees the router's host IP as source — SNAT is
// automatic, so no iptables MASQUERADE is needed in netstack mode.
//
// wireguard-go's own netstack keeps its *stack.Stack private and runs with
// HandleLocal:true (deliver-to-local-only, no forwarding), which is why we
// stand up our own stack here rather than wrapping theirs.
package wgmgr

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nsRouterNIC = 1

// RoutingNet is a userspace netstack that implements tun.Device (bridged to
// WireGuard) and can forward traffic destined to advertised LAN subnets out to
// the real network. It is a drop-in replacement for wireguard-go's netstack.Net
// for the manager and the host→mesh Forwarder (DialContext / DialUDP).
type RoutingNet struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	localAddr      netip.Addr
	dialer         net.Dialer

	mu      sync.RWMutex
	subnets []netip.Prefix // advertised routes this peer forwards to the real LAN
}

// createRoutingNetTUN builds the routing-capable netstack for the given mesh
// address. It returns the same object as both a tun.Device (for WireGuard) and
// a *RoutingNet (for dialing / subnet configuration).
func createRoutingNetTUN(localAddr netip.Addr, mtu int) (tun.Device, *RoutingNet, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        false,
	}
	dev := &RoutingNet{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
		localAddr:      localAddr,
	}

	sackEnabled := tcpip.TCPSACKEnabled(true)
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled); err != nil {
		return nil, nil, fmt.Errorf("enable TCP SACK: %v", err)
	}

	dev.ep.AddNotify(dev)
	if err := dev.stack.CreateNIC(nsRouterNIC, dev.ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}

	proto := ipv4.ProtocolNumber
	if localAddr.Is6() {
		proto = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddrFromSlice(localAddr.AsSlice()).WithPrefix(),
	}
	if err := dev.stack.AddProtocolAddress(nsRouterNIC, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", localAddr, err)
	}

	// Default routes so host→mesh dials leave via the NIC (→ WireGuard).
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nsRouterNIC})
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nsRouterNIC})

	// Accept packets for addresses we don't own (LAN dst) and reply with a
	// spoofed source (the LAN IP) — required for subnet forwarding.
	if err := dev.stack.SetPromiscuousMode(nsRouterNIC, true); err != nil {
		return nil, nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}
	if err := dev.stack.SetSpoofing(nsRouterNIC, true); err != nil {
		return nil, nil, fmt.Errorf("SetSpoofing: %v", err)
	}

	// Install tcp/udp forwarders that proxy connections to advertised subnets
	// out to the real network via the host stack.
	tcpFwd := tcp.NewForwarder(dev.stack, 0, 2048, dev.handleTCP)
	dev.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(dev.stack, dev.handleUDP)
	dev.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	dev.events <- tun.EventUp
	return dev, dev, nil
}

// SetSubnets configures which destination prefixes this peer forwards to the
// real LAN. Called from the engine when the peer's advertised routes change.
func (n *RoutingNet) SetSubnets(subnets []netip.Prefix) {
	n.mu.Lock()
	n.subnets = append(n.subnets[:0:0], subnets...)
	n.mu.Unlock()
	if len(subnets) > 0 {
		log.Info().Interface("subnets", subnets).Msg("netstack subnet router: forwarding enabled")
	}
}

// shouldForward reports whether dst falls inside a configured advertised subnet.
func (n *RoutingNet) shouldForward(dst netip.Addr) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, s := range n.subnets {
		if s.Contains(dst) {
			return true
		}
	}
	return false
}

func (n *RoutingNet) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dst, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok || !n.shouldForward(dst) {
		req.Complete(true) // send RST — not a forwarded destination
		return
	}
	var wq waiter.Queue
	ep, tcperr := req.CreateEndpoint(&wq)
	if tcperr != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	inConn := gonet.NewTCPConn(&wq, ep)

	target := net.JoinHostPort(dst.String(), fmt.Sprintf("%d", id.LocalPort))
	go func() {
		defer inConn.Close()
		outConn, err := n.dialer.DialContext(context.Background(), "tcp", target)
		if err != nil {
			log.Debug().Err(err).Str("dst", target).Msg("subnet router: TCP dial to LAN failed")
			return
		}
		defer outConn.Close()
		pipeConns(inConn, outConn)
	}()
}

func (n *RoutingNet) handleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	dst, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok || !n.shouldForward(dst) {
		return
	}
	var wq waiter.Queue
	ep, uerr := req.CreateEndpoint(&wq)
	if uerr != nil {
		return
	}
	inConn := gonet.NewUDPConn(n.stack, &wq, ep)

	target := net.JoinHostPort(dst.String(), fmt.Sprintf("%d", id.LocalPort))
	go func() {
		defer inConn.Close()
		outConn, err := n.dialer.DialContext(context.Background(), "udp", target)
		if err != nil {
			log.Debug().Err(err).Str("dst", target).Msg("subnet router: UDP dial to LAN failed")
			return
		}
		defer outConn.Close()
		pipeConns(inConn, outConn)
	}()
}

// pipeConns copies bytes bidirectionally between two connections until either
// side closes or errors.
func pipeConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// ---- tun.Device ----

func (n *RoutingNet) Name() (string, error)     { return "go", nil }
func (n *RoutingNet) File() *os.File            { return nil }
func (n *RoutingNet) Events() <-chan tun.Event  { return n.events }
func (n *RoutingNet) MTU() (int, error)         { return n.mtu, nil }
func (n *RoutingNet) BatchSize() int            { return 1 }

func (n *RoutingNet) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-n.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	m, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = m
	return 1, nil
}

func (n *RoutingNet) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			n.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

// WriteNotify drains outbound packets from the stack toward WireGuard.
func (n *RoutingNet) WriteNotify() {
	pkt := n.ep.Read()
	if pkt.IsNil() {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	n.incomingPacket <- view
}

func (n *RoutingNet) Close() error {
	n.stack.RemoveNIC(nsRouterNIC)
	if n.events != nil {
		close(n.events)
	}
	n.ep.Close()
	if n.incomingPacket != nil {
		close(n.incomingPacket)
	}
	return nil
}

// ---- dialing (host→mesh forwarder support) ----

// DialContext dials addr through the tunnel (used by the host→mesh Forwarder).
func (n *RoutingNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", address, err)
	}
	proto := ipv4.ProtocolNumber
	if ap.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	full := tcpip.FullAddress{NIC: nsRouterNIC, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, n.stack, full, proto)
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

// DialUDP opens a UDP conn through the tunnel (used by the host→mesh Forwarder).
func (n *RoutingNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	proto := ipv4.ProtocolNumber
	var full *tcpip.FullAddress
	if raddr != nil {
		if a, ok := netip.AddrFromSlice(raddr.IP); ok && a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		full = &tcpip.FullAddress{NIC: nsRouterNIC, Addr: tcpip.AddrFromSlice(raddr.IP), Port: uint16(raddr.Port)}
	}
	return gonet.DialUDP(n.stack, nil, full, proto)
}
