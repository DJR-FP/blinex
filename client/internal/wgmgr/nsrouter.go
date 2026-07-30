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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	xicmp "golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
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

// meshExclude is never proxied out to the real network even under a 0.0.0.0/0
// (exit-node) advertisement — mesh-internal traffic must stay on the mesh.
var meshExclude = netip.MustParsePrefix("100.64.0.0/10")

// shouldForward reports whether dst is a destination this peer proxies to the
// real network: inside a configured advertised subnet (a specific LAN, or
// 0.0.0.0/0 for an exit node), a routable unicast address, and not mesh-internal.
func (n *RoutingNet) shouldForward(dst netip.Addr) bool {
	if !dst.IsValid() || dst.IsLoopback() || dst.IsUnspecified() ||
		dst.IsLinkLocalUnicast() || dst.IsMulticast() || meshExclude.Contains(dst) {
		return false
	}
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

// interceptICMPv4 detects an IPv4 ICMP echo request to a forwarded destination
// and re-originates it from the host (see forwardICMPv4). gVisor exposes tcp/udp
// Forwarders but not one for ICMP, so ping-through-router is handled at the link
// layer. Returns true if the packet was consumed (must not be injected).
func (n *RoutingNet) interceptICMPv4(packet []byte) bool {
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return false
	}
	if packet[9] != uint8(header.ICMPv4ProtocolNumber) {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || len(packet) < ihl+header.ICMPv4MinimumSize {
		return false
	}
	if packet[ihl] != byte(header.ICMPv4Echo) { // ICMP type 8 = echo request
		return false
	}
	dst, ok := netip.AddrFromSlice(packet[16:20])
	if !ok || !n.shouldForward(dst) {
		return false
	}
	src, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return false
	}
	icmpMsg := append([]byte(nil), packet[ihl:]...)
	go n.forwardICMPv4(src, dst, icmpMsg)
	return true
}

// forwardICMPv4 pings dst from the host and, on success, injects a crafted echo
// reply back toward src (the mesh sender) so ping/traceroute work through a
// netstack exit node / subnet router.
func (n *RoutingNet) forwardICMPv4(src, dst netip.Addr, icmpMsg []byte) {
	defer func() { _ = recover() }() // incomingPacket may close on shutdown

	ident := binary.BigEndian.Uint16(icmpMsg[4:6])
	seq := binary.BigEndian.Uint16(icmpMsg[6:8])
	payload := icmpMsg[header.ICMPv4MinimumSize:]
	if !pingHost(dst, ident, seq, payload) {
		return
	}

	total := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	pkt := make([]byte, total)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(dst.AsSlice()), // reply comes "from" the target
		DstAddr:     tcpip.AddrFromSlice(src.AsSlice()), // back to the mesh sender
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	ic := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	ic.SetType(header.ICMPv4EchoReply)
	ic.SetCode(0)
	ic.SetIdent(ident)
	ic.SetSequence(seq)
	copy(pkt[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], payload)
	ic.SetChecksum(0)
	ic.SetChecksum(^checksum.Checksum(ic, 0))

	n.incomingPacket <- buffer.NewViewWithData(pkt)
}

// pingHost echoes dst from the host, preferring an unprivileged datagram ICMP
// socket and falling back to a raw socket. Returns true if a reply arrives.
func pingHost(dst netip.Addr, ident, seq uint16, payload []byte) bool {
	msg := xicmp.Message{
		Type: xipv4.ICMPTypeEcho, Code: 0,
		Body: &xicmp.Echo{ID: int(ident), Seq: int(seq), Data: payload},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	for _, network := range []string{"udp4", "ip4:icmp"} {
		c, err := xicmp.ListenPacket(network, "0.0.0.0")
		if err != nil {
			continue
		}
		var to net.Addr = &net.IPAddr{IP: net.IP(dst.AsSlice())}
		if network == "udp4" {
			to = &net.UDPAddr{IP: net.IP(dst.AsSlice())}
		}
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := c.WriteTo(wire, to); err != nil {
			c.Close()
			continue
		}
		resp := make([]byte, 1500)
		nn, _, err := c.ReadFrom(resp)
		c.Close()
		if err != nil {
			continue
		}
		if rm, err := xicmp.ParseMessage(1, resp[:nn]); err == nil && rm.Type == xipv4.ICMPTypeEchoReply {
			return true
		}
	}
	return false
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
		// ICMP echo to a forwarded destination is handled out-of-band (the
		// gVisor stack has no ICMP transport forwarder like tcp/udp do).
		if n.interceptICMPv4(packet) {
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
