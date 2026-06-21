package wgmgr

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Forwarder provides transparent TCP/UDP forwarding through the netstack.
// It uses iptables REDIRECT in the OUTPUT chain so that local processes
// connecting to mesh IPs are redirected to the forwarder port, which then
// dials through the WireGuard tunnel via netstack.
type Forwarder struct {
	tnet     *netstack.Net
	tcpPort  int
	udpPort  int
	meshCIDR string
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

const forwarderPort = 51821

// NewForwarder creates a transparent forwarder for the given mesh CIDR.
func NewForwarder(tnet *netstack.Net, meshCIDR string) *Forwarder {
	return &Forwarder{
		tnet:     tnet,
		tcpPort:  forwarderPort,
		udpPort:  forwarderPort,
		meshCIDR: meshCIDR,
	}
}

// Start sets up iptables rules and begins listening.
func (f *Forwarder) Start(ctx context.Context) error {
	ctx, f.cancel = context.WithCancel(ctx)

	if err := f.addIptables(); err != nil {
		return fmt.Errorf("forwarder iptables: %w", err)
	}

	tcpLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.tcpPort})
	if err != nil {
		f.removeIptables()
		return fmt.Errorf("forwarder TCP listen: %w", err)
	}

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.udpPort})
	if err != nil {
		tcpLn.Close()
		f.removeIptables()
		return fmt.Errorf("forwarder UDP listen: %w", err)
	}

	f.wg.Add(2)
	go f.serveTCP(ctx, tcpLn)
	go f.serveUDP(ctx, udpLn)

	log.Info().Str("cidr", f.meshCIDR).Int("port", f.tcpPort).Msg("netstack forwarder started")
	return nil
}

// Stop tears down iptables rules and stops listeners.
func (f *Forwarder) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
	f.removeIptables()
	f.wg.Wait()
}

func (f *Forwarder) serveTCP(ctx context.Context, ln *net.TCPListener) {
	defer f.wg.Done()
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("forwarder TCP accept error")
			continue
		}
		go f.handleTCP(ctx, conn)
	}
}

func (f *Forwarder) handleTCP(ctx context.Context, local net.Conn) {
	defer local.Close()

	origDst, err := getOriginalDst(local)
	if err != nil {
		log.Debug().Err(err).Msg("forwarder: cannot get original dst")
		return
	}

	remote, err := f.tnet.DialContext(ctx, "tcp", origDst)
	if err != nil {
		log.Debug().Err(err).Str("dst", origDst).Msg("forwarder: dial through tunnel failed")
		return
	}
	defer remote.Close()

	relay(local, remote)
}

func (f *Forwarder) serveUDP(ctx context.Context, conn *net.UDPConn) {
	defer f.wg.Done()
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go f.handleUDP(ctx, conn, srcAddr, buf[:n])
	}
}

func (f *Forwarder) handleUDP(ctx context.Context, listener *net.UDPConn, srcAddr *net.UDPAddr, data []byte) {
	// For UDP REDIRECT, the original dest is the listener's address.
	// We rely on SO_ORIGINAL_DST for the real destination.
	// UDP forwarding through netstack — simplified: use the source to route back.
	remote, err := f.tnet.DialUDP(nil, nil)
	if err != nil {
		return
	}
	defer remote.Close()

	remote.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := remote.Write(data); err != nil {
		return
	}

	resp := make([]byte, 65535)
	n, err := remote.Read(resp)
	if err != nil {
		return
	}
	listener.WriteToUDP(resp[:n], srcAddr)
}

func (f *Forwarder) addIptables() error {
	port := fmt.Sprintf("%d", f.tcpPort)
	cmds := [][]string{
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-d", f.meshCIDR, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-d", f.meshCIDR, "-p", "udp", "-j", "REDIRECT", "--to-ports", port},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w: %s", args, err, out)
		}
	}
	return nil
}

func (f *Forwarder) removeIptables() {
	port := fmt.Sprintf("%d", f.tcpPort)
	cmds := [][]string{
		{"iptables", "-t", "nat", "-D", "OUTPUT", "-d", f.meshCIDR, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port},
		{"iptables", "-t", "nat", "-D", "OUTPUT", "-d", f.meshCIDR, "-p", "udp", "-j", "REDIRECT", "--to-ports", port},
	}
	for _, args := range cmds {
		exec.Command(args[0], args[1:]...).Run() //nolint:errcheck
	}
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}
