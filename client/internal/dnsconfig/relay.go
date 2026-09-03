package dnsconfig

import (
	"net"
	"sync"

	"github.com/rs/zerolog/log"
)

// relay is a dumb UDP forwarder from a privileged port (53, what every OS's
// system resolver actually queries) to the agent's own resolver (53535, an
// unprivileged port chosen so the agent doesn't need root just to run).
// Netstack peers have no real network interface to hang a per-link DNS
// override off of (that's what dnsconfig.Apply/Revert use on kernel-TUN
// Linux instead), so making the system's global DNS settings point at
// 127.0.0.1:53 only works if something is actually listening there.
type relay struct {
	conn net.PacketConn
	stop chan struct{}
	wg   sync.WaitGroup
}

// startRelay binds listenAddr (normally "127.0.0.1:53") and forwards every
// packet to targetAddr (normally "127.0.0.1:53535"), and forwards the
// response back. Returns nil if the bind fails (e.g. no permission for the
// privileged port) — the caller should treat that as "netstack DNS
// auto-configuration unavailable" and fall back to leaving DNS untouched,
// not as a fatal error.
func startRelay(listenAddr, targetAddr string) *relay {
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Warn().Err(err).Str("addr", listenAddr).Msg("dnsconfig: could not bind DNS relay port (needs root/admin) — leaving system DNS untouched")
		return nil
	}
	r := &relay{conn: conn, stop: make(chan struct{})}
	r.wg.Add(1)
	go r.serve(targetAddr)
	return r
}

func (r *relay) serve(targetAddr string) {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.stop:
				return // Close() caused this, not a real error
			default:
				return
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go r.forward(pkt, addr, targetAddr)
	}
}

func (r *relay) forward(pkt []byte, replyTo net.Addr, targetAddr string) {
	upstream, err := net.Dial("udp", targetAddr)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(pkt); err != nil {
		return
	}
	resp := make([]byte, 4096)
	n, err := upstream.Read(resp)
	if err != nil {
		return
	}
	_, _ = r.conn.WriteTo(resp[:n], replyTo)
}

func (r *relay) Close() {
	close(r.stop)
	_ = r.conn.Close()
	r.wg.Wait()
}
