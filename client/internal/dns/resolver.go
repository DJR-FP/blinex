package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/dns/dnsmessage"
)

// Resolver is a simple UDP DNS server that answers A queries for the mesh
// domain (e.g. "laptop.alice.blinex") and forwards everything else upstream.
type Resolver struct {
	listenAddr string
	suffix     string // e.g. "blinex" — without the trailing dot
	upstream   string // e.g. "8.8.8.8:53"

	mu      sync.RWMutex
	records map[string]net.IP   // "hostname.suffix" → IP
	blocked map[string]struct{} // malicious domains, FQDN with trailing dot → blocked
}

func New(listenAddr, suffix, upstream string) *Resolver {
	return &Resolver{
		listenAddr: listenAddr,
		suffix:     strings.ToLower(strings.Trim(suffix, ".")),
		upstream:   upstream,
		records:    make(map[string]net.IP),
		blocked:    make(map[string]struct{}),
	}
}

// SetBlocklist replaces the malicious-domain list wholesale. domains are
// plain names without a trailing dot (e.g. "evil.example"); blocking a
// domain also blocks all of its subdomains.
func (r *Resolver) SetBlocklist(domains []string) {
	blocked := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		blocked[d+"."] = struct{}{}
	}
	r.mu.Lock()
	r.blocked = blocked
	r.mu.Unlock()
}

// isBlocked reports whether name (a lowercased FQDN with trailing dot) or
// any parent domain of it is on the blocklist.
func (r *Resolver) isBlocked(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.blocked) == 0 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := range labels {
		if _, ok := r.blocked[strings.Join(labels[i:], ".")+"."]; ok {
			return true
		}
	}
	return false
}

// Upsert adds or updates a DNS record. label is the host part (e.g. "laptop").
func (r *Resolver) Upsert(label, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fqdn := strings.ToLower(label+"."+r.suffix) + "."
	r.records[fqdn] = net.ParseIP(ip)
	log.Debug().Str("fqdn", fqdn).Str("ip", ip).Msg("DNS record upserted")
}

// Remove deletes a DNS record.
func (r *Resolver) Remove(label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fqdn := strings.ToLower(label+"."+r.suffix) + "."
	delete(r.records, fqdn)
}

// Serve starts the UDP listener and blocks until it returns an error.
func (r *Resolver) Serve() error {
	pc, err := net.ListenPacket("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("DNS listen %s: %w", r.listenAddr, err)
	}
	defer pc.Close()
	log.Info().Str("addr", r.listenAddr).Str("suffix", r.suffix).Msg("DNS resolver started")

	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		// Copy the packet: buf is reused by the next ReadFrom, so the handler
		// goroutine must not alias it.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go r.handle(pc, addr, pkt)
	}
}

func (r *Resolver) handle(pc net.PacketConn, addr net.Addr, raw []byte) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return
	}
	if len(msg.Questions) == 0 {
		return
	}

	q := msg.Questions[0]
	name := strings.ToLower(q.Name.String())

	r.mu.RLock()
	ip, ok := r.records[name]
	r.mu.RUnlock()

	if ok && q.Type == dnsmessage.TypeA && ip.To4() != nil {
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 msg.ID,
				Response:           true,
				Authoritative:      true,
				RecursionDesired:   msg.RecursionDesired,
				RecursionAvailable: false,
			},
			Questions: msg.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: [4]byte(ip.To4())},
			}},
		}
		packed, err := resp.Pack()
		if err == nil {
			_, _ = pc.WriteTo(packed, addr)
		}
		return
	}

	if r.isBlocked(name) {
		r.respondNXDOMAIN(pc, addr, msg)
		return
	}

	// Forward to upstream resolver.
	r.forward(pc, addr, raw)
}

// respondNXDOMAIN answers a query for a blocked domain with NXDOMAIN rather
// than forwarding it — the standard "this domain does not exist" response,
// so callers fail the same way they would for a genuinely dead domain.
func (r *Resolver) respondNXDOMAIN(pc net.PacketConn, addr net.Addr, msg dnsmessage.Message) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.ID,
			Response:           true,
			Authoritative:      true,
			RCode:              dnsmessage.RCodeNameError,
			RecursionDesired:   msg.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: msg.Questions,
	}
	packed, err := resp.Pack()
	if err == nil {
		_, _ = pc.WriteTo(packed, addr)
	}
}

func (r *Resolver) forward(pc net.PacketConn, addr net.Addr, raw []byte) {
	conn, err := net.Dial("udp", r.upstream)
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write(raw); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	_, _ = pc.WriteTo(buf[:n], addr)
}
