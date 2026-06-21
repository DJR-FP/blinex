package grpcserver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/blinex/management/internal/domain"
)

// IPAM allocates IPs from a CGNAT block (default: 100.64.0.0/10).
type IPAM struct {
	mu      sync.Mutex
	network *net.IPNet
	next    uint32 // next host address to hand out
	leased  map[string]uint32 // wgPubKey → allocated host uint32
}

func NewIPAM(cidr string) (*IPAM, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	base := binary.BigEndian.Uint32(network.IP)
	return &IPAM{
		network: network,
		next:    base + 1, // skip network address
		leased:  make(map[string]uint32),
	}, nil
}

// Allocate returns the existing IP for key, or assigns a new one.
func (i *IPAM) Allocate(wgPubKey string) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if host, ok := i.leased[wgPubKey]; ok {
		return hostToIP(host), nil
	}
	mask := binary.BigEndian.Uint32(i.network.Mask)
	broadcast := binary.BigEndian.Uint32(i.network.IP) | ^mask
	if i.next >= broadcast {
		return "", fmt.Errorf("IPAM pool exhausted")
	}
	host := i.next
	i.next++
	i.leased[wgPubKey] = host
	return hostToIP(host), nil
}

// PreloadPeers restores IPAM state from persisted peers so that IPs already
// assigned in a previous run are not re-allocated after a server restart.
// Must be called before the server begins serving requests.
func (i *IPAM) PreloadPeers(peers []*domain.Peer) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, p := range peers {
		if p.IP == "" {
			continue
		}
		ip := net.ParseIP(p.IP)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		host := binary.BigEndian.Uint32(v4)
		i.leased[p.WGPubKey] = host
		if host >= i.next {
			i.next = host + 1
		}
	}
}

func hostToIP(host uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, host)
	return ip.String()
}
