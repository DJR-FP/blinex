package grpcserver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
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

func hostToIP(host uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, host)
	return ip.String()
}
