package wgmgr

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// flowKey identifies one direction of a flow: who is sending, to whom, and
// over which ports. For ICMP echo both port fields hold the echo identifier,
// which a reply copies from its request — that is what lets a ping be matched
// back to the ping that caused it.
type flowKey struct {
	proto uint8
	src   netip.Addr
	dst   netip.Addr
	sport uint16
	dport uint16
}

// reverse returns the key the reply to this packet will have.
func (k flowKey) reverse() flowKey {
	return flowKey{proto: k.proto, src: k.dst, dst: k.src, sport: k.dport, dport: k.sport}
}

// parseFlowKey extracts a flow key from a raw IPv4 packet, reporting false for
// anything it cannot key on (non-IPv4, truncated, or a protocol other than
// TCP/UDP/ICMP-echo).
func parseFlowKey(pkt []byte) (flowKey, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return flowKey{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return flowKey{}, false
	}
	src, ok1 := netip.AddrFromSlice(pkt[12:16])
	dst, ok2 := netip.AddrFromSlice(pkt[16:20])
	if !ok1 || !ok2 {
		return flowKey{}, false
	}
	k := flowKey{proto: pkt[9], src: src, dst: dst}
	switch pkt[9] {
	case 6, 17: // tcp, udp
		if len(pkt) < ihl+4 {
			return flowKey{}, false
		}
		k.sport = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		k.dport = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	case 1: // icmp: only echo request/reply carry an identifier to match on
		if len(pkt) < ihl+6 {
			return flowKey{}, false
		}
		if t := pkt[ihl]; t != 8 && t != 0 {
			return flowKey{}, false
		}
		id := binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
		k.sport, k.dport = id, id
	default:
		return flowKey{}, false
	}
	return k, true
}

// conntrackTTL is how long a flow stays eligible to have its reply accepted.
// Generous enough for a slow round trip, short enough that the table reflects
// current activity rather than history.
const conntrackTTL = 2 * time.Minute

// conntrackMax caps the table so a burst of outbound flows cannot grow it
// without bound. On overflow the table is cleared rather than evicted
// one-by-one: replies to genuinely active flows are re-established by the next
// outbound packet, so the cost is a brief policy tightening, not a leak.
const conntrackMax = 8192

// conntrack records flows this host originated so their replies can be
// accepted without a matching ACL rule.
//
// Policy rules expand to *mesh peer IPs*, so a reply from inside a routed
// subnet — or from the internet by way of an exit node — matches no rule and
// is default-denied. Tracking the outbound direction and admitting only its
// return is the same guarantee iptables gives with
// `-m conntrack --ctstate ESTABLISHED,RELATED`, which is what acl_linux.go
// installs for the identical reason. A stateless alternative would have to
// allow the whole source prefix, and for an exit node that prefix is
// 0.0.0.0/0 — default-deny switched off.
type conntrack struct {
	mu    sync.Mutex
	flows map[flowKey]time.Time
	now   func() time.Time // injectable for tests
}

func newConntrack() *conntrack {
	return &conntrack{flows: make(map[flowKey]time.Time), now: time.Now}
}

// observeOutbound records that this host sent pkt, so the matching reply will
// be admitted by allowInbound.
func (c *conntrack) observeOutbound(pkt []byte) {
	k, ok := parseFlowKey(pkt)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.flows) >= conntrackMax {
		c.flows = make(map[flowKey]time.Time)
	}
	c.flows[k.reverse()] = c.now()
}

// allowInbound reports whether pkt is the reply to a flow this host started.
// An expired entry is removed as it is found, which keeps the table trimmed
// without a sweeper goroutine.
func (c *conntrack) allowInbound(pkt []byte) bool {
	k, ok := parseFlowKey(pkt)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen, ok := c.flows[k]
	if !ok {
		return false
	}
	if c.now().Sub(seen) > conntrackTTL {
		delete(c.flows, k)
		return false
	}
	return true
}
