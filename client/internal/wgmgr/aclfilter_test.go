package wgmgr

import (
	"encoding/binary"
	"net/netip"
	"testing"

	commonv1 "github.com/blinex/gen/common/v1"
)

// buildIPv4Packet constructs a minimal (no-options, no payload beyond the
// 4 bytes needed for a port) IPv4 packet for exercising aclFilterAllows.
// proto: 6=tcp, 17=udp, 1=icmp, 0=other/unrecognized.
func buildIPv4Packet(t *testing.T, src, dst netip.Addr, proto byte, dport uint16) []byte {
	t.Helper()
	pkt := make([]byte, 24)
	pkt[0] = 0x45 // version 4, IHL 5 (20 bytes)
	pkt[9] = proto
	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[22:24], dport) // dest port at offset IHL+2
	return pkt
}

func TestACLFilterAllows(t *testing.T) {
	web := netip.MustParseAddr("100.64.0.7")
	other := netip.MustParseAddr("100.64.0.9")
	db := netip.MustParseAddr("192.168.5.10")

	tcpPkt := func(src, dst netip.Addr, port uint16) []byte { return buildIPv4Packet(t, src, dst, 6, port) }
	icmpPkt := func(src, dst netip.Addr) []byte { return buildIPv4Packet(t, src, dst, 1, 0) }

	// No rules configured at all (nil slice, e.g. pre-first-sync) is handled
	// by aclFilterTUN.Write's rulesSet check, not aclFilterAllows itself —
	// here we're testing the "policy active with zero/no matching rules"
	// case, which must default-deny.
	if aclFilterAllows(tcpPkt(web, db, 5432), nil) {
		t.Fatal("no rules must default-deny")
	}

	// allow other -> 192.168.5.0/24 (all protocols), nothing for web.
	rules := []*commonv1.Rule{
		{Src: "100.64.0.9/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	}
	if aclFilterAllows(tcpPkt(web, db, 5432), rules) {
		t.Error("web has no matching allow rule, must stay denied")
	}
	if aclFilterAllows(icmpPkt(web, db), rules) {
		t.Error("no rule matches web for icmp either, must stay denied")
	}
	if !aclFilterAllows(tcpPkt(other, db, 5432), rules) {
		t.Error("matching source must be allowed")
	}

	// Higher-priority deny exception overriding a broader allow (listed
	// first, as the server sends rules priority-ascending).
	rules = []*commonv1.Rule{
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "tcp", Port: 22, Action: "deny", Enabled: true, Priority: 50},
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	}
	if aclFilterAllows(tcpPkt(web, db, 22), rules) {
		t.Error("tcp/22 deny exception must block")
	}
	if !aclFilterAllows(tcpPkt(web, db, 5432), rules) {
		t.Error("other ports still allowed by the broad allow")
	}

	// Disabled rules are ignored.
	rules = []*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "allow", Enabled: false, Priority: 100},
	}
	if aclFilterAllows(tcpPkt(web, db, 22), rules) {
		t.Error("disabled allow must be ignored, falling back to default-deny")
	}

	// Wildcard allow permits everything.
	rules = []*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	}
	if !aclFilterAllows(tcpPkt(web, db, 22), rules) {
		t.Error("wildcard allow must permit")
	}

	// Non-IPv4 / malformed input passes through unfiltered rather than
	// panicking — mirrors Linux's iptables BLINEX-ACL never seeing IPv6.
	if !aclFilterAllows([]byte{0x60, 0, 0, 0}, rules) {
		t.Error("non-IPv4 packet must pass through unfiltered")
	}
	if !aclFilterAllows([]byte{0x45}, rules) {
		t.Error("truncated packet must pass through unfiltered, not panic")
	}
}
