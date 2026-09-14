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

// TestACLFilterTransitBypassesPolicy pins the Linux-parity rule that made
// subnet routing work on Windows: only traffic addressed to this host is
// policed. Forwarded traffic is accepted, because on Linux
// routing_linux.go's `iptables -I FORWARD -i blinex0 -j ACCEPT` sits above
// the jump to BLINEX-ACL and accepts it before the chain runs.
//
// Before this, the Windows filter policed transit too, and since rules
// expand to mesh peer IPs a LAN destination matched nothing and was
// default-denied — every forwarded packet dropped, verified live.
func TestACLFilterTransitBypassesPolicy(t *testing.T) {
	// A policy that allows only mesh peer → mesh peer, as group expansion produces.
	rules := []*commonv1.Rule{{
		Src: "100.64.0.9", Dst: "100.64.0.10", Protocol: "all", Action: "allow", Enabled: true,
	}}
	locals := map[netip.Addr]struct{}{
		netip.MustParseAddr("100.64.0.10"):    {},
		netip.MustParseAddr("192.168.100.47"): {},
	}

	icmpPkt := func(src, dst netip.Addr) []byte { return buildIPv4Packet(t, src, dst, 1, 0) }

	lanHost := netip.MustParseAddr("192.168.100.1")
	mesh := netip.MustParseAddr("100.64.0.10")
	peer := netip.MustParseAddr("100.64.0.9")
	stranger := netip.MustParseAddr("100.64.0.8")

	// Transit to the advertised LAN: not addressed to us, so not policed.
	if !aclFilterAllowsFor(icmpPkt(peer, lanHost), rules, locals) {
		t.Error("forwarded LAN traffic was dropped; subnet routing cannot work")
	}
	// Still policed when it terminates here.
	if !aclFilterAllowsFor(icmpPkt(peer, mesh), rules, locals) {
		t.Error("allowed mesh→this-host traffic was dropped")
	}
	if aclFilterAllowsFor(icmpPkt(stranger, mesh), rules, locals) {
		t.Error("traffic to this host from a peer with no matching rule was allowed")
	}
	// A local non-mesh address of ours is still "to us", so still policed —
	// matching Linux, where such a packet goes to INPUT, not FORWARD.
	if aclFilterAllowsFor(icmpPkt(peer, netip.MustParseAddr("192.168.100.47")), rules, locals) {
		t.Error("traffic to our own LAN address bypassed policy; it should be policed like INPUT")
	}
	// With no local set known, fail closed: police everything.
	if aclFilterAllowsFor(icmpPkt(peer, lanHost), rules, nil) {
		t.Error("with an unknown local-address set the filter must fail closed")
	}
}
