package wgmgr

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// icmpEcho builds an ICMP echo request (type 8) or reply (type 0) carrying id.
func icmpEcho(t *testing.T, src, dst netip.Addr, typ byte, id uint16) []byte {
	t.Helper()
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 1
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	pkt[20] = typ
	binary.BigEndian.PutUint16(pkt[24:26], id)
	return pkt
}

func tcpSeg(t *testing.T, src, dst netip.Addr, sport, dport uint16) []byte {
	t.Helper()
	pkt := make([]byte, 24)
	pkt[0] = 0x45
	pkt[9] = 6
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	return pkt
}

// The gap this fixes: a peer consuming a subnet route sends to a host inside
// that subnet, and the reply comes back from an address no ACL rule mentions
// (rules expand to mesh peer IPs). Verified live before the fix — the request
// left correctly and the reply was silently dropped on arrival.
func TestConntrackAdmitsRepliesToOurOwnFlows(t *testing.T) {
	me := netip.MustParseAddr("100.64.0.10")
	lanHost := netip.MustParseAddr("10.0.0.1")
	stranger := netip.MustParseAddr("10.0.0.99")

	ct := newConntrack()

	// Unsolicited inbound is not admitted.
	if ct.allowInbound(icmpEcho(t, lanHost, me, 8, 7)) {
		t.Error("inbound with no matching outbound flow was admitted")
	}

	// We ping out; the reply must be admitted.
	ct.observeOutbound(icmpEcho(t, me, lanHost, 8, 7))
	if !ct.allowInbound(icmpEcho(t, lanHost, me, 0, 7)) {
		t.Error("reply to our own ping was not admitted")
	}
	// A different echo id is a different flow.
	if ct.allowInbound(icmpEcho(t, lanHost, me, 0, 8)) {
		t.Error("reply with an unrelated echo id was admitted")
	}
	// A different host is a different flow.
	if ct.allowInbound(icmpEcho(t, stranger, me, 0, 7)) {
		t.Error("reply from a host we never contacted was admitted")
	}
}

func TestConntrackTCPPortsMustMatch(t *testing.T) {
	me := netip.MustParseAddr("100.64.0.10")
	srv := netip.MustParseAddr("10.0.0.5")

	ct := newConntrack()
	ct.observeOutbound(tcpSeg(t, me, srv, 51000, 443))

	if !ct.allowInbound(tcpSeg(t, srv, me, 443, 51000)) {
		t.Error("reply on the same 4-tuple was not admitted")
	}
	// Same hosts, different port pair: an unrelated connection the server
	// tried to open back to us, which policy must still govern.
	if ct.allowInbound(tcpSeg(t, srv, me, 443, 51001)) {
		t.Error("a different port pair was admitted")
	}
	if ct.allowInbound(tcpSeg(t, srv, me, 22, 51000)) {
		t.Error("a different server port was admitted")
	}
}

func TestConntrackEntriesExpire(t *testing.T) {
	me := netip.MustParseAddr("100.64.0.10")
	peer := netip.MustParseAddr("10.0.0.5")

	now := time.Unix(1_000_000, 0)
	ct := newConntrack()
	ct.now = func() time.Time { return now }

	ct.observeOutbound(tcpSeg(t, me, peer, 4000, 80))
	if !ct.allowInbound(tcpSeg(t, peer, me, 80, 4000)) {
		t.Fatal("reply not admitted while fresh")
	}
	now = now.Add(conntrackTTL + time.Second)
	if ct.allowInbound(tcpSeg(t, peer, me, 80, 4000)) {
		t.Error("expired flow still admitted")
	}
	if len(ct.flows) != 0 {
		t.Errorf("expired entry not dropped from the table: %d left", len(ct.flows))
	}
}

func TestConntrackIgnoresUnkeyableTraffic(t *testing.T) {
	ct := newConntrack()
	// Too short, not IPv4, and a protocol with no ports must all be no-ops
	// rather than panics or accidental admissions.
	for _, pkt := range [][]byte{{}, {0x45}, {0x60, 0, 0, 0}, make([]byte, 24)} {
		ct.observeOutbound(pkt)
		if ct.allowInbound(pkt) {
			t.Errorf("unkeyable packet admitted: %v", pkt)
		}
	}
}
