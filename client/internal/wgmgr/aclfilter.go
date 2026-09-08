package wgmgr

import (
	"encoding/binary"
	"net/netip"
	"strings"

	commonv1 "github.com/blinex/gen/common/v1"
)

// aclFilterAllows evaluates policy for one decrypted IPv4 packet about to be
// delivered into the OS (used by aclFilterTUN, Windows-only — see
// aclfilter_windows.go — but kept platform-agnostic so it can be unit
// tested directly rather than only cross-compile-checked). Mirrors
// nsrouter.go's RoutingNet.aclAllows: same first-match-wins, default-deny
// semantics against the same already group-expanded, priority-ordered rule
// list, just matched against a raw wire-format packet instead of
// gVisor-derived connection metadata.
//
// Non-IPv4 traffic (this mesh is IPv4-only) passes through unfiltered,
// matching Linux: the `iptables` binary BLINEX-ACL is installed under never
// sees IPv6 packets either.
func aclFilterAllows(pkt []byte, rules []*commonv1.Rule) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return true
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return true
	}
	src, ok1 := netip.AddrFromSlice(pkt[12:16])
	dst, ok2 := netip.AddrFromSlice(pkt[16:20])
	if !ok1 || !ok2 {
		return true
	}

	var proto string
	switch pkt[9] {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 1:
		proto = "icmp"
	default:
		proto = ""
	}

	var dport uint16
	if (proto == "tcp" || proto == "udp") && len(pkt) >= ihl+4 {
		dport = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !aclHostMatch(r.Src, src) || !aclHostMatch(r.Dst, dst) {
			continue
		}
		if p := strings.ToLower(r.Protocol); p != "" && p != "all" {
			if p != proto {
				continue
			}
			if r.Port > 0 && (p == "tcp" || p == "udp") && uint16(r.Port) != dport {
				continue
			}
		}
		return r.Action == "allow"
	}
	return false // default deny — no rule matched, including the zero-rules case
}
