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
	return aclFilterAllowsFor(pkt, rules, nil)
}

// aclFilterAllowsFor is aclFilterAllows with the set of this host's own IPv4
// addresses, so transit traffic can be told apart from traffic terminating
// here.
//
// Only packets addressed TO this host are policed. That is not a loosening
// invented here — it is what Linux has always actually done, and Windows
// diverging from it is why subnet routing failed live on VirtWin with every
// forwarded packet silently dropped. acl_linux.go hooks BLINEX-ACL into both
// INPUT and FORWARD, but routing_linux.go's AddMasquerade *inserts* blanket
// accepts at the head of FORWARD:
//
//	iptables -I FORWARD -i blinex0 -j ACCEPT
//	iptables -I FORWARD -o blinex0 -j ACCEPT
//
// `-I` puts them above the `-A FORWARD ... -j BLINEX-ACL` jump, so on a Linux
// subnet router forwarded traffic is accepted before the ACL chain ever sees
// it. The Windows filter sits on the decrypted-packet path instead, where it
// sees transit and local traffic alike, and policed both — and since rules
// expand to mesh peer IPs, nothing matches a LAN destination and default-deny
// dropped it.
//
// Passing a nil/empty locals set polices everything, which keeps the
// conservative behaviour for callers that cannot enumerate local addresses.
func aclFilterAllowsFor(pkt []byte, rules []*commonv1.Rule, locals map[netip.Addr]struct{}) bool {
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

	// Transit: destined somewhere other than this host, i.e. being forwarded
	// out to an advertised subnet. Linux accepts these ahead of the ACL chain;
	// match that rather than default-denying them.
	if len(locals) > 0 {
		if _, isLocal := locals[dst]; !isLocal {
			return true
		}
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
