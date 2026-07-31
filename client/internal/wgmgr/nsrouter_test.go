package wgmgr

import (
	"net/netip"
	"testing"

	commonv1 "github.com/blinex/gen/common/v1"
)

// The forwarders only proxy connections whose destination falls inside a
// configured advertised subnet; SetSubnets(nil) disables forwarding. This
// gating is what makes the netstack peer a *subnet* router rather than an open
// relay, and mirrors the reconcile-on-withdraw behaviour verified live.
func TestRoutingNetSubnetGating(t *testing.T) {
	n := &RoutingNet{}

	if n.shouldForward(netip.MustParseAddr("10.222.0.5")) {
		t.Fatal("no subnets configured: must not forward")
	}

	n.SetSubnets([]netip.Prefix{
		netip.MustParsePrefix("10.222.0.0/24"),
		netip.MustParsePrefix("192.168.5.0/24"),
	})
	for _, in := range []string{"10.222.0.5", "10.222.0.254", "192.168.5.9"} {
		if !n.shouldForward(netip.MustParseAddr(in)) {
			t.Errorf("%s is in an advertised subnet: must forward", in)
		}
	}
	for _, out := range []string{"10.223.0.1", "192.168.6.1", "8.8.8.8"} {
		if n.shouldForward(netip.MustParseAddr(out)) {
			t.Errorf("%s is outside advertised subnets: must not forward", out)
		}
	}

	// Withdrawing routes disables forwarding (teardown).
	n.SetSubnets(nil)
	if n.shouldForward(netip.MustParseAddr("10.222.0.5")) {
		t.Fatal("after SetSubnets(nil): must not forward")
	}
}

// An exit node advertises 0.0.0.0/0 and must forward arbitrary internet
// destinations — but never mesh-internal, loopback, link-local or multicast
// traffic, even under the catch-all.
func TestRoutingNetExitNodeGating(t *testing.T) {
	n := &RoutingNet{}
	n.SetSubnets([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})

	for _, in := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if !n.shouldForward(netip.MustParseAddr(in)) {
			t.Errorf("exit node must forward internet dst %s", in)
		}
	}
	for _, ex := range []string{"100.64.0.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0"} {
		if n.shouldForward(netip.MustParseAddr(ex)) {
			t.Errorf("exit node must NOT forward %s (mesh/loopback/link-local/multicast)", ex)
		}
	}
}

// A netstack router/exit has no iptables, so it enforces ACL policy in
// userspace over the traffic it forwards. This must match the kernel BLINEX-ACL
// semantics: priority-ordered, first match wins, default allow.
func TestRoutingNetACLEnforcement(t *testing.T) {
	n := &RoutingNet{}
	web := netip.MustParseAddr("100.64.0.7") // mesh sender
	db := netip.MustParseAddr("192.168.5.10")
	other := netip.MustParseAddr("100.64.0.9")

	// No rules => allow (deny-by-exception).
	if !n.aclAllows(web, db, "tcp", 5432) {
		t.Fatal("no rules must default-allow")
	}

	// deny web -> 192.168.5.0/24 (all protocols).
	n.SetACLRules([]*commonv1.Rule{
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "deny", Enabled: true, Priority: 100},
	})
	if n.aclAllows(web, db, "tcp", 5432) {
		t.Error("deny web->db must block")
	}
	if n.aclAllows(web, db, "icmp", 0) {
		t.Error("deny (all) must block icmp too")
	}
	if !n.aclAllows(other, db, "tcp", 5432) {
		t.Error("non-matching source must still be allowed")
	}

	// Higher-priority allow exception for tcp/22 (listed first, as the server
	// sends rules priority-ascending).
	n.SetACLRules([]*commonv1.Rule{
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "tcp", Port: 22, Action: "allow", Enabled: true, Priority: 50},
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "deny", Enabled: true, Priority: 100},
	})
	if !n.aclAllows(web, db, "tcp", 22) {
		t.Error("tcp/22 allow exception must permit")
	}
	if n.aclAllows(web, db, "tcp", 5432) {
		t.Error("other ports still denied by the broad deny")
	}

	// Disabled rules are ignored.
	n.SetACLRules([]*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "deny", Enabled: false, Priority: 100},
	})
	if !n.aclAllows(web, db, "tcp", 22) {
		t.Error("disabled deny must be ignored")
	}

	// Wildcard deny blocks everything.
	n.SetACLRules([]*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "deny", Enabled: true, Priority: 100},
	})
	if n.aclAllows(web, db, "tcp", 22) {
		t.Error("wildcard deny must block")
	}
}
