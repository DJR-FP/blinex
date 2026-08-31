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
	// Excluded even under 0.0.0.0/0: mesh, loopback, link-local, multicast,
	// unspecified — AND private (RFC1918/ULA), which an exit must not expose.
	for _, ex := range []string{"100.64.0.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
		"192.168.1.10", "10.0.0.5", "172.16.9.9", "fd00::1"} {
		if n.shouldForward(netip.MustParseAddr(ex)) {
			t.Errorf("exit node must NOT forward %s", ex)
		}
	}

	// But an EXPLICIT subnet advertisement for a private range is still forwarded
	// (that's a subnet router, not an exit-node catch-all).
	n.SetSubnets([]netip.Prefix{netip.MustParsePrefix("192.168.5.0/24")})
	if !n.shouldForward(netip.MustParseAddr("192.168.5.10")) {
		t.Error("explicit private subnet advertisement must be forwarded")
	}
	if n.shouldForward(netip.MustParseAddr("192.168.6.10")) {
		t.Error("private dst outside the advertised subnet must not be forwarded")
	}
}

// A netstack router/exit has no iptables, so it enforces ACL policy in
// userspace over the traffic it forwards. This must match the kernel BLINEX-ACL
// semantics: priority-ordered, first match wins, default deny.
func TestRoutingNetACLEnforcement(t *testing.T) {
	n := &RoutingNet{}
	web := netip.MustParseAddr("100.64.0.7") // mesh sender
	db := netip.MustParseAddr("192.168.5.10")
	other := netip.MustParseAddr("100.64.0.9")

	// No rules => deny.
	if n.aclAllows(web, db, "tcp", 5432) {
		t.Fatal("no rules must default-deny")
	}

	// allow other -> 192.168.5.0/24 (all protocols), nothing for web.
	n.SetACLRules([]*commonv1.Rule{
		{Src: "100.64.0.9/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	})
	if n.aclAllows(web, db, "tcp", 5432) {
		t.Error("web has no matching allow rule, must stay denied")
	}
	if n.aclAllows(web, db, "icmp", 0) {
		t.Error("no rule matches web for icmp either, must stay denied")
	}
	if !n.aclAllows(other, db, "tcp", 5432) {
		t.Error("matching source must be allowed")
	}

	// Higher-priority deny exception overriding a broader allow (listed
	// first, as the server sends rules priority-ascending).
	n.SetACLRules([]*commonv1.Rule{
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "tcp", Port: 22, Action: "deny", Enabled: true, Priority: 50},
		{Src: "100.64.0.7/32", Dst: "192.168.5.0/24", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	})
	if n.aclAllows(web, db, "tcp", 22) {
		t.Error("tcp/22 deny exception must block")
	}
	if !n.aclAllows(web, db, "tcp", 5432) {
		t.Error("other ports still allowed by the broad allow")
	}

	// Disabled rules are ignored — with only a disabled allow, default-deny
	// still applies.
	n.SetACLRules([]*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "allow", Enabled: false, Priority: 100},
	})
	if n.aclAllows(web, db, "tcp", 22) {
		t.Error("disabled allow must be ignored, falling back to default-deny")
	}

	// Wildcard allow permits everything.
	n.SetACLRules([]*commonv1.Rule{
		{Src: "*", Dst: "*", Protocol: "all", Action: "allow", Enabled: true, Priority: 100},
	})
	if !n.aclAllows(web, db, "tcp", 22) {
		t.Error("wildcard allow must permit")
	}
}
