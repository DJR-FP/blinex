package wgmgr

import (
	"net/netip"
	"testing"
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
