package grpcserver

import (
	"testing"

	"github.com/blinex/management/internal/domain"
)

func peersFixture() []*domain.Peer {
	return []*domain.Peer{
		{WGPubKey: "gw", AdvertisedRoutes: []string{"0.0.0.0/0"}},
		{WGPubKey: "subnet-only", AdvertisedRoutes: []string{"192.168.1.0/24"}},
		{WGPubKey: "client-a", ExitNode: "gw"},
		{WGPubKey: "client-b"},
		{WGPubKey: "client-c", ExitNode: "subnet-only"},
		{WGPubKey: "client-d", ExitNode: "vanished"},
		{WGPubKey: "self-ref", ExitNode: "self-ref", AdvertisedRoutes: []string{"0.0.0.0/0"}},
	}
}

// The whole point of the change: choosing an exit node is per device. A peer
// that did not opt in must not be handed one just because someone on the
// account advertises 0.0.0.0/0 — that behaviour redirected every peer's
// default route at once.
func TestExitNodeIsPerDevice(t *testing.T) {
	peers := peersFixture()

	if got := resolveExitNode(peers, "client-a"); got != "gw" {
		t.Errorf("opted-in peer: got %q, want \"gw\"", got)
	}
	if got := resolveExitNode(peers, "client-b"); got != "" {
		t.Errorf("peer that did not opt in must get none, got %q", got)
	}
	if got := resolveExitNode(peers, "gw"); got != "" {
		t.Errorf("the gateway itself must not route through anything, got %q", got)
	}
}

// A selection is validated, not trusted. Routing a device's entire default
// route at a gateway that is not offering one is worse than using no exit
// node at all, so every failure resolves to "".
func TestExitNodeSelectionIsValidated(t *testing.T) {
	peers := peersFixture()

	for _, tc := range []struct{ name, self string }{
		{"gateway stopped advertising a default route", "client-c"},
		{"gateway no longer exists", "client-d"},
		{"peer selected itself", "self-ref"},
		{"peer not in the account at all", "stranger"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveExitNode(peers, tc.self); got != "" {
				t.Errorf("got %q, want \"\" — an unusable selection must resolve to no exit node", got)
			}
		})
	}
}

// Removing the advertisement must withdraw it from everyone using it, without
// anyone having to change their own setting.
func TestExitNodeWithdrawnWhenGatewayStopsAdvertising(t *testing.T) {
	peers := peersFixture()
	if got := resolveExitNode(peers, "client-a"); got != "gw" {
		t.Fatalf("precondition failed: got %q", got)
	}
	for _, p := range peers {
		if p.WGPubKey == "gw" {
			p.AdvertisedRoutes = nil
		}
	}
	if got := resolveExitNode(peers, "client-a"); got != "" {
		t.Errorf("got %q, want \"\" once the gateway stops advertising", got)
	}
}
