package grpcserver

import (
	"testing"

	"github.com/blinex/management/internal/domain"
)

func TestIPAMAllocateStablePerKey(t *testing.T) {
	ipam, err := NewIPAM("100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ipam.Allocate("keyA")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ipam.Allocate("keyA")
	if a != again {
		t.Fatalf("same key got different IPs: %s vs %s", a, again)
	}
	b, _ := ipam.Allocate("keyB")
	if a == b {
		t.Fatalf("different keys got same IP: %s", a)
	}
}

func TestIPAMFirstAddressSkipsNetwork(t *testing.T) {
	ipam, _ := NewIPAM("100.64.0.0/10")
	ip, _ := ipam.Allocate("k")
	if ip != "100.64.0.1" {
		t.Fatalf("expected first host 100.64.0.1, got %s", ip)
	}
}

func TestIPAMReleaseFreesKey(t *testing.T) {
	ipam, _ := NewIPAM("100.64.0.0/10")
	first, _ := ipam.Allocate("keyA")
	ipam.Release("keyA")
	// Re-allocating the same key after release yields a fresh (next) address,
	// proving the lease was dropped.
	reused, _ := ipam.Allocate("keyA")
	if reused == first {
		t.Fatalf("expected a new IP after release, got same %s", reused)
	}
}

func TestIPAMExhaustion(t *testing.T) {
	// /30 → hosts .1 and .2 usable (network .0, next stops at broadcast .3).
	ipam, err := NewIPAM("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipam.Allocate("a"); err != nil {
		t.Fatalf("first alloc failed: %v", err)
	}
	if _, err := ipam.Allocate("b"); err != nil {
		t.Fatalf("second alloc failed: %v", err)
	}
	if _, err := ipam.Allocate("c"); err == nil {
		t.Fatal("expected pool exhaustion error")
	}
}

func TestIPAMPreloadPeersRestoresLeases(t *testing.T) {
	ipam, _ := NewIPAM("100.64.0.0/10")
	ipam.PreloadPeers([]*domain.Peer{
		{WGPubKey: "keyA", IP: "100.64.0.5"},
		{WGPubKey: "keyB", IP: "100.64.0.9"},
	})
	// Existing key keeps its IP.
	if ip, _ := ipam.Allocate("keyA"); ip != "100.64.0.5" {
		t.Fatalf("expected preloaded 100.64.0.5, got %s", ip)
	}
	// New key must not collide with the highest preloaded address.
	next, _ := ipam.Allocate("keyC")
	if next == "100.64.0.5" || next == "100.64.0.9" {
		t.Fatalf("new allocation collided with preloaded IP: %s", next)
	}
}

func TestIPAMInvalidCIDR(t *testing.T) {
	if _, err := NewIPAM("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
