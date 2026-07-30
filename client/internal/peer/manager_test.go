package peer

import (
	"testing"

	commonv1 "github.com/blinex/gen/common/v1"
)

func p(key, ip, host string, allowed ...string) *commonv1.Peer {
	return &commonv1.Peer{WgPubKey: key, Ip: ip, Hostname: host, AllowedIps: allowed}
}

func TestDiffAddsNewPeers(t *testing.T) {
	m := New()
	added, updated, removed := m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a")})
	if len(added) != 1 || len(updated) != 0 || len(removed) != 0 {
		t.Fatalf("expected 1 added, got a=%d u=%d r=%d", len(added), len(updated), len(removed))
	}
}

func TestDiffDetectsNoChange(t *testing.T) {
	m := New()
	set := []*commonv1.Peer{p("k1", "100.64.0.1", "a", "100.64.0.1/32")}
	m.Diff(set)
	added, updated, removed := m.Diff(set)
	if len(added)+len(updated)+len(removed) != 0 {
		t.Fatalf("expected no changes, got a=%d u=%d r=%d", len(added), len(updated), len(removed))
	}
}

func TestDiffDetectsUpdate(t *testing.T) {
	m := New()
	m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a")})
	_, updated, _ := m.Diff([]*commonv1.Peer{p("k1", "100.64.0.2", "a")}) // IP changed
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated, got %d", len(updated))
	}
}

func TestDiffDetectsAllowedIPChange(t *testing.T) {
	m := New()
	m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a", "100.64.0.1/32")})
	_, updated, _ := m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a", "100.64.0.1/32", "10.0.0.0/24")})
	if len(updated) != 1 {
		t.Fatalf("expected update on allowed-ip change, got %d", len(updated))
	}
}

func TestDiffDetectsRemoval(t *testing.T) {
	m := New()
	m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a"), p("k2", "100.64.0.2", "b")})
	_, _, removed := m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a")})
	if len(removed) != 1 || removed[0].WgPubKey != "k2" {
		t.Fatalf("expected k2 removed, got %+v", removed)
	}
}

func TestAllReturnsSnapshot(t *testing.T) {
	m := New()
	m.Diff([]*commonv1.Peer{p("k1", "100.64.0.1", "a"), p("k2", "100.64.0.2", "b")})
	if len(m.All()) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(m.All()))
	}
}

func TestAllowedIPsEqual(t *testing.T) {
	if !allowedIPsEqual([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("identical slices should be equal")
	}
	if allowedIPsEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("different lengths should not be equal")
	}
	if allowedIPsEqual([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("different contents should not be equal")
	}
}
