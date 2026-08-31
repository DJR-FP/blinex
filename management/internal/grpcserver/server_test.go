package grpcserver

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/blinex/gen/common/v1"
	managementv1 "github.com/blinex/gen/management/v1"
	"github.com/blinex/management/internal/auth"
	"github.com/blinex/management/internal/domain"
	"github.com/blinex/management/internal/store/memory"
)

func newTestServer(t *testing.T) (*Server, *memory.Store) {
	t.Helper()
	st := memory.New("seed-key")
	ipam, err := NewIPAM("100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	authMgr := auth.NewManager("test-secret-at-least-32-bytes-long!!")
	return New(st, authMgr, ipam, "100.64.0.0/10", "blinex"), st
}

func TestLoginRejectsMissingFields(t *testing.T) {
	s, _ := newTestServer(t)
	if _, err := s.Login(context.Background(), &managementv1.LoginRequest{WgPubKey: "k"}); err == nil {
		t.Fatal("expected error for missing setup key")
	}
	if _, err := s.Login(context.Background(), &managementv1.LoginRequest{SetupKey: "seed-key"}); err == nil {
		t.Fatal("expected error for missing pubkey")
	}
}

func TestLoginRejectsBadSetupKey(t *testing.T) {
	s, _ := newTestServer(t)
	_, err := s.Login(context.Background(), &managementv1.LoginRequest{SetupKey: "nope", WgPubKey: "k"})
	if err == nil {
		t.Fatal("expected error for invalid setup key")
	}
}

func TestLoginAllocatesPeerAndToken(t *testing.T) {
	s, st := newTestServer(t)
	resp, err := s.Login(context.Background(), &managementv1.LoginRequest{
		SetupKey: "seed-key", WgPubKey: "pk1",
		Meta: &commonv1.PeerMeta{Hostname: "laptop", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Token == "" || resp.PeerId == "" {
		t.Fatal("expected token and peer id")
	}
	if resp.NetworkConfig.Address != "100.64.0.1/32" {
		t.Fatalf("unexpected address %s", resp.NetworkConfig.Address)
	}
	p, err := st.GetPeer(context.Background(), "pk1")
	if err != nil {
		t.Fatalf("peer not saved: %v", err)
	}
	if p.Hostname != "laptop" {
		t.Fatalf("hostname not saved: %+v", p)
	}
	if len(p.Groups) != 1 || p.Groups[0] != domain.DefaultGroupName {
		t.Fatalf("a first-time enrollee must be in Default and nothing else, got %+v", p.Groups)
	}
}

func TestLoginAutoGroupsFromSetupKey(t *testing.T) {
	s, st := newTestServer(t)
	ctx := context.Background()
	_ = st.CreateSetupKey(ctx, &domain.SetupKey{
		ID: "grouped", AccountID: "default", Key: "grouped-key",
		AutoGroups: []string{"web", domain.DefaultGroupName}, // Default listed explicitly too, must not duplicate
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if _, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "grouped-key", WgPubKey: "pk-web"}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	p, _ := st.GetPeer(ctx, "pk-web")
	if len(p.Groups) != 2 {
		t.Fatalf("expected Default + web with no duplicate, got %+v", p.Groups)
	}
	if p.Groups[0] != domain.DefaultGroupName || p.Groups[1] != "web" {
		t.Fatalf("expected [Default web], got %+v", p.Groups)
	}
}

func TestLoginReenrollPreservesGroups(t *testing.T) {
	s, st := newTestServer(t)
	ctx := context.Background()
	first, _ := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "seed-key", WgPubKey: "pk1"})

	// Operator adds groups/routes out of band.
	p, _ := st.GetPeer(ctx, "pk1")
	p.Groups = []string{domain.DefaultGroupName, "prod"}
	p.AdvertisedRoutes = []string{"10.0.0.0/24"}
	_ = st.SavePeer(ctx, p)

	// Agent restarts and re-enrolls with the same key.
	second, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "seed-key", WgPubKey: "pk1"})
	if err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if first.NetworkConfig.Address != second.NetworkConfig.Address {
		t.Fatalf("IP changed on re-enroll: %s -> %s", first.NetworkConfig.Address, second.NetworkConfig.Address)
	}
	after, _ := st.GetPeer(ctx, "pk1")
	if len(after.Groups) != 2 || after.Groups[1] != "prod" {
		t.Fatalf("groups lost on re-enroll: %+v", after.Groups)
	}
	if len(after.AdvertisedRoutes) != 1 {
		t.Fatalf("routes lost on re-enroll: %+v", after.AdvertisedRoutes)
	}
}

func TestLoginRejectsCrossAccountHijack(t *testing.T) {
	s, st := newTestServer(t)
	ctx := context.Background()
	// Peer enrolled under the default account.
	if _, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "seed-key", WgPubKey: "victim-key"}); err != nil {
		t.Fatal(err)
	}
	// Attacker holds a setup key for a different account.
	_, _ = st.GetOrCreateAccount(ctx, "attacker")
	_ = st.CreateSetupKey(ctx, &domain.SetupKey{ID: "atk", AccountID: "attacker", Key: "attacker-key"})

	_, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "attacker-key", WgPubKey: "victim-key"})
	if err == nil {
		t.Fatal("expected cross-account re-enrollment to be rejected")
	}
	// Victim record must be untouched.
	p, _ := st.GetPeer(ctx, "victim-key")
	if p.AccountID != "default" {
		t.Fatalf("victim peer was hijacked to account %s", p.AccountID)
	}
}

func TestEphemeralKeyRejectedAfterUse(t *testing.T) {
	s, st := newTestServer(t)
	ctx := context.Background()
	_ = st.CreateSetupKey(ctx, &domain.SetupKey{ID: "ek", AccountID: "default", Key: "eph", Ephemeral: true, ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "eph", WgPubKey: "pk-eph"}); err != nil {
		t.Fatalf("first ephemeral use should succeed: %v", err)
	}
	if _, err := s.Login(ctx, &managementv1.LoginRequest{SetupKey: "eph", WgPubKey: "pk-eph-2"}); err == nil {
		t.Fatal("expected ephemeral key to be rejected after first use")
	}
}

func TestExpandGroupRule(t *testing.T) {
	groupIPs := map[string][]string{
		"web": {"100.64.0.1", "100.64.0.2"},
		"db":  {"100.64.0.9"},
	}
	// group:web -> group:db expands to 2x1 = 2 concrete rules.
	r := &domain.Rule{ID: "r", Src: "group:web", Dst: "group:db", Action: "allow"}
	out := expandGroupRule(r, groupIPs)
	if len(out) != 2 {
		t.Fatalf("expected 2 expanded rules, got %d", len(out))
	}
	for _, er := range out {
		if er.Dst != "100.64.0.9" {
			t.Fatalf("unexpected dst %s", er.Dst)
		}
	}
}

func TestExpandGroupRuleEmptyGroupDropsRule(t *testing.T) {
	out := expandGroupRule(&domain.Rule{Src: "group:missing", Dst: "*"}, map[string][]string{})
	if out != nil {
		t.Fatalf("expected nil for unresolved group, got %+v", out)
	}
}

func TestExpandGroupRuleNoGroupsPassthrough(t *testing.T) {
	r := &domain.Rule{Src: "*", Dst: "10.0.0.0/24"}
	out := expandGroupRule(r, nil)
	if len(out) != 1 || out[0] != r {
		t.Fatal("non-group rule should pass through unchanged")
	}
}

func TestToDNSLabel(t *testing.T) {
	cases := map[string]string{
		"Laptop":        "laptop",
		"my host.local": "my-host-local",
		"--weird--":     "weird",
	}
	for in, want := range cases {
		if got := toDNSLabel(in); got != want {
			t.Errorf("toDNSLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := toDNSLabel(""); got == "" || len(got) < 5 {
		t.Errorf("empty hostname should get a generated label, got %q", got)
	}
}

func TestBuildSyncResponseIncludesRoutesAndAllowedIPs(t *testing.T) {
	s, _ := newTestServer(t)
	peers := []*domain.Peer{{
		ID: "1", WGPubKey: "k1", IP: "100.64.0.1",
		AllowedIPs: []string{"100.64.0.1/32"}, AdvertisedRoutes: []string{"10.0.0.0/24"},
	}}
	resp := s.buildSyncResponse(peers, nil)
	if len(resp.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(resp.Peers))
	}
	// AllowedIps must include both the /32 and the advertised route.
	found := map[string]bool{}
	for _, ip := range resp.Peers[0].AllowedIps {
		found[ip] = true
	}
	if !found["100.64.0.1/32"] || !found["10.0.0.0/24"] {
		t.Fatalf("allowed IPs missing entries: %+v", resp.Peers[0].AllowedIps)
	}
	if len(resp.Routes) != 1 || resp.Routes[0].Network != "10.0.0.0/24" {
		t.Fatalf("routes not built: %+v", resp.Routes)
	}
}
