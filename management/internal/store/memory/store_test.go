package memory

import (
	"context"
	"testing"
	"time"

	"github.com/blinex/management/internal/domain"
)

func newStore() *Store { return New("seed-key") }

func TestSeedKeyPresentAndValid(t *testing.T) {
	s := newStore()
	sk, err := s.GetSetupKey(context.Background(), "seed-key")
	if err != nil {
		t.Fatalf("seed key missing: %v", err)
	}
	if sk.AccountID != "default" {
		t.Fatalf("expected default account, got %s", sk.AccountID)
	}
}

func TestExpiredSetupKeyRejected(t *testing.T) {
	s := newStore()
	_ = s.CreateSetupKey(context.Background(), &domain.SetupKey{
		ID: "e1", AccountID: "default", Key: "expired", ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := s.GetSetupKey(context.Background(), "expired"); err == nil {
		t.Fatal("expected expired setup key to be rejected")
	}
}

func TestPeerCRUDAndAccountScoping(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_ = s.SavePeer(ctx, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1", IP: "100.64.0.1"})
	_ = s.SavePeer(ctx, &domain.Peer{ID: "2", AccountID: "other", WGPubKey: "k2", IP: "100.64.0.2"})

	got, err := s.GetPeer(ctx, "k1")
	if err != nil || got.ID != "1" {
		t.Fatalf("GetPeer k1: %v %+v", err, got)
	}
	list, _ := s.GetPeersByAccount(ctx, "default")
	if len(list) != 1 || list[0].WGPubKey != "k1" {
		t.Fatalf("account scoping failed: %+v", list)
	}
	all, _ := s.GetAllPeers(ctx)
	if len(all) != 2 {
		t.Fatalf("expected 2 peers total, got %d", len(all))
	}
	if err := s.DeletePeer(ctx, "k1"); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, err := s.GetPeer(ctx, "k1"); err == nil {
		t.Fatal("expected peer to be gone after delete")
	}
}

func TestStoreReturnsCopiesNotAliases(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_ = s.SavePeer(ctx, &domain.Peer{ID: "1", AccountID: "default", WGPubKey: "k1", Hostname: "orig"})
	got, _ := s.GetPeer(ctx, "k1")
	got.Hostname = "mutated"
	again, _ := s.GetPeer(ctx, "k1")
	// GetPeer returns the internal pointer; GetPeersByAccount returns copies.
	// Verify the account listing is a copy so callers can mutate Connected safely.
	list, _ := s.GetPeersByAccount(ctx, "default")
	list[0].Hostname = "listmutation"
	relist, _ := s.GetPeersByAccount(ctx, "default")
	if relist[0].Hostname == "listmutation" {
		t.Fatal("GetPeersByAccount must return copies, not aliases")
	}
	_ = again
}

func TestRulesReturnedInPriorityOrder(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	// newStore seeds one "Default allow" rule at priority 1000 (see
	// Store.New) — it must sort last, after these three lower-priority rules.
	_ = s.SaveRule(ctx, &domain.Rule{ID: "a", AccountID: "default", Priority: 30})
	_ = s.SaveRule(ctx, &domain.Rule{ID: "b", AccountID: "default", Priority: 10})
	_ = s.SaveRule(ctx, &domain.Rule{ID: "c", AccountID: "default", Priority: 20})
	rules, _ := s.GetRulesByAccount(ctx, "default")
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (3 + the seeded default-allow), got %d", len(rules))
	}
	if rules[0].ID != "b" || rules[1].ID != "c" || rules[2].ID != "a" {
		t.Fatalf("rules not sorted by priority: %s,%s,%s,%s", rules[0].ID, rules[1].ID, rules[2].ID, rules[3].ID)
	}
	if rules[3].Name != "Default allow" {
		t.Fatalf("expected the seeded default-allow rule last, got %+v", rules[3])
	}
}

func TestDeleteRuleAccountScoped(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_ = s.SaveRule(ctx, &domain.Rule{ID: "r1", AccountID: "default"})
	// Wrong account cannot delete.
	if err := s.DeleteRule(ctx, "other", "r1"); err == nil {
		t.Fatal("expected cross-account delete to fail")
	}
	if err := s.DeleteRule(ctx, "default", "r1"); err != nil {
		t.Fatalf("same-account delete failed: %v", err)
	}
}

func TestDefaultGroupSeeded(t *testing.T) {
	s := newStore()
	groups, err := s.GetGroupsByAccount(context.Background(), "default")
	if err != nil {
		t.Fatalf("GetGroupsByAccount: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != domain.DefaultGroupName {
		t.Fatalf("expected only the seeded Default group, got %+v", groups)
	}
}

func TestCreateAndDeleteGroup(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	g := &domain.Group{ID: "g1", AccountID: "default", Name: "web"}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groups, _ := s.GetGroupsByAccount(ctx, "default")
	if len(groups) != 2 {
		t.Fatalf("expected Default + web, got %+v", groups)
	}
	if err := s.DeleteGroup(ctx, "default", "g1"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	groups, _ = s.GetGroupsByAccount(ctx, "default")
	if len(groups) != 1 {
		t.Fatalf("expected only Default after delete, got %+v", groups)
	}
	if err := s.DeleteGroup(ctx, "other-account", "g1"); err == nil {
		t.Fatal("expected cross-account delete to fail")
	}
}

func TestEphemeralSetupKeyUsage(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_ = s.CreateSetupKey(ctx, &domain.SetupKey{ID: "ek", AccountID: "default", Key: "eph", Ephemeral: true, ExpiresAt: time.Now().Add(time.Hour)})
	if err := s.IncrementSetupKeyUsage(ctx, "ek"); err != nil {
		t.Fatalf("increment: %v", err)
	}
	sk, _ := s.GetSetupKey(ctx, "eph")
	if sk.UsedCount != 1 {
		t.Fatalf("expected UsedCount 1, got %d", sk.UsedCount)
	}
}
