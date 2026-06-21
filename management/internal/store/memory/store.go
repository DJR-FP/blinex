package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/blinex/management/internal/domain"
	"github.com/blinex/management/internal/store"
)

// Store is a thread-safe in-memory implementation of store.Store.
// Use it for development and integration tests; replace with postgres.Store in production.
type Store struct {
	mu        sync.RWMutex
	accounts  map[string]*domain.Account
	setupKeys map[string]*domain.SetupKey // keyed by SetupKey.Key (the secret token)
	peers     map[string]*domain.Peer     // keyed by WGPubKey
	rules     map[string]*domain.Rule     // keyed by Rule.ID
}

var _ store.Store = (*Store)(nil)

func New(seedKey string) *Store {
	s := &Store{
		accounts:  make(map[string]*domain.Account),
		setupKeys: make(map[string]*domain.SetupKey),
		peers:     make(map[string]*domain.Peer),
		rules:     make(map[string]*domain.Rule),
	}
	accountID := "default"
	s.accounts[accountID] = &domain.Account{
		ID:        accountID,
		Name:      "Default",
		CreatedAt: time.Now(),
	}
	s.setupKeys[seedKey] = &domain.SetupKey{
		ID:        uuid.NewString(),
		AccountID: accountID,
		Key:       seedKey,
		Name:      "Default key",
		Ephemeral: false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	return s
}

func (s *Store) GetOrCreateAccount(ctx context.Context, id string) (*domain.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.accounts[id]; ok {
		return a, nil
	}
	a := &domain.Account{ID: id, Name: id, CreatedAt: time.Now()}
	s.accounts[id] = a
	return a, nil
}

func (s *Store) GetSetupKey(ctx context.Context, key string) (*domain.SetupKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sk, ok := s.setupKeys[key]
	if !ok {
		return nil, fmt.Errorf("setup key not found")
	}
	if time.Now().After(sk.ExpiresAt) {
		return nil, fmt.Errorf("setup key expired")
	}
	return sk, nil
}

func (s *Store) CreateSetupKey(ctx context.Context, sk *domain.SetupKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setupKeys[sk.Key] = sk
	return nil
}

func (s *Store) GetSetupKeysByAccount(_ context.Context, accountID string) ([]*domain.SetupKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*domain.SetupKey
	for _, sk := range s.setupKeys {
		if sk.AccountID == accountID {
			cp := *sk
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *Store) DeleteSetupKey(_ context.Context, accountID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sk := range s.setupKeys {
		if sk.ID == id && sk.AccountID == accountID {
			delete(s.setupKeys, k)
			return nil
		}
	}
	return fmt.Errorf("setup key not found")
}

func (s *Store) IncrementSetupKeyUsage(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sk := range s.setupKeys {
		if sk.ID == keyID {
			sk.UsedCount++
			return nil
		}
	}
	return fmt.Errorf("setup key id not found: %s", keyID)
}

func (s *Store) GetPeer(ctx context.Context, wgPubKey string) (*domain.Peer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.peers[wgPubKey]
	if !ok {
		return nil, fmt.Errorf("peer not found: %s", wgPubKey)
	}
	return p, nil
}

func (s *Store) GetPeersByAccount(ctx context.Context, accountID string) ([]*domain.Peer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*domain.Peer
	for _, p := range s.peers {
		if p.AccountID == accountID {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *Store) GetAllPeers(_ context.Context) ([]*domain.Peer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*domain.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func (s *Store) SavePeer(ctx context.Context, peer *domain.Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *peer
	s.peers[peer.WGPubKey] = &cp
	return nil
}

func (s *Store) DeletePeer(ctx context.Context, wgPubKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, wgPubKey)
	return nil
}

func (s *Store) GetRulesByAccount(_ context.Context, accountID string) ([]*domain.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*domain.Rule
	for _, r := range s.rules {
		if r.AccountID == accountID {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *Store) SaveRule(_ context.Context, rule *domain.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *rule
	s.rules[rule.ID] = &cp
	return nil
}

func (s *Store) DeleteRule(_ context.Context, accountID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok || r.AccountID != accountID {
		return fmt.Errorf("rule not found")
	}
	delete(s.rules, id)
	return nil
}
