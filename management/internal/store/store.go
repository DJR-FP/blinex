package store

import (
	"context"

	"github.com/meshnet/management/internal/domain"
)

// Store defines the persistence interface. Swap in-memory for PostgreSQL without
// touching any service code.
type Store interface {
	// Accounts
	GetOrCreateAccount(ctx context.Context, id string) (*domain.Account, error)

	// Setup keys
	GetSetupKey(ctx context.Context, key string) (*domain.SetupKey, error)
	GetSetupKeysByAccount(ctx context.Context, accountID string) ([]*domain.SetupKey, error)
	CreateSetupKey(ctx context.Context, sk *domain.SetupKey) error
	DeleteSetupKey(ctx context.Context, accountID, id string) error
	IncrementSetupKeyUsage(ctx context.Context, keyID string) error

	// Peers
	GetPeer(ctx context.Context, wgPubKey string) (*domain.Peer, error)
	GetPeersByAccount(ctx context.Context, accountID string) ([]*domain.Peer, error)
	GetAllPeers(ctx context.Context) ([]*domain.Peer, error)
	SavePeer(ctx context.Context, peer *domain.Peer) error
	DeletePeer(ctx context.Context, wgPubKey string) error

	// Rules
	GetRulesByAccount(ctx context.Context, accountID string) ([]*domain.Rule, error)
	SaveRule(ctx context.Context, rule *domain.Rule) error
	DeleteRule(ctx context.Context, accountID, id string) error
}
