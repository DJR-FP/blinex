package peer

import (
	"sync"

	commonv1 "github.com/meshnet/gen/common/v1"
	"github.com/rs/zerolog/log"
)

// Manager tracks the set of known remote peers and detects changes.
type Manager struct {
	mu    sync.RWMutex
	peers map[string]*commonv1.Peer // keyed by WGPubKey
}

func New() *Manager {
	return &Manager{peers: make(map[string]*commonv1.Peer)}
}

// Diff computes which peers were added, updated, and removed compared to the
// current set. Returns slices of peers in each category.
func (m *Manager) Diff(incoming []*commonv1.Peer) (added, updated, removed []*commonv1.Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	incomingMap := make(map[string]*commonv1.Peer, len(incoming))
	for _, p := range incoming {
		incomingMap[p.WgPubKey] = p
	}

	// Detect added / updated.
	for _, p := range incoming {
		if existing, ok := m.peers[p.WgPubKey]; !ok {
			added = append(added, p)
		} else if existing.Ip != p.Ip || existing.Hostname != p.Hostname || !allowedIPsEqual(existing.AllowedIps, p.AllowedIps) {
			updated = append(updated, p)
		}
	}

	// Detect removed.
	for key, p := range m.peers {
		if _, ok := incomingMap[key]; !ok {
			removed = append(removed, p)
		}
	}

	// Commit the new state.
	m.peers = incomingMap

	log.Debug().
		Int("added", len(added)).
		Int("updated", len(updated)).
		Int("removed", len(removed)).
		Msg("peer diff")

	return added, updated, removed
}

func allowedIPsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (m *Manager) All() []*commonv1.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*commonv1.Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p)
	}
	return out
}
