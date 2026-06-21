package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	PeerID    string `json:"peer_id"`
	WGPubKey  string `json:"wg_pub_key"`
	AccountID string `json:"account_id"`
	Role      string `json:"role"` // "peer" or "admin"
	jwt.RegisteredClaims
}

type Manager struct {
	secret  []byte
	mu      sync.RWMutex
	revoked map[string]time.Time // wgPubKey → revocation time
}

func NewManager(secret string) *Manager {
	return &Manager{
		secret:  []byte(secret),
		revoked: make(map[string]time.Time),
	}
}

func (m *Manager) IssueAdminToken(accountID string) (string, error) {
	claims := Claims{
		AccountID: accountID,
		Role:      "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) IssueToken(peerID, wgPubKey, accountID string) (string, error) {
	claims := Claims{
		PeerID:    peerID,
		WGPubKey:  wgPubKey,
		AccountID: accountID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// RevokeByWGKey immediately invalidates all tokens for the given WireGuard public key.
func (m *Manager) RevokeByWGKey(wgPubKey string) {
	m.mu.Lock()
	m.revoked[wgPubKey] = time.Now()
	m.mu.Unlock()
}

func (m *Manager) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	// Check revocation list: reject tokens issued before the revocation time.
	m.mu.RLock()
	revokedAt, isRevoked := m.revoked[claims.WGPubKey]
	m.mu.RUnlock()
	if isRevoked {
		issuedAt := claims.IssuedAt.Time
		if !issuedAt.After(revokedAt) {
			return nil, fmt.Errorf("token has been revoked")
		}
	}
	return claims, nil
}
