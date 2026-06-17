package domain

import "time"

type Account struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// SetupKey is a pre-shared enrollment token.
type SetupKey struct {
	ID        string
	AccountID string
	Key       string // the secret token presented by the agent
	Name      string
	Ephemeral bool // single-use if true
	UsedCount int
	CreatedAt time.Time
	ExpiresAt time.Time
}
