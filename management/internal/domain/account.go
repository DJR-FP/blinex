package domain

import "time"

type Account struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// SetupKey is a pre-shared enrollment token.
type SetupKey struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Ephemeral bool      `json:"ephemeral"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
