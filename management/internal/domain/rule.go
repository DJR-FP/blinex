package domain

import "time"

// Rule defines an access control policy for mesh traffic.
// Rules are evaluated in ascending priority order (lowest priority number first).
// If no rule matches, the default policy is to allow.
type Rule struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	Src       string    `json:"src"`      // source CIDR, peer IP, or "*"
	Dst       string    `json:"dst"`      // destination CIDR, peer IP, or "*"
	Protocol  string    `json:"protocol"` // "tcp", "udp", "icmp", "all"
	Port      int       `json:"port"`     // destination port; 0 = any
	Action    string    `json:"action"`   // "allow" or "deny"
	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority"` // lower = evaluated first
	CreatedAt time.Time `json:"created_at"`
}
