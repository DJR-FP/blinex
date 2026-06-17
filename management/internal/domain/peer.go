package domain

import "time"

type Peer struct {
	ID         string
	AccountID  string
	WGPubKey   string // base64 WireGuard public key
	IP         string // assigned CGNAT IP, e.g. "100.64.0.5"
	Hostname   string
	OS         string
	Kernel     string
	DNSLabel   string // slug used in Magic DNS, e.g. "laptop"
	AllowedIPs []string
	Connected  bool
	LastSeen   time.Time
	CreatedAt  time.Time
}
