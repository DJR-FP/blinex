package domain

import "time"

type Peer struct {
	ID               string    `json:"id"`
	AccountID        string    `json:"account_id"`
	WGPubKey         string    `json:"wg_pub_key"`
	IP               string    `json:"ip"`
	Hostname         string    `json:"hostname"`
	OS               string    `json:"os"`
	Kernel           string    `json:"kernel"`
	DNSLabel         string    `json:"dns_label"`
	Tags             []string  `json:"tags"`
	AllowedIPs       []string  `json:"allowed_ips"`
	AdvertisedRoutes []string  `json:"advertised_routes"` // CIDRs this peer advertises to the mesh
	Connected        bool      `json:"connected"`
	LastSeen         time.Time `json:"last_seen"`
	CreatedAt        time.Time `json:"created_at"`
}
