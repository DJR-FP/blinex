package domain

import "time"

// DefaultGroupName is the group every peer belongs to, always, regardless of
// enrollment path or later reassignment. Seeded per account; not deletable.
const DefaultGroupName = "Default"

// Group is a named collection of peers, used as the src/dst unit in access
// control rules ("group:<name>") and, indirectly, as the reachability
// boundary for advertised routes and exit nodes (both are just ACL-governed
// destinations). Membership lives on the peer (Peer.Groups), not here — a
// Group row exists so a group can be created, renamed, or listed even with
// zero current members, and so setup keys can reference one by name.
type Group struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
