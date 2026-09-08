//go:build windows

package acl

import (
	"fmt"
	"sync"

	commonv1 "github.com/blinex/gen/common/v1"
)

// RuleApplier is implemented by wgmgr's Windows ACL packet filter
// (aclFilterTUN). Declared here rather than imported directly to avoid a
// client/internal/acl <-> client/internal/wgmgr import cycle — wgmgr already
// depends on nothing in acl, and registering a filter instance by interface
// name is all this package needs from it.
type RuleApplier interface {
	SetRules(rules []*commonv1.Rule)
	ClearRules()
}

var (
	mu      sync.Mutex
	filters = map[string]RuleApplier{}
)

// RegisterFilter makes a Windows ACL packet filter reachable by interface
// name, so EnsureChain/ApplyRules (called from engine.go exactly like the
// Linux iptables path, no call-site changes needed) can find it. Called from
// wgmgr's tun_windows.go right after the wintun adapter is created.
func RegisterFilter(iface string, f RuleApplier) {
	mu.Lock()
	filters[iface] = f
	mu.Unlock()
}

// UnregisterFilter removes a filter registered by RegisterFilter, called on
// interface teardown.
func UnregisterFilter(iface string) {
	mu.Lock()
	delete(filters, iface)
	mu.Unlock()
}

// EnsureChain is a no-op on Windows: unlike the iptables chain it mirrors,
// there's nothing to pre-create — the filter already exists once the wintun
// adapter itself does, wired up by tun_windows.go.
func EnsureChain(_ string) error { return nil }

// ApplyRules installs a new ACL policy on the registered filter for iface.
// Called on every sync, same cadence as the Linux path flushing and
// reinstalling the iptables chain (see acl_linux.go's ApplyRules doc).
func ApplyRules(rules []*commonv1.Rule, iface string) error {
	mu.Lock()
	f := filters[iface]
	mu.Unlock()
	if f == nil {
		return fmt.Errorf("no ACL filter registered for interface %q (not up yet?)", iface)
	}
	f.SetRules(rules)
	return nil
}

// RemoveChain clears the installed policy, matching Linux's RemoveChain:
// once torn down, traffic reverts to whatever the OS would otherwise allow
// (no BLINEX-ACL chain means the base INPUT/FORWARD ACCEPT policy applies on
// Linux; here it means the filter goes back to its pre-first-sync
// let-everything-through state).
func RemoveChain(iface string) {
	mu.Lock()
	f := filters[iface]
	mu.Unlock()
	if f != nil {
		f.ClearRules()
	}
}
