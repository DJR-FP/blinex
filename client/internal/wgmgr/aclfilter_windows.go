//go:build windows

package wgmgr

import (
	"sync"

	commonv1 "github.com/blinex/gen/common/v1"
	"golang.zx2c4.com/wireguard/tun"
)

// aclFilterTUN wraps a real kernel tun.Device to enforce ACL policy on
// Windows, which has no equivalent of the iptables BLINEX-ACL chain Linux
// peers use (see acl_linux.go). Windows Firewall can't substitute for it:
// its block rules always take precedence over allow rules regardless of
// scope or creation order, so there's no way to express "default deny, a
// few specific allows" the way an ordered iptables chain does. Instead this
// filters in the same place wireguard-go itself sits — decrypted packets
// pass through Write() on their way into the OS (both traffic destined for
// this host and traffic being forwarded onward as a subnet router/exit
// node, exactly the set BLINEX-ACL covers via its INPUT+FORWARD hooks) — so
// evaluation order and default-deny semantics are just Go code (see
// aclfilter.go's aclFilterAllows), matching buildIPTablesArgs' matching
// precisely rather than approximating it.
//
// Read() (packets leaving this host, outbound to a peer) is intentionally
// left unfiltered — BLINEX-ACL isn't hooked to OUTPUT either, so a peer can
// always originate traffic; only what other peers may send it is policed.
type aclFilterTUN struct {
	tun.Device

	mu       sync.RWMutex
	rules    []*commonv1.Rule
	rulesSet bool // false until the first ApplyRules call — see Write()
}

func newACLFilterTUN(inner tun.Device) *aclFilterTUN {
	return &aclFilterTUN{Device: inner}
}

// SetRules installs a new ACL policy, replacing whatever was there before.
// Called from acl_windows.go's ApplyRules on every sync, same cadence as
// acl_linux.go's ApplyRules flushing and reinstalling the iptables chain.
// A sync with zero rules still means a policy is active (deny-all, same as
// Linux's ApplyRules([]) installing just the terminal DROP) — protobuf
// deserializes an empty repeated field as a nil slice, so nil rules here is
// NOT the same as no policy at all; see ClearRules for that case.
func (f *aclFilterTUN) SetRules(rules []*commonv1.Rule) {
	f.mu.Lock()
	f.rules = rules
	f.rulesSet = true
	f.mu.Unlock()
}

// ClearRules reverts to the pre-first-sync let-everything-through state,
// called when the chain itself is torn down (RemoveChain) rather than when
// policy is merely updated to zero rules (SetRules(nil) from a real sync).
func (f *aclFilterTUN) ClearRules() {
	f.mu.Lock()
	f.rules = nil
	f.rulesSet = false
	f.mu.Unlock()
}

func (f *aclFilterTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.RLock()
	rules, rulesSet := f.rules, f.rulesSet
	f.mu.RUnlock()

	// Before the first sync response installs a policy, behave like Linux's
	// OS-level INPUT/FORWARD default-ACCEPT policy before EnsureChain/
	// ApplyRules ever run: let traffic through rather than blocking the
	// agent's own bootstrap.
	if !rulesSet {
		return f.Device.Write(bufs, offset)
	}

	allowed := bufs[:0:0]
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		if aclFilterAllows(b[offset:], rules) {
			allowed = append(allowed, b)
		}
	}
	if len(allowed) == 0 {
		return len(bufs), nil
	}
	// wireguard-go discards the returned count (device/receive.go only checks
	// the error), so reporting the full input length regardless of how many
	// packets were actually dropped is safe and matches a firewall DROP:
	// the caller sees no error, the packet just never arrives.
	_, err := f.Device.Write(allowed, offset)
	return len(bufs), err
}
