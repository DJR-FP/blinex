//go:build !linux && !windows

package wgmgr

func (m *Manager) setKernelAddress(_ string) error {
	// These platforms always use netstack mode; this should never be called.
	return nil
}

func (m *Manager) cleanupKernelTUN() {}

// UsesGlobalDNS reports whether the OS's DNS resolver needs a global
// override rather than a per-link one. True everywhere without a per-link
// implementation (only Linux has one, via resolvectl) — see wireguard_linux.go
// and wireguard_windows.go.
func (m *Manager) UsesGlobalDNS() bool { return true }
