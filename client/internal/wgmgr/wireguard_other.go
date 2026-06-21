//go:build !linux

package wgmgr

func (m *Manager) setKernelAddress(_ string) error {
	// Non-Linux always uses netstack mode; this should never be called.
	return nil
}

func (m *Manager) cleanupKernelTUN() {}
