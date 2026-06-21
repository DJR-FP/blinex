//go:build linux

package wgmgr

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func (m *Manager) setKernelAddress(cidr string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return fmt.Errorf("link %q not found: %w", m.ifaceName, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", cidr, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("setting address: %w", err)
	}
	return netlink.LinkSetUp(link)
}

func (m *Manager) cleanupKernelTUN() {
	link, err := netlink.LinkByName(m.ifaceName)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
}
