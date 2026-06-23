//go:build linux

package wgmgr

import (
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
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
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up link: %w", err)
	}

	// Add a route for the full mesh range so traffic to other peers
	// goes through this interface. The /32 address alone creates no route.
	_, meshNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       meshNet,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		log.Warn().Err(err).Msg("failed to add mesh route")
	} else {
		log.Info().Str("range", "100.64.0.0/10").Str("iface", m.ifaceName).Msg("added mesh route")
	}
	return nil
}

func (m *Manager) cleanupKernelTUN() {
	link, err := netlink.LinkByName(m.ifaceName)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
}
