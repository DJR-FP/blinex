package routing

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
)

// EnableForwarding turns on IPv4 packet forwarding so this device can act as a
// router for advertised subnets or as an exit node.
func EnableForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

// AddMasquerade adds an iptables POSTROUTING MASQUERADE rule so that traffic
// forwarded from the mesh is NATted to the device's external IP.
// Idempotent — safe to call multiple times.
func AddMasquerade() error {
	// Check first to avoid duplicate rules.
	if exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-j", "MASQUERADE").Run() == nil {
		return nil
	}
	out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables masquerade: %w: %s", err, out)
	}
	// Accept all forwarded traffic (permissive; fine for a controlled VPN exit node).
	exec.Command("iptables", "-I", "FORWARD", "-j", "ACCEPT").Run() //nolint:errcheck
	return nil
}

// RemoveMasquerade removes the masquerade rule set by AddMasquerade.
func RemoveMasquerade() {
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE").Run() //nolint:errcheck
	exec.Command("iptables", "-D", "FORWARD", "-j", "ACCEPT").Run()                      //nolint:errcheck
}

// AddRoute installs an OS route for cidr via the named network interface.
func AddRoute(cidr, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %q: %w", iface, err)
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	})
}

// RemoveRoute removes the OS route for cidr via the named interface.
// Best-effort; errors are silently ignored.
func RemoveRoute(cidr, iface string) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	netlink.RouteDel(&netlink.Route{ //nolint:errcheck
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	})
}
