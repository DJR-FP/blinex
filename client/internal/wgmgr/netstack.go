//go:build linux

package wgmgr

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// createTUN attempts to create a kernel TUN device. If /dev/net/tun is
// missing it tries to create the device node (works in privileged LXC).
// Returns the TUN device or an error.
func createTUN(ifaceName string) (tun.Device, error) {
	tunDev, err := tun.CreateTUN(ifaceName, defaultMTU)
	if err == nil {
		return tunDev, nil
	}

	if !isTUNUnavailable(err) {
		return nil, err
	}

	log.Warn().Msg("/dev/net/tun not available, attempting to create it")
	if mkErr := os.MkdirAll("/dev/net", 0755); mkErr != nil {
		return nil, fmt.Errorf("creating TUN %q: %w (also failed to mkdir /dev/net: %v)", ifaceName, err, mkErr)
	}
	// mknod /dev/net/tun c 10 200
	if mkErr := mknodTUN(); mkErr != nil {
		return nil, fmt.Errorf("creating TUN %q: %w (also failed to mknod: %v)", ifaceName, err, mkErr)
	}

	return tun.CreateTUN(ifaceName, defaultMTU)
}

// createNetstackTUN creates a userspace TUN via gVisor netstack.
// The address must be known at creation time.
func createNetstackTUN(addr netip.Addr) (tun.Device, *netstack.Net, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{addr},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		defaultMTU,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating netstack TUN: %w", err)
	}
	return tunDev, tnet, nil
}

func isTUNUnavailable(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "/dev/net/tun") &&
		(strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file"))
}
