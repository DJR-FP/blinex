//go:build !linux

package wgmgr

import (
	"fmt"
	"net/netip"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

// createTUN always fails on non-Linux platforms since kernel TUN is not supported.
func createTUN(_ string) (tun.Device, error) {
	return nil, fmt.Errorf("/dev/net/tun does not exist on %s — using netstack", runtime.GOOS)
}

func isTUNUnavailable(_ error) bool { return true }

func mknodTUN() error { return fmt.Errorf("mknod not supported on %s", runtime.GOOS) }

func createNetstackTUN(addr netip.Addr) (tun.Device, *RoutingNet, error) {
	return createRoutingNetTUN(addr, defaultMTU)
}
