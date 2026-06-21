//go:build !linux

package routing

import (
	"fmt"
	"net"
	"runtime"
)

func EnableForwarding() error {
	return fmt.Errorf("IP forwarding not supported on %s", runtime.GOOS)
}

func AddMasquerade() error {
	return fmt.Errorf("masquerade not supported on %s", runtime.GOOS)
}

func RemoveMasquerade() {}

func AddRoute(cidr, iface string) error {
	return fmt.Errorf("OS routing not supported on %s", runtime.GOOS)
}

func RemoveRoute(cidr, iface string) {}

func GetDefaultGateway() (net.IP, string, error) {
	return nil, "", fmt.Errorf("default gateway lookup not supported on %s", runtime.GOOS)
}

func AddHostRoute(ip, gwIP net.IP, ifaceName string) error {
	return fmt.Errorf("host routes not supported on %s", runtime.GOOS)
}

func RemoveHostRoute(ip net.IP, ifaceName string) {}
