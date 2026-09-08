//go:build windows

package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// natName is the WinNAT instance this agent owns. WinNAT (New-NetNat) does
// forwarding and NAT together as one Windows-native feature — no separate
// forwarding toggle or Routing and Remote Access setup needed, unlike the
// classic /proc/sys/net/ipv4/ip_forward + iptables MASQUERADE pairing Linux
// uses (see routing_linux.go).
const natName = "BlinexNAT"

// meshCIDR mirrors routing_linux.go's AddMasquerade: NAT is scoped to
// traffic sourced from the mesh range specifically, not every route on the
// box.
const winMeshCIDR = "100.64.0.0/10"

// EnableForwarding is a no-op on Windows: New-NetNat (see AddMasquerade)
// enables forwarding for its internal prefix as part of creating the NAT
// instance itself. Kept so the engine.go call site stays platform-agnostic.
func EnableForwarding() error { return nil }

// AddMasquerade creates the WinNAT instance NATting mesh-sourced traffic
// out whatever interface a forwarded packet's route selects — the same
// semantics as routing_linux.go's `iptables -t nat -A POSTROUTING -s
// 100.64.0.0/10 -j MASQUERADE` (no `-o iface` restriction there either).
// Idempotent — safe to call on every sync.
func AddMasquerade(_ string) error {
	cmd := fmt.Sprintf(
		`if (-not (Get-NetNat -Name %[1]q -ErrorAction SilentlyContinue)) { `+
			`New-NetNat -Name %[1]q -InternalIPInterfaceAddressPrefix %[2]q | Out-Null }`,
		natName, winMeshCIDR)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput(); err != nil {
		return fmt.Errorf("New-NetNat: %w: %s", err, out)
	}
	return nil
}

// RemoveMasquerade tears down the WinNAT instance created by AddMasquerade.
func RemoveMasquerade(_ string) {
	cmd := fmt.Sprintf(`Remove-NetNat -Name %q -Confirm:$false -ErrorAction SilentlyContinue`, natName)
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).Run() //nolint:errcheck
}

// AddRoute installs an OS route for cidr via the named network interface —
// used both for subnet routes advertised by other peers (so this host can
// reach them) and, via activateExitNode, the exit-node split-tunnel /1s.
func AddRoute(cidr, iface string) error {
	cmd := fmt.Sprintf(
		`if (-not (Get-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[2]q -ErrorAction SilentlyContinue)) { `+
			`New-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[2]q | Out-Null }`,
		iface, cidr)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput(); err != nil {
		return fmt.Errorf("New-NetRoute %s via %s: %w: %s", cidr, iface, err, out)
	}
	return nil
}

// RemoveRoute removes the OS route for cidr via the named interface.
// Best-effort; errors are silently ignored, matching routing_linux.go.
func RemoveRoute(cidr, iface string) {
	cmd := fmt.Sprintf(`Remove-NetRoute -InterfaceAlias %q -DestinationPrefix %q -Confirm:$false -ErrorAction SilentlyContinue`, iface, cidr)
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).Run() //nolint:errcheck
}

// GetDefaultGateway returns the IPv4 default route's gateway IP and
// interface alias — the lowest-metric 0.0.0.0/0 route, which is never the
// wintun adapter itself (it only ever carries the mesh /10 route).
func GetDefaultGateway() (net.IP, string, error) {
	cmd := `$r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Sort-Object -Property RouteMetric | Select-Object -First 1; ` +
		`Write-Output ($r.NextHop + "|" + $r.InterfaceAlias)`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("Get-NetRoute default: %w: %s", err, out)
	}
	line := strings.TrimSpace(string(out))
	parts := strings.SplitN(line, "|", 2)
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("unexpected Get-NetRoute output: %q", line)
	}
	ip := net.ParseIP(strings.TrimSpace(parts[0]))
	if ip == nil {
		return nil, "", fmt.Errorf("could not parse gateway IP from %q", line)
	}
	return ip, strings.TrimSpace(parts[1]), nil
}

// AddHostRoute pins a /32 host route for ip via gwIP on the named interface
// — used to keep the management/signal connection on the original gateway
// when an exit node route is active (see engine.go's activateExitNode).
func AddHostRoute(ip, gwIP net.IP, ifaceName string) error {
	dst := ip.String() + "/32"
	cmd := fmt.Sprintf(
		`Remove-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[2]q -Confirm:$false -ErrorAction SilentlyContinue; `+
			`New-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[2]q -NextHop %[3]q | Out-Null`,
		ifaceName, dst, gwIP.String())
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput(); err != nil {
		return fmt.Errorf("pin host route %s via %s: %w: %s", ip, gwIP, err, out)
	}
	return nil
}

// RemoveHostRoute removes the /32 host route for ip on the named interface.
// Best-effort; errors are silently ignored, matching routing_linux.go.
func RemoveHostRoute(ip net.IP, ifaceName string) {
	cmd := fmt.Sprintf(`Remove-NetRoute -InterfaceAlias %q -DestinationPrefix %q -Confirm:$false -ErrorAction SilentlyContinue`, ifaceName, ip.String()+"/32")
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).Run() //nolint:errcheck
}
