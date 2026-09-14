//go:build windows

package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// natName is the WinNAT instance this agent owns.
//
// WinNAT does NOT stand in for forwarding, contrary to what this file
// originally assumed. Verified live on Windows 10 Pro 22H2: with a NAT
// instance requested and routes advertised, every interface still reported
// `Forwarding: Disabled` and no mesh→LAN packet was ever forwarded. Windows
// routes between two interfaces only when forwarding is enabled on them, the
// same way Linux needs ip_forward on top of an iptables MASQUERADE rule — NAT
// rewrites addresses, it does not make the host a router. EnableForwarding
// below therefore does real work, and is not the no-op it used to be.
const natName = "BlinexNAT"

// meshCIDR mirrors routing_linux.go's AddMasquerade: NAT is scoped to
// traffic sourced from the mesh range specifically, not every route on the
// box.
const winMeshCIDR = "100.64.0.0/10"

// EnableForwarding turns on IPv4 forwarding, the Windows analogue of
// routing_linux.go writing 1 to /proc/sys/net/ipv4/ip_forward.
//
// Linux's switch is global; Windows has no single equivalent that takes
// effect without a reboot (the IPEnableRouter registry value needs one), so
// this sets the per-interface flag on every connected non-loopback interface
// instead. That is the same reachable set as the global flag, and it applies
// immediately. Both the ingress interface (the mesh device a forwarded packet
// arrives on) and the egress interface (the LAN it leaves by) need it, which
// is why this cannot be narrowed to the WireGuard interface alone.
func EnableForwarding() error {
	const cmd = `Get-NetIPInterface -AddressFamily IPv4 | ` +
		`Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -notlike 'Loopback*' } | ` +
		`Set-NetIPInterface -Forwarding Enabled -ErrorAction Stop`
	if out, err := powershell(cmd); err != nil {
		return fmt.Errorf("Set-NetIPInterface -Forwarding Enabled: %w: %s", err, out)
	}
	return nil
}

// winNATAvailable reports whether this Windows installation actually has the
// WinNAT CIM class registered.
//
// It is not present everywhere. On a stock Windows 10 Pro 22H2 with no
// Hyper-V or Containers feature installed, `Get-CimClass MSFT_NetNat` finds
// nothing and every New-NetNat call fails with "Invalid class"
// (HRESULT 0x80041010) — confirmed live, which is how the missing-NAT case
// was found at all. Checking first lets AddMasquerade say what is actually
// wrong instead of surfacing a CIM error that names no remedy.
func winNATAvailable() bool {
	out, err := powershell(`if (Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_NetNat ` +
		`-ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`)
	return err == nil && strings.Contains(string(out), "yes")
}

func powershell(cmd string) ([]byte, error) {
	return exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
}

// AddMasquerade creates the WinNAT instance NATting mesh-sourced traffic
// out whatever interface a forwarded packet's route selects — the same
// semantics as routing_linux.go's `iptables -t nat -A POSTROUTING -s
// 100.64.0.0/10 -j MASQUERADE` (no `-o iface` restriction there either).
// Idempotent — safe to call on every sync.
func AddMasquerade(_ string) error {
	if !winNATAvailable() {
		return fmt.Errorf("WinNAT is not available on this Windows installation " +
			"(the MSFT_NetNat CIM class is not registered), so mesh traffic cannot be " +
			"NATted onto the LAN. Enable the optional feature that provides it — " +
			"Hyper-V or Containers — or give the LAN router a static route for " +
			"100.64.0.0/10 via this host and NAT is not needed")
	}
	cmd := fmt.Sprintf(
		`if (-not (Get-NetNat -Name %[1]q -ErrorAction SilentlyContinue)) { `+
			`New-NetNat -Name %[1]q -InternalIPInterfaceAddressPrefix %[2]q | Out-Null }`,
		natName, winMeshCIDR)
	if out, err := powershell(cmd); err != nil {
		return fmt.Errorf("New-NetNat: %w: %s", err, out)
	}
	return nil
}

// RemoveMasquerade tears down the WinNAT instance created by AddMasquerade.
func RemoveMasquerade(_ string) {
	if !winNATAvailable() {
		return // nothing was ever created
	}
	cmd := fmt.Sprintf(`Remove-NetNat -Name %q -Confirm:$false -ErrorAction SilentlyContinue`, natName)
	_, _ = powershell(cmd)
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
