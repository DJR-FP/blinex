//go:build windows

package wgmgr

import (
	"fmt"
	"net/netip"
	"os/exec"
	"time"

	"github.com/blinex/client/internal/acl"
	"github.com/rs/zerolog/log"
)

// meshCIDR is the whole mesh address range. A single /32 address alone
// creates no route to any other peer — mirrors wireguard_linux.go's
// equivalent hardcoded route via netlink.
const meshCIDR = "100.64.0.0/10"

// setKernelAddress assigns the peer's mesh IP to the wintun adapter and adds
// a route for the full mesh range, via PowerShell's networking cmdlets
// (consistent with how dnsconfig_windows.go already manages this OS).
// New-NetIPAddress can briefly fail to see a just-created wintun adapter
// before NDIS finishes registering it, so this retries rather than failing
// outright on the first attempt.
//
// A freshly created adapter also defaults to the "Public" firewall profile,
// which blocks unsolicited inbound traffic (including ICMP echo) by
// default — verified live that this is exactly why a peer could ping out
// through the tunnel but never be pinged: ICE's own connectivity checks
// proved the tunnel was healthy in both directions, so the packets were
// arriving and being silently dropped by the OS firewall, not lost in
// transit. Setting the adapter to "Private" (the mesh is a trusted network,
// same reasoning Tailscale/WireGuard-for-Windows apply) plus one explicit,
// interface-scoped allow rule for ICMPv4 echo covers both the default case
// and any policy that overrides the profile default.
func (m *Manager) setKernelAddress(cidr string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", cidr, err)
	}
	ip := prefix.Addr().String()

	cmd := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; `+
			`Remove-NetIPAddress -InterfaceAlias %[1]q -Confirm:$false -ErrorAction SilentlyContinue; `+
			`New-NetIPAddress -InterfaceAlias %[1]q -IPAddress %[2]q -PrefixLength 32 | Out-Null; `+
			`if (-not (Get-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[3]q -ErrorAction SilentlyContinue)) { `+
			`New-NetRoute -InterfaceAlias %[1]q -DestinationPrefix %[3]q | Out-Null }; `+
			`Set-NetConnectionProfile -InterfaceAlias %[1]q -NetworkCategory Private -ErrorAction SilentlyContinue; `+
			`if (-not (Get-NetFirewallRule -DisplayName %[4]q -ErrorAction SilentlyContinue)) { `+
			`New-NetFirewallRule -DisplayName %[4]q -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -InterfaceAlias %[1]q | Out-Null }`,
		m.ifaceName, ip, meshCIDR, "Blinex Mesh (ICMPv4-In)")

	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
		if err == nil {
			log.Info().Str("iface", m.ifaceName).Str("addr", ip).Str("range", meshCIDR).Msg("configured wintun interface and mesh route")
			return nil
		}
		lastErr = fmt.Errorf("%w: %s", err, out)
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("configuring interface %q after retries: %w", m.ifaceName, lastErr)
}

// cleanupKernelTUN unregisters this interface's ACL filter (see
// tun_windows.go's createTUN) so a later reinstall doesn't reuse a stale
// entry — the adapter's own IP configuration needs no equivalent cleanup
// here: closing it (done by the tun.Device's own Close, called before this)
// already tears that down, unlike Linux where the kernel interface itself
// persists unless explicitly deleted.
func (m *Manager) cleanupKernelTUN() {
	acl.UnregisterFilter(m.ifaceName)
}

// UsesGlobalDNS reports whether the OS's DNS resolver needs a global
// override rather than a per-link one. Always true on Windows, kernel-TUN
// or not — there is no per-link Windows implementation (see
// dnsconfig_windows.go), only the global override.
func (m *Manager) UsesGlobalDNS() bool { return true }
