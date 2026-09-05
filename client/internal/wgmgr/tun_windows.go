//go:build windows

package wgmgr

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/tun"
)

// createTUN creates a real Windows network adapter via the wintun driver,
// giving Windows peers a normal kernel interface — and OS-level reachability
// (ping, RDP, any app) to the mesh — instead of the userspace-only netstack
// every Windows agent used until now.
func createTUN(ifaceName string) (tun.Device, error) {
	if err := ensureWintunDLL(); err != nil {
		return nil, fmt.Errorf("wintun.dll: %w", err)
	}
	return tun.CreateTUN(ifaceName, defaultMTU)
}

// isTUNUnavailable is always true on Windows: any failure to create the
// wintun adapter (missing driver certificate trust, not running elevated,
// etc.) falls back to userspace netstack mode instead of refusing to start —
// the same safety net every Windows install has relied on until now.
func isTUNUnavailable(_ error) bool { return true }

func createNetstackTUN(addr netip.Addr) (tun.Device, *RoutingNet, error) {
	return createRoutingNetTUN(addr, defaultMTU)
}

// ensureWintunDLL extracts our embedded copy of wintun.dll next to the
// running executable. Windows only searches the application directory and
// System32 for a DLL a process loads by name (never PATH), and wintun.dll
// is not a Windows system component — so without this, tun.CreateTUN's
// LoadLibrary call fails on every machine that hasn't separately installed
// WireGuard or Wintun itself.
func ensureWintunDLL() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own executable: %w", err)
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if info, err := os.Stat(dst); err == nil && info.Size() == int64(len(wintunDLL)) {
		return nil
	}
	if err := os.WriteFile(dst, wintunDLL, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	log.Info().Str("path", dst).Msg("wintun: extracted driver DLL next to executable")
	return nil
}
