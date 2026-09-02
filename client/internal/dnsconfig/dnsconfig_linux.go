//go:build linux

// Package dnsconfig points the OS at the agent's own Magic DNS resolver, the
// way NetBird/Tailscale's MagicDNS does — without this, Magic DNS hostnames
// and malicious-domain filtering only work if a user manually reconfigures
// their system DNS, which most people never do. "Protected by default" only
// holds if the OS is actually asking the agent's resolver.
package dnsconfig

import (
	"os/exec"

	"github.com/rs/zerolog/log"
)

// Apply makes iface (a real kernel WireGuard interface) the system's default
// DNS route via systemd-resolved: resolverAddr answers every query, not just
// mesh hostnames. It is a no-op (with a warning) if resolvectl isn't
// available — e.g. a distro without systemd-resolved — rather than a hard
// failure, since the mesh itself works fine without it.
//
// Crash safety: this is deliberately per-link (blinex0), not a global
// override. If the agent dies uncleanly, the kernel destroys the
// non-persistent TUN device, and systemd-resolved drops the per-link DNS
// config the instant the link disappears — verified live: a SIGKILL leaves
// the rest of the system resolving normally within seconds, no stuck DNS,
// no manual recovery needed. That property is why this only targets a real
// kernel interface (netstack peers have no link for the OS to tie the
// override's lifetime to, and need a different approach — not yet built).
func Apply(iface, resolverAddr string) {
	if !available() {
		log.Warn().Msg("dnsconfig: resolvectl not found, skipping automatic DNS configuration (Magic DNS/domain filtering will only apply if you point your system DNS at the agent manually)")
		return
	}
	if out, err := exec.Command("resolvectl", "dns", iface, resolverAddr).CombinedOutput(); err != nil {
		log.Warn().Err(err).Str("output", string(out)).Msg("dnsconfig: resolvectl dns failed")
		return
	}
	// "~." is systemd-resolved's syntax for "route every query through this
	// link's DNS server" (a routing-only domain, not a search suffix) — it's
	// what makes this the *default* resolver rather than a split-DNS
	// exception for one suffix.
	if out, err := exec.Command("resolvectl", "domain", iface, "~.").CombinedOutput(); err != nil {
		log.Warn().Err(err).Str("output", string(out)).Msg("dnsconfig: resolvectl domain failed")
		return
	}
	log.Info().Str("iface", iface).Str("resolver", resolverAddr).Msg("dnsconfig: system DNS now routed through the agent")
}

// Revert undoes Apply on a clean shutdown. Best-effort: if the interface is
// already gone (the common path — Close() has usually torn down the TUN
// device by the time this runs) resolvectl has nothing to revert and errors,
// which is expected and not logged as a failure.
func Revert(iface string) {
	if !available() {
		return
	}
	exec.Command("resolvectl", "revert", iface).Run() //nolint:errcheck
}

func available() bool {
	_, err := exec.LookPath("resolvectl")
	return err == nil
}
