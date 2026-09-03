//go:build linux

// Package dnsconfig points the OS at the agent's own Magic DNS resolver, the
// way NetBird/Tailscale's MagicDNS does — without this, Magic DNS hostnames
// and malicious-domain filtering only work if a user manually reconfigures
// their system DNS, which most people never do. "Protected by default" only
// holds if the OS is actually asking the agent's resolver.
package dnsconfig

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

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
// override's lifetime to — see ApplyGlobal for that case).
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

// resolvBackupPath holds a copy of /etc/resolv.conf from before ApplyGlobal
// overwrote it, so RevertGlobal can put it back. Only ApplyGlobal writes this
// file, and only when it doesn't already exist — see ApplyGlobal for why.
const resolvBackupPath = "/etc/blinex/resolv.conf.bak"

var globalMu sync.Mutex
var globalRelay *relay

// ApplyGlobal is the netstack-mode equivalent of Apply: netstack peers
// (unprivileged LXC, and Windows/macOS via their own implementations) have
// no real network interface, so there's nothing to attach a per-link DNS
// override to — resolvectl's own routing-domain mechanism doesn't help
// either, since plenty of these hosts (verified live: a Proxmox-managed LXC
// container) have systemd-resolved running but /etc/resolv.conf is a plain
// static file that never reads from it. The only thing that reliably works
// everywhere is what every one of these systems already falls back to: a
// literal /etc/resolv.conf pointing at 127.0.0.1, backed by a real listener
// on port 53 (the resolver itself binds the unprivileged 53535 so the agent
// doesn't need root just to start; ApplyGlobal relays 53 → 53535).
//
// Crash safety here is weaker than Apply's free ride from OS interface
// teardown — there's no interface to disappear. It leans on two things
// instead: systemd's Restart=on-failure (confirmed present on both Linux
// test peers, 3s restart delay) means a crashed agent's relay comes back
// within seconds, and the backup-only-if-absent rule below means a restart
// after a crash never overwrites the *real* original resolv.conf with our
// own override — so however many times the process restarts, RevertGlobal
// still restores the actual original when it finally runs cleanly.
func ApplyGlobal(resolverAddr string) {
	globalMu.Lock()
	defer globalMu.Unlock()

	r := startRelay("127.0.0.1:53", resolverAddr)
	if r == nil {
		return // already logged; leave DNS untouched
	}
	globalRelay = r

	if err := os.MkdirAll("/etc/blinex", 0755); err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not create /etc/blinex, skipping resolv.conf takeover")
		return
	}
	// Only back up if no backup exists yet: on a crash-triggered restart, the
	// file on disk right now is already OUR override, not the real original —
	// backing it up here would permanently lose the real original.
	if _, err := os.Stat(resolvBackupPath); os.IsNotExist(err) {
		current, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not read /etc/resolv.conf to back it up, skipping resolv.conf takeover")
			return
		}
		if err := os.WriteFile(resolvBackupPath, current, 0644); err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not write resolv.conf backup, skipping resolv.conf takeover")
			return
		}
	}
	content := fmt.Sprintf("# managed by blinex-agent — original backed up at %s\nnameserver 127.0.0.1\n", resolvBackupPath)
	if err := os.WriteFile("/etc/resolv.conf", []byte(content), 0644); err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not write /etc/resolv.conf")
		return
	}
	log.Info().Str("resolver", resolverAddr).Msg("dnsconfig: system DNS now routed through the agent (global override)")
}

// RevertGlobal undoes ApplyGlobal on a clean shutdown.
func RevertGlobal() {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalRelay != nil {
		globalRelay.Close()
		globalRelay = nil
	}
	backup, err := os.ReadFile(resolvBackupPath)
	if err != nil {
		return // never applied, or already reverted
	}
	if err := os.WriteFile("/etc/resolv.conf", backup, 0644); err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not restore /etc/resolv.conf")
		return
	}
	_ = os.Remove(resolvBackupPath)
	log.Info().Msg("dnsconfig: restored original /etc/resolv.conf")
}
