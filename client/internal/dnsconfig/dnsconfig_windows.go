//go:build windows

package dnsconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Windows never has a kernel-TUN interface (see wgmgr's createTUN — it
// always fails on non-Linux), so Apply/Revert (the per-link path) has
// nothing to attach to here. ApplyGlobal is the real implementation.
func Apply(_, _ string) {}
func Revert(_ string)   {}

// backupPath persists the original per-adapter DNS servers so a restart
// after a crash can still restore them later, mirroring the Linux netstack
// approach — only ApplyGlobal writes it, and only if it doesn't already
// exist (see ApplyGlobal for why that matters).
var backupPath = filepath.Join(os.Getenv("ProgramData"), "blinex", "dns-backup.json")

type adapterDNS struct {
	InterfaceIndex  int      `json:"InterfaceIndex"`
	InterfaceAlias  string   `json:"InterfaceAlias"`
	ServerAddresses []string `json:"ServerAddresses"`
}

var globalMu sync.Mutex
var globalRelay *relay

// ApplyGlobal is the Windows netstack path: no real interface exists to
// hang a per-link override off, so instead it starts a UDP relay on :53
// (what Set-DnsClientServerAddress-configured adapters actually query) that
// forwards to the resolver's real listener on :53535, then points every
// "Up" network adapter's DNS servers at 127.0.0.1.
//
// Crash safety is weaker than the kernel-TUN path (no OS-level interface
// teardown to lean on): if the process is killed, the adapters stay pointed
// at 127.0.0.1 with nothing listening until the agent restarts. Unlike the
// Linux services (systemd Restart=on-failure), nothing currently
// auto-restarts a crashed Windows agent — see the roadmap for proper
// service installation. The backup file is written to disk specifically so
// that whenever the agent does come back (even minutes later, started by
// hand), it restores the *real* original DNS rather than treating its own
// override as the original to preserve.
func ApplyGlobal(resolverAddr string) {
	globalMu.Lock()
	defer globalMu.Unlock()

	r := startRelay("127.0.0.1:53", resolverAddr)
	if r == nil {
		return // already logged; leave DNS untouched
	}
	globalRelay = r

	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not create backup directory, skipping DNS takeover")
		return
	}

	// Only back up if no backup exists yet: on a crash-triggered restart, the
	// adapters right now are already pointed at US, not the real original —
	// backing them up here would permanently lose the real original.
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		current, err := queryAdapterDNS()
		if err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not read current adapter DNS settings, skipping DNS takeover")
			return
		}
		data, err := json.Marshal(current)
		if err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not serialize DNS backup")
			return
		}
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			log.Warn().Err(err).Msg("dnsconfig: could not write DNS backup")
			return
		}
	}

	backup, err := readBackup()
	if err != nil {
		log.Warn().Err(err).Msg("dnsconfig: could not read DNS backup, skipping DNS takeover")
		return
	}
	applied := 0
	for _, a := range backup {
		if err := setAdapterDNS(a.InterfaceIndex, []string{"127.0.0.1"}); err != nil {
			log.Warn().Err(err).Str("adapter", a.InterfaceAlias).Msg("dnsconfig: failed to set adapter DNS")
			continue
		}
		applied++
	}
	log.Info().Int("adapters", applied).Str("resolver", resolverAddr).Msg("dnsconfig: system DNS now routed through the agent (global override)")
}

// RecoverStaleGlobalOverride restores adapter DNS from a leftover backup
// file *before* enrollment is attempted — breaking a real deadlock verified
// live: if a previous run's revert-on-shutdown fails (confirmed happening —
// Windows tears down the CIM/WMI provider these PowerShell calls need before
// giving services a chance to finish cleanup), adapters stay pointed at
// 127.0.0.1 with nothing listening. ApplyGlobal's own recovery only helps
// once the agent has already enrolled — but enrolling needs to resolve the
// management server's hostname, which is exactly what stale DNS breaks, so
// nothing here ever reaches ApplyGlobal again on its own. Call this once at
// startup, before the first enrollment attempt.
func RecoverStaleGlobalOverride() {
	globalMu.Lock()
	defer globalMu.Unlock()

	backup, err := readBackup()
	if err != nil {
		return // no leftover state — nothing to recover
	}
	for _, a := range backup {
		if len(a.ServerAddresses) == 0 {
			exec.Command("powershell", "-NoProfile", "-Command",
				"Set-DnsClientServerAddress -InterfaceIndex "+strconv.Itoa(a.InterfaceIndex)+" -ResetServerAddresses").Run() //nolint:errcheck
			continue
		}
		if err := setAdapterDNS(a.InterfaceIndex, a.ServerAddresses); err != nil {
			log.Warn().Err(err).Str("adapter", a.InterfaceAlias).Msg("dnsconfig: failed to recover stale adapter DNS at startup")
		}
	}
	log.Info().Msg("dnsconfig: recovered adapter DNS left stuck by a previous unclean shutdown")
	// Deliberately not removing the backup file: ApplyGlobal will run again
	// shortly (after this startup's own enrollment succeeds) and re-apply
	// the override using this same backup as the source of truth for the
	// real original settings, exactly as it would on any other restart.
}

// RevertGlobal undoes ApplyGlobal on a clean shutdown.
func RevertGlobal() {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalRelay != nil {
		globalRelay.Close()
		globalRelay = nil
	}
	backup, err := readBackup()
	if err != nil {
		return // never applied, or already reverted
	}
	// Track success per adapter rather than assuming it: during a system
	// shutdown/reboot, Windows tears down the CIM/WMI provider these
	// PowerShell calls depend on before giving services a chance to finish
	// cleanup, so a revert attempt can fail here — verified live (a
	// CimJob_BrokenCimSession error mid-reboot left every adapter stuck on
	// 127.0.0.1 with nothing behind it, breaking DNS resolution entirely on
	// the next boot, for as long as nobody noticed). Only clear the backup
	// file when every adapter actually reverted, so a startup that finds a
	// leftover backup — because a previous revert partially failed — still
	// has the real original settings to restore instead of losing them.
	allOK := true
	for _, a := range backup {
		var restoreErr error
		if len(a.ServerAddresses) == 0 {
			restoreErr = exec.Command("powershell", "-NoProfile", "-Command",
				"Set-DnsClientServerAddress -InterfaceIndex "+strconv.Itoa(a.InterfaceIndex)+" -ResetServerAddresses").Run()
		} else {
			restoreErr = setAdapterDNS(a.InterfaceIndex, a.ServerAddresses)
		}
		if restoreErr != nil {
			log.Warn().Err(restoreErr).Str("adapter", a.InterfaceAlias).Msg("dnsconfig: failed to restore adapter DNS")
			allOK = false
		}
	}
	if !allOK {
		log.Warn().Msg("dnsconfig: DNS restore incomplete — leaving the backup file in place so the next startup can retry with the real original settings")
		return
	}
	_ = os.Remove(backupPath)
	log.Info().Msg("dnsconfig: restored original adapter DNS settings")
}

func readBackup() ([]adapterDNS, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, err
	}
	var backup []adapterDNS
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, err
	}
	return backup, nil
}

func queryAdapterDNS() ([]adapterDNS, error) {
	script := `Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
		$dns = Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4
		[PSCustomObject]@{InterfaceIndex=$_.InterfaceIndex; InterfaceAlias=$_.Name; ServerAddresses=@($dns.ServerAddresses)}
	} | ConvertTo-Json`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil, err
	}
	var adapters []adapterDNS
	// A single "Up" adapter serializes to a JSON object, not an array —
	// PowerShell's ConvertTo-Json quirk. Try array first, fall back to one.
	if err := json.Unmarshal(out, &adapters); err != nil {
		var single adapterDNS
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, err
		}
		adapters = []adapterDNS{single}
	}
	return adapters, nil
}

func setAdapterDNS(interfaceIndex int, servers []string) error {
	script := "Set-DnsClientServerAddress -InterfaceIndex " + strconv.Itoa(interfaceIndex) + " -ServerAddresses " + psStringArray(servers)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// psStringArray renders a Go string slice as a PowerShell array literal,
// e.g. ["127.0.0.1"] -> @('127.0.0.1'). Every value here comes from our own
// relay address or from IPs PowerShell itself reported back to us (never
// free-form user input), so a plain single-quote escape is sufficient.
func psStringArray(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}
